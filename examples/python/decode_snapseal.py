#!/usr/bin/env python3
"""Independent SnapSeal Argon2id v3 reader. MIT, Copyright 2026 ShoGroupSpace.

Requires Python 3.12+, cryptography, argon2-cffi and Pillow. Handles original
lossless PNG packets, including PNGs with an additional photo-recovery channel.
JPEG coefficient recovery belongs to the full TypeScript codec, not this example.
Passwords are requested locally; this module performs no network operations.
"""
from __future__ import annotations

import argparse
import io
import itertools
import json
import re
import unicodedata
import zlib
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image

MAX_SOURCE = 50 * 1024 * 1024
MAX_ENVELOPE = MAX_SOURCE + 4096
MAX_PNG = MAX_ENVELOPE + 1024 * 1024
MAX_CONTAINER = MAX_PNG + 256
MAX_PIXELS = (MAX_ENVELOPE + 18) // 3 + 1024 * 1024
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


class DecodeError(ValueError):
    """Unsupported, malformed or unauthenticated protected file."""


@dataclass(frozen=True)
class DecodedFile:
    data: bytes
    filename: str
    content_kind: str


def _uint(data: bytes, offset: int, size: int = 4, endian: str = "big") -> int:
    if offset < 0 or offset + size > len(data):
        raise DecodeError("Truncated file")
    return int.from_bytes(data[offset:offset + size], endian)


def _unzip(data: bytes) -> bytes:
    # Read only SnapSeal's fixed-name, stored, single-PNG ZIP. Never decompress
    # arbitrary archives or trust attacker-advertised allocation sizes.
    name = b"protected-image.png"
    if len(data) < 98 + 2 * len(name):
        raise DecodeError("Invalid SnapSeal ZIP")
    u16 = lambda at: _uint(data, at, 2, "little")
    u32 = lambda at: _uint(data, at, 4, "little")
    end = len(data) - 22
    size, central = u32(18), u32(end + 16)
    if (u32(0) != 0x04034B50 or u32(end) != 0x06054B50
            or u16(end + 4) or u16(end + 6) or u16(end + 8) != 1
            or u16(end + 10) != 1 or u16(end + 20)
            or u16(4) > 20 or u16(6) or u16(8) or u16(28)
            or u16(26) != len(name) or size != u32(22)
            or not 33 <= size <= MAX_PNG
            or central != 30 + len(name) + size
            or u32(end + 12) != 46 + len(name)
            or central + 46 + len(name) != end):
        raise DecodeError("Unsupported SnapSeal ZIP layout")
    if (u32(central) != 0x02014B50 or u16(central + 6) > 20
            or u16(central + 8) or u16(central + 10)
            or u32(central + 16) != u32(14)
            or u32(central + 20) != size or u32(central + 24) != size
            or u16(central + 28) != len(name) or u16(central + 30)
            or u16(central + 32) or u16(central + 34) or u32(central + 42)
            or data[30:30 + len(name)] != name
            or data[central + 46:central + 46 + len(name)] != name):
        raise DecodeError("Inconsistent ZIP directory")
    png = data[30 + len(name):central]
    if not png.startswith(PNG_MAGIC) or zlib.crc32(png) != u32(14):
        raise DecodeError("Damaged ZIP contents")
    return png


def _rectangles(width: int, height: int, flags: int):
    if width < 512 or height < 256 or flags not in (1, 2, 3):
        raise DecodeError("Invalid artwork layout")
    rectangles = []
    if flags & 1:
        badge_width = min(180, width // 3)
        for y in (8, height - 40):
            for x in (8, width - 8 - badge_width):
                rectangles.append((x, y, badge_width, 32))
    if flags & 2:
        label_width = min(400, width - 32)
        rectangles.append(((width - label_width) // 2, height - 96, label_width, 44))
    return rectangles


def _packet_bytes(rgba: bytes, width: int, height: int, bits: int, rectangles=()):
    value = count = 0
    mask, parts = (1 << bits) - 1, 8 // bits
    for y in range(height):
        spans = sorted((x, x + w) for x, top, w, h in rectangles if top <= y < top + h)
        left = 0
        for start, stop in [*spans, (width, width)]:
            for x in range(left, start):
                at = (y * width + x) * 4
                if rgba[at + 3] != 255:
                    raise DecodeError("Non-opaque packet pixels")
                for channel in rgba[at:at + 3]:
                    value = (value << bits) | (channel & mask)
                    count += 1
                    if count == parts:
                        yield value
                        value = count = 0
            left = max(left, stop)


def extract_envelope(data: bytes) -> bytes:
    if len(data) > MAX_CONTAINER:
        raise DecodeError("Protected file exceeds the size limit")
    if data.startswith(b"SNAPSEAL"):
        _header(data)
        return data
    if data.startswith(b"PK\x03\x04"):
        data = _unzip(data)
    if len(data) > MAX_PNG:
        raise DecodeError("PNG exceeds the size limit")
    if not data.startswith(PNG_MAGIC):
        raise DecodeError("Use the TypeScript codec for JPEG photo recovery")
    if len(data) < 33 or _uint(data, 8) != 13 or data[12:16] != b"IHDR":
        raise DecodeError("Invalid PNG header")
    width, height = _uint(data, 16), _uint(data, 20)
    if not (0 < width <= 16384 and 0 < height <= 16384 and width * height <= MAX_PIXELS):
        raise DecodeError("Unsafe PNG dimensions")
    try:
        # Verify CRCs before pixel decoding. Pillow's default color handling does
        # not apply ICC/gamma transformations; stored channel values stay exact.
        with Image.open(io.BytesIO(data), formats=["PNG"]) as image:
            image.verify()
        with Image.open(io.BytesIO(data), formats=["PNG"]) as image:
            if image.size != (width, height) or getattr(image, "n_frames", 1) != 1:
                raise DecodeError("Unsupported PNG frames")
            rgba = image.convert("RGBA").tobytes()
    except (OSError, ValueError, Image.DecompressionBombError) as error:
        raise DecodeError("Invalid PNG pixels") from error
    for bits in (8, 2):
        prefix = bytes(itertools.islice(_packet_bytes(rgba, width, height, bits), 20))
        styled = prefix.startswith(b"SNAPSEALART")
        if not styled and not prefix.startswith(b"SNAPSEALPNG"):
            continue
        expected = (ord("3") if bits == 8 else ord("4")) if styled else (ord("1") if bits == 8 else ord("2"))
        if prefix[11] != expected:
            raise DecodeError("Unsupported pixel packet version")
        header_size, size = (20 if styled else 16), _uint(prefix, 12)
        rectangles = _rectangles(width, height, prefix[16]) if styled else []
        if styled and prefix[17:20] != b"\0\0\0":
            raise DecodeError("Invalid artwork packet header")
        used = sum(w * h for _, _, w, h in rectangles)
        capacity = (width * height - used) * 3 * bits // 8 - header_size
        limit = MAX_ENVELOPE if styled or bits == 8 else 8 * 1024 * 1024 + 4096
        if not 62 <= size <= min(limit, capacity):
            raise DecodeError("Invalid envelope length")
        stream = _packet_bytes(rgba, width, height, bits, rectangles)
        header = bytes(itertools.islice(stream, header_size))
        if header != prefix[:header_size]:
            raise DecodeError("Inconsistent pixel header")
        envelope = bytes(itertools.islice(stream, size))
        if len(envelope) != size:
            raise DecodeError("Truncated envelope")
        _header(envelope)
        return envelope
    raise DecodeError("No supported lossless SnapSeal packet found")


def _header(data: bytes):
    if not 62 <= len(data) <= MAX_ENVELOPE or data[:8] != b"SNAPSEAL":
        raise DecodeError("Invalid encrypted envelope")
    version = data[8]
    if version != 3:
        raise DecodeError("This example requires an Argon2id v3 file; use the full TypeScript codec for older files")
    if (len(data) < 70 or data[9:12] != b"\x01\x13\x01"
            or _uint(data, 12) != 65536 or _uint(data, 16) != 3):
        raise DecodeError("Unsupported Argon2id profile")
    return version, 48, data[20:36], data[36:48]


def _safe_filename(name: str) -> str:
    name = re.split(r"[/\\]", name)[-1]
    name = re.sub(r'[<>:"|?*\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]', "_", name).strip().rstrip(". ")
    extension = re.search(r"\.[a-zA-Z0-9]{1,16}$", name)
    suffix = extension.group() if extension else ""
    stem = name[:-len(suffix)] if suffix else name
    name = (stem[:180 - len(suffix)] + suffix).rstrip(". ") or "file"
    if re.match(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", name, re.I):
        name = "_" + name
    return name


def _reject_json_constant(value: str):
    raise ValueError(f"Invalid JSON constant: {value}")


def decode_file(data: bytes, password: str) -> DecodedFile:
    envelope = extract_envelope(data)
    version, offset, salt, iv = _header(envelope)
    if not isinstance(password, str) or not 1 <= len(password) <= 256 or len(password.encode("utf-8")) > 1024:
        raise DecodeError("Invalid password length")
    payload = None
    # Match the current reader: exact bytes first; canonical keyboard variants
    # only after authentication failure. Never trim spaces or fold case.
    candidates = dict.fromkeys((password, unicodedata.normalize("NFC", password), unicodedata.normalize("NFD", password)))
    for candidate in candidates:
        secret = candidate.encode("utf-8")
        if len(candidate) > 256 or len(secret) > 1024:
            raise DecodeError("Invalid normalized password length")
        key = hash_secret_raw(secret, salt, time_cost=3, memory_cost=65536,
                              parallelism=1, hash_len=32, type=Type.ID, version=19)
        try:
            payload = AESGCM(key).decrypt(iv, envelope[offset:], envelope[:offset])
            break
        except InvalidTag:
            continue
    if payload is None:
        raise DecodeError("Wrong password or damaged encrypted data")
    length = _uint(payload, 0)
    if not 2 <= length <= 2048 or 4 + length > len(payload):
        raise DecodeError("Invalid authenticated metadata length")
    try:
        metadata = json.loads(payload[4:4 + length].decode("utf-8"), parse_constant=_reject_json_constant)
    except (UnicodeError, ValueError) as error:
        raise DecodeError("Invalid authenticated metadata") from error
    if not isinstance(metadata, dict) or not isinstance(metadata.get("filename"), str) or len(metadata["filename"]) > 2048:
        raise DecodeError("Invalid authenticated filename")
    original = payload[4 + length:]
    if len(original) > MAX_SOURCE:
        raise DecodeError("Restored file exceeds the size limit")
    kind = metadata.get("contentKind")
    if "contentKind" in metadata:
        if kind not in ("file", "text"):
            raise DecodeError("Invalid authenticated content kind")
    else:
        signatures = {"image/png": PNG_MAGIC, "image/jpeg": b"\xff\xd8\xff", "image/gif": b"GIF8", "image/webp": b"RIFF"}
        mime = metadata.get("mimeType")
        if mime not in signatures or not original.startswith(signatures[mime]):
            raise DecodeError("Invalid authenticated image type")
        if mime == "image/webp" and original[8:12] != b"WEBP":
            raise DecodeError("Invalid WebP signature")
        try:
            with Image.open(io.BytesIO(original)) as image:
                w, h = image.size
                if not (0 < w <= 16384 and 0 < h <= 16384 and w * h <= 64 * 1024 * 1024):
                    raise DecodeError("Unsafe restored image dimensions")
        except (OSError, ValueError, Image.DecompressionBombError) as error:
            raise DecodeError("Invalid restored image header") from error
        kind = "image"
    filename = _safe_filename(metadata["filename"])
    if kind == "image":
        extension = {"image/png": "png", "image/jpeg": "jpg", "image/gif": "gif", "image/webp": "webp"}[metadata["mimeType"]]
        stem = re.sub(r"\.[^.]*$", "", filename)[:160].strip().rstrip(". ") or "image"
        filename = f"{stem}.{extension}"
    return DecodedFile(original, filename, kind)


def decode_path(path: Path, password: str) -> DecodedFile:
    # Read at most one byte over the bound, even if a file grows after stat().
    if path.stat().st_size > MAX_CONTAINER:
        raise DecodeError("Protected file exceeds the size limit")
    with path.open("rb") as stream:
        return decode_file(stream.read(MAX_CONTAINER + 1), password)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, default=Path("restored"))
    args = parser.parse_args()
    try:
        result = decode_path(args.input, getpass("Password: "))
        args.out.mkdir(parents=True, exist_ok=True)
        with (args.out / result.filename).open("xb") as output:
            output.write(result.data)
    except (DecodeError, OSError) as error:
        parser.exit(1, f"{error}\n")
    print(f"Restored {result.filename}")


if __name__ == "__main__":
    main()
