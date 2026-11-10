"""Independent Python reader vs Node-generated vectors and real TS PNG output."""
import base64
import io
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
import zipfile

from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "examples/python"))
import decode_snapseal as reader

VECTORS = json.loads((ROOT / "tests/fixtures/vectors/manifest.json").read_text("utf-8"))


def png_packet(envelope, bits, flags=0):
    width, height = (512, 256) if flags else (64, 64)
    pixels = bytearray([128, 128, 128, 255] * width * height)
    prefix = b"SNAPSEALART" + (b"3" if bits == 8 else b"4") if flags else b"SNAPSEALPNG" + (b"1" if bits == 8 else b"2")
    header = prefix + len(envelope).to_bytes(4, "big")
    if flags:
        header += bytes([flags, 0, 0, 0])
    data = header + envelope
    # Independently paint public rectangles and enumerate eligible RGB channels.
    rectangles = []
    if flags & 1:
        for y in [8, height - 40]:
            for x in [8, width - 8 - min(180, width // 3)]:
                rectangles.append((x, y, min(180, width // 3), 32))
    if flags & 2:
        rectangles.append(((width - min(400, width - 32)) // 2, height - 96, min(400, width - 32), 44))
    channels = (value for byte in data for value in ((byte >> shift) & ((1 << bits) - 1) for shift in range(8 - bits, -1, -bits)))
    for y in range(height):
        for x in range(width):
            if any(left <= x < left + w and top <= y < top + h for left, top, w, h in rectangles):
                continue
            for c in range(3):
                value = next(channels, None)
                if value is None:
                    image = Image.frombytes("RGBA", (width, height), bytes(pixels))
                    output = io.BytesIO(); image.save(output, format="PNG")
                    return output.getvalue()
                at = (y * width + x) * 4 + c
                pixels[at] = (pixels[at] & ~((1 << bits) - 1)) | value
    raise AssertionError("Test carrier too small")


def wrap_zip(png):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("protected-image.png", png)
    return output.getvalue()


class PythonDecoderTests(unittest.TestCase):
    def test_native_node_v3_vector_and_all_pixel_layouts(self):
        for vector in VECTORS[2:]:
            envelope = (ROOT / "tests/fixtures/vectors" / vector["file"]).read_bytes()
            expected = base64.b64decode(vector["originalBase64"])
            for bits, flags in [(8, 0), (2, 0), (8, 1), (2, 2), (2, 3)]:
                with self.subTest(version=vector["file"], bits=bits, flags=flags):
                    png = png_packet(envelope, bits, flags)
                    for data in [envelope, png, wrap_zip(png)]:
                        result = reader.decode_file(data, vector["password"])
                        self.assertEqual(result.data, expected)
                        self.assertEqual(result.filename, vector["metadata"]["filename"])

    def test_example_explicitly_requires_v3_without_changing_full_codec(self):
        for vector in VECTORS[:2]:
            envelope = (ROOT / "tests/fixtures/vectors" / vector["file"]).read_bytes()
            with self.assertRaisesRegex(reader.DecodeError, "Argon2id v3"):
                reader.decode_file(envelope, vector["password"])

    def test_wrong_password_and_tampered_tag_never_return_plaintext(self):
        vector = VECTORS[2]
        envelope = (ROOT / "tests/fixtures/vectors" / vector["file"]).read_bytes()
        with self.assertRaises(reader.DecodeError):
            reader.decode_file(envelope, "Wrong password")
        modified = bytearray(envelope); modified[-1] ^= 1
        with self.assertRaises(reader.DecodeError):
            reader.decode_file(bytes(modified), vector["password"])

    def test_hostile_work_factor_rejected_before_derivation(self):
        vector = VECTORS[2]
        envelope = bytearray((ROOT / "tests/fixtures/vectors" / vector["file"]).read_bytes())
        envelope[12:16] = b"\xff" * 4
        with patch.object(reader, "hash_secret_raw", side_effect=AssertionError("KDF must not run")):
            with self.assertRaises(reader.DecodeError):
                reader.decode_file(bytes(envelope), vector["password"])

    def test_zip_crc_paths_extra_entries_and_compression_are_rejected(self):
        vector = VECTORS[2]
        png = png_packet((ROOT / "tests/fixtures/vectors" / vector["file"]).read_bytes(), 8)
        damaged = bytearray(wrap_zip(png)); damaged[55] ^= 1
        with self.assertRaises(reader.DecodeError): reader.extract_envelope(bytes(damaged))
        for name, compression, extra in [("../escape.png", 0, False), ("protected-image.png", 8, False), ("protected-image.png", 0, True)]:
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", compression=compression) as archive:
                archive.writestr(name, png)
                if extra: archive.writestr("other.png", png)
            with self.assertRaises(reader.DecodeError): reader.extract_envelope(output.getvalue())

    def test_jpeg_requires_full_typescript_recovery_reader(self):
        data = (ROOT / "tests/fixtures/jpeg-channel/q60.jpg").read_bytes()
        with self.assertRaisesRegex(reader.DecodeError, "TypeScript"):
            reader.extract_envelope(data)

    def test_huge_dimensions_are_rejected_before_pillow(self):
        png = reader.PNG_MAGIC + struct.pack(">I4sII", 13, b"IHDR", 16384, 16384) + b"\0" * 9
        with patch.object(reader.Image, "open", side_effect=AssertionError("Decoder must not allocate")):
            with self.assertRaises(reader.DecodeError): reader.extract_envelope(png)

    def test_safe_leaf_names_and_windows_device_names(self):
        for source, expected in [("../../note.txt", "note.txt"), ("CON.txt", "_CON.txt"), ("a:b.exe", "a_b.exe"), ("", "file")]:
            self.assertEqual(reader._safe_filename(source), expected)

    def test_real_typescript_anti_compression_png(self):
        manifest_path = ROOT / "tests/fixtures/python/manifest.json"
        fixture = json.loads(manifest_path.read_text("utf-8"))
        result = reader.decode_file((manifest_path.parent / "protected.png").read_bytes(), fixture["password"])
        self.assertEqual(result.data, base64.b64decode(fixture["originalBase64"]))

    def test_authenticated_image_and_binary_file_metadata(self):
        vector = VECTORS[2]
        header = (ROOT / "tests/fixtures/vectors" / vector["file"]).read_bytes()[:48]
        key = reader.hash_secret_raw(vector["password"].encode(), header[20:36],
                                     time_cost=3, memory_cost=65536, parallelism=1,
                                     hash_len=32, type=reader.Type.ID, version=19)
        image = base64.b64decode(VECTORS[0]["originalBase64"])
        for metadata, original, kind, filename in [
            ({"filename": "photo.jpeg", "mimeType": "image/png"}, image, "image", "photo.png"),
            ({"filename": "../data.bin", "contentKind": "file"}, bytes(range(256)), "file", "data.bin"),
        ]:
            meta = json.dumps(metadata).encode()
            payload = len(meta).to_bytes(4, "big") + meta + original
            envelope = header + reader.AESGCM(key).encrypt(header[36:48], payload, header)
            result = reader.decode_file(envelope, vector["password"])
            self.assertEqual((result.data, result.content_kind, result.filename), (original, kind, filename))


if __name__ == "__main__":
    unittest.main()
