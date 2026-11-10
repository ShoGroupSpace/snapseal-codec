# SnapSeal protected PNG containers

## Automatic creation budget (unreleased, November 8, 2026)

Automatic photo recovery is capped at 280,000 **encrypted** bytes, including the
envelope's metadata and authentication overhead. Its existing 1024/1280px
profiles, error correction and exact/Q60/repeated-JPEG validation are unchanged.
The 1280px hard capacity is 293,914 bytes when reserving artwork/guard regions,
or 306,179 undecorated; 320,000 does not fit. Larger automatic outputs use compact
lossless storage instead of selecting a 2560px HD carrier. Standard-capacity
validation can still fall back to file-only output when recovery fails.

This changes creation policy, not the formats or encryption. Explicit `hd`
encoding remains available to compatibility/research callers, and readers retain
existing 2560px HD PNG/JPEG support. The historical HD measurements below remain
format evidence, not the current automatic creation default.

## Optional compression, public artwork and online links (November 7, 2026)

Original-file preservation remains the default. The optional Standard/HD image
compression control creates a JPEG copy **before encryption** and displays its
size. This changes the encrypted input, including transparency/animation where
applicable; it never modifies the source on the device. Switching back to
Original restores the exact source bytes. Non-image files and typed notes are
never passed through this compressor. Targets include authenticated-envelope
overhead, not just the JPEG size.

Branding is enabled by default in the shared UI. The API defaults to undecorated
output for existing integrations. Four logo/name plates and an optional public
label are painted before final output validation. They are **public artwork**,
not authenticated plaintext. Labels are limited to 48 UTF-16 code units, with
control characters removed. Neither decoration is added after channel testing.

Decorated lossless output uses `SNAPSEALART` (11 bytes) followed by ASCII `3`
for 8-bit RGB storage or `4` for 2-bit RGB storage, a four-byte big-endian
envelope length, one byte of flags (bit 0: branding; bit 1: label), and three
zero bytes. The 20-byte header and envelope use a row-major RGB stream,
skipping every pixel in the public artwork rectangles. `styled-packet.ts`
defines the exact geometry and capacity. Images are at least 512 by 256 pixels;
larger lossless canvases grow to include the reserved area.

Decorated JPEG recovery uses **SSJ3**, with the SSJ2 header fields and coding.
It filters the existing spread permutation to exclude all possible artwork
rectangles plus an eight-pixel guard band around each. Header and payload both
use this filtered permutation. Bit density is recalculated from the remaining
blocks, subject to the existing density limit and self-tests. New readers try
SSJ2 and SSJ3; legacy readers remain available. Older SnapSeal versions cannot
read decorated lossless packets or SSJ3. Recipients need the current reader.

The encoder still checks exact recovery after Q60 and Q85→Q60 conversions with
Reed–Solomon safety headroom. Failed tests fall back to a lossless PNG with file
delivery guidance. Passing is a local simulation, not a guarantee about Telegram,
resizing, or another unknown photo pipeline. Branding/label browser tests cover
280,000-byte Standard and 1,000,000-byte HD envelopes on noise, tiger, galaxy,
and flat black artwork. PNG, Q75, Q60 and repeated Q85→Q60 all restored the exact
authenticated bytes in Chromium.

Optional online sharing transports the **raw authenticated envelope**, without
the carrier PNG. `.snapseal` downloads are bounded and parsed with the same
envelope reader before asking for a password. Nothing is decrypted server-side.
Read IDs and deletion tokens are separate random capabilities; the deletion
token is not included in the recipient link. Deployment, retention, abuse limits,
and the isolated verification page are documented in `DEPLOY.md` at the repo root.

A protected image is an ordinary opaque PNG whose RGB pixels encode an
authenticated encrypted envelope. V1 looks like noise; optional V2 retains a
recognizable cover picture. Both can contain either encryption envelope below:
v1 for images, or v2 for arbitrary files/text. Pixel-container and encryption
versions are separate fields and must not be confused.
The format does not
depend on a PNG metadata chunk, filename, browser storage, account or backend.
The hosted transport remains separate. Unreleased hosted-helper hardening now
places the same v3 Argon2id envelope in its existing `ciphertextBase64` field, with
duplicated salt/IV/work-factor metadata checked against the authenticated header.
Its reader retains bounded fallback for historical raw AES-GCM ciphertext. Older
hosted clients cannot read this new output; the hosted platform stays disabled.

## V1 pixel container (noise)

Read pixels left to right, top to bottom, then R, G, B per pixel. Alpha is 255.
The byte stream is:

| Field | Size | Meaning |
| --- | --- | --- |
| Magic | 12 bytes | ASCII `SNAPSEALPNG1` |
| Envelope length | 4 bytes | Unsigned big-endian |
| Envelope | Given length | Encrypted envelope below |
| Padding | Remaining channels | Zeroes; ignored |

The encoder uses a width between 64 and 2048 pixels and enough rows for the
payload. These dimensions do not match the source image and are not required
for decoding. The decoder bounds PNG dimensions and pixel count before decoding
to limit memory use. RGB values must remain exact; decoding does not repair
lossy edits. Pixel-preserving PNG re-encoding can change compression or metadata.

## V2 pixel container (cover picture)

The same packet layout uses the 12-byte ASCII magic `SNAPSEALPNG2`. Each packet
byte is split into four pairs of bits, most significant pair first. Store each
pair in the two least significant bits of successive R, G and B channels, in
row-major order; skip alpha. Preserve each channel's upper six bits. Each changed
channel differs from the rendered cover by at most 3. All alpha values are 255.
That bound describes only the low-bit storage step; the optional DCT recovery
copy below also modifies the visible cover, sometimes noticeably.

Capacity in bytes is `floor(width * height * 3 / 4)`, including the 16-byte pixel
header. The decoder detects V1 or V2 from the magic, checks the version-specific
envelope limit and available capacity, and validates every used pixel's alpha
(including header and final partial pixel) before allocating the envelope.

V2 accepts original images up to 8 MiB and envelopes up to 8 MiB + 4096 bytes.
Its square carrier is at least 1024 pixels wide, enlarged in multiples of 8 to
fit the packet; the maximum is 3352 square, below 12 megapixels. V1 retains its
50 MiB original-image limit. Both decoders share the existing bounded PNG input
size and decoded pixel count.

Covers are rendered and resized before embedding. The 29 generated presets are
bundled locally in both products. Custom raster covers are limited to 8 MiB,
16 megapixels and 8192 pixels per edge, validated before decoding, flattened onto
white and normalized locally to a 1024-square PNG. Animation and source metadata
are discarded. Visible cover pixels are public and are not authenticated by the
envelope. High-bit-only cover changes can preserve the encrypted payload; changes
to payload bits must pass the existing AES-GCM authentication check.

This is an appearance option, not a claim that encrypted data is undetectable.
The fixed magic and low-bit statistics reveal the format. Resizing, photo
compression, colour correction and JPEG conversion can damage the payload.

## Experimental JPEG recovery copies

The PNG always retains its lossless V2 packet. Eligible cover files additionally
carry the same encrypted envelope in luminance DCT coefficients. The original
private image and its encryption are never resized, recompressed or changed.

New output uses these conservative limits, measured in encrypted bytes:

| Envelope | Cover side / recovery | Noise side / recovery |
| --- | --- | --- |
| 62–3,933 bytes | 1024 / legacy `SNAPSEALJPG1` | 1024 / legacy `SNAPSEALJPG1` |
| 3,934–64,000 bytes | 1280 / `SSJ2` | 1024 / `SSJ2` |
| 64,001–200,000 bytes | 1280 / `SSJ2`, adaptive contrast | 1280 / `SSJ2`, 4× spacing |
| 200,001–280,000 bytes | 1280 / `SSJ2`, adaptive contrast and peak reduction | 1280 / `SSJ2`, 3.75× spacing and peak reduction |
| 280,001–1,000,000 bytes in Auto / HD | 2560 / `SSJ2`, adaptive contrast | 2560 / `SSJ2`, density-based spacing |
| Over 1,000,000 bytes | Lossless capacity / file delivery | Lossless capacity / file delivery |

Standard photo mode attempts recovery through the same 280,000-byte limit for
cover and noise. Automatic, the shared UI default, selects HD (2560 square) for
280,001–1,000,000 encrypted bytes; an explicit HD choice uses 2560 even for a
small input. Standard keeps the old size limit, and File disables the recovery
copy, preserving the cover appearance and compact lossless noise storage.
The byte-only API defaults to Standard for existing integrations; callers opt
into Automatic / HD via the third `recoveryMode` argument.

Cover mode uses a larger carrier for modest payloads to reduce the visible pattern. Above
an effective density of 120,000 bytes per 1280-square frame it tries full contrast, the midpoint between full and
the density-derived contrast, then density-derived contrast. Each candidate
starts from the original rendered artwork, with at most three attempts. The
first candidate passing all recovery checks is kept. This retains the highest
contrast among the tested candidates; it is not a perceptual-quality optimum.
Dense files can visibly obscure the cover. There is no separate 64 KB appearance
cap or visual-distortion rejection. If all candidates fail, the rendered
artwork is restored before adding the low-bit lossless packet.

Eligible noise
starts at neutral gray and becomes a visible encoded pattern. It uses a V2
low-bit lossless packet so that the packet does not overwrite the DCT copy.
Above the recovery limit, noise retains the compact V1 packet and its 50 MiB
original-file limit. Cover output retains its 8 MiB limit. The original bytes,
including image metadata, are never recompressed, resized, or split.
Both carrier geometries depend on encrypted byte count, not the source image's
aspect ratio or dimensions. Lossless cover canvases grow as needed; noise grows
as a compact rectangle outside the recovery range. Supported original images
are bounded to 16,384 pixels per side and 64 megapixels. Custom cover artwork is
resized and center-cropped to fill the output, with automatic enlargement and a
notice about softness. This changes only the public cover, not the private image.

The renderer compares every recovered byte after writing the V2 packet, then
checks the final pixels through a single quality-0.60 conversion and separately
quality 0.85 followed by 0.60. Each SSJ2 check must use at most 12 of the 16-symbol
per-codeword correction budget. A double conversion can improve rounding
alignment by chance, so it does not replace the single-conversion check.
If either check fails, it restores the rendered cover and emits only a lossless
packet (V2 for covers, V1 for noise). The result reports whether recovery passed;
the UI warns before encryption when the envelope exceeds capacity and after
encryption if the check failed. These local encoder checks do not reproduce all
messenger processing and are not a Telegram compatibility guarantee.

`SSJ2` reads exactly 1024, 1280 or 2560 square frames, on the unshifted 8×8 grid.
HD output requires keeping the dimensions and enabling HD / High Quality in
the sending app. The UI warns before and after creation and appends that advice
to copied recipient instructions. Normal photo mode can reduce it and destroy
the channel. Every HD candidate passes the same exact-byte, Q60, Q85→Q60 and
12-of-16 correction-budget gates as Standard; no weaker gate is used for HD.
Contrast, carrier allocation and peak search follow encrypted bytes per block,
so at 2560 the effective density is one quarter the same payload at 1280.
The tiny legacy profile is used only on a 1024-square carrier.
Block `i` maps to `i * 4051 modulo (side² / 64)`, a permutation for all three sizes.
The first 128 scattered blocks carry a Reed–Solomon (64,16) header, four bits per
block in luma frequencies (1,1), (1,2), (2,1), (2,2), with binary lattice step 48.
All integers are unsigned big-endian:

| Header offset | Size | Meaning |
| --- | --- | --- |
| 0 | 4 | ASCII `SSJ2` |
| 4 | 1 | Bits per body block, 1–110 |
| 5 | 1 | Step multiplier index into `[2,3,4,6,3.75]`; old indices are unchanged |
| 6 | 2 | Frame side, exactly matching the decoded bitmap |
| 8 | 4 | Envelope byte count, bounded by coded frame capacity |
| 12 | 4 | Envelope CRC-32 |

The remaining blocks carry interleaved Reed–Solomon (255,223) codewords, with
32 parity bytes repairing at most 16 byte errors per word. Byte `n` of word `w`
is stored at `n * codewordCount + w`; the final data word is zero-padded.
Carrier allocation is deterministic from header fields, with up to three Gray
coded bits per coefficient. The base table and allocation procedure are fixed
in `src/jpeg-channel.ts`; the header records the multiplier, so later encoder
profile choices do not change decoding. DC is reserved for gamut adjustments.
Chroma is flattened in 2×2 cells and reduced where needed to limit clipping.
Up to three alternating projections adjust non-carrier coefficients when a
block's luminance range would clip; denser 1280-pixel product profiles use up to
ten, or thirty for the denser 200,001–280,000-byte profile. From 120,001 bytes, luma excursions and chroma are multiplied by
`max(0.25, 1 - (bytes - 120000) / 80000)` up to 200,000 bytes, then
`max(0.15, 0.25 - (bytes - 200000) / 500000)`, before embedding. For HD research
samples, density is normalized to the equivalent 1280-square payload first. This sacrifices cover
contrast for signal headroom. Near-zero carrier ties are deterministically
balanced between equivalent lattice points to avoid aligned peaks in flat
covers and noise. The resulting carrier symbols and wire format are unchanged.
For the densest profile, a bounded four-pass search changes coefficient values
by whole lattice periods to reduce pixel peaks without changing their symbols.
Ten further gamut iterations refine that choice. Difficult artwork can still
exhaust the correction budget.

CRC and error correction detect/repair transport damage; neither authenticates
anything. Recovered bytes still require the unchanged AES-GCM authentication.
The decoder bounds dimensions, header values and lengths before body allocation.
It also continues reading the earlier `SNAPSEALJPG1` 1024/2048 profiles and
prototype `SSJ2` 1024 frames. Lossless PNG and ZIP interoperability is unchanged.

JPEG file input first reads quantized luma coefficients directly, using the same
header, allocation, RS and CRC checks as the pixel reader. The adapter admits
only bounded 8-bit grayscale/YCbCr baseline or progressive JPEGs, checks marker,
table and scan structure before allocation, and accepts restart markers. It runs
in a disposable worker: 32 MiB maximum JPEG input, 96 MiB tracked coefficient
allocation, at most 64 scans, and a 20-second deadline. No password or plaintext
enters this worker. Completion, failure, timeout and cancellation terminate it.
Native pixel decoding remains the fallback. The block-reader API avoids creating
an additional full-image Float64 coefficient array. Clipboard pixels do not
retain the original JPEG coefficients and use the pixel path.

The channel does not recover from resizing, cropping, rotation, screenshots or
arbitrary filtering. JPEG success depends on the encoder, subsampling, cover and
payload. Local Pillow and browser JPEG round trips are useful tests, not proof
of compatibility with Telegram or other messengers. Send the original PNG as a
file/document or use SnapSeal ZIP for reliable delivery.

The 280,000-byte noise policy is a tested product limit, not a theoretical ceiling.
The earlier 4× profile exhausted its error-correction margin above 200,000 bytes.
Finer 3.75× spacing, lower cover contrast, equivalent-symbol peak reduction and
additional gamut iterations support the 280,000-byte profile. Exploratory
300,000-byte profiles used up to all 16 correction symbols, and 306,000-byte
profiles failed repeated JPEG conversion with the pixel reader. Later direct
coefficient experiments recovered 306,179 bytes at 1280 square across the tested
cover matrix, but those nearly-noise profiles are not production cover defaults.
The user reported successful Telegram HD transfers of earlier 500 KB and 1 MB
cover samples; 1 MB failed normal photo mode. Product creation is now enabled
through 1,000,000 encrypted bytes with mandatory local self-checks. These older
Telegram observations do not validate every new cover or input. New 1.22 MB
profiles remain research-only and are not automatically selected.
A multi-megabyte original cannot be promised to survive
in one recompressed photo simply by increasing the PNG dimensions: platforms
can resize it and discard those extra pixels.

The user reported successful real Telegram transfers of both earlier 174,511-byte
adaptive cover/noise samples. That result does not validate these newer profiles.
New multiplier-index files need a current reader after JPEG conversion; older
readers can still read their unchanged lossless PNG packet.

Research context: [Butora, Puteaux and Bas, Errorless Robust JPEG Steganography
using Outputs of JPEG Coders](https://arxiv.org/abs/2211.04750), sections II-B,
III-D and VI, assumes knowledge of the compressor and acknowledges finite robust
capacity. The current channel uses QIM and error correction, not that paper's
lattice/STC algorithm, and does not inherit its errorless claim.

## V3 authenticated Argon2id envelope (unreleased creation default)

| Field | Offset | Size / fixed value |
| --- | --- | --- |
| ASCII `SNAPSEAL` | 0 | 8 bytes |
| Envelope version | 8 | 1 byte: `3` |
| KDF identifier | 9 | 1 byte: `1` (Argon2id) |
| Argon2 algorithm version | 10 | 1 byte: `0x13` |
| Parallelism | 11 | 1 byte: `1` |
| Memory in KiB | 12 | 4-byte unsigned big-endian: `65536` |
| Passes | 16 | 4-byte unsigned big-endian: `3` |
| Random salt | 20 | 16 bytes |
| Random IV | 36 | 12 bytes |
| Ciphertext and GCM tag | 48 | Remaining bytes; final 16 bytes are tag |

Argon2id derives 32 key bytes from the exact UTF-8 password and salt. The key
is imported as a non-extractable AES-256-GCM key, then the temporary key bytes
are wiped. All 48 header bytes are GCM additional data. Only the exact profile
above is accepted; malformed/unknown cost fields fail before KDF allocation.
The existing password rules and explicit weak-password option are retained.

The encrypted payload remains the four-byte metadata length, bounded UTF-8 JSON
metadata and exact original bytes. Image metadata uses `filename` and `mimeType`;
file/text metadata uses `filename` and `contentKind`. The discriminator is now
inside authenticated encryption. There is no padding or source recompression.
Envelope sizing APIs include the extra seven header bytes, so the existing
280,000-byte photo-recovery budget remains an encrypted-byte budget.

The pinned `hash-wasm` 4.12.0 implementation and its MIT license are bundled.
Browser windows use one disposable worker per KDF, a serialized per-context
queue, cancellation and a 30-second deadline; completion terminates the worker.
No password/files are sent to a network service. The worker receives only
bounded password bytes and salt, never original files. WebAssembly compilation
requires `wasm-unsafe-eval`, without general JavaScript `unsafe-eval`. Worker/
WASM failure does not downgrade to PBKDF2. Offline asset caches include the
worker. Non-window environments without Worker use the same fixed Argon2id
implementation directly, not a different KDF.

Independent native Node Argon2id/AES-GCM tests verify exact interoperability.
Readers retain the two PBKDF2 formats below. Existing files are not rewritten;
old readers reject v3, so publish the updated website reader before distributing
v3-producing extension builds. Physical-phone latency/memory validation remains
distinct from desktop Chromium measurements and viewport/CPU simulation.

## Legacy authenticated PBKDF2 envelopes (read compatibility)

| Field | Offset | Size |
| --- | --- | --- |
| ASCII `SNAPSEAL` | 0 | 8 bytes |
| Version: 1 (image) or 2 (file/text) | 8 | 1 byte |
| PBKDF2 iterations: 600000 | 9 | 4 bytes, unsigned big-endian |
| Random salt | 13 | 16 bytes |
| Random IV | 29 | 12 bytes |
| Ciphertext and GCM tag | 41 | Remaining bytes; last 16 bytes are tag |

The password is encoded as UTF-8 exactly, including spaces and Unicode, without
normalization. Creation requires 12–256 Unicode code points and a non-whitespace
character. PBKDF2-HMAC-SHA-256 derives a non-extractable AES-256-GCM key. A fresh
salt and IV are generated for every protection operation. All 41 header bytes
are authenticated as GCM additional data. Version and work factor are validated
before derivation; both versions accept only the fixed work factor.

The plaintext is a 4-byte unsigned big-endian metadata length, UTF-8 JSON
`{"filename":"image.png","mimeType":"image/png"}`, followed by the exact original
image bytes. Metadata is encrypted too. URLs, page titles and passwords are not
included by this format. Image bytes can still contain their original metadata;
this tool does not strip it. Decoding verifies the tag, validates metadata and
the image signature, and sanitizes the download filename/extension. Supported
source formats for v1 are PNG, JPEG, WebP and GIF; SVG/HTML are rejected.

### V2 arbitrary files and text

The website accepts any file extension, including TXT, PDF, ZIP and EXE, within
the same byte limits: 50 MiB in noise mode or 8 MiB in cover mode. Empty files
are valid. Payload dimensions do not constrain opaque file storage. The output
is still one protected PNG, optionally wrapped in a ZIP for reliable delivery.
JPEG recovery is bounded by encrypted byte count, not the original file type;
the experimental limits are 280,000 encrypted bytes for Standard and 1,000,000
for HD, irrespective of file type. The cryptographic metadata and tag count
toward those limits.

V2 uses the same authenticated 41-byte header, KDF and AES-GCM construction.
Its encrypted metadata is `{"filename":"document.pdf","contentKind":"file"}`
or `{"filename":"note.txt","contentKind":"text"}`, followed by the exact original
bytes. The metadata length is checked against the 2,048-byte bound before JSON
parsing. Only `file` and `text` are accepted kinds. No user-supplied MIME type is
retained. Filenames are sanitized against paths, control/bidi characters,
Windows device names and alternate data streams; ordinary extensions survive.

All v2 downloads use `application/octet-stream` with an explicit download name.
Validated, bounded PNG/JPEG/GIF/WebP bytes may get a separate raster preview;
SVG, HTML, PDFs, executables and other formats are never embedded or executed.
The Text tab encodes a note as UTF-8 `note.txt`. A text payload of at most 64 KiB
can be displayed in an inert, read-only textarea; larger notes are download-only.
Uploading a TXT file instead preserves its original encoding and line endings.

The extension creates image payloads only; the website also creates files/text.
Both now create v3 envelopes and read the v1/v2 formats above. Existing files remain
readable. Older readers reject v2 as an unsupported version; deploying the
updated reader is required before distributing these new file containers.
Arbitrary file protection does not inspect files for malware or make them safe
to run after download.

Source images are limited to 50 MiB. Envelopes are capped at 50 MiB + 4096 bytes
and PNG input at that limit + 1 MiB. This encoding does not compress encrypted
data effectively, so protected files can be larger than the source.

Source image headers are checked before preview decoding or encryption: each
dimension must be at most 16384 pixels and the area at most 64 megapixels
(64 × 1024 × 1024 pixels). PNG, JPEG, GIF and WebP dimension headers are parsed
with bounds checks. The protected PNG decoder also checks the IHDR chunk length
and verifies the decoded bitmap dimensions against the inspected header.

## Handling and verification

Weak passwords remain vulnerable to offline guessing. Password loss cannot be
recovered. Protection does not erase original files, extension history or the
clipboard, and recipients can retain decrypted images. Clearing the tool
releases its working references and blob URLs; it is not a guarantee of secure
memory erasure by the browser or operating system.

Unit tests cover independent Node AES-GCM interoperability, altered ciphertext,
salt, IV and tag, wrong passwords, hostile headers and unsafe metadata. Chromium
tests cover actual clipboard transfer, pixel-preserving canvas re-encoding,
changed pixels, exact original recovery, and extension/website compatibility.
These tests do not constitute an independent security audit.

Algorithm references: [Web Crypto AES-GCM parameters](https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams)
and [OWASP PBKDF2 guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

## UI, generated passwords and incoming shares

The shared site/extension UI uses one visible password field and keeps the
password in component memory after protection, until Clear, replacement or
mode change. It is never put into the recipient message or storage. The default
UI generator chooses eight independent words uniformly from the 7,776-word EFF
large list with CSPRNG rejection sampling (approximately 103 bits). Spaces are
part of the password. The 24-character API generator remains unchanged. EFF
word-list attribution and its CC BY 4.0 notice ship with both builds.

Multiple website inputs become an encrypted v2 `file` payload named `files.zip`.
The flat STORE archive has UTF-8 sanitized leaf names, case-insensitive duplicate
resolution and CRCs. Original entry bytes are unchanged. There are at most 100
entries; the entire archive, including headers, must fit 50 MiB. It is downloaded
as an opaque file after decryption, never extracted by this application.

The installed website's optional native share target accepts a bounded multipart
POST locally in its service worker. It retains at most one pending share in RAM
for up to 45 seconds, keyed by a random, single-use nonce. The worker transfers
File objects/plain text over a same-origin MessageChannel and releases its
references. An expired/consumed share requires choosing the originals again.
Only public application files are cached for offline operation; originals,
passwords, ciphertext, decrypted files and nonce URLs are not written to those
caches or IndexedDB. This memory lifetime is not a secure-erasure guarantee.
