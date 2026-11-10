# Codec format and current policy

This repository preserves the SnapSeal workspace codec extracted on
**November 10, 2026**. The detailed [upstream format notes](UPSTREAM-FORMAT.md)
include historical implementation/research measurements. Read their dated
policy overrides before older sections. In particular, old tables describing
automatic HD promotion are historical, not the current default.

Current creation uses Argon2id v3, a separate version from PNG pixel/container
versions. Readers also support v1/v2 PBKDF2, including the exact original
password bytes. Creation does not write PBKDF2 or attempt a downgrade.

Automatic recovery stops at 280,000 encrypted bytes; larger files use lossless
PNG. Explicit HD remains available at up to 1,000,000 encrypted bytes, with
2560-square legacy support retained in readers. File-only mode skips the
recovery copy. Exact/Q60/Q85→Q60 validation and Reed–Solomon correction headroom
remain mandatory before an encoder reports successful photo recovery.

The core API defaults to `standard` and no branding for existing integrations.
The offline app and CLI explicitly choose the website workflow's `auto` and
branding defaults. Compression of the private original is always a separate
opt-in. The password, decrypted bytes and encrypted metadata are never put in
the public cover/label.

Fixture provenance:

- `tests/fixtures/vectors`: fixed, independent Node crypto v1/v2/v3 envelopes.
  Public passwords/salts/IVs exist only to make the vectors reproducible. Run
  `npm run fixtures:generate` to reproduce them. Never reuse those constants
  for real encryption.
- `tests/fixtures/jpeg-channel`: pre-existing SSJ2 fixtures from the product,
  made using independent Pillow JPEG conversion. Recorded SHA-256 values and
  public test passwords verify the exact envelope and original after recovery.
- Browser tests: the actual current encoder, decorated PNG, ZIP, and single
  and repeated JPEG conversion, with AES-GCM and exact-byte verification.

No success here establishes arbitrary messenger compatibility, resize recovery,
password recovery, invisibility, or an independent audit.
