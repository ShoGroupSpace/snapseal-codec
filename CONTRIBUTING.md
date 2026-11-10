# Contributing

Use Node 24.22+, `npm ci`, and the checks documented in README. Keep the lockfile.
Add a fixed fixture and independent decoding evidence for format changes.
Readers must continue opening existing password, PNG, JPEG, and ZIP versions.
Do not weaken KDF profiles, remove authenticated-header checks or turn a failed
authentication into a best-effort plaintext result.

`src/crypto` and `src/image` are extracted product codec sources. `UPSTREAM.json`
records their hashes and provenance; `tests/upstream.test.ts` detects drift.
Reconcile source changes with SnapSeal before updating those recorded hashes.
Do not update hashes just to make unexplained differences pass. Worker/logo
embedding belongs in the build adapter, not in encryption/channel algorithms.

No online sharing, hosted accounts, telemetry, billing, capture history,
credentials, or user-provided files belong in this repository. Keep test data
synthetic and public. Public offline-app labels reuse the 51 product catalogs;
retain completeness when changing the interface.
