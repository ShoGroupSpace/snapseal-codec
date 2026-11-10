# JPEG coefficient reader

Based on jpeg-js v0.4.4, https://github.com/jpeg-js/jpeg-js/blob/v0.4.4/lib/decoder.js

Upstream SHA-256: a3f175fd6f62d142aad94d3bd90f3a30be4e076baf9b6a6fa31c8e84d9d4aa9f.
The original Apache-2.0 notice and the project's BSD-3-Clause license are retained.

SnapSeal changes (7 November 2026): expose coefficients before IDCT and the
allocation counter; reject entropy EOF; use an ES module export. The adapter
accepts a restricted JPEG subset with frame, scan, table and allocation limits.
Production invokes it in a disposable worker with a 20-second deadline.
It reads existing SSJ2 files; it introduces no new encryption or wire format.
This is not an independent security audit.
