# Security

For a suspected vulnerability, use GitHub's **Security → Report a vulnerability**
when available. If private reporting is unavailable, use the contact route at
[snapseal.app/contacts](https://snapseal.app/contacts) to arrange private details.
Do not publish passwords, original private files, exploit files containing user
data, or live access tokens in public issues.

This is a source extraction with compatibility tests, not an independently
audited cryptographic product. A protected file and its correct password are
required. Forgotten passwords cannot be recovered. A recipient can retain any
decrypted original. Public covers/labels are not authenticated plaintext.

Untrusted files are bounded before expensive decoding; KDF costs are fixed and
validated before derivation. Browser Argon2id and JPEG coefficient work runs in
disposable workers with deadlines. Node callers processing untrusted jobs on a
server should impose their own process resource/time limits and concurrency
controls. The Node API does not provide browser-worker cancellation for a
synchronous PNG/JPEG parse.
