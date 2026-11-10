# SSJ2 compatibility fixtures

Created before the production coefficient reader, using the November 7 research
baseline and independent Pillow JPEG conversion. Q60, progressive Q60, and
Q85 → Q60 contain the same random encrypted envelope. The JSON records SHA-256
hashes and a public test password; no user data is included.

These are simulated conversions, not files received through Telegram. They
exercise compatibility with the existing SSJ2 format and authentication of exact
original bytes, including rejection of wrong passwords and modified ciphertext.
