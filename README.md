<p align="center"><img src="assets/logo.png" width="96" alt="SnapSeal logo"></p>

# SnapSeal encoder and decoder for TypeScript

An open-source TypeScript library for encrypting **images, files and text** into
PNG images and restoring the original bytes with a password.

Built from the same code used by
[SnapSeal — screenshot capture, editing and encrypted file protection](https://snapseal.app/),
the library lets you add SnapSeal-compatible encoding and decoding to your own
tools. It combines AES-256-GCM encryption, Argon2id key derivation and PNG
steganography, with an optional JPEG recovery channel for supported photo
compression. Existing PBKDF2-protected files remain readable. Processing stays
local, without an account, upload or SnapSeal server.

## Build and test

Use Node 24.22 or newer. From a fresh checkout:

```sh
npm ci
npm run typecheck
npm test
npm run build
npx playwright install chromium
npm run test:browser
```

Build creates `dist/snapseal-codec.html`, ESM libraries, declarations and licenses.
Tests include independent Node Argon2id/AES-GCM and PBKDF2 implementations, fixed
v1/v2/v3 vectors, actual JPEG fixtures, hostile headers, wrong passwords,
tampering, exact-byte restoration, offline browser checks, and simulated Q60 and
Q85→Q60 recovery. Synthetic fixtures contain no private user data. CI runs these
checks and uploads the built offline app. No independent security audit is claimed.

This repository is ready to consume from source/GitHub. It is **not published to
npm**; `private: true` prevents accidental registry publication.

## TypeScript / JavaScript API

After building, use `./dist/browser.js` in a browser bundle (or the package's
`/browser` export when installed from a checkout):

```ts
import {
  protectFile, encodeProtectedPNGWithInfo, protectedImageZIP, decodeFile,
} from './dist/browser.js';

const original = new TextEncoder().encode('A private note 🌍\r\n');
const envelope = await protectFile(original, 'note.txt', password, {
  contentKind: 'text', // generic files use 'file'; images also have protectImageFile
});
const result = await encodeProtectedPNGWithInfo(envelope, undefined, {
  recoveryMode: 'auto',
  visual: { branding: true },
});
const png = result.bytes;
const zip = protectedImageZIP(png);
console.log(result.jpegRecovery); // actual validated result, never assume true

const restored = await decodeFile(zip, password);
// restored.bytes, restored.filename, restored.mimeType, restored.contentKind
```

`encodeProtectedPNGWithInfo(envelope, coverBytes, options)` supports the same
custom raster covers, branding/label reservations, noise/cover PNG layouts,
legacy/SSJ2/SSJ3 recovery channels, encoder checks and file-only fallbacks as
SnapSeal. `compressOriginal` is an explicit, separate opt-in: default encoding
preserves the input's exact bytes. A compressed original restores the prepared
image instead. `allowWeakPassword: true` is an explicit per-operation API option;
it never weakens the KDF. Passwords, labels, covers and returned arrays are the
caller's responsibility; labels and covers are public.

`./dist/index.js` exposes runtime-independent encryption, password generation,
pixel packets, recovery channels, and ZIP/bundle primitives. `./dist/node.js`
adds `decodeContainer` and `decodeFile` for PNG/JPEG/ZIP/raw decoding in Node
without Chromium. `bundleFiles` produces a flat ZIP before encryption; decoded
bundles remain one ZIP file, preserving the original entries. The API does not
silently extract arbitrary archives.

## Command line

```sh
node bin/snapseal.mjs decode protected-image.zip --out restored
node bin/snapseal.mjs encode original.pdf --out protected.png --recovery auto
node bin/snapseal.mjs encode photo.png --out cover.png --cover public-cover.png
node bin/snapseal.mjs encode original.txt --out file-only.png --recovery file
```

Decode runs directly in Node. Encode runs the **same browser encoder** in local
headless Chromium, so it includes anti-compression creation and validation;
install Chromium with `npx playwright install chromium` first. Passwords are
prompted without echo and confirmed for creation. Automation can use
`--password-stdin` with one UTF-8 password and an optional final newline. There is
no password command-line argument or password URL. Output files are created
exclusively; existing files are never overwritten. CLI encode never contacts
SnapSeal or any other HTTP service.

## Format and compatibility

| Layer | Create | Read |
| --- | --- | --- |
| Password envelope | v3 Argon2id + AES-256-GCM | v1 image/v2 file PBKDF2 + v3 Argon2id |
| Lossless PNG | V1 noise, V2 cover, decorated ART 3/4 | All of these |
| Photo recovery | Legacy channel, SSJ2, SSJ3 | Legacy 1024/2048, SSJ2/SSJ3 1024/1280/2560 |
| Transport | PNG, bounded single-PNG ZIP, raw envelope API | PNG, supported JPEG, bounded single-PNG ZIP, raw envelope |

**Release distinction:** this extraction includes the workspace's unreleased
Argon2id v3 changes. Published SnapSeal 2.0.2 uses older PBKDF2 formats. Old
readers may reject newly created v3 files; use this reader for them. This repo
does not deploy a new website or extension. New creation never silently
downgrades to PBKDF2. Both old password formats remain readable, including short
historical passwords and the same Unicode compatibility behavior.

The v3 profile is fixed: Argon2id 1.3, 64 MiB, three passes, one lane, 32-byte
key, AES-256-GCM with a 128-bit tag and authenticated header. Legacy PBKDF2 uses
600,000 HMAC-SHA-256 iterations. New passwords normally require 12–256 Unicode
characters. Defaults preserve spaces/case and source bytes.

Noise input is bounded to 50 MiB; cover input to 8 MiB. Automatic/Standard photo
recovery attempts at most 280,000 **encrypted bytes**; explicit HD supports up
to 1,000,000 and remains for compatibility/research. Encoder validation can
fall back to lossless PNG even within those budgets. Readers retain old HD
files. Size checks and recognition are not authentication: only successful
AES-GCM decryption authenticates the contents.

See [FORMAT.md](docs/FORMAT.md) for current policy and the detailed source format.
[UPSTREAM.json](UPSTREAM.json) records the exact extracted sources and hashes.
Core algorithm sources are preserved; the build only embeds workers and the
logo to support offline/file use. Original applications have not yet migrated
to this repository as a dependency. Future changes must preserve compatibility
vectors and be reconciled with the applications.

## License and contributions

[MIT](LICENSE), with [third-party notices](THIRD-PARTY-NOTICES.md). The existing
SnapSeal logo is included for project identification. Trademark rights are not
granted. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Offline app

Download `snapseal-codec.html` from [Releases](https://github.com/ShoGroupSpace/snapseal-codec/releases),
save it, and open it in a current desktop Chromium browser. It is a single HTML
file containing the codec, WebAssembly, workers, logo, 51 language catalogs and
license notices. It works from disk with the network disconnected. No CDN,
analytics, account or remote service is used. Keep a copy with your archives.

Choose **Unlock file**, select a protected PNG, supported JPEG, SnapSeal ZIP, or
raw `.snapseal` envelope, enter the password, and download the original.
Generic files are downloads only; HTML, SVG and executables are never rendered.

Choose **Protect file** to create a PNG or ZIP using the same encoder as the
website/extension. Automatic recovery is the current workspace default. A custom
cover is optional; leaving it empty uses noise. The developer-facing Standard,
HD and file-only options remain available for compatibility and research.
The compact offline interface does not reproduce the full screenshot studio.
Browser memory/performance varies; physical-phone performance is not certified.

**Keep your password. There is no password recovery.** Send the original PNG or
ZIP as a file/document. JPEG recovery is best effort: supported same-size photo
compression may work; arbitrary compression, resizing, cropping, rotation and
messenger transformations can destroy the payload. Neither embedding nor public
cover artwork makes the contents undetectable or proves cover authenticity.
