// @vitest-environment node
import { createCipheriv, createDecipheriv, argon2Sync } from 'node:crypto';
import { beforeAll, expect, it } from 'vitest';
import { protectFile, protectedFileEnvelopeLength, unlockProtectedFile, unlockImageFile, protectImageFile, imagePreviewMime, safeFileFilename, MAX_FILE_BYTES } from '../src/index';

const password = 'Exact private file roundtrip 2026';
const pdf = new TextEncoder().encode('%PDF-1.7\nPrivate document\0\xff\n%%EOF');
let envelope: Uint8Array;
beforeAll(async () => { envelope = await protectFile(pdf, 'private-document.pdf', password); });

it('opens exact legacy password bytes and equivalent Unicode keyboard forms without trimming spaces', async () => {
  const composed = 'Caf\u00e9 private password', decomposed = composed.normalize('NFD');
  for (const original of [composed, decomposed]) {
    const file = await protectFile(pdf, 'unicode.pdf', original);
    for (const entered of [composed, decomposed]) expect((await unlockProtectedFile(file, entered)).bytes).toEqual(pdf);
    await expect(unlockProtectedFile(file, ` ${original}`)).rejects.toMatchObject({ code: 'unlock-failed' });
  }
}, 30_000);

it.each([
  ['manual.pdf', pdf],
  ['archive.zip', Uint8Array.from([80, 75, 3, 4, 0, 255, 128])],
  ['program.exe', Uint8Array.from([77, 90, 0, 0, 128, 255])],
  ['empty.dat', new Uint8Array()],
  ['без розширення 日本語', Uint8Array.from([0, 1, 128, 255, 0])],
  ['page.html', new TextEncoder().encode('<script>globalThis.executed=true</script>')],
  ['vector.svg', new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>')],
])('preserves every byte and safe filename of %s, with an inert download type', async (filename, bytes) => {
  const encoded = await protectFile(bytes, filename, password);
  expect(encoded[8]).toBe(3);
  expect(encoded.length).toBe(protectedFileEnvelopeLength(bytes, filename));
  expect(await unlockProtectedFile(encoded, password)).toEqual({ bytes, filename, contentKind: 'file', mimeType: 'application/octet-stream' });
  expect(imagePreviewMime(bytes)).toBeNull();
  await expect(unlockImageFile(encoded, password)).rejects.toMatchObject({ code: 'unsupported-image' });
});

it('keeps text whitespace, Unicode and line endings exactly, and records text only inside authenticated metadata', async () => {
  const bytes = new TextEncoder().encode('  Привіт 🌍\r\n<script>not executed</script>\n\t');
  const encoded = await protectFile(bytes, 'note.txt', password, { contentKind: 'text' });
  expect(encoded.length).toBe(protectedFileEnvelopeLength(bytes, 'note.txt', 'text'));
  expect(await unlockProtectedFile(encoded, password)).toEqual({ bytes, filename: 'note.txt', contentKind: 'text', mimeType: 'application/octet-stream' });
  expect(Buffer.from(encoded).includes(Buffer.from('note.txt'))).toBe(false);
});

it('interoperates with independent Argon2id/AES-GCM and rejects a changed version discriminator', async () => {
  const key = argon2Sync('argon2id', { message: password, nonce: envelope.slice(20, 36), memory: 65536, passes: 3, parallelism: 1, tagLength: 32 });
  const decipher = createDecipheriv('aes-256-gcm', key, envelope.slice(36, 48));
  decipher.setAAD(envelope.slice(0, 48)); decipher.setAuthTag(envelope.slice(-16));
  const payload = Buffer.concat([decipher.update(envelope.slice(48, -16)), decipher.final()]);
  const length = payload.readUInt32BE();
  expect(JSON.parse(payload.subarray(4, 4 + length).toString('utf8'))).toEqual({ filename: 'private-document.pdf', contentKind: 'file' });
  expect(payload.subarray(4 + length)).toEqual(Buffer.from(pdf));
  const headerChanged = envelope.slice(); headerChanged[8] = 1;
  await expect(unlockProtectedFile(headerChanged, password)).rejects.toMatchObject({ code: 'invalid-file' });
  await expect(unlockProtectedFile(envelope, 'Wrong private file password')).rejects.toMatchObject({ code: 'unlock-failed' });
  const corrupt = envelope.slice(); corrupt[corrupt.length - 1] ^= 1;
  await expect(unlockProtectedFile(corrupt, password)).rejects.toMatchObject({ code: 'unlock-failed' });
});

it('rejects malformed authenticated file metadata and work factors before exposing data', async () => {
  const key = argon2Sync('argon2id', { message: password, nonce: envelope.slice(20, 36), memory: 65536, passes: 3, parallelism: 1, tagLength: 32 });
  for (const metadata of [null, { filename: 7, contentKind: 'file' }, { filename: 'a.exe', contentKind: 'image' }, { filename: 'a'.repeat(2049), contentKind: 'file' }]) {
    const raw = Buffer.from(JSON.stringify(metadata)), length = Buffer.alloc(4); length.writeUInt32BE(raw.length);
    const cipher = createCipheriv('aes-256-gcm', key, envelope.slice(36, 48)); cipher.setAAD(envelope.slice(0, 48));
    const malformed = Buffer.concat([envelope.slice(0, 48), cipher.update(Buffer.concat([length, raw, pdf])), cipher.final(), cipher.getAuthTag()]);
    await expect(unlockProtectedFile(malformed, password)).rejects.toMatchObject({ code: 'invalid-file' });
  }
  const expensive = envelope.slice(); new DataView(expensive.buffer).setUint32(12, 0xffffffff);
  await expect(unlockProtectedFile(expensive, password)).rejects.toMatchObject({ code: 'invalid-file' });
  await expect(protectFile(new Uint8Array(MAX_FILE_BYTES + 1), 'large.bin', password)).rejects.toMatchObject({ code: 'too-large' });
});

it('keeps existing image envelopes readable and accepts oversized raster headers only as opaque files', async () => {
  const png = Uint8Array.from(Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==', 'base64'));
  const old = await protectImageFile(png, 'original.png', password);
  expect(old[8]).toBe(3);
  expect(await unlockProtectedFile(old, password)).toMatchObject({ bytes: png, filename: 'original.png', contentKind: 'image' });
  const huge = png.slice(); new DataView(huge.buffer).setUint32(16, 0x7fffffff);
  expect(imagePreviewMime(huge)).toBeNull();
  const stored = await protectFile(huge, 'large-dimensions.png', password);
  expect((await unlockProtectedFile(stored, password)).bytes).toEqual(huge);
});

it('sanitizes unsafe names while retaining normal extensions', () => {
  expect(safeFileFilename('../../private.pdf')).toBe('private.pdf');
  expect(safeFileFilename('C:\\files\\CON.exe')).toBe('_CON.exe');
  expect(safeFileFilename('a\u202Efdp.exe:stream')).toBe('a_fdp.exe_stream');
  expect(safeFileFilename('..')).toBe('file');
  expect(safeFileFilename('報告 📁.pdf')).toBe('報告 📁.pdf');
});
