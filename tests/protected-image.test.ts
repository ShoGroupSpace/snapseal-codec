// @vitest-environment node
import { createDecipheriv, createCipheriv, argon2Sync } from 'node:crypto';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { detectImageMime, validateImageDimensions, MAX_IMAGE_BYTES, protectImageFile, protectedImageEnvelopeLength, protectedImageEnvelopeOverhead, unlockImageFile, generateImagePassword } from '../src/index';

const image = Uint8Array.from(Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==', 'base64'));
const password = ' a long 🔐 private phrase ';
let envelope: Uint8Array;
beforeAll(async () => { envelope = await protectImageFile(image, '../../private holiday.png', password); });

function independentKey() { return argon2Sync('argon2id', { message: password, nonce: envelope.slice(20, 36), memory: 65536, passes: 3, parallelism: 1, tagLength: 32 }); }

describe('protected image encryption', () => {
  it('reserves exact metadata overhead without placeholder image bytes', async () => {
    const filename = '../../private holiday 🌍.png';
    const protectedBytes = await protectImageFile(image, filename, password);
    expect(protectedImageEnvelopeOverhead(filename, 'image/png') + image.length).toBe(protectedBytes.length);
    const jpeg = Uint8Array.from([255,216,255,192,0,8,8,0,2,0,3,1]);
    expect(protectedImageEnvelopeOverhead('photo 🌍.jpg', 'image/jpeg') + jpeg.length).toBe((await protectImageFile(jpeg, 'photo 🌍.jpg', password)).length);
    expect(() => protectedImageEnvelopeLength(new Uint8Array(), filename)).toThrow('unsupported-image');
    expect(() => protectedImageEnvelopeOverhead(filename, 'image/svg+xml')).toThrow('unsupported-image');
  });
  it('generates unbiased 24-character passwords using only secure randomness and clears its random buffer', () => {
    let buffer: Uint8Array | undefined;
    const rng = vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation((array: any) => {
      buffer = array; array.set(Array.from({ length: 24 }, (_, index) => [0, 63, 64, 127, 128, 255][index % 6])); return array;
    });
    try { expect(generateImagePassword()).toBe('A_A_A_'.repeat(4)); expect(buffer?.every(byte => byte === 0)).toBe(true); }
    finally { rng.mockRestore(); }
    expect(generateImagePassword()).toMatch(/^[A-Za-z0-9_-]{24}$/);
    expect(generateImagePassword()).not.toBe(generateImagePassword());
  });
  it('fails closed when secure randomness is unavailable', () => {
    const rng = vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(() => { throw new Error('RNG unavailable'); });
    try { expect(() => generateImagePassword()).toThrow('RNG unavailable'); } finally { rng.mockRestore(); }
  });
  it('requires an explicit override for one-character passwords without weakening Argon2id', async () => {
    await expect(protectImageFile(image, 'image.png', 'x')).rejects.toMatchObject({ code: 'password-too-short' });
    const short = await protectImageFile(image, 'image.png', 'x', { allowWeakPassword: true });
    expect(short[8]).toBe(3); expect(new DataView(short.buffer).getUint32(12)).toBe(65536); expect(new DataView(short.buffer).getUint32(16)).toBe(3);
    expect((await unlockImageFile(short, 'x')).bytes).toEqual(image);
    await expect(unlockImageFile(short, 'y')).rejects.toMatchObject({ code: 'unlock-failed' });
    await expect(protectImageFile(image, 'image.png', 'x')).rejects.toMatchObject({ code: 'password-too-short' });
  });
  it('keeps empty, whitespace-only and oversized passwords invalid even with the short-password override', async () => {
    for (const invalid of ['', ' ', '\t\n', 'x'.repeat(257)]) {
      await expect(protectImageFile(image, 'image.png', invalid, { allowWeakPassword: true })).rejects.toMatchObject({ code: 'password-too-short' });
    }
  });
  it('rejects oversized or truncated image headers before a decoder allocates pixels', async () => {
    expect(validateImageDimensions(image)).toEqual({ width: 1, height: 1 });
    const huge = image.slice(); new DataView(huge.buffer).setUint32(16, 0x7fffffff);
    expect(() => validateImageDimensions(huge)).toThrow();
    await expect(protectImageFile(huge, 'bomb.png', password)).rejects.toMatchObject({ code: 'unsafe-dimensions' });
    for (let size = 8; size < 33; size++) expect(() => validateImageDimensions(image.slice(0, size))).toThrow();
    const gif = new TextEncoder().encode('GIF89a\x01\x00\x02\x00');
    expect(validateImageDimensions(gif)).toEqual({ width: 1, height: 2 });
    gif[6] = 255; gif[7] = 255;
    expect(() => validateImageDimensions(gif)).toThrow();
    const jpeg = Uint8Array.from([255,216,255,192,0,8,8,0,2,0,3,1]);
    expect(validateImageDimensions(jpeg)).toEqual({ width: 3, height: 2 });
    expect(() => validateImageDimensions(jpeg.slice(0, 9))).toThrow();
    const webp = new Uint8Array(30); webp.set(new TextEncoder().encode('RIFF')); webp.set(new TextEncoder().encode('WEBPVP8X'), 8);
    new DataView(webp.buffer).setUint32(4, 22, true); new DataView(webp.buffer).setUint32(16, 10, true);
    webp[24] = 3; webp[27] = 4;
    expect(validateImageDimensions(webp)).toEqual({ width: 4, height: 5 });
    webp[24] = webp[25] = webp[26] = 255;
    expect(() => validateImageDimensions(webp)).toThrow();
  });
  it('restores exact original bytes and a safe filename, with Unicode passwords preserved', async () => {
    expect(await unlockImageFile(envelope, password)).toEqual({ bytes: image, filename: 'private holiday.png', mimeType: 'image/png' });
    expect(Buffer.from(envelope).includes(Buffer.from('private holiday'))).toBe(false);
    expect(Buffer.from(envelope).includes(Buffer.from(password))).toBe(false);
  });

  it('uses unique randomness and interoperates with an independent AES-GCM implementation', async () => {
    const second = await protectImageFile(image, 'private holiday.png', password);
    expect(second.slice(20, 48)).not.toEqual(envelope.slice(20, 48));
    const decipher = createDecipheriv('aes-256-gcm', independentKey(), envelope.slice(36, 48));
    decipher.setAAD(envelope.slice(0, 48));
    decipher.setAuthTag(envelope.slice(-16));
    const payload = Buffer.concat([decipher.update(envelope.slice(48, -16)), decipher.final()]);
    const length = payload.readUInt32BE();
    expect(JSON.parse(payload.subarray(4, 4 + length).toString())).toEqual({ filename: 'private holiday.png', mimeType: 'image/png' });
    expect(payload.subarray(4 + length)).toEqual(Buffer.from(image));
  });

  it('rejects wrong passwords, altered salt, IV, ciphertext and authentication tag', async () => {
    await expect(unlockImageFile(envelope, password.trim())).rejects.toMatchObject({ code: 'unlock-failed' });
    for (const offset of [20, 36, 60, envelope.length - 1]) {
      const changed = envelope.slice(); changed[offset] ^= 1;
      await expect(unlockImageFile(changed, password)).rejects.toMatchObject({ code: 'unlock-failed' });
    }
  });

  it('rejects invalid headers, unsupported versions and hostile work factors', async () => {
    await expect(unlockImageFile(image, password)).rejects.toMatchObject({ code: 'invalid-file' });
    const version = envelope.slice(); version[8] = 99;
    await expect(unlockImageFile(version, password)).rejects.toMatchObject({ code: 'unsupported-version' });
    const expensive = envelope.slice(); new DataView(expensive.buffer).setUint32(12, 0xffffffff);
    await expect(unlockImageFile(expensive, password)).rejects.toMatchObject({ code: 'invalid-file' });
    await expect(unlockImageFile(envelope.slice(0, 50), password)).rejects.toMatchObject({ code: 'invalid-file' });
  });

  it('checks authenticated metadata and rejects active image formats', async () => {
    const metadata = Buffer.from(JSON.stringify({ filename: 'payload.html', mimeType: 'text/html' }));
    const length = Buffer.alloc(4); length.writeUInt32BE(metadata.length);
    const cipher = createCipheriv('aes-256-gcm', independentKey(), envelope.slice(36, 48));
    cipher.setAAD(envelope.slice(0, 48));
    const payload = Buffer.concat([length, metadata, image]);
    const malicious = Buffer.concat([envelope.slice(0, 48), cipher.update(payload), cipher.final(), cipher.getAuthTag()]);
    await expect(unlockImageFile(malicious, password)).rejects.toMatchObject({ code: 'invalid-file' });
    expect(() => detectImageMime(new TextEncoder().encode('<svg onload="alert(1)"></svg>'))).toThrow();
  });

  it('bounds input before encryption and avoids misleading download extensions', async () => {
    for (const weak of ['short', '            ', 'x'.repeat(257)]) {
      await expect(protectImageFile(image, 'image.png', weak)).rejects.toMatchObject({ code: 'password-too-short' });
    }
    await expect(protectImageFile(new Uint8Array(MAX_IMAGE_BYTES + 1), 'large.png', password)).rejects.toMatchObject({ code: 'too-large' });
    const file = await protectImageFile(image, '..\\CON.html', password);
    expect((await unlockImageFile(file, password)).filename).toBe('_CON.png');
  });
});
