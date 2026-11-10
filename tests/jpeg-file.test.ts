// @vitest-environment node
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { unlockImageFile } from '../src/index';
import { extractJPEGFile, preflightJPEG } from '../src/image/jpeg-file';
import { extractJPEGChannelCoefficients, jpegRecoverySide } from '../src/image/jpeg-channel';
const fixture = (file: string) => new Uint8Array(readFileSync(new URL(`./fixtures/jpeg-channel/${file}`, import.meta.url)));
const manifest = JSON.parse(new TextDecoder().decode(fixture('manifest.json')));
const sha = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

it.each(['q60.jpg', 'q60-progressive.jpg', 'q85-q60.jpg'])('recovers existing SSJ2 ciphertext and authenticates exact original bytes from %s', async file => {
  const { envelope, stats } = extractJPEGFile(fixture(file));
  expect(sha(envelope)).toBe(manifest.envelopeSHA256);
  expect(stats.worstCodeword).toBeLessThanOrEqual(12);
  expect(sha((await unlockImageFile(envelope, manifest.password)).bytes)).toBe(manifest.originalSHA256);
  await expect(unlockImageFile(envelope, 'wrong password')).rejects.toMatchObject({ code: 'unlock-failed' });
  const tampered = envelope.slice(); tampered[tampered.length - 1] ^= 1;
  await expect(unlockImageFile(tampered, manifest.password)).rejects.toMatchObject({ code: 'unlock-failed' });
}, 20_000);

it('bounds malformed JPEGs before coefficient allocation', () => {
  const jpeg = fixture('q60.jpg');
  for (const length of [0, 1, 2, 3, 32, 100, jpeg.length - 2]) expect(() => preflightJPEG(jpeg.subarray(0, length))).toThrow();
  expect(() => preflightJPEG(new Uint8Array(32 * 1024 * 1024 + 1))).toThrow();
  const trailing = new Uint8Array(jpeg.length + 1); trailing.set(jpeg);
  expect(() => preflightJPEG(trailing)).toThrow();
  // Independently patch the SOF dimensions, precision and sampling.
  const sof = jpeg.findIndex((value, at) => value === 255 && jpeg[at + 1] === 192);
  expect(sof).toBeGreaterThan(0);
  for (const [offset, value] of [[4, 12], [5, 255], [7, 255], [9, 4], [11, 255]]) {
    const bad = jpeg.slice(); bad[sof + offset] = value;
    expect(() => preflightJPEG(bad)).toThrow();
  }
  const corrupt = jpeg.slice(); corrupt.fill(0, 1024, corrupt.length - 2);
  expect(() => extractJPEGFile(corrupt)).toThrow();
});

it('rejects invalid coefficient sources and keeps creation limits separate from readable old files', () => {
  expect(() => extractJPEGChannelCoefficients(4096, () => {})).toThrow();
  expect(() => extractJPEGChannelCoefficients(1280, (_, output) => output.fill(NaN))).toThrow();
  expect(jpegRecoverySide(3933, true)).toBe(1024);
  expect(jpegRecoverySide(3934, true)).toBe(1280);
  expect(jpegRecoverySide(64_000, true)).toBe(1280);
  expect(jpegRecoverySide(64_001, true)).toBe(1280);
  expect(jpegRecoverySide(280_000, true)).toBe(1280);
  expect(jpegRecoverySide(280_001, true)).toBeNull();
  expect(jpegRecoverySide(280_000, false)).toBe(1280);
  expect(jpegRecoverySide(280_001, false)).toBeNull();
});
