// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { protectImageFile, protectedImageEnvelopeLength, unlockImageFile } from '../src/index';
import { embedJPEGRecovery, extractJPEGRecovery, recoverySide, transportCRC } from '../src/image/jpeg-recovery';
import { embedPixelPacket, extractPixelPacket } from '../src/image/pixel-packet';
import { coverOutputSide, protectedPNGDimensions } from '../src/image/png-container';
import { jpegCoverContrasts } from '../src/image/jpeg-channel';
import { protectedImageZIP, extractProtectedImageZIP } from '../src/image/sharing-zip';

const image = Uint8Array.from(Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==', 'base64'));
const password = 'Transport tests preserve encryption';
function canvas(side = 1024, brightness = 128) {
  const frame = new Uint8ClampedArray(side * side * 4).fill(brightness);
  for (let at = 3; at < frame.length; at += 4) frame[at] = 255;
  return frame;
}
describe('bounded JPEG recovery and lossless sharing', () => {
  it('preserves legacy decoding, authenticates recovered data and rejects a wrong password', async () => {
    const bytes = await protectImageFile(image, 'private.png', password), frame = canvas();
    expect(protectedImageEnvelopeLength(image, 'private.png')).toBe(bytes.length);
    embedJPEGRecovery(frame, 1024, 1024, bytes); embedPixelPacket(frame, bytes, 2);
    expect(extractPixelPacket(frame)).toEqual(bytes);
    const recovered = extractJPEGRecovery(frame, 1024, 1024);
    expect((await unlockImageFile(recovered, password)).bytes).toEqual(image);
    await expect(unlockImageFile(recovered, 'wrong password')).rejects.toMatchObject({ code: 'unlock-failed' });
    const modified = recovered.slice(); modified[modified.length - 1] ^= 1;
    await expect(unlockImageFile(modified, password)).rejects.toMatchObject({ code: 'unlock-failed' });
  });
  it.each([0, 255])('recovers from a saturated flat cover at brightness %i', brightness => {
    const bytes = Uint8Array.from({ length: 3933 }, (_, index) => index * 83 & 255), frame = canvas(1024, brightness);
    embedJPEGRecovery(frame, 1024, 1024, bytes); embedPixelPacket(frame, bytes, 2);
    expect(extractJPEGRecovery(frame, 1024, 1024)).toEqual(bytes);
  });
  it('bounds capacities and allocates a larger cover only where needed', () => {
    expect(recoverySide(3933)).toBe(1024); expect(recoverySide(3934)).toBe(2048);
    expect(recoverySide(16125)).toBe(2048); expect(recoverySide(16126)).toBeNull();
    for (const bad of [NaN, -1, 0, 61, 100.5, Infinity]) expect(recoverySide(bad)).toBeNull();
    expect(coverOutputSide(3934)).toBe(1280); expect(coverOutputSide(16126)).toBe(1280);
    expect(coverOutputSide(64000)).toBe(1280); expect(coverOutputSide(64001)).toBe(1280);
    expect(coverOutputSide(120000)).toBe(1280); expect(coverOutputSide(280000)).toBe(1280); expect(coverOutputSide(280001)).toBe(1024);
    expect(coverOutputSide(1024 * 1024)).toBeGreaterThan(1024);
    expect(() => embedJPEGRecovery(canvas(), 1024, 1024, new Uint8Array(3934))).toThrow('too-large');
    expect(() => extractJPEGRecovery(canvas(), 1024, 1024)).toThrow('invalid-file');
    expect(() => extractJPEGRecovery(new Uint8ClampedArray(16), 1024, 1024)).toThrow('invalid-file');
    expect(() => extractJPEGRecovery(canvas(), 1024, 1023)).toThrow('invalid-file');
  });
  it('sizes both lossless carriers for the entire payload, independent of the original aspect ratio', () => {
    for (const cover of [true, false]) {
      for (const bytes of [62, 3933, 3934, 64000, 64001, 280000, 280001, 1024 * 1024, 8 * 1024 * 1024]) {
        const { width, height } = protectedPNGDimensions(bytes, cover);
        const lowBits = cover || bytes <= 280000;
        expect(width * height * 3 / (lowBits ? 4 : 1)).toBeGreaterThanOrEqual(bytes + 16);
        if (cover || bytes <= 280000) expect(height).toBe(width);
      }
    }
    const large = protectedPNGDimensions(50 * 1024 * 1024 + 4096, false);
    expect(large.width * large.height * 3).toBeGreaterThanOrEqual(50 * 1024 * 1024 + 4096 + 16);
    for (const bad of [NaN, Infinity, -1, 0, 61, 62.5]) expect(() => protectedPNGDimensions(bad, false)).toThrow('invalid-file');
  });
  it('tries bounded contrast candidates from clear to more aggressive without changing data capacity', () => {
    expect(jpegCoverContrasts(32000, 1280)).toEqual([1]);
    expect(jpegCoverContrasts(200000, 1280)).toEqual([1, .625, .25]);
    expect(jpegCoverContrasts(280000, 1280)).toEqual([1, .575, .15]);
    for (const [bytes, side] of [[NaN, 1280], [280001, 1280], [200000, 4096]]) expect(() => jpegCoverContrasts(bytes, side)).toThrow('invalid-file');
  });
  it('corrects localized damage within the Reed–Solomon budget and rejects a destroyed header', () => {
    const frame = canvas(), bytes = Uint8Array.from({ length: 3933 }, (_, index) => index * 37 & 255);
    embedJPEGRecovery(frame, 1024, 1024, bytes);
    function eraseByte(index: number) {
      for (let half = 0; half < 2; half++) {
        const slot = (index * 2 + half) * 4051 % (1024 * 1024 / 64);
        const x = slot % 128 * 8, y = Math.floor(slot / 128) * 8;
        for (let dy = 0; dy < 8; dy++) for (let dx = 0; dx < 8; dx++) {
          const at = ((y + dy) * 1024 + x + dx) * 4;
          frame[at] = frame[at + 1] = frame[at + 2] = 128;
        }
      }
    }
    for (let index = 127; index < 159; index++) eraseByte(index);
    expect(extractJPEGRecovery(frame, 1024, 1024)).toEqual(bytes);
    for (let index = 0; index < 255; index++) eraseByte(index);
    expect(() => extractJPEGRecovery(frame, 1024, 1024)).toThrow('invalid-file');
  });
  it('uses the standard ZIP CRC and stores only the unchanged protected image with no private name', () => {
    expect(transportCRC(new TextEncoder().encode('123456789'))).toBe(0xcbf43926);
    const zip = protectedImageZIP(image), view = new DataView(zip.buffer);
    expect(view.getUint32(0, true)).toBe(0x04034b50);
    const length = view.getUint16(26, true), name = new TextDecoder().decode(zip.subarray(30, 30 + length));
    expect(name).toBe('protected-image.png'); expect(view.getUint16(8, true)).toBe(0);
    expect(zip.slice(30 + length, 30 + length + image.length)).toEqual(image);
    expect(view.getUint32(14, true)).toBe(transportCRC(image));
    expect(view.getUint16(zip.length - 12, true)).toBe(1);
    expect(extractProtectedImageZIP(zip)).toEqual(image);
  });
  it('rejects altered payloads, compressed/encrypted entries, paths, multiple entries, forged sizes and truncation before opening a ZIP', () => {
    const original = protectedImageZIP(image);
    const mutations = [
      (bytes: Uint8Array) => { bytes[49] ^= 1; },
      (bytes: Uint8Array) => { bytes[6] = 1; },
      (bytes: Uint8Array) => { bytes[8] = 8; },
      (bytes: Uint8Array) => { bytes[30] = 46; bytes[31] = 46; bytes[32] = 47; },
      (bytes: Uint8Array) => { new DataView(bytes.buffer).setUint32(18, 0xffffffff, true); },
      (bytes: Uint8Array) => { bytes[bytes.length - 12] = 2; },
      (bytes: Uint8Array) => { new DataView(bytes.buffer).setUint32(bytes.length - 6, 0xffffffff, true); },
    ];
    for (const mutate of mutations) { const bytes = original.slice(); mutate(bytes); expect(() => extractProtectedImageZIP(bytes)).toThrow('invalid-file'); }
    for (const size of [0, 30, 100, original.length - 1]) expect(() => extractProtectedImageZIP(original.slice(0, size))).toThrow('invalid-file');
  });
});
