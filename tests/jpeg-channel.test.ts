// @vitest-environment node
import { createHash, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';
import { protectImageFile, unlockImageFile } from '../src/index';
import { channelCarriers, channelProfile, embedJPEGChannel, extractJPEGChannel, extractJPEGChannelWithStats, jpegChannelSide, jpegChannelContrast, MAX_CHANNEL_BYTES } from '../src/image/jpeg-channel';
import { embedPixelPacket, extractPixelPacket } from '../src/image/pixel-packet';
import { transportCRC } from '../src/image/jpeg-recovery';

const { GenericGF, ReedSolomonEncoder } = createRequire(new URL('../package.json', import.meta.url))('@zxing/library');

const SIDE = 1024, password = 'Channel transport keeps encryption';
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==', 'base64');
const TG1024 = [4, 4, 4, 5, 7, 10, 15, 22, 4, 4, 5, 7, 9, 10, 14, 20, 4, 5, 6, 8, 11, 16, 24, 30, 5, 7, 8, 10, 14, 19, 28, 36, 7, 9, 11, 14, 18, 24, 34, 42, 10, 10, 16, 19, 24, 32, 40, 48, 15, 14, 24, 28, 34, 40, 48, 56, 22, 20, 30, 36, 42, 48, 56, 64];
const TG1280 = [4, 6, 6, 9, 13, 22, 30, 40, 7, 7, 8, 11, 15, 32, 40, 50, 8, 7, 9, 13, 22, 32, 44, 55, 8, 10, 12, 16, 29, 40, 50, 60, 10, 12, 21, 31, 38, 48, 60, 70, 13, 20, 31, 40, 48, 60, 70, 80, 27, 36, 44, 50, 60, 70, 80, 90, 40, 50, 55, 60, 70, 80, 90, 99];

function sha(bytes: Uint8Array) { return createHash('sha256').update(bytes).digest('hex'); }
/** Textured, saturated cover with hard edges, deterministic across runs. */
function cover(side = SIDE) {
  const frame = new Uint8ClampedArray(side * side * 4);
  for (let y = 0, at = 0; y < side; y++) for (let x = 0; x < side; x++, at += 4) {
    const wave = 60 * Math.sin(x / 19) * Math.cos(y / 27), band = (x >> 5) + (y >> 5) & 1 ? 40 : -40;
    frame[at] = 128 + wave + band; frame[at + 1] = y * 255 / side; frame[at + 2] = 255 - x * 255 / side; frame[at + 3] = 255;
  }
  return frame;
}
const COS = Array.from({ length: 8 }, (_, u) => Array.from({ length: 8 }, (_, x) => Math.cos((2 * x + 1) * u * Math.PI / 16) * (u ? .5 : Math.SQRT1_2 / 2)));
/** Independently construct a valid RS header, including hostile field values. */
function replaceHeader(frame: Uint8ClampedArray, header: Uint8Array, side = SIDE) {
  const words = new Int32Array(64); words.set(header);
  new ReedSolomonEncoder(GenericGF.QR_CODE_FIELD_256).encode(words, 48);
  const modes = [[1, 1], [1, 2], [2, 1], [2, 2]];
  for (let index = 0; index < 128; index++) {
    const slot = index * 4051 % (side * side / 64), left = slot % (side / 8) * 8, top = Math.floor(slot / (side / 8)) * 8;
    const value = index & 1 ? words[index >> 1] & 15 : words[index >> 1] >> 4;
    for (let y = 0; y < 8; y++) for (let x = 0; x < 8; x++) {
      let luma = 128;
      for (let part = 0; part < 4; part++) if (value >> 3 - part & 1) luma += 48 * COS[modes[part][0]][y] * COS[modes[part][1]][x];
      const at = ((top + y) * side + left + x) * 4;
      frame[at] = frame[at + 1] = frame[at + 2] = luma; frame[at + 3] = 255;
    }
  }
}
/** Same-size JPEG round trip, luma only: 2-D DCT, quantize, inverse, round. */
function jpegLuma(frame: Uint8ClampedArray, table: number[]) {
  const out = frame.slice(), y = new Float64Array(64), d = new Float64Array(64), side = Math.sqrt(frame.length / 4);
  for (let top = 0; top < side; top += 8) for (let left = 0; left < side; left += 8) {
    for (let row = 0; row < 8; row++) for (let col = 0; col < 8; col++) {
      const at = ((top + row) * side + left + col) * 4;
      y[row * 8 + col] = .299 * frame[at] + .587 * frame[at + 1] + .114 * frame[at + 2] - 128;
    }
    for (let v = 0; v < 8; v++) for (let u = 0; u < 8; u++) {
      let sum = 0;
      for (let row = 0; row < 8; row++) for (let col = 0; col < 8; col++) sum += y[row * 8 + col] * COS[v][row] * COS[u][col];
      d[v * 8 + u] = v + u ? Math.round(sum / table[v * 8 + u]) * table[v * 8 + u] : sum;
    }
    for (let row = 0; row < 8; row++) for (let col = 0; col < 8; col++) {
      let sum = 0;
      for (let v = 0; v < 8; v++) for (let u = 0; u < 8; u++) sum += d[v * 8 + u] * COS[v][row] * COS[u][col];
      const at = ((top + row) * side + left + col) * 4, change = sum - y[row * 8 + col];
      for (let channel = 0; channel < 3; channel++) out[at + channel] = frame[at + channel] + change;
    }
  }
  return out;
}
async function envelopeOf(length: number) {
  const overhead = (await protectImageFile(new Uint8Array(PNG), 'p.png', password)).length - PNG.length;
  const original = new Uint8Array(randomBytes(length - overhead)); original.set(PNG);
  const envelope = await protectImageFile(original, 'p.png', password);
  expect(envelope.length).toBe(length);
  return { original, envelope };
}

describe('high-capacity JPEG channel', () => {
  it.each([['1024 table', TG1024], ['coarser 1280 table', TG1280]])('recovers a 118,186-byte envelope byte for byte through the measured %s', async (_, table) => {
    const { original, envelope } = await envelopeOf(118_186), frame = cover();
    embedJPEGChannel(frame, SIDE, SIDE, envelope); embedPixelPacket(frame, envelope, 2);
    expect(extractPixelPacket(frame)).toEqual(envelope);
    const { envelope: read, stats } = extractJPEGChannelWithStats(jpegLuma(frame, table), SIDE, SIDE);
    expect(sha(read)).toBe(sha(envelope));
    expect(sha((await unlockImageFile(read, password)).bytes)).toBe(sha(original));
    await expect(unlockImageFile(read, 'a different password')).rejects.toMatchObject({ code: 'unlock-failed' });
    expect(stats.worstCodeword).toBeLessThanOrEqual(16);
  }, 60_000);
  it('never returns altered bytes: AES-GCM still rejects any payload change', async () => {
    const { envelope } = await envelopeOf(4_000), frame = cover();
    embedJPEGChannel(frame, SIDE, SIDE, envelope);
    const read = extractJPEGChannel(frame, SIDE, SIDE); read[read.length - 1] ^= 1;
    await expect(unlockImageFile(read, password)).rejects.toMatchObject({ code: 'unlock-failed' });
  }, 30_000);
  it.each([118_186, 120_000, 160_000, 200_000])('uses a stronger 1280-pixel profile for %i bytes without changing the encrypted file', async length => {
    const side = jpegChannelSide(length)!;
    expect(side).toBe(1280); expect(channelProfile(length, side)!.step).toBe(4);
    const { original, envelope } = await envelopeOf(length), frame = cover(side);
    embedJPEGChannel(frame, side, side, envelope); embedPixelPacket(frame, envelope, 2);
    expect(extractPixelPacket(frame)).toEqual(envelope);
    const read = extractJPEGChannel(jpegLuma(frame, TG1280), side, side);
    expect(sha(read)).toBe(sha(envelope));
    expect(sha((await unlockImageFile(read, password)).bytes)).toBe(sha(original));
  }, 60_000);
  it('survives saturated covers, where gamut limits would otherwise clip the data', () => {
    for (const value of [0, 255]) {
      const frame = new Uint8ClampedArray(SIDE * SIDE * 4).fill(value), bytes = new Uint8Array(randomBytes(118_186));
      for (let at = 3; at < frame.length; at += 4) frame[at] = 255;
      embedJPEGChannel(frame, SIDE, SIDE, bytes);
      expect(sha(extractJPEGChannel(frame, SIDE, SIDE))).toBe(sha(bytes));
    }
  }, 30_000);
  it('repairs scattered block damage and rejects a destroyed image', () => {
    const frame = cover(), bytes = new Uint8Array(randomBytes(40_000));
    embedJPEGChannel(frame, SIDE, SIDE, bytes);
    const damaged = frame.slice();
    for (let top = 512; top < 576; top++) for (let left = 256; left < 320; left++) {
      const at = (top * SIDE + left) * 4; damaged[at] = damaged[at + 1] = damaged[at + 2] = 128;
    }
    const { envelope, stats } = extractJPEGChannelWithStats(damaged, SIDE, SIDE);
    expect(sha(envelope)).toBe(sha(bytes)); expect(stats.correctedSymbols).toBeGreaterThan(0);
    expect(() => extractJPEGChannel(cover(), SIDE, SIDE)).toThrow('invalid-file');
    expect(() => extractJPEGChannel(new Uint8ClampedArray(16), SIDE, SIDE)).toThrow('invalid-file');
    expect(() => extractJPEGChannel(frame, SIDE, SIDE - 1)).toThrow('invalid-file');
  }, 30_000);
  it('bounds profiles and derives identical carriers from the header values', () => {
    for (const bad of [NaN, -1, 0, 61, 62.5, Infinity, MAX_CHANNEL_BYTES + 1]) expect(channelProfile(bad)).toBeNull();
    for (const bad of [NaN, -1, 0, 61, 62.5, Infinity, 280_001]) expect(jpegChannelSide(bad)).toBeNull();
    expect(jpegChannelSide(64_000)).toBe(1024); expect(jpegChannelSide(64_001)).toBe(1280);
    expect(jpegChannelSide(200_000)).toBe(1280);
    expect(jpegChannelSide(280_000)).toBe(1280);
    expect(channelProfile(280_000, 1280)?.step).toBe(3.75);
    expect(channelProfile(1_000_000, 2560)?.step).toBe(3.75);
    expect(jpegChannelSide(1_000_000)).toBeNull(); // HD is research-only for creation.
    expect(jpegChannelContrast(280_000)).toBe(.15);
    expect(jpegChannelContrast(120_000)).toBe(1); expect(jpegChannelContrast(160_000)).toBe(.5); expect(jpegChannelContrast(200_000)).toBe(.25);
    expect(channelProfile(64_000, 4096)).toBeNull();
    for (const bad of [NaN, Infinity, -1, 0, 1.5, 111]) expect(() => channelCarriers(bad, 3)).toThrow('invalid-file');
    expect(() => channelCarriers(10, 5 as 3)).toThrow('invalid-file');
    expect(channelProfile(MAX_CHANNEL_BYTES)).not.toBeNull();
    expect(channelProfile(118_186)!.step).toBe(2);
    expect(channelProfile(4_000)!.step).toBeGreaterThan(2);
    const small = channelProfile(4_000)!, large = channelProfile(118_186)!;
    expect(small.bitsPerBlock).toBeLessThan(large.bitsPerBlock);
    const carriers = channelCarriers(large.bitsPerBlock, large.step);
    expect(carriers.reduce((sum, carrier) => sum + carrier.bits, 0)).toBe(large.bitsPerBlock);
    expect(carriers.every(carrier => carrier.at > 0)).toBe(true); // DC stays free for gamut.
    expect(() => embedJPEGChannel(cover(), SIDE, SIDE, new Uint8Array(MAX_CHANNEL_BYTES + 1))).toThrow('too-large');
  });
  it.each([[280_000, 1280], [1_000_000, 2560]])('preserves authenticated bytes in the %i-byte capacity profile', async (length, side) => {
    const { original, envelope } = await envelopeOf(length), frame = cover(side);
    const written = embedJPEGChannel(frame, side, side, envelope);
    expect(written.step).toBe(3.75);
    embedPixelPacket(frame, envelope, 2);
    expect(extractPixelPacket(frame)).toEqual(envelope);
    const read = extractJPEGChannel(jpegLuma(frame, TG1280), side, side);
    expect(sha(read)).toBe(sha(envelope));
    expect(sha((await unlockImageFile(read, password)).bytes)).toBe(sha(original));
  }, 120_000);
  it('rejects RS-valid malicious headers before body allocation and rejects a valid body with the wrong CRC', () => {
    const bytes = new Uint8Array(randomBytes(4_000)), frame = cover();
    embedJPEGChannel(frame, SIDE, SIDE, bytes);
    const profile = channelProfile(bytes.length)!, header = new Uint8Array(16), view = new DataView(header.buffer);
    view.setUint32(0, 0x53534a32); header[4] = profile.bitsPerBlock; header[5] = 3;
    view.setUint16(6, SIDE); view.setUint32(8, bytes.length); view.setUint32(12, transportCRC(bytes));
    replaceHeader(frame, header);
    expect(sha(extractJPEGChannel(frame, SIDE, SIDE))).toBe(sha(bytes));
    for (const [offset, value] of [[0, 0], [4, 0], [4, 111], [5, 255], [6, 0], [8, 0], [8, 0xffffffff], [12, (transportCRC(bytes) ^ 1) >>> 0]]) {
      const changed = header.slice(), fields = new DataView(changed.buffer);
      if (offset === 4 || offset === 5) changed[offset] = value;
      else if (offset === 6) fields.setUint16(offset, value);
      else fields.setUint32(offset, value);
      replaceHeader(frame, changed);
      expect(() => extractJPEGChannel(frame, SIDE, SIDE)).toThrow('invalid-file');
    }
  }, 30_000);
});
