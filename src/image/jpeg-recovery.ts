import GenericGF from '@zxing/library/esm/core/common/reedsolomon/GenericGF';
import ReedSolomonEncoder from '@zxing/library/esm/core/common/reedsolomon/ReedSolomonEncoder';
import ReedSolomonDecoder from '@zxing/library/esm/core/common/reedsolomon/ReedSolomonDecoder';
import { ProtectedImageError } from '../crypto/protected-image';

// Experimental same-dimension JPEG recovery layer. This is a transport code,
// not encryption: recovered bytes still require the existing AES-GCM check.
const DATA = 127, CODE = 255, PARITY = CODE - DATA;
const MAGIC = new TextEncoder().encode('SNAPSEALJPG1');
const STEP = 64;
const encoder = new ReedSolomonEncoder(GenericGF.QR_CODE_FIELD_256);
const decoder = new ReedSolomonDecoder(GenericGF.QR_CODE_FIELD_256);
const modes = [[1, 1], [2, 1], [1, 2], [2, 2]];
const basis = modes.map(([u, v]) => Float64Array.from({ length: 64 }, (_, index) =>
  .25 * Math.cos((2 * (index % 8) + 1) * u * Math.PI / 16) * Math.cos((2 * Math.floor(index / 8) + 1) * v * Math.PI / 16)));
export const MAX_JPEG_RECOVERY_BYTES = 16_125;
const crcTable = Uint32Array.from({ length: 256 }, (_, value) => {
  for (let bit = 0; bit < 8; bit++) value = value >>> 1 ^ (value & 1 ? 0xedb88320 : 0);
  return value >>> 0;
});

export function recoverySide(length: number): number | null {
  if (!Number.isInteger(length) || length < 62 || length > MAX_JPEG_RECOVERY_BYTES) return null;
  return length <= 3933 ? 1024 : 2048;
}
function invalid(): never { throw new ProtectedImageError('invalid-file'); }
export function transportCRC(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = crc >>> 8 ^ crcTable[(crc ^ byte) & 255];
  return (crc ^ 0xffffffff) >>> 0;
}
function encoded(bytes: Uint8Array): Uint8Array {
  const result = new Uint8Array(Math.ceil(bytes.length / DATA) * CODE);
  for (let offset = 0, at = 0; offset < bytes.length; offset += DATA, at += CODE) {
    const block = new Int32Array(CODE); block.set(bytes.subarray(offset, offset + DATA));
    encoder.encode(block, PARITY); result.set(block, at);
  }
  return result;
}
function decoded(bytes: Uint8Array, length: number): Uint8Array {
  if (bytes.length % CODE || length > bytes.length / CODE * DATA) invalid();
  const result = new Uint8Array(length);
  try {
    for (let offset = 0, at = 0; offset < bytes.length; offset += CODE, at += DATA) {
      const block = Int32Array.from(bytes.subarray(offset, offset + CODE));
      decoder.decode(block, PARITY); result.set(block.subarray(0, Math.min(DATA, length - at)), at);
    }
  } catch { invalid(); }
  return result;
}
function validate(frame: Uint8ClampedArray, width: number, height: number) {
  if ((width !== 1024 && width !== 2048) || height !== width || frame.length !== width * height * 4) invalid();
}
function coefficients(frame: Uint8ClampedArray, width: number, slot: number): number[] {
  const origin = Math.floor(slot / (width / 8)) * 8 * width + slot % (width / 8) * 8;
  const sums = [0, 0, 0, 0];
  for (let pixel = 0; pixel < 64; pixel++) {
    const at = (origin + Math.floor(pixel / 8) * width + pixel % 8) * 4;
    const y = .299 * frame[at] + .587 * frame[at + 1] + .114 * frame[at + 2];
    for (let mode = 0; mode < 4; mode++) sums[mode] += y * basis[mode][pixel];
  }
  return sums;
}
function read(frame: Uint8ClampedArray, width: number, start: number, length: number): Uint8Array {
  const result = new Uint8Array(length), blocks = width * width / 64;
  for (let block = 0; block < length * 2; block++) {
    const values = coefficients(frame, width, (start * 2 + block) * 4051 % blocks);
    let nibble = 0;
    for (let mode = 0; mode < 4; mode++) nibble = nibble << 1 | (Math.round(values[mode] / STEP) & 1);
    result[block >>> 1] |= nibble << (block % 2 ? 0 : 4);
  }
  return result;
}
export function embedJPEGRecovery(frame: Uint8ClampedArray, width: number, height: number, envelope: Uint8Array) {
  validate(frame, width, height);
  const side = recoverySide(envelope.length);
  if (!side || side > width) throw new ProtectedImageError('too-large');
  const header = new Uint8Array(DATA); header.set(MAGIC);
  const view = new DataView(header.buffer);
  view.setUint16(12, width); view.setUint16(14, height); view.setUint32(16, envelope.length); view.setUint32(20, transportCRC(envelope));
  const packet = new Uint8Array(CODE + Math.ceil(envelope.length / DATA) * CODE);
  packet.set(encoded(header)); packet.set(encoded(envelope), CODE);
  const blocks = width * height / 64;
  if (packet.length * 2 > blocks) throw new ProtectedImageError('too-large');
  for (let block = 0; block < packet.length * 2; block++) {
    const slot = block * 4051 % blocks;
    const nibble = packet[block >>> 1] >>> (block % 2 ? 0 : 4) & 15;
    const values = coefficients(frame, width, slot);
    const targets = values.map((value, mode) => {
      let quantized = Math.round(value / STEP);
      if ((quantized & 1) !== (nibble >>> (3 - mode) & 1)) quantized += value >= quantized * STEP ? 1 : -1;
      return quantized * STEP;
    });
    const origin = Math.floor(slot / (width / 8)) * 8 * width + slot % (width / 8) * 8;
    for (let pass = 0; pass < 3; pass++) {
      const current = pass ? coefficients(frame, width, slot) : values;
      for (let pixel = 0; pixel < 64; pixel++) {
        let change = 0;
        for (let mode = 0; mode < 4; mode++) change += (targets[mode] - current[mode]) * basis[mode][pixel];
        const at = (origin + Math.floor(pixel / 8) * width + pixel % 8) * 4;
        for (let channel = 0; channel < 3; channel++) frame[at + channel] += change;
      }
    }
  }
}
export function extractJPEGRecovery(frame: Uint8ClampedArray, width: number, height: number): Uint8Array {
  validate(frame, width, height);
  const header = decoded(read(frame, width, 0, CODE), DATA);
  if (!MAGIC.every((value, index) => header[index] === value)) invalid();
  const view = new DataView(header.buffer), length = view.getUint32(16);
  const side = recoverySide(length);
  if (view.getUint16(12) !== width || view.getUint16(14) !== height || !side || side > width) invalid();
  const count = Math.ceil(length / DATA) * CODE;
  if ((CODE + count) * 2 > width * height / 64) invalid();
  const envelope = decoded(read(frame, width, CODE, count), length);
  if (transportCRC(envelope) !== view.getUint32(20)) invalid();
  return envelope;
}
