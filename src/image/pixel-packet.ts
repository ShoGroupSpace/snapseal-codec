import { MAX_PROTECTED_IMAGE_BYTES, ProtectedImageError } from '../crypto/protected-image';

const PREFIX = new TextEncoder().encode('SNAPSEALPNG');
export const PIXEL_HEADER_BYTES = 16;
export const MAX_COVER_IMAGE_BYTES = 8 * 1024 * 1024;
export const MAX_COVER_ENVELOPE_BYTES = MAX_COVER_IMAGE_BYTES + 4096;
export type PixelEncoding = 8 | 2;
export function envelopeLimit(bits: PixelEncoding) { return bits === 2 ? MAX_COVER_ENVELOPE_BYTES : MAX_PROTECTED_IMAGE_BYTES; }

/** V1 uses whole RGB bytes; V2 changes only their two low bits. Both carry the
 * same authenticated envelope. The pixel container itself is not encryption. */
export function embedPixelPacket(frame: Uint8ClampedArray, envelope: Uint8Array, bits: PixelEncoding) {
  if (envelope.length < 62) throw new ProtectedImageError('invalid-file');
  if (envelope.length > envelopeLimit(bits)) throw new ProtectedImageError('too-large');
  const channelsPerByte = 8 / bits;
  const channels = (PIXEL_HEADER_BYTES + envelope.length) * channelsPerByte;
  if (frame.length % 4 || channels > frame.length / 4 * 3) throw new ProtectedImageError('invalid-file');
  const header = new Uint8Array(PIXEL_HEADER_BYTES);
  header.set(PREFIX); header[11] = bits === 2 ? 50 : 49;
  new DataView(header.buffer).setUint32(12, envelope.length);
  const mask = (1 << bits) - 1;
  for (let channel = 0; channel < channels; channel++) {
    const byte = Math.floor(channel / channelsPerByte);
    const value = byte < PIXEL_HEADER_BYTES ? header[byte] : envelope[byte - PIXEL_HEADER_BYTES];
    const at = Math.floor(channel / 3) * 4 + channel % 3;
    const part = value >>> ((channelsPerByte - 1 - channel % channelsPerByte) * bits) & mask;
    frame[at] = (frame[at] & ~mask) | part;
  }
}

export function extractPixelPacket(frame: Uint8ClampedArray): Uint8Array {
  if (frame.length % 4 || frame.length / 4 * 3 < PIXEL_HEADER_BYTES) throw new ProtectedImageError('invalid-file');
  function at(index: number, bits: PixelEncoding) {
    let value = 0;
    for (let part = 0; part < 8 / bits; part++) {
      const channel = index * (8 / bits) + part;
      if (channel >= frame.length / 4 * 3) throw new ProtectedImageError('invalid-file');
      value = value << bits | (frame[Math.floor(channel / 3) * 4 + channel % 3] & ((1 << bits) - 1));
    }
    return value;
  }
  let bits: PixelEncoding;
  if (PREFIX.every((value, index) => at(index, 8) === value)) {
    if (at(11, 8) !== 49) throw new ProtectedImageError('unsupported-version');
    bits = 8;
  } else if (frame.length / 4 * 3 >= PIXEL_HEADER_BYTES * 4 && PREFIX.every((value, index) => at(index, 2) === value)) {
    if (at(11, 2) !== 50) throw new ProtectedImageError('unsupported-version');
    bits = 2;
  } else throw new ProtectedImageError('invalid-file');
  const sizeBytes = Uint8Array.from({ length: 4 }, (_, index) => at(12 + index, bits));
  const size = new DataView(sizeBytes.buffer).getUint32(0);
  const channels = (PIXEL_HEADER_BYTES + size) * (8 / bits);
  // Bound the advertised allocation, and check alpha for header and payload.
  if (size < 62 || size > envelopeLimit(bits) || channels > frame.length / 4 * 3) throw new ProtectedImageError('invalid-file');
  for (let pixel = 0; pixel < Math.ceil(channels / 3); pixel++) {
    if (frame[pixel * 4 + 3] !== 255) throw new ProtectedImageError('invalid-file');
  }
  const envelope = new Uint8Array(size);
  for (let index = 0; index < size; index++) envelope[index] = at(PIXEL_HEADER_BYTES + index, bits);
  return envelope;
}

export function protectedDimensions(envelopeLength: number, cover: boolean) {
  if (!Number.isInteger(envelopeLength) || envelopeLength < 62) throw new ProtectedImageError('invalid-file');
  const bits = cover ? 2 : 8;
  if (envelopeLength > envelopeLimit(bits)) throw new ProtectedImageError('too-large');
  const pixels = Math.ceil((PIXEL_HEADER_BYTES + envelopeLength) * 8 / (3 * bits));
  if (cover) {
    const side = Math.max(1024, Math.ceil(Math.sqrt(pixels) / 8) * 8);
    return { width: side, height: side };
  }
  const width = Math.min(2048, Math.max(64, Math.ceil(Math.sqrt(pixels))));
  return { width, height: Math.ceil(pixels / width) };
}
