/** Node reader: exact PNG samples, bounded JPEG decoding, no browser required. */
import { PNG } from 'pngjs';
import { inspectProtectedFile, validateImageDimensions, MAX_PROTECTED_IMAGE_BYTES, ProtectedImageError, unlockProtectedFile } from './crypto/protected-image';
import { extractPixelPacket } from './image/pixel-packet';
import { extractStyledPacket } from './image/styled-packet';
import { extractJPEGChannel } from './image/jpeg-channel';
import { extractJPEGRecovery } from './image/jpeg-recovery';
import { extractJPEGFile } from './image/jpeg-file';
import decodeJPEG from './image/vendor/jpeg-decoder.js';
import { extractProtectedImageZIP, MAX_CONTAINER_FILE_BYTES } from './image/sharing-zip';
export * from './index';
const MAX_PIXELS = Math.ceil((MAX_PROTECTED_IMAGE_BYTES + 16) / 3) + 1024 * 1024;
export function decodeContainer(input: Uint8Array): Uint8Array {
  if (input.length > MAX_CONTAINER_FILE_BYTES) throw new ProtectedImageError('too-large');
  if (new TextDecoder().decode(input.subarray(0, 8)) === 'SNAPSEAL') { inspectProtectedFile(input); return input.slice(); }
  let bytes = input;
  if (bytes[0] === 80 && bytes[1] === 75 && bytes[2] === 3 && bytes[3] === 4) bytes = extractProtectedImageZIP(bytes);
  if (bytes.length > MAX_PROTECTED_IMAGE_BYTES + 1024 * 1024) throw new ProtectedImageError('too-large');
  const jpeg = bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255;
  let size: { width: number; height: number };
  try { size = validateImageDimensions(bytes); } catch (error) { if (error instanceof ProtectedImageError) throw error; throw new ProtectedImageError('invalid-file'); }
  const { width, height } = size;
  if (width * height > MAX_PIXELS) throw new ProtectedImageError('unsafe-dimensions');
  if (jpeg && (width !== height || ![1024, 1280, 2048, 2560].includes(width))) throw new ProtectedImageError('invalid-file');
  let envelope: Uint8Array | undefined;
  if (jpeg && width !== 2048) { try { envelope = extractJPEGFile(bytes).envelope; } catch { /* Match browser pixel fallback. */ } }
  if (!envelope) {
    let pixels: Uint8ClampedArray;
    try {
      if (jpeg) {
        // Same bounded vendored JPEG decoder, using its normal IDCT fallback.
        const image = (decodeJPEG as unknown as (bytes: Uint8Array, options: object) => { width: number; height: number; data: Uint8Array })(bytes, { useTArray: true, tolerantDecoding: false, maxResolutionInMP: MAX_PIXELS / 1e6, maxMemoryUsageInMB: 192 });
        if (image.width !== width || image.height !== height) throw new Error('size');
        pixels = new Uint8ClampedArray(image.data);
      } else {
        if (bytes[0] !== 137) throw new ProtectedImageError('invalid-file');
        const image = PNG.sync.read(Buffer.from(bytes), { checkCRC: true });
        if (image.width !== width || image.height !== height) throw new Error('size');
        pixels = new Uint8ClampedArray(image.data);
      }
    } catch { throw new ProtectedImageError('invalid-file'); }
    let pixelError: unknown;
    if (!jpeg) { try { envelope = extractStyledPacket(pixels, width, height) ?? extractPixelPacket(pixels); } catch (error) { pixelError = error; } }
    if (!envelope && width === height && [1024, 1280, 2560].includes(width)) { try { envelope = extractJPEGChannel(pixels, width, height); } catch { /* Legacy fallback. */ } }
    if (!envelope && width === height && [1024, 2048].includes(width)) { try { envelope = extractJPEGRecovery(pixels, width, height); } catch { /* Invalid container. */ } }
    if (!envelope) throw pixelError instanceof ProtectedImageError ? pixelError : new ProtectedImageError('invalid-file');
  }
  inspectProtectedFile(envelope);
  return envelope;
}
export async function decodeFile(input: Uint8Array, password: string, signal?: AbortSignal) {
  signal?.throwIfAborted();
  return unlockProtectedFile(decodeContainer(input), password, { signal });
}
