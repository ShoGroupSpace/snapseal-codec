import { inspectProtectedFile,detectImageMime, validateImageDimensions, MAX_PROTECTED_IMAGE_BYTES, ProtectedImageError } from '../crypto/protected-image';
import { embedPixelPacket, extractPixelPacket, MAX_COVER_IMAGE_BYTES, protectedDimensions } from './pixel-packet';
import { embedJPEGRecovery, extractJPEGRecovery, recoverySide } from './jpeg-recovery';
import { embedJPEGChannel, extractJPEGChannel, extractJPEGChannelWithStats, jpegRecoverySide, jpegCoverContrasts, type JPEGRecoveryMode } from './jpeg-channel';
import { extractProtectedImageZIP, MAX_CONTAINER_FILE_BYTES } from './sharing-zip';
import { readJPEGFile } from './jpeg-worker-client';
import { embedStyledPacket,extractStyledPacket,styledCapacity,visualFlags,type VisualOptions } from './styled-packet';
import { visualOverlay } from './visual-overlay';

const PNG_MAGIC = [137, 80, 78, 71, 13, 10, 26, 10];
const MAX_PIXELS = Math.ceil((MAX_PROTECTED_IMAGE_BYTES + 16) / 3) + 1024 * 1024;
const MAX_COVER_SOURCE_PIXELS = 16 * 1024 * 1024;

export function coverOutputSide(envelopeLength: number, mode: JPEGRecoveryMode = 'standard') {
  return Math.max(protectedDimensions(envelopeLength, true).width, jpegRecoverySide(envelopeLength, true, mode) ?? 0);
}

/** Carrier geometry depends on encrypted byte count, never original dimensions.
 * JPEG recovery uses supported square canvases. Larger lossless carriers grow
 * to fit the exact packet, including metadata and authentication overhead. */
export function protectedPNGDimensions(envelopeLength: number, cover: boolean, mode: JPEGRecoveryMode = 'standard',visual:VisualOptions={}) {
  const dimensions = protectedDimensions(envelopeLength, cover);
  const recovery = jpegRecoverySide(envelopeLength, cover, mode);
  let width = cover ? coverOutputSide(envelopeLength, mode) : recovery ?? dimensions.width;
  let height=cover||recovery?width:dimensions.height;
  const flags=visualFlags(visual);
  if(flags){width=Math.max(width,512);height=Math.max(height,256);while(styledCapacity(width,height,cover||recovery?2:8,flags)<envelopeLength){if(cover||recovery){width+=8;height=width;}else height+=8;}}
  return {width,height};
}

export class CoverImageError extends Error {
  constructor(readonly code: 'too-large' | 'invalid') { super(code); this.name = 'CoverImageError'; }
}

/** Validate custom covers before image decoding. Never accept SVG/HTML. */
export function validateCoverImage(bytes: Uint8Array) {
  if (bytes.length > MAX_COVER_IMAGE_BYTES) throw new CoverImageError('too-large');
  try {
    const size = validateImageDimensions(bytes);
    if (size.width > 8192 || size.height > 8192 || size.width * size.height > MAX_COVER_SOURCE_PIXELS) throw new CoverImageError('too-large');
    return { ...size, mimeType: detectImageMime(bytes) };
  } catch (error) {
    if (error instanceof CoverImageError) throw error;
    if (error instanceof ProtectedImageError && error.code === 'unsafe-dimensions') throw new CoverImageError('too-large');
    throw new CoverImageError('invalid');
  }
}

/** Flatten and downsize the preview. The encoder separately validates and
 * draws the original cover, preserving detail when a larger output is needed.
 * Neither animation nor source metadata is copied into the protected PNG. */
export async function prepareCoverImage(bytes: Uint8Array): Promise<Uint8Array> {
  const source = validateCoverImage(bytes);
  let bitmap: ImageBitmap | undefined;
  const canvas = document.createElement('canvas');
  try {
    bitmap = await createImageBitmap(new Blob([Uint8Array.from(bytes)], { type: source.mimeType }));
    if (!bitmap.width || !bitmap.height || bitmap.width > 8192 || bitmap.height > 8192 || bitmap.width * bitmap.height > MAX_COVER_SOURCE_PIXELS) throw new CoverImageError('too-large');
    canvas.width = canvas.height = 1024;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new ProtectedImageError('unsupported-browser');
    ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, 1024, 1024);
    const scale = Math.max(1024 / bitmap.width, 1024 / bitmap.height);
    ctx.drawImage(bitmap, (1024 - bitmap.width * scale) / 2, (1024 - bitmap.height * scale) / 2, bitmap.width * scale, bitmap.height * scale);
    const blob = await new Promise<Blob>((resolve, reject) => canvas.toBlob(blob => blob ? resolve(blob) : reject(new CoverImageError('invalid')), 'image/png'));
    return new Uint8Array(await blob.arrayBuffer());
  } catch (error) {
    if (error instanceof CoverImageError || error instanceof ProtectedImageError) throw error;
    throw new CoverImageError('invalid');
  } finally { bitmap?.close(); canvas.width = canvas.height = 1; }
}

export interface EncodedProtectedPNG { bytes: Uint8Array; jpegRecovery: boolean; recoverySide?: number; }
export type PNGEncodingOptions = { recoveryMode?: JPEGRecoveryMode; onProgress?: (stage: 'creating' | 'checking' | 'saving') => void; visual?:VisualOptions };

/** A local stress test, not a guarantee about a messenger's unknown encoder.
 * Test both single and repeated JPEG conversion of the final lossless packet.
 * Repeated conversion can accidentally improve quantization alignment, so it
 * must not replace the single-conversion check. Keep correction headroom too. */
async function checkJPEGRecovery(frame: ImageData, envelope: Uint8Array, legacy: boolean): Promise<boolean> {
  const canvas = document.createElement('canvas');
  canvas.width = frame.width; canvas.height = frame.height;
  try {
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) throw new ProtectedImageError('unsupported-browser');
    for (const chain of [[.60], [.85, .60]]) {
      ctx.putImageData(frame, 0, 0);
      for (const quality of chain) {
        const jpeg = await new Promise<Blob>((resolve, reject) => canvas.toBlob(blob => blob ? resolve(blob) : reject(new ProtectedImageError('invalid-file')), 'image/jpeg', quality));
        // A browser that silently substitutes PNG did not perform the test.
        if (jpeg.type !== 'image/jpeg') return false;
        const bitmap = await createImageBitmap(jpeg);
        try { ctx.drawImage(bitmap, 0, 0); } finally { bitmap.close(); }
      }
      const pixels = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
      const decoded = legacy ? null : extractJPEGChannelWithStats(pixels, canvas.width, canvas.height);
      const read = decoded?.envelope ?? extractJPEGRecovery(pixels, canvas.width, canvas.height);
      if (read.length !== envelope.length || !read.every((byte, at) => byte === envelope[at])) return false;
      // RS can correct 16 symbols per word. Do not advertise a recovery copy
      // already using its entire repair budget in the local encoder test.
      if (decoded && decoded.stats.worstCodeword > 12) return false;
    }
    return true;
  } catch (error) {
    if (error instanceof ProtectedImageError && error.code === 'invalid-file') return false;
    throw error;
  } finally { canvas.width = canvas.height = 1; }
}

/** Existing byte-only API, also used by integrations outside the shared UI. */
export async function encodeProtectedPNG(envelope: Uint8Array, cover?: Uint8Array, options: PNGEncodingOptions = {}): Promise<Uint8Array> {
  return (await encodeProtectedPNGWithInfo(envelope, cover, options)).bytes;
}

/** V1 is compact noise; V2 carries the unchanged envelope in a visible cover.
 * A bounded additional DCT copy attempts same-size JPEG recovery. */
export async function encodeProtectedPNGWithInfo(envelope: Uint8Array, cover?: Uint8Array, { recoveryMode = 'standard', onProgress,visual={} }: PNGEncodingOptions = {}): Promise<EncodedProtectedPNG> {
  onProgress?.('creating');
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  const { width, height } = protectedPNGDimensions(envelope.length, Boolean(cover), recoveryMode,visual);
  const recovery = jpegRecoverySide(envelope.length, Boolean(cover), recoveryMode);
  const canvas = document.createElement('canvas');
  const flags=visualFlags(visual),paint=flags?await visualOverlay(width,height,visual):undefined;
  const lossless=(frame:Uint8ClampedArray,bits:2|8)=>{paint?.(frame);if(flags)embedStyledPacket(frame,width,height,envelope,bits,flags);else embedPixelPacket(frame,envelope,bits);};
  let bitmap: ImageBitmap | undefined;
  try {
    const source = cover ? validateCoverImage(cover) : null;
    if (cover && source) {
      try { bitmap = await createImageBitmap(new Blob([Uint8Array.from(cover)], { type: source.mimeType })); }
      catch { throw new CoverImageError('invalid'); }
      if (!bitmap.width || !bitmap.height || bitmap.width > 8192 || bitmap.height > 8192 || bitmap.width * bitmap.height > MAX_COVER_SOURCE_PIXELS) throw new CoverImageError('too-large');
    }
    canvas.width = width; canvas.height = height;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) throw new ProtectedImageError('unsupported-browser');
    let frame: ImageData;
    if (bitmap) {
      ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, width, height);
      const scale = Math.max(width / bitmap.width, height / bitmap.height);
      ctx.drawImage(bitmap, (width - bitmap.width * scale) / 2, (height - bitmap.height * scale) / 2, bitmap.width * scale, bitmap.height * scale);
      frame = ctx.getImageData(0, 0, width, height);
    } else {
      frame = ctx.createImageData(width, height);
      for (let pixel = 0; pixel < width * height; pixel++) {
        const at = pixel * 4;
        if (recovery) frame.data[at] = frame.data[at + 1] = frame.data[at + 2] = 128;
        frame.data[at + 3] = 255;
      }
    }
    let jpegRecovery = false;
    if (recovery) {
      const rendered = frame.data.slice();
      // Retain the less intrusive, heavily redundant legacy profile for tiny
      // files. Larger files use the higher-capacity interleaved channel.
      const legacy = !flags && width === 1024 && recoverySide(envelope.length) === 1024;
      const contrasts = cover && !legacy ? jpegCoverContrasts(envelope.length, width) : [undefined];
      for (const contrast of contrasts) {
        frame.data.set(rendered);
        // Let the busy state paint, including between expensive candidates.
        await new Promise<void>(resolve => setTimeout(resolve, 0));
        try {
          if (legacy) embedJPEGRecovery(frame.data, width, height, envelope);
          else embedJPEGChannel(frame.data, width, height, envelope, contrast,Boolean(flags),flags);
          // Validate after the lossless copy is written: its low-bit changes are
          // part of the actual image, not merely a clean DCT lab frame.
          lossless(frame.data,2);
          const read = legacy ? extractJPEGRecovery(frame.data, width, height) : extractJPEGChannel(frame.data, width, height);
          jpegRecovery = read.length === envelope.length && read.every((byte, at) => byte === envelope[at]);
          if (jpegRecovery) { onProgress?.('checking'); await new Promise<void>(resolve => setTimeout(resolve, 0)); jpegRecovery = await checkJPEGRecovery(frame, envelope, legacy); }
          if (jpegRecovery) break;
        } catch (error) {
          jpegRecovery = false;
          if (!(error instanceof ProtectedImageError) || error.code !== 'invalid-file') throw error;
        }
      }
      // Highly saturated or pathological artwork may exceed the correction
      // budget. Preserve its appearance and exact lossless packet instead of
      // advertising a recovery copy that failed its own check.
      if (!jpegRecovery) frame.data.set(rendered);
    }
    // Keep the v2 packet last so existing readers remain compatible.
    // Noise with JPEG recovery also needs the low-bit packet: writing eight
    // bits per channel here would overwrite the frequency-domain recovery copy.
    lossless(frame.data,cover || jpegRecovery ? 2 : 8);
    ctx.putImageData(frame, 0, 0);
    onProgress?.('saving');
    const blob = await new Promise<Blob>((resolve, reject) => canvas.toBlob(blob => blob ? resolve(blob) : reject(new ProtectedImageError('invalid-file')), 'image/png'));
    if (blob.size > MAX_PROTECTED_IMAGE_BYTES + 1024 * 1024) throw new ProtectedImageError('too-large');
    return { bytes: new Uint8Array(await blob.arrayBuffer()), jpegRecovery, ...(jpegRecovery && recovery ? { recoverySide: recovery } : {}) };
  } finally { bitmap?.close(); canvas.width = canvas.height = 1; }
}

export async function decodeProtectedPNG(png: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
  signal?.throwIfAborted();
  if (png.length > MAX_CONTAINER_FILE_BYTES) throw new ProtectedImageError('too-large');
  if(new TextDecoder().decode(png.subarray(0,8))==='SNAPSEAL'){inspectProtectedFile(png);return png;}
  if (png[0] === 80 && png[1] === 75 && png[2] === 3 && png[3] === 4) png = extractProtectedImageZIP(png);
  if (png.length > MAX_PROTECTED_IMAGE_BYTES + 1024 * 1024) throw new ProtectedImageError('too-large');
  const jpeg = png[0] === 255 && png[1] === 216 && png[2] === 255;
  let width: number, height: number;
  if (jpeg) {
    try { ({ width, height } = validateImageDimensions(png)); }
    catch { throw new ProtectedImageError('invalid-file'); }
    // Fixed supported sizes only; 2048 remains readable for legacy files,
    // Keep 2560 readable for older automatically selected or explicit HD files.
    // Neither channel attempts resize recovery.
    if (height !== width || (width !== 1024 && width !== 1280 && width !== 2048 && width !== 2560)) throw new ProtectedImageError('invalid-file');
  } else {
    if (png.length < 33 || !PNG_MAGIC.every((value, index) => png[index] === value) ||
    new TextDecoder().decode(png.subarray(12, 16)) !== 'IHDR') throw new ProtectedImageError('invalid-file');
    const header = new DataView(png.buffer, png.byteOffset, png.byteLength);
    if (header.getUint32(8) !== 13) throw new ProtectedImageError('invalid-file');
    width = header.getUint32(16); height = header.getUint32(20);
  }
  if (!width || !height || width > 16384 || height > 16384 || width * height > MAX_PIXELS) throw new ProtectedImageError('unsafe-dimensions');
  if (jpeg && width !== 2048) {
    const envelope = await readJPEGFile(png, signal);
    signal?.throwIfAborted();
    if (envelope) return envelope;
  }
  let bitmap: ImageBitmap | undefined;
  const canvas = document.createElement('canvas');
  try {
    bitmap = await createImageBitmap(new Blob([Uint8Array.from(png)], { type: jpeg ? 'image/jpeg' : 'image/png' }), { colorSpaceConversion: 'none', premultiplyAlpha: 'none' });
    signal?.throwIfAborted();
    if (bitmap.width !== width || bitmap.height !== height) throw new ProtectedImageError('invalid-file');
    canvas.width = width; canvas.height = height;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) throw new ProtectedImageError('unsupported-browser');
    ctx.drawImage(bitmap, 0, 0);
    const frame = ctx.getImageData(0, 0, width, height).data;
    let pixelError: ProtectedImageError | undefined;
    if (!jpeg) {
      try { return extractStyledPacket(frame,width,height)??extractPixelPacket(frame); }
      catch (error) {
        if (!(error instanceof ProtectedImageError) || (error.code !== 'invalid-file' && error.code !== 'unsupported-version')) throw error;
        pixelError = error;
      }
    }
    if (width === height && (width === 1024 || width === 1280 || width === 2560)) {
      try { return extractJPEGChannel(frame, width, height); }
      catch (error) { if (!(error instanceof ProtectedImageError) || error.code !== 'invalid-file') throw error; }
    }
    if (width === height && (width === 1024 || width === 2048)) {
      try { return extractJPEGRecovery(frame, width, height); }
      catch (error) { if (!(error instanceof ProtectedImageError) || error.code !== 'invalid-file') throw error; }
    }
    throw pixelError ?? new ProtectedImageError('invalid-file');
  } catch (error) {
    if (error instanceof ProtectedImageError) throw error;
    throw new ProtectedImageError('invalid-file');
  } finally { bitmap?.close(); canvas.width = canvas.height = 1; }
}
