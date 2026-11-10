import { deriveArgon2 } from './argon2-client';
import { ARGON2_MEMORY_KIB, ARGON2_PASSES, ARGON2_LANES, ARGON2_VERSION } from './argon2-core';

const MAGIC = new TextEncoder().encode('SNAPSEAL');
const VERSION = 1;
const FILE_VERSION = 2;
const ITERATIONS = 600_000;
const LEGACY_HEADER_SIZE = 41;
const ARGON_ENVELOPE_VERSION = 3;
const HEADER_SIZE = 48;
export const MAX_IMAGE_BYTES = 50 * 1024 * 1024;
export const MAX_FILE_BYTES = MAX_IMAGE_BYTES;
export const MAX_IMAGE_PIXELS = 64 * 1024 * 1024;
export const MAX_PROTECTED_IMAGE_BYTES = MAX_IMAGE_BYTES + 4096;

export type ProtectedImageErrorCode = 'invalid-file' | 'unsupported-version' | 'too-large' | 'unsafe-dimensions' | 'unsupported-image' | 'password-too-short' | 'unlock-failed' | 'unsupported-browser';
export class ProtectedImageError extends Error {
  constructor(readonly code: ProtectedImageErrorCode) {
    super(code);
    this.name = 'ProtectedImageError';
  }
}
export type UnlockedImage = { bytes: Uint8Array; filename: string; mimeType: string };
export type UnlockedFile = UnlockedImage & { contentKind: 'image' | 'file' | 'text' };

/** Raster-only preview eligibility. Arbitrary files never reach a document,
 * script, PDF, SVG or HTML renderer. A failed image check still permits opaque
 * storage through the generic file API. */
export function imagePreviewMime(bytes: Uint8Array): string | null {
  try { validateImageDimensions(bytes); return detectImageMime(bytes); }
  catch { return null; }
}

function cryptoApi() {
  if (!globalThis.crypto?.subtle) throw new ProtectedImageError('unsupported-browser');
  return globalThis.crypto;
}

function passwordBytes(password: string, creating: boolean, allowWeakPassword = false) {
  if (typeof password !== 'string' || password.length > 512) throw new ProtectedImageError(creating ? 'password-too-short' : 'unlock-failed');
  const bytes = new TextEncoder().encode(password);
  // Preserve spaces and Unicode exactly. Bound input before a costly KDF.
  const length = Array.from(password).length;
  if ((creating && (length < (allowWeakPassword ? 1 : 12) || !password.trim())) || !length || length > 256 || bytes.length > 1024) {
    throw new ProtectedImageError(creating ? 'password-too-short' : 'unlock-failed');
  }
  return bytes;
}

function startsWith(bytes: Uint8Array, values: number[], offset = 0) {
  return values.every((value, index) => bytes[offset + index] === value);
}

export function detectImageMime(bytes: Uint8Array): string {
  if (startsWith(bytes, [137, 80, 78, 71, 13, 10, 26, 10])) return 'image/png';
  if (startsWith(bytes, [255, 216, 255])) return 'image/jpeg';
  if (startsWith(bytes, [82, 73, 70, 70]) && startsWith(bytes, [87, 69, 66, 80], 8)) return 'image/webp';
  if (startsWith(bytes, [71, 73, 70, 56]) && [55, 57].includes(bytes[4]) && bytes[5] === 97) return 'image/gif';
  throw new ProtectedImageError('unsupported-image');
}

/** Bound decoded image allocation before an untrusted file reaches a preview. */
export function validateImageDimensions(bytes: Uint8Array) {
  const mime = detectImageMime(bytes);
  const data = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  function checked(width: number, height: number) {
    if (!width || !height) throw new ProtectedImageError('unsupported-image');
    if (width > 16384 || height > 16384 || width * height > MAX_IMAGE_PIXELS) throw new ProtectedImageError('unsafe-dimensions');
    return { width, height };
  }
  try {
    if (mime === 'image/png') {
      if (bytes.length < 33 || data.getUint32(8) !== 13 || !startsWith(bytes, [73, 72, 68, 82], 12)) throw new Error();
      return checked(data.getUint32(16), data.getUint32(20));
    }
    if (mime === 'image/gif') return checked(data.getUint16(6, true), data.getUint16(8, true));
    if (mime === 'image/jpeg') {
      let at = 2;
      while (at < bytes.length) {
        if (bytes[at++] !== 255) throw new Error();
        while (bytes[at] === 255) at++;
        const marker = bytes[at++];
        if (marker === 0xda || marker === 0xd9) break;
        if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) continue;
        const size = data.getUint16(at);
        if (size < 2 || at + size > bytes.length) throw new Error();
        if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) {
          if (size < 8) throw new Error();
          return checked(data.getUint16(at + 5), data.getUint16(at + 3));
        }
        at += size;
      }
    }
    if (mime === 'image/webp') {
      const end = data.getUint32(4, true) + 8;
      if (end > bytes.length) throw new Error();
      for (let at = 12; at + 8 <= end;) {
        const size = data.getUint32(at + 4, true); const body = at + 8;
        if (body + size > end) throw new Error();
        const type = String.fromCharCode(...bytes.subarray(at, at + 4));
        if (type === 'VP8X' && size >= 10) {
          const u24 = (offset: number) => bytes[offset] + bytes[offset + 1] * 256 + bytes[offset + 2] * 65536;
          return checked(1 + u24(body + 4), 1 + u24(body + 7));
        }
        if (type === 'VP8L' && size >= 5 && bytes[body] === 0x2f) {
          const bits = data.getUint32(body + 1, true);
          return checked((bits & 0x3fff) + 1, ((bits >>> 14) & 0x3fff) + 1);
        }
        if (type === 'VP8 ' && size >= 10 && startsWith(bytes, [0x9d, 0x01, 0x2a], body + 3)) {
          return checked(data.getUint16(body + 6, true) & 0x3fff, data.getUint16(body + 8, true) & 0x3fff);
        }
        at = body + size + (size % 2);
      }
    }
  } catch (error) {
    if (error instanceof ProtectedImageError) throw error;
  }
  throw new ProtectedImageError('unsupported-image');
}

function safeFilename(filename: string, mimeType: string) {
  const extension = ({ 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp', 'image/gif': 'gif' } as Record<string, string>)[mimeType];
  const base = filename.split(/[/\\]/).pop()!.replace(/[<>:"|?*\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '_').replace(/\.[^.]*$/, '').slice(0, 160).trim().replace(/[. ]+$/, '');
  const safeBase = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(base) ? `_${base}` : base;
  return `${safeBase || 'image'}.${extension}`;
}

/** Preserve the file extension, but never permit paths, control characters,
 * bidi disguises, device names or Windows alternate data streams. */
export function safeFileFilename(filename: string): string {
  const leaf = filename.split(/[/\\]/).pop()!.replace(/[<>:"|?*\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '_').trim().replace(/[. ]+$/, '');
  const extension = leaf.match(/\.[a-zA-Z0-9]{1,16}$/)?.[0] ?? '';
  const stem = extension ? leaf.slice(0, -extension.length) : leaf;
  let name = (Array.from(stem).slice(0, 180 - extension.length).join('') + extension).replace(/[. ]+$/, '') || 'file';
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name)) name = `_${name}`;
  return name;
}

async function deriveKey(password: Uint8Array, salt: Uint8Array, iterations: number) {
  const subtle = cryptoApi().subtle;
  const material = await subtle.importKey('raw', Uint8Array.from(password), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: Uint8Array.from(salt), iterations }, material,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function deriveEnvelopeKey(password: Uint8Array, parameters: ReturnType<typeof readProtectedHeader>, signal?: AbortSignal) {
  if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError');
  if (parameters.kdf === 'PBKDF2') return deriveKey(password, parameters.salt, parameters.iterations);
  let raw: Uint8Array;
  try { raw = await deriveArgon2(password, parameters.salt, signal); }
  catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ProtectedImageError('unsupported-browser');
  }
  const material = Uint8Array.from(raw);
  try { return await cryptoApi().subtle.importKey('raw', material, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']); }
  finally { raw.fill(0); material.fill(0); }
}

/** Internal transport bridge; all cost fields are checked before any KDF. */
export function readProtectedHeader(file: Uint8Array) {
  if (file.length > MAX_PROTECTED_IMAGE_BYTES) throw new ProtectedImageError('too-large');
  if (file.length < LEGACY_HEADER_SIZE + 21 || !MAGIC.every((value, index) => file[index] === value)) throw new ProtectedImageError('invalid-file');
  const version = file[8], view = new DataView(file.buffer, file.byteOffset, file.byteLength);
  if (version === VERSION || version === FILE_VERSION) {
    if (view.getUint32(9) !== ITERATIONS) throw new ProtectedImageError('invalid-file');
    return { version, kdf: 'PBKDF2' as const, iterations: ITERATIONS, headerSize: LEGACY_HEADER_SIZE, salt: file.slice(13, 29), iv: file.slice(29, 41) };
  }
  if (version !== ARGON_ENVELOPE_VERSION) throw new ProtectedImageError('unsupported-version');
  if (file.length < HEADER_SIZE + 22 || file[9] !== 1 || file[10] !== ARGON2_VERSION || file[11] !== ARGON2_LANES || view.getUint32(12) !== ARGON2_MEMORY_KIB || view.getUint32(16) !== ARGON2_PASSES) throw new ProtectedImageError('invalid-file');
  return { version, kdf: 'Argon2id' as const, iterations: ARGON2_PASSES, headerSize: HEADER_SIZE, salt: file.slice(20, 36), iv: file.slice(36, 48) };
}

function imageMetadata(filename: string, mimeType: string) {
  return new TextEncoder().encode(JSON.stringify({ filename: safeFilename(filename, mimeType), mimeType }));
}

/** Metadata overhead for a known output format, before its image bytes exist. */
export function protectedImageEnvelopeOverhead(filename: string, mimeType: string) {
  if (!['image/png', 'image/jpeg', 'image/webp', 'image/gif'].includes(mimeType)) throw new ProtectedImageError('unsupported-image');
  return HEADER_SIZE + 16 + 4 + imageMetadata(filename, mimeType).length;
}

/** Exact encrypted size, without running the password KDF or changing the image. */
export function protectedImageEnvelopeLength(bytes: Uint8Array, filename: string) {
  return protectedImageEnvelopeOverhead(filename, detectImageMime(bytes)) + bytes.length;
}

function fileMetadata(filename: string, contentKind: 'file' | 'text') {
  if (contentKind !== 'file' && contentKind !== 'text') throw new ProtectedImageError('invalid-file');
  return new TextEncoder().encode(JSON.stringify({ filename: safeFileFilename(filename), contentKind }));
}

export function protectedFileEnvelopeLength(bytes: Uint8Array, filename: string, contentKind: 'file' | 'text' = 'file') {
  return HEADER_SIZE + 16 + 4 + fileMetadata(filename, contentKind).length + bytes.length;
}

/** Opaque bytes, including empty files. No untrusted MIME type is retained. */
export async function protectFile(bytes: Uint8Array, filename: string, password: string, options: { allowWeakPassword?: boolean; contentKind?: 'file' | 'text'; signal?: AbortSignal } = {}): Promise<Uint8Array> {
  if (bytes.length > MAX_FILE_BYTES) throw new ProtectedImageError('too-large');
  return protectPayload(bytes, fileMetadata(filename, options.contentKind ?? 'file'), password, options.allowWeakPassword, options.signal);
}

/** A self-contained, authenticated v3 file. No password, URL or title is stored. */
export async function protectImageFile(bytes: Uint8Array, filename: string, password: string, options: { allowWeakPassword?: boolean; signal?: AbortSignal } = {}): Promise<Uint8Array> {
  if (!bytes.length || bytes.length > MAX_IMAGE_BYTES) throw new ProtectedImageError('too-large');
  const mimeType = detectImageMime(bytes);
  validateImageDimensions(bytes);
  return protectPayload(bytes, imageMetadata(filename, mimeType), password, options.allowWeakPassword, options.signal);
}

async function protectPayload(bytes: Uint8Array, metadata: Uint8Array, password: string, allowWeakPassword = false, signal?: AbortSignal): Promise<Uint8Array> {
  // Explicit, per-operation policy override; never reduce the KDF work factor.
  const secret = passwordBytes(password, true, allowWeakPassword === true);
  const header = new Uint8Array(HEADER_SIZE);
  header.set(MAGIC); header[8] = ARGON_ENVELOPE_VERSION; header[9] = 1; header[10] = ARGON2_VERSION; header[11] = ARGON2_LANES;
  new DataView(header.buffer).setUint32(12, ARGON2_MEMORY_KIB);
  new DataView(header.buffer).setUint32(16, ARGON2_PASSES);
  cryptoApi().getRandomValues(header.subarray(20, 36));
  cryptoApi().getRandomValues(header.subarray(36, 48));
  const payload = new Uint8Array(4 + metadata.length + bytes.length);
  new DataView(payload.buffer).setUint32(0, metadata.length);
  payload.set(metadata, 4); payload.set(bytes, 4 + metadata.length);
  try {
    const parameters = { version: ARGON_ENVELOPE_VERSION, kdf: 'Argon2id' as const, iterations: ARGON2_PASSES, headerSize: HEADER_SIZE, salt: header.slice(20, 36), iv: header.slice(36, 48) };
    const key = await deriveEnvelopeKey(secret, parameters, signal);
    if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError');
    const ciphertext = await cryptoApi().subtle.encrypt({ name: 'AES-GCM', iv: header.subarray(36, 48), additionalData: header, tagLength: 128 }, key, payload);
    const result = new Uint8Array(HEADER_SIZE + ciphertext.byteLength);
    result.set(header); result.set(new Uint8Array(ciphertext), HEADER_SIZE);
    return result;
  } finally {
    secret.fill(0); payload.fill(0);
  }
}

export async function unlockProtectedFile(file: Uint8Array, password: string, options: { signal?: AbortSignal } = {}): Promise<UnlockedFile> {
  const parameters = readProtectedHeader(file), { version, headerSize } = parameters;
  const header = file.slice(0, headerSize);
  passwordBytes(password, false).fill(0);
  // Keep exact-byte compatibility with every existing envelope. Only after an
  // authentication failure try the two canonical Unicode forms, so visually
  // identical composed/decomposed input works across keyboards. Never trim,
  // case-fold or apply compatibility normalization to passwords.
  const candidates = [...new Set([password, password.normalize('NFC'), password.normalize('NFD')])];
  let payload: Uint8Array;
  let decrypted: Uint8Array | undefined;
  for (const candidate of candidates) {
    const secret = passwordBytes(candidate, false);
    try {
      const key = await deriveEnvelopeKey(secret, parameters, options.signal);
      if (options.signal?.aborted) throw new DOMException('Cancelled', 'AbortError');
      decrypted = new Uint8Array(await cryptoApi().subtle.decrypt({ name: 'AES-GCM', iv: parameters.iv, additionalData: header, tagLength: 128 }, key, file.slice(headerSize)));
      break;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw error;
      if (error instanceof ProtectedImageError) throw error;
      if (!(error instanceof Error) || error.name !== 'OperationError') throw new ProtectedImageError('unlock-failed');
    } finally { secret.fill(0); }
  }
  if (!decrypted) throw new ProtectedImageError('unlock-failed');
  payload = decrypted;
  try {
    const length = new DataView(payload.buffer).getUint32(0);
    if (length < 2 || length > 2048 || 4 + length > payload.length) throw new Error();
    const metadata = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload.subarray(4, 4 + length)));
    const bytes = payload.slice(4 + length);
    if (bytes.length > MAX_IMAGE_BYTES) throw new Error();
    if (!metadata || typeof metadata !== 'object' || typeof metadata.filename !== 'string' || metadata.filename.length > 2048) throw new Error();
    if (version === FILE_VERSION || (version === ARGON_ENVELOPE_VERSION && metadata.contentKind !== undefined)) {
      if (metadata.contentKind !== 'file' && metadata.contentKind !== 'text') throw new Error();
      // Always download opaque data, regardless of claimed type or filename.
      // Inline image previews have a separate bounded raster-only check.
      return { bytes, filename: safeFileFilename(metadata.filename), mimeType: 'application/octet-stream', contentKind: metadata.contentKind };
    }
    const mimeType = detectImageMime(bytes);
    validateImageDimensions(bytes);
    if (metadata.mimeType !== mimeType || typeof metadata.filename !== 'string') throw new Error();
    return { bytes, mimeType, filename: safeFilename(metadata.filename, mimeType), contentKind: 'image' };
  } catch { throw new ProtectedImageError('invalid-file'); }
  finally { payload.fill(0); }
}

/** Checks the envelope header; authentication still requires the password. */
export function inspectProtectedFile(file: Uint8Array): void {
  readProtectedHeader(file);
}

/** Keep the existing image-only API strict for image integrations. */
export async function unlockImageFile(file: Uint8Array, password: string): Promise<UnlockedImage> {
  const result = await unlockProtectedFile(file, password);
  if (result.contentKind !== 'image') throw new ProtectedImageError('unsupported-image');
  return { bytes: result.bytes, filename: result.filename, mimeType: result.mimeType };
}
