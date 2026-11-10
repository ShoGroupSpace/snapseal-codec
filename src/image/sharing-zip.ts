import { transportCRC } from './jpeg-recovery';
import { MAX_PROTECTED_IMAGE_BYTES, ProtectedImageError } from '../crypto/protected-image';

export const MAX_CONTAINER_FILE_BYTES = MAX_PROTECTED_IMAGE_BYTES + 1024 * 1024 + 256;
const nameBytes = new TextEncoder().encode('protected-image.png');

/** One fixed-name, uncompressed entry. Preserves every protected PNG byte and
 * encourages messengers to send a document instead of recompressing a photo. */
export function protectedImageZIP(png: Uint8Array): Uint8Array {
  const name = nameBytes;
  const result = new Uint8Array(30 + name.length + png.length + 46 + name.length + 22);
  const view = new DataView(result.buffer), crc = transportCRC(png);
  view.setUint32(0, 0x04034b50, true); view.setUint16(4, 20, true);
  view.setUint16(12, 33, true); // 1980-01-01; no private capture date in ZIP metadata.
  view.setUint32(14, crc, true); view.setUint32(18, png.length, true); view.setUint32(22, png.length, true);
  view.setUint16(26, name.length, true); result.set(name, 30); result.set(png, 30 + name.length);
  const central = 30 + name.length + png.length;
  view.setUint32(central, 0x02014b50, true); view.setUint16(central + 4, 20, true); view.setUint16(central + 6, 20, true);
  view.setUint16(central + 14, 33, true); view.setUint32(central + 16, crc, true);
  view.setUint32(central + 20, png.length, true); view.setUint32(central + 24, png.length, true);
  view.setUint16(central + 28, name.length, true); result.set(name, central + 46);
  const end = central + 46 + name.length;
  view.setUint32(end, 0x06054b50, true); view.setUint16(end + 8, 1, true); view.setUint16(end + 10, 1, true);
  view.setUint32(end + 12, 46 + name.length, true); view.setUint32(end + 16, central, true);
  return result;
}

/** Read only the one-entry, stored ZIP profile emitted above. No decompressor,
 * paths, nested archives, encrypted entries or attacker-advertised allocations.
 * Both directories must describe exactly the same entry and pass its CRC. */
export function extractProtectedImageZIP(zip: Uint8Array): Uint8Array {
  const invalid = (): never => { throw new ProtectedImageError('invalid-file'); };
  if (zip.length > MAX_CONTAINER_FILE_BYTES) throw new ProtectedImageError('too-large');
  if (zip.length < 30 + 46 + 22 + nameBytes.length * 2) invalid();
  const view = new DataView(zip.buffer, zip.byteOffset, zip.byteLength), end = zip.length - 22;
  const u16 = (at: number) => view.getUint16(at, true), u32 = (at: number) => view.getUint32(at, true);
  if (u32(0) !== 0x04034b50 || u32(end) !== 0x06054b50 || u16(end + 4) || u16(end + 6) ||
    u16(end + 8) !== 1 || u16(end + 10) !== 1 || u16(end + 20)) invalid();
  const size = u32(18), directory = u32(end + 16), directorySize = u32(end + 12);
  if (u16(4) > 20 || u16(6) || u16(8) || u16(26) !== nameBytes.length || u16(28) ||
    size !== u32(22) || size < 33 || size > MAX_PROTECTED_IMAGE_BYTES + 1024 * 1024 ||
    directory !== 30 + nameBytes.length + size || directorySize !== 46 + nameBytes.length || directory + directorySize !== end) invalid();
  // The arithmetic above bounds every central-directory read and payload slice.
  if (u32(directory) !== 0x02014b50 || u16(directory + 6) > 20 || u16(directory + 8) || u16(directory + 10) ||
    u32(directory + 16) !== u32(14) || u32(directory + 20) !== size || u32(directory + 24) !== size ||
    u16(directory + 28) !== nameBytes.length || u16(directory + 30) || u16(directory + 32) ||
    u16(directory + 34) || u32(directory + 42)) invalid();
  if (!nameBytes.every((value, index) => zip[30 + index] === value && zip[directory + 46 + index] === value)) invalid();
  const png = zip.subarray(30 + nameBytes.length, directory);
  if (![137, 80, 78, 71, 13, 10, 26, 10].every((value, index) => png[index] === value) || transportCRC(png) !== u32(14)) invalid();
  return png.slice();
}
