import { MAX_FILE_BYTES, ProtectedImageError, safeFileFilename } from '../crypto/protected-image';
import { transportCRC } from './jpeg-recovery';
export const MAX_BUNDLE_FILES = 100;
export type BundleEntry = { filename: string; bytes: Uint8Array };

/** Flat, stored ZIP. Originals stay exact; names are sanitized and deduplicated.
 * No archive extraction or decompression is performed on input files. */
export function bundleFiles(files: BundleEntry[]): Uint8Array {
  if (!files.length || files.length > MAX_BUNDLE_FILES) throw new ProtectedImageError('too-large');
  const names = new Set<string>();
  const entries = files.map(file => {
    const clean = safeFileFilename(file.filename); let name = clean, suffix = 1;
    const dot = clean.lastIndexOf('.'), stem = dot > 0 ? clean.slice(0, dot) : clean, ext = dot > 0 ? clean.slice(dot) : '';
    while (names.has(name.toLocaleLowerCase('en-US'))) name = `${stem} (${++suffix})${ext}`;
    names.add(name.toLocaleLowerCase('en-US'));
    return { bytes: file.bytes, name: new TextEncoder().encode(name), crc: 0 };
  });
  const size = 22 + entries.reduce((sum, entry) => sum + 76 + entry.name.length * 2 + entry.bytes.length, 0);
  if (size > MAX_FILE_BYTES) throw new ProtectedImageError('too-large');
  const output = new Uint8Array(size), view = new DataView(output.buffer); let at = 0;
  const offsets: number[] = [];
  for (const entry of entries) {
    offsets.push(at); entry.crc = transportCRC(entry.bytes);
    view.setUint32(at, 0x04034b50, true); view.setUint16(at + 4, 20, true); view.setUint16(at + 6, 0x800, true);
    view.setUint16(at + 12, 33, true); view.setUint32(at + 14, entry.crc, true);
    view.setUint32(at + 18, entry.bytes.length, true); view.setUint32(at + 22, entry.bytes.length, true);
    view.setUint16(at + 26, entry.name.length, true); output.set(entry.name, at + 30); output.set(entry.bytes, at + 30 + entry.name.length);
    at += 30 + entry.name.length + entry.bytes.length;
  }
  const central = at;
  entries.forEach((entry, index) => {
    view.setUint32(at, 0x02014b50, true); view.setUint16(at + 4, 20, true); view.setUint16(at + 6, 20, true); view.setUint16(at + 8, 0x800, true);
    view.setUint16(at + 14, 33, true); view.setUint32(at + 16, entry.crc, true); view.setUint32(at + 20, entry.bytes.length, true); view.setUint32(at + 24, entry.bytes.length, true);
    view.setUint16(at + 28, entry.name.length, true); view.setUint32(at + 42, offsets[index], true); output.set(entry.name, at + 46); at += 46 + entry.name.length;
  });
  view.setUint32(at, 0x06054b50, true); view.setUint16(at + 8, entries.length, true); view.setUint16(at + 10, entries.length, true);
  view.setUint32(at + 12, at - central, true); view.setUint32(at + 16, central, true);
  return output;
}
