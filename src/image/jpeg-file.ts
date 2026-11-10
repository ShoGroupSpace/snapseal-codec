import decode from './vendor/jpeg-decoder.js';
import { extractJPEGChannelCoefficients } from './jpeg-channel';

function bad(): never { throw new Error('Unsupported or damaged JPEG'); }

/** Strict, allocation-free structural validation before the entropy decoder.
 * The browser's native decoder remains the fallback for other valid JPEGs. */
export function preflightJPEG(bytes: Uint8Array) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 4 || bytes.length > 32 * 1024 * 1024 || bytes[0] !== 255 || bytes[1] !== 216) bad();
  let at = 2, scans = 0;
  let info: { width: number; height: number; progressive: boolean; ids: number[] } | undefined;
  const tables = new Set<number>();
  const u16 = (p: number) => (bytes[p] << 8) | bytes[p + 1];
  while (at < bytes.length) {
    if (bytes[at++] !== 255) bad();
    while (bytes[at] === 255) at++;
    const marker = bytes[at++];
    if (marker === 217) {
      if (!info || !scans || at !== bytes.length) bad();
      return info;
    }
    if (at + 2 > bytes.length) bad();
    const length = u16(at), end = at + length;
    if (length < 2 || end > bytes.length) bad();
    if (marker === 192 || marker === 194) {
      if (info || length < 11) bad();
      const height = u16(at + 3), width = u16(at + 5), count = bytes[at + 7];
      if (bytes[at + 2] !== 8 || width !== height || ![1024, 1280, 2560].includes(width) || ![1, 3].includes(count) || length !== 8 + count * 3) bad();
      const ids: number[] = [];
      for (let c = 0; c < count; c++) {
        const p = at + 8 + c * 3, h = bytes[p + 1] >> 4, v = bytes[p + 1] & 15;
        if (ids.includes(bytes[p]) || !h || !v || h > 2 || v > 2 || bytes[p + 2] > 3) bad();
        ids.push(bytes[p]);
      }
      if (ids[0] !== 1 || (count === 3 && ids.join() !== '1,2,3')) bad();
      info = { width, height, progressive: marker === 194, ids };
    } else if (marker === 219) {
      for (let p = at + 2; p < end;) {
        const table = bytes[p++];
        if (table > 3 || p + 64 > end) bad(); // 8-bit quantizers only.
        for (let i = 0; i < 64; i++) if (!bytes[p++]) bad();
      }
    } else if (marker === 196) {
      for (let p = at + 2; p < end;) {
        const table = bytes[p++];
        if ((table >> 4) > 1 || (table & 15) > 3 || p + 16 > end) bad();
        let count = 0, slots = 1;
        for (let n = 0; n < 16; n++) {
          const codes = bytes[p++]; count += codes; slots = slots * 2 - codes;
          if (slots < 0) bad();
        }
        if (!count || count > 256 || p + count > end) bad();
        // Bound entropy receive loops and coefficient amplitudes.
        for (let n = 0; n < count; n++) {
          const symbol = bytes[p++];
          if (table < 16 ? symbol > 11 : (symbol & 15) > 10) bad();
        }
        tables.add(table);
      }
    } else if (marker === 221) {
      if (length !== 4) bad();
    } else if (marker === 218) {
      if (!info || ++scans > 64) bad();
      const count = bytes[at + 2];
      if (!count || count > info.ids.length || length !== 6 + 2 * count) bad();
      const start = bytes[end - 3], finish = bytes[end - 2], approximation = bytes[end - 1];
      const high = approximation >> 4, low = approximation & 15;
      if (start > finish || finish > 63 || high > 13 || low > 13 || (high && high !== low + 1)) bad();
      if (info.progressive ? (start === 0 ? finish !== 0 : count !== 1) : (start !== 0 || finish !== 63 || approximation !== 0)) bad();
      const seen = new Set<number>();
      for (let c = 0; c < count; c++) {
        const id = bytes[at + 3 + c * 2], table = bytes[at + 4 + c * 2];
        if (!info.ids.includes(id) || seen.has(id) || (table >> 4) > 3 || (table & 15) > 3) bad();
        if (start === 0 && high === 0 && !tables.has(table >> 4)) bad();
        if (finish > 0 && !tables.has(16 | (table & 15))) bad();
        seen.add(id);
      }
    } else if (!(marker >= 224 && marker <= 239) && marker !== 254) bad();
    at = end;
    if (marker === 218) {
      while (at < bytes.length) {
        if (bytes[at++] !== 255) continue;
        const start = at - 1;
        while (bytes[at] === 255) at++;
        if (bytes[at] === 0 || (bytes[at] >= 208 && bytes[at] <= 215)) { at++; continue; }
        at = start; break;
      }
    }
  }
  return bad();
}

/** Call in the disposable JPEG worker, never synchronously on the UI thread. */
export function extractJPEGFile(bytes: Uint8Array) {
  const info = preflightJPEG(bytes);
  const image = decode(bytes, { coefficientsOnly: true, useTArray: true, tolerantDecoding: false, maxResolutionInMP: 6.56, maxMemoryUsageInMB: 96 });
  const y = image.components[0], grid = info.width / 8;
  if (image.width !== info.width || image.height !== info.height || y.scaleX !== 1 || y.scaleY !== 1 || !y.quantizationTable || y.quantizationTable.some(q => q < 1 || q > 255)) bad();
  return extractJPEGChannelCoefficients(info.width, (slot, output) => {
    const block = y.blocks[Math.floor(slot / grid)]?.[slot % grid];
    if (!block || block.length !== 64) bad();
    for (let i = 0; i < 64; i++) output[i] = block[i] * y.quantizationTable[i];
  });
}
