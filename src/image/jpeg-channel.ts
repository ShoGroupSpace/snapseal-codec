import GenericGF from '@zxing/library/esm/core/common/reedsolomon/GenericGF';
import ReedSolomonEncoder from '@zxing/library/esm/core/common/reedsolomon/ReedSolomonEncoder';
import ReedSolomonDecoder from '@zxing/library/esm/core/common/reedsolomon/ReedSolomonDecoder';
import { ProtectedImageError } from '../crypto/protected-image';
import { transportCRC } from './jpeg-recovery';
import { visualRects } from './styled-packet';

/**
 * Experimental, bounded JPEG recovery channel.
 *
 * A transport code, not encryption: it carries the existing AES-256-GCM envelope
 * inside quantized luma DCT coefficients on the unshifted 8x8 grid, so bytes are
 * recovered exactly or the read fails. The recipient needs no cover and no table:
 * only the steps below, which are derived from the header.
 *
 * Quantization-index modulation gives coefficients room for JPEG rounding, and
 * interleaved Reed-Solomon codewords repair remaining byte errors. RGB clipping,
 * chroma conversion and encoder differences still matter: this is not a promise
 * that arbitrary recompression, resizing, or a particular messenger will work.
 */

const DEFAULT_SIDE = 1024, MAGIC = 0x53534a32; // "SSJ2"
const SPREAD = 4051; // Coprime with supported block counts (16384, 25600, 102400).
const RS_TOTAL = 255, RS_DATA = 223, RS_PARITY = RS_TOTAL - RS_DATA;
export const JPEG_RECOVERY_MAX_BYTES = 280_000;
export const JPEG_RECOVERY_HD_MAX_BYTES = 1_000_000;
export type JPEGRecoveryMode = 'auto' | 'standard' | 'hd' | 'file';
const HEADER_DATA = 16, HEADER_TOTAL = 64, HEADER_BLOCKS = HEADER_TOTAL * 2, HEADER_STEP = 48;
const HEADER_MODES = [9, 10, 17, 18]; // (1,1) (1,2) (2,1) (2,2)
const MARGIN = 8, CHROMA_MARGIN = 20; // Headroom for later changes that would otherwise clip.
const LOW_FREQUENCY_PENALTY = .12;
const MAX_BITS_PER_COEFFICIENT = 3, MAX_BITS_PER_BLOCK = 110, MIN_BODY_BYTES = 62;
// Append only: header indices 0–3 are used by existing files.
export const CHANNEL_STEP_MULTIPLIERS = [2, 3, 4, 6, 3.75] as const;
export type ChannelStep = typeof CHANNEL_STEP_MULTIPLIERS[number];

// Measured from a real Telegram 1024px output (row = vertical frequency).
const TELEGRAM_1024 = [
  4, 4, 4, 5, 7, 10, 15, 22,
  4, 4, 5, 7, 9, 10, 14, 20,
  4, 5, 6, 8, 11, 16, 24, 0,
  5, 7, 8, 10, 14, 19, 28, 0,
  7, 9, 11, 14, 18, 24, 34, 0,
  10, 10, 16, 19, 24, 32, 0, 0,
  15, 14, 24, 28, 34, 0, 0, 0,
  22, 20, 0, 0, 0, 0, 0, 0,
];
// Measured from a real Telegram 1280px output: coarser, so tables are not constant.
const TELEGRAM_1280 = [
  3, 6, 6, 9, 13, 22, 0, 0,
  7, 7, 8, 11, 15, 32, 0, 0,
  8, 7, 9, 13, 22, 32, 0, 0,
  8, 10, 12, 16, 29, 0, 0, 0,
  10, 12, 21, 31, 38, 0, 0, 0,
  13, 20, 31, 0, 0, 0, 0, 0,
  27, 36, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
];
// A 2x step fully covers the 1024 table and tolerates the 1280 table by 1.25x.
const BASE = TELEGRAM_1024.map((q, at) => q ? Math.max(q, Math.ceil(TELEGRAM_1280[at] / 1.6)) : 0);

const ZIGZAG = Array.from({ length: 64 }, (_, at) => at)
  .sort((a, b) => ((a >> 3) + (a & 7)) - ((b >> 3) + (b & 7)) || (a >> 3) - (b >> 3));
const COS = Float64Array.from({ length: 64 }, (_, at) => {
  const u = at >> 3, x = at & 7;
  return Math.cos((2 * x + 1) * u * Math.PI / 16) * (u ? .5 : Math.SQRT1_2 / 2);
});

const gf = GenericGF.QR_CODE_FIELD_256;
const rsEncoder = new ReedSolomonEncoder(gf), rsDecoder = new ReedSolomonDecoder(gf);
function invalid(): never { throw new ProtectedImageError('invalid-file'); }

export interface ChannelStats {
  bitsPerBlock: number; step: ChannelStep; bytes: number; codewords: number;
  correctedSymbols: number; worstCodeword: number;
}
interface Carrier { at: number; step: number; bits: number; }

function supportedSide(side: number) { return side === 1024 || side === 1280 || side === 2560; }

/** Product limit is deliberately below the experimental transport's capacity. */
export function jpegChannelSide(bytes: number): number | null {
  if (!Number.isInteger(bytes) || bytes < MIN_BODY_BYTES || bytes > JPEG_RECOVERY_MAX_BYTES) return null;
  return bytes <= 64_000 ? 1024 : 1280;
}

export function jpegRecoverySide(bytes: number, cover: boolean, mode: JPEGRecoveryMode = 'standard'): number | null {
  if (!Number.isInteger(bytes) || bytes < MIN_BODY_BYTES || mode === 'file') return null;
  // Automatic creation stays within the standard profile's conservative size
  // budget. Explicit HD remains for compatibility/research, never UI promotion.
  if (mode === 'hd') return bytes <= JPEG_RECOVERY_HD_MAX_BYTES ? 2560 : null;
  if (mode !== 'auto' && mode !== 'standard') return null;
  const side = jpegChannelSide(bytes);
  if (!side) return null;
  // More pixels for modest cover payloads reduce the visible pattern. Tiny
  // envelopes retain the old 1024px recovery format chosen by the container.
  return cover && bytes > 3_933 ? 1280 : side;
}

/** Spend cover contrast, never original-image quality, on denser carrier signals. */
export function jpegChannelContrast(bytes: number): number {
  if (bytes > 200_000) return Math.max(.15, .25 - (bytes - 200_000) / 500_000);
  return bytes <= 120_000 ? 1 : Math.max(.25, 1 - (bytes - 120_000) / 80_000);
}

/** Try to retain artwork before spending contrast on recovery. This changes
 * only the carrier's appearance; the channel header and decoder stay the same.
 * Bounded to three candidates so difficult artwork cannot cause an open-ended
 * search. Noise needs no appearance search. Every candidate is stress-tested by
 * the container after the lossless copy has been written. */
export function jpegCoverContrasts(bytes: number, side: number): number[] {
  if (!supportedSide(side) || !Number.isInteger(bytes) || bytes < MIN_BODY_BYTES || bytes > (side === 2560 ? JPEG_RECOVERY_HD_MAX_BYTES : JPEG_RECOVERY_MAX_BYTES)) invalid();
  const density = bytes * 1280 * 1280 / (side * side);
  const baseline = side >= 1280 ? jpegChannelContrast(density) : 1;
  return baseline === 1 ? [1] : [1, (1 + baseline) / 2, baseline];
}

/** Deterministic: both sides derive the same carriers from the header values. */
export function channelCarriers(bitsPerBlock: number, multiplier: ChannelStep): Carrier[] {
  if (!Number.isInteger(bitsPerBlock) || bitsPerBlock < 1 || bitsPerBlock > MAX_BITS_PER_BLOCK || !CHANNEL_STEP_MULTIPLIERS.includes(multiplier)) invalid();
  const bits = new Array<number>(64).fill(0);
  for (let used = 0; used < bitsPerBlock; used++) {
    let best = -1, bestAmplitude = Infinity;
    for (const at of ZIGZAG) {
      if (!at || !BASE[at] || bits[at] >= MAX_BITS_PER_COEFFICIENT) continue;
      // Slightly prefer mid frequencies: low-frequency noise is the most visible.
      const lowFrequency = Math.max(0, 4 - (at >> 3) - (at & 7));
      const amplitude = (2 << bits[at]) * BASE[at] * multiplier * (1 + LOW_FREQUENCY_PENALTY * lowFrequency);
      if (amplitude < bestAmplitude) { best = at; bestAmplitude = amplitude; }
    }
    if (best < 0) throw new ProtectedImageError('too-large');
    bits[best]++;
  }
  return ZIGZAG.filter(at => bits[at]).map(at => ({ at, bits: bits[at], step: BASE[at] * multiplier }));
}

function codedLength(bytes: number) { return Math.ceil(bytes / RS_DATA) * RS_TOTAL; }

/** Fewest bits per block for this payload; amplitude therefore follows payload size. */
export function channelProfile(bytes: number, side = DEFAULT_SIDE, styled = false): { bitsPerBlock: number; step: ChannelStep } | null {
  if (!supportedSide(side) || !Number.isInteger(bytes) || bytes < MIN_BODY_BYTES) return null;
  const bitsPerBlock = Math.ceil(codedLength(bytes) * 8 / ((styled?styledSlots(side).length:side*side/64) - HEADER_BLOCKS));
  if (bitsPerBlock > MAX_BITS_PER_BLOCK) return null;
  // Spend spare amplitude on margin against coarser tables when the payload allows.
  const density = bytes * 1280 * 1280 / (side * side);
  return { bitsPerBlock, step: bitsPerBlock <= 12 ? 6 : bitsPerBlock <= 44 || (side >= 1280 && density <= 200_000) ? 4 : side >= 1280 && density <= JPEG_RECOVERY_MAX_BYTES ? 3.75 : 2 };
}
export const MAX_CHANNEL_BYTES = Math.floor(MAX_BITS_PER_BLOCK * (DEFAULT_SIDE * DEFAULT_SIDE / 64 - HEADER_BLOCKS) / 8 / RS_TOTAL) * RS_DATA;

function forward(input: Float64Array, output: Float64Array, scratch: Float64Array) {
  for (let y = 0; y < 8; y++) for (let u = 0; u < 8; u++) {
    let sum = 0;
    for (let x = 0; x < 8; x++) sum += input[y * 8 + x] * COS[u * 8 + x];
    scratch[y * 8 + u] = sum;
  }
  for (let u = 0; u < 8; u++) for (let v = 0; v < 8; v++) {
    let sum = 0;
    for (let y = 0; y < 8; y++) sum += scratch[y * 8 + u] * COS[v * 8 + y];
    output[v * 8 + u] = sum;
  }
}
function inverse(input: Float64Array, output: Float64Array, scratch: Float64Array) {
  for (let v = 0; v < 8; v++) for (let x = 0; x < 8; x++) {
    let sum = 0;
    for (let u = 0; u < 8; u++) sum += input[v * 8 + u] * COS[u * 8 + x];
    scratch[v * 8 + x] = sum;
  }
  for (let x = 0; x < 8; x++) for (let y = 0; y < 8; y++) {
    let sum = 0;
    for (let v = 0; v < 8; v++) sum += scratch[v * 8 + x] * COS[v * 8 + y];
    output[y * 8 + x] = sum;
  }
}

function blockAt(index: number, side: number) { return index * SPREAD % (side * side / 64); }
const styledSlotCache=new Map<number,Uint32Array>();
/** SSJ3 leaves 8-pixel guard bands around every possible public decoration.
 * The fixed layout is recoverable from JPEG pixels or coefficients alone. */
function styledSlots(side:number){
 const cached=styledSlotCache.get(side);if(cached)return cached;
 const rects=visualRects(side,side,3),columns=side/8,slots:number[]=[];
 for(let index=0;index<side*side/64;index++){const slot=blockAt(index,side),x=slot%columns*8,y=Math.floor(slot/columns)*8;
  if(!rects.some(r=>x<r.x+r.width+8&&x+8>r.x-8&&y<r.y+r.height+8&&y+8>r.y-8))slots.push(slot);
 }
 const result=Uint32Array.from(slots);styledSlotCache.set(side,result);return result;
}
/** Unused SSJ3 decoration slots are cosmetic only. Match the channel's spatial
 * coverage without changing its fixed slot map, header or payload capacity. */
function unusedDecorationSlots(side:number,flags:number,lastDataSlot:number){
 if(flags===3)return [];
 const unused=visualRects(side,side,3&~flags),active=visualRects(side,side,flags),columns=side/8,slots:number[]=[];
 for(let index=0;index<side*side/64;index++){
  const slot=blockAt(index,side),x=slot%columns*8,y=Math.floor(slot/columns)*8;
  const overlaps=(r:{x:number;y:number;width:number;height:number})=>x<r.x+r.width+8&&x+8>r.x-8&&y<r.y+r.height+8&&y+8>r.y-8;
  if(unused.some(overlaps)&&!active.some(overlaps))slots.push(slot);
  // Tiny payloads touch only part of the spread; do not turn an unused label
  // into a denser patch than its surroundings by filling its entire rectangle.
  if(slot===lastDataSlot)break;
 }
 return slots;
}
function originOf(slot: number, side: number) { return (Math.floor(slot / (side / 8)) * 8 * side + slot % (side / 8) * 8) * 4; }
function gray(value: number) { return value ^ value >> 1; }
function ungray(value: number) { let out = value; for (let shift = 1; shift < 4; shift <<= 1) out ^= out >> shift; return out; }
function validateFrame(frame: Uint8ClampedArray, width: number, height: number) {
  if (!supportedSide(width) || height !== width || frame.length !== width * width * 4) invalid();
}

/** Nearest lattice point whose index has the wanted residue. */
function snap(value: number, step: number, levels: number, symbol: number) {
  const scaled = value / step, nearest = Math.round(scaled);
  let delta = ((symbol - nearest) % levels + levels) % levels;
  if (delta * 2 > levels) delta -= levels;
  else if (delta * 2 === levels && scaled < nearest) delta -= levels;
  return (nearest + delta) * step;
}
function residue(value: number, step: number, levels: number) {
  return (Math.round(value / step) % levels + levels) % levels;
}

/** Writes one block of already-lattice coefficients back, keeping RGB in gamut. */
function writeBlock(frame: Uint8ClampedArray, origin: number, side: number, cover: Float64Array, spatial: Float64Array) {
  let low = Infinity, high = -Infinity;
  for (let pixel = 0; pixel < 64; pixel++) {
    const value = spatial[pixel] + 128;
    if (value < low) low = value;
    if (value > high) high = value;
  }
  // DC is never a carrier, so a block offset moves pixels without touching data.
  const shift = high - low >= 255 - 2 * MARGIN ? 127.5 - (high + low) / 2
    : low < MARGIN ? MARGIN - low : high > 255 - MARGIN ? 255 - MARGIN - high : 0;
  // Chroma carries no data. Writing it as flat 2x2 cells means 4:2:0 subsampling
  // barely changes it, and the headroom keeps the decoded RGB from clipping, which
  // would otherwise corrupt the luma read back from that pixel.
  for (let cellY = 0; cellY < 8; cellY += 2) for (let cellX = 0; cellX < 8; cellX += 2) {
    let cb = 0, cr = 0;
    for (let dy = 0; dy < 2; dy++) for (let dx = 0; dx < 2; dx++) {
      const pixel = (cellY + dy) * 8 + cellX + dx;
      cb += cover[pixel * 2] / 4; cr += cover[pixel * 2 + 1] / 4;
    }
    const r = 1.402 * cr, g = -.344136 * cb - .714136 * cr, b = 1.772 * cb;
    let saturation = 1;
    for (let dy = 0; dy < 2; dy++) for (let dx = 0; dx < 2; dx++) {
      const y = spatial[(cellY + dy) * 8 + cellX + dx] + 128 + shift;
      for (const excursion of [r, g, b]) {
        if (!excursion) continue;
        const room = excursion > 0 ? 255 - CHROMA_MARGIN - y : y - CHROMA_MARGIN;
        if (Math.abs(excursion) * saturation > room) saturation = Math.max(0, room) / Math.abs(excursion);
      }
    }
    for (let dy = 0; dy < 2; dy++) for (let dx = 0; dx < 2; dx++) {
      const pixel = (cellY + dy) * 8 + cellX + dx, y = spatial[pixel] + 128 + shift;
      const at = origin + ((cellY + dy) * side + cellX + dx) * 4;
      frame[at] = y + r * saturation; frame[at + 1] = y + g * saturation; frame[at + 2] = y + b * saturation;
    }
  }
}
function loadBlock(frame: Uint8ClampedArray, origin: number, side: number, luma: Float64Array, chroma?: Float64Array) {
  for (let row = 0, pixel = 0; row < 8; row++) {
    let at = origin + row * side * 4;
    for (let column = 0; column < 8; column++, pixel++, at += 4) {
      const r = frame[at], g = frame[at + 1], b = frame[at + 2];
      luma[pixel] = .299 * r + .587 * g + .114 * b - 128;
      if (chroma) {
        chroma[pixel * 2] = -.168736 * r - .331264 * g + .5 * b;
        chroma[pixel * 2 + 1] = .5 * r - .418688 * g - .081312 * b;
      }
    }
  }
}

/** Hard-edged artwork can clip despite DC centering. Alternate projections
 * onto the legal pixel range and the fixed carrier coefficients, allowing only
 * non-carrier detail to move. This reduces clipping without changing a symbol
 * or the wire format. Work is bounded even when the constraints cannot all fit. */
function fitGamut(dct: Float64Array, spatial: Float64Array, scratch: Float64Array, targets: Float64Array, modes: readonly number[], passes: number) {
  const range = 255 - 2 * MARGIN;
  let low = Infinity, high = -Infinity;
  for (const value of spatial) { low = Math.min(low, value); high = Math.max(high, value); }
  if (high - low <= range) return;
  targets.set(dct);
  for (let pass = 0; pass < passes; pass++) {
    const shift = -.5 - (high + low) / 2;
    for (let at = 0; at < 64; at++) spatial[at] = Math.max(MARGIN - 128, Math.min(127 - MARGIN, spatial[at] + shift));
    forward(spatial, dct, scratch);
    for (const at of modes) dct[at] = targets[at];
    inverse(dct, spatial, scratch);
    low = Infinity; high = -Infinity;
    for (const value of spatial) { low = Math.min(low, value); high = Math.max(high, value); }
    if (high - low <= range) break;
  }
}

/** The same QIM symbol has several equivalent coefficient values. Choosing a
 * different representative can reduce RGB clipping without changing a bit.
 * Search is bounded and encoder-only; readers use the same lattice residues. */
function clippingScore(values: Float64Array) {
  const range = 255 - 2 * MARGIN;
  let low = Infinity, high = -Infinity;
  for (const value of values) { low = Math.min(low, value); high = Math.max(high, value); }
  if (high - low <= range) return 0;
  const center = (high + low) / 2;
  let score = 0;
  for (const value of values) { const excess = Math.max(0, Math.abs(value - center) - range / 2); score += excess * excess; }
  return score;
}
function improvePeaks(dct: Float64Array, spatial: Float64Array, carriers: readonly Carrier[], candidate: Float64Array, best: Float64Array) {
  let bestScore = clippingScore(spatial);
  for (let pass = 0; pass < 4 && bestScore; pass++) {
    let selected = -1, selectedDelta = 0;
    for (const carrier of carriers) {
      const period = carrier.step * (1 << carrier.bits), value = dct[carrier.at];
      const delta = value >= 0 ? -period : period;
      if (Math.abs(value + delta) > Math.abs(value) + carrier.step) continue;
      const v = carrier.at >> 3, u = carrier.at & 7;
      for (let pixel = 0; pixel < 64; pixel++) candidate[pixel] = spatial[pixel] + delta * COS[v * 8 + (pixel >> 3)] * COS[u * 8 + (pixel & 7)];
      const score = clippingScore(candidate);
      if (score + 1e-8 < bestScore) { selected = carrier.at; selectedDelta = delta; bestScore = score; best.set(candidate); }
    }
    if (selected < 0) break;
    dct[selected] += selectedDelta; spatial.set(best);
  }
}

function makeHeader(bytes: Uint8Array, side: number, bitsPerBlock: number, step: ChannelStep,styled=false) {
  const header = new Uint8Array(HEADER_TOTAL), view = new DataView(header.buffer);
  view.setUint32(0, styled?MAGIC+1:MAGIC); header[4] = bitsPerBlock; header[5] = CHANNEL_STEP_MULTIPLIERS.indexOf(step);
  view.setUint16(6, side); view.setUint32(8, bytes.length); view.setUint32(12, transportCRC(bytes));
  const words = new Int32Array(HEADER_TOTAL); words.set(header.subarray(0, HEADER_DATA));
  rsEncoder.encode(words, HEADER_TOTAL - HEADER_DATA);
  return Uint8Array.from(words);
}
function encodeBody(bytes: Uint8Array) {
  const codewords = Math.ceil(bytes.length / RS_DATA), coded = new Uint8Array(codewords * RS_TOTAL);
  const words = new Int32Array(RS_TOTAL);
  for (let word = 0; word < codewords; word++) {
    words.fill(0); words.set(bytes.subarray(word * RS_DATA, (word + 1) * RS_DATA));
    rsEncoder.encode(words, RS_PARITY);
    // Interleave: byte n of each codeword is adjacent only to other codewords.
    for (let at = 0; at < RS_TOTAL; at++) coded[at * codewords + word] = words[at];
  }
  return coded;
}

/** Embeds the envelope. Mutates RGB in place; alpha is left untouched.
 * activeVisualFlags affects cosmetic filler only, never the SSJ3 slot map. */
export function embedJPEGChannel(frame: Uint8ClampedArray, width: number, height: number, envelope: Uint8Array, coverContrast?: number,styled=false,activeVisualFlags=3): ChannelStats {
  validateFrame(frame, width, height);
  if (coverContrast !== undefined && (!Number.isFinite(coverContrast) || coverContrast < 0 || coverContrast > 1)) invalid();
  if(styled&&(!Number.isInteger(activeVisualFlags)||activeVisualFlags<1||activeVisualFlags>3))invalid();
  const slots=styled?styledSlots(width):null,profile=channelProfile(envelope.length,width,styled);
  if (!profile) throw new ProtectedImageError('too-large');
  const header = makeHeader(envelope, width, profile.bitsPerBlock, profile.step,styled), coded = encodeBody(envelope);
  const carriers = channelCarriers(profile.bitsPerBlock, profile.step);
  const bodyModes = carriers.map(carrier => carrier.at);
  const luma = new Float64Array(64), chroma = new Float64Array(128), spatial = new Float64Array(64);
  const dct = new Float64Array(64), scratch = new Float64Array(64);
  const targets = new Float64Array(64);
  const candidate = new Float64Array(64), best = new Float64Array(64);
  // HD has four times the block area. Profile strength follows density, rather
  // than weakening the channel simply because the encrypted file is larger.
  const density = envelope.length * 1280 * 1280 / (width * width);
  const contrast = coverContrast ?? (width >= 1280 && density <= JPEG_RECOVERY_MAX_BYTES ? jpegChannelContrast(density) : 1);
  const dataBlocks=HEADER_BLOCKS+Math.ceil(coded.length*8/profile.bitsPerBlock);
  const fillerSlots=slots?unusedDecorationSlots(width,activeVisualFlags,slots[dataBlocks-1]):[];
  let bit = 0;
  for (let index = 0; index < dataBlocks+fillerSlots.length; index++) {
    const filler=index>=dataBlocks,slot=filler?fillerSlots[index-dataBlocks]:slots?slots[index]:blockAt(index,width);
    const origin = originOf(slot,width);
    loadBlock(frame, origin, width, luma, chroma);
    for (let at = 0; at < luma.length; at++) luma[at] *= contrast;
    for (let at = 0; at < chroma.length; at++) chroma[at] *= contrast;
    forward(luma, dct, scratch);
    if (index < HEADER_BLOCKS) {
      const value = index & 1 ? header[index >> 1] & 15 : header[index >> 1] >> 4;
      HEADER_MODES.forEach((mode, part) => { dct[mode] = snap(dct[mode], HEADER_STEP, 2, value >> 3 - part & 1); });
    } else {
      for (const carrier of carriers) {
        let symbol = 0;
        if(filler){
          // Deterministic public texture, never another copy of private bytes.
          let noise=Math.imul(slot+1,carrier.at*1664525+1013904223);noise^=noise>>>16;
          symbol=noise&((1<<carrier.bits)-1);
        }else{
          for (let part = 0; part < carrier.bits; part++, bit++) {
            const byte = bit >> 3;
            symbol = symbol << 1 | (byte < coded.length ? coded[byte] >> 7 - (bit & 7) & 1 : 0);
          }
        }
        // Flat covers/noise otherwise choose the same positive half-lattice tie
        // repeatedly, producing large pixel peaks. Balance ties deterministically;
        // either sign represents exactly the same encoded symbol.
        const tie = Math.abs(dct[carrier.at]) < .0001
          ? (Math.imul(index + 1, carrier.at * 1664525 + 1013904223) >>> 16 & 1 ? .001 : -.001) : 0;
        dct[carrier.at] = snap(dct[carrier.at] + tie, carrier.step, 1 << carrier.bits, gray(symbol));
      }
    }
    inverse(dct, spatial, scratch);
    fitGamut(dct, spatial, scratch, targets, index < HEADER_BLOCKS ? HEADER_MODES : bodyModes, contrast < .25 ? 30 : contrast < 1 ? 10 : 3);
    if (index >= HEADER_BLOCKS && width >= 1280 && density > 200_000 && density <= JPEG_RECOVERY_MAX_BYTES) {
      improvePeaks(dct, spatial, carriers, candidate, best);
      fitGamut(dct, spatial, scratch, targets, bodyModes, 10);
    }
    writeBlock(frame, origin, width, chroma, spatial);
  }
  return { ...profile, bytes: envelope.length, codewords: Math.ceil(envelope.length / RS_DATA), correctedSymbols: 0, worstCodeword: 0 };
}

type BlockReader = (slot: number, output: Float64Array) => void;

function readHeader(readBlock: BlockReader, side: number,styled=false) {
  const slots=styled?styledSlots(side):null;
  const dct = new Float64Array(64);
  const words = new Int32Array(HEADER_TOTAL);
  for (let index = 0; index < HEADER_BLOCKS; index++) {
    readBlock(slots?slots[index]:blockAt(index,side),dct);
    let value = 0;
    for (const mode of HEADER_MODES) value = value << 1 | residue(dct[mode], HEADER_STEP, 2);
    words[index >> 1] |= index & 1 ? value : value << 4;
  }
  try { rsDecoder.decode(words, HEADER_TOTAL - HEADER_DATA); } catch { invalid(); }
  const bytes = Uint8Array.from(words.subarray(0, HEADER_DATA)), view = new DataView(bytes.buffer);
  if (view.getUint32(0) !== (styled?MAGIC+1:MAGIC) || view.getUint16(6) !== side) invalid();
  const bitsPerBlock = bytes[4], step = CHANNEL_STEP_MULTIPLIERS[bytes[5]], length = view.getUint32(8);
  if (!step || !bitsPerBlock || bitsPerBlock > MAX_BITS_PER_BLOCK) invalid();
  if (length < MIN_BODY_BYTES || codedLength(length) * 8 > bitsPerBlock * ((slots?.length??side*side/64) - HEADER_BLOCKS)) invalid();
  return { bitsPerBlock, step, length, crc: view.getUint32(12),slots };
}

export function extractJPEGChannelWithStats(frame: Uint8ClampedArray, width: number, height: number): { envelope: Uint8Array; stats: ChannelStats } {
  validateFrame(frame, width, height);
  const luma = new Float64Array(64), scratch = new Float64Array(64);
  return extractChannel(width, (slot, output) => {
    loadBlock(frame, originOf(slot, width), width, luma); forward(luma, output, scratch);
  });
}

/** File JPEGs retain coefficients that are lost in RGB reconstruction. Both
 * entry points share exactly the same framing, bounds, RS and CRC validation.
 * A block callback avoids a second full-image coefficient allocation on phones. */
export function extractJPEGChannelCoefficients(side: number, readBlock: BlockReader) {
  if (!supportedSide(side)) invalid();
  return extractChannel(side, (slot, output) => {
    readBlock(slot, output);
    if (!output.every(value => Number.isFinite(value) && Math.abs(value) <= 1048576)) invalid();
  });
}

function extractChannel(width:number,readBlock:BlockReader):{envelope:Uint8Array;stats:ChannelStats}{
 try{return extractChannelLayout(width,readBlock,false);}catch(error){if(!(error instanceof ProtectedImageError)||error.code!=='invalid-file')throw error;}
 return extractChannelLayout(width,readBlock,true);
}
function extractChannelLayout(width: number, readBlock: BlockReader,styled:boolean): { envelope: Uint8Array; stats: ChannelStats } {
  const {bitsPerBlock,step,length,crc,slots}=readHeader(readBlock,width,styled),blocks=slots?.length??width*width/64;
  const carriers = channelCarriers(bitsPerBlock, step), coded = new Uint8Array(codedLength(length));
  const dct = new Float64Array(64);
  let bit = 0;
  for (let index = HEADER_BLOCKS; index < blocks && bit >> 3 < coded.length; index++) {
    readBlock(slots?slots[index]:blockAt(index,width),dct);
    for (const carrier of carriers) {
      const symbol = ungray(residue(dct[carrier.at], carrier.step, 1 << carrier.bits));
      for (let part = carrier.bits - 1; part >= 0; part--, bit++) {
        if (bit >> 3 < coded.length && symbol >> part & 1) coded[bit >> 3] |= 128 >> (bit & 7);
      }
    }
  }
  const codewords = coded.length / RS_TOTAL, envelope = new Uint8Array(length), words = new Int32Array(RS_TOTAL);
  let correctedSymbols = 0, worstCodeword = 0;
  for (let word = 0; word < codewords; word++) {
    for (let at = 0; at < RS_TOTAL; at++) words[at] = coded[at * codewords + word];
    try { rsDecoder.decode(words, RS_PARITY); } catch { invalid(); }
    let corrected = 0;
    for (let at = 0; at < RS_TOTAL; at++) if (words[at] !== coded[at * codewords + word]) corrected++;
    correctedSymbols += corrected; worstCodeword = Math.max(worstCodeword, corrected);
    envelope.set(words.subarray(0, Math.min(RS_DATA, length - word * RS_DATA)), word * RS_DATA);
  }
  if (transportCRC(envelope) !== crc) invalid();
  return { envelope, stats: { bitsPerBlock, step, bytes: length, codewords, correctedSymbols, worstCodeword } };
}

export function extractJPEGChannel(frame: Uint8ClampedArray, width: number, height: number): Uint8Array {
  return extractJPEGChannelWithStats(frame, width, height).envelope;
}
