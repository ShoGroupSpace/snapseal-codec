import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { PNG } from 'pngjs';
import { expect, it } from 'vitest';
import { decodeFile, decodeContainer, embedPixelPacket, protectedDimensions, protectedImageZIP } from '../src/node';
const vectors = JSON.parse(readFileSync(new URL('./fixtures/vectors/manifest.json', import.meta.url), 'utf8'));
for (const vector of vectors) {
  const envelope = new Uint8Array(readFileSync(new URL(`./fixtures/vectors/${vector.file}`, import.meta.url)));
  it(`decodes independent ${vector.file} through raw, PNG V1/V2 and ZIP`, async () => {
    expect(createHash('sha256').update(envelope).digest('hex')).toBe(vector.envelopeSHA256);
    for (const bits of [8, 2] as const) {
      const { width, height } = protectedDimensions(envelope.length, bits === 2);
      const rgba = new Uint8ClampedArray(width * height * 4).fill(255); embedPixelPacket(rgba, envelope, bits);
      const png = new Uint8Array(PNG.sync.write({ width, height, data: Buffer.from(rgba) }));
      for (const container of [envelope, png, protectedImageZIP(png)]) {
        const decoded = await decodeFile(container, vector.password);
        expect(Buffer.from(decoded.bytes).toString('base64')).toBe(vector.originalBase64);
        expect(decoded.filename).toBe(vector.metadata.filename);
      }
      const damaged = protectedImageZIP(png); damaged[55] ^= 1; expect(() => decodeContainer(damaged)).toThrow();
    }
    await expect(decodeFile(envelope, vector.password + 'wrong')).rejects.toMatchObject({ code: 'unlock-failed' });
  });
}
it('bounds malformed PNG dimensions before decompression', () => {
  const bytes = new Uint8Array(33); bytes.set([137,80,78,71,13,10,26,10]); const v = new DataView(bytes.buffer); v.setUint32(8,13); bytes.set([73,72,68,82],12); v.setUint32(16,16384); v.setUint32(20,16384);
  expect(() => decodeContainer(bytes)).toThrow('unsafe-dimensions');
  for (const size of [0,1,7,16,32]) expect(() => decodeContainer(bytes.subarray(0,size))).toThrow();
});
