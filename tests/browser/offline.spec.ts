import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { decodeFile as decodeNode } from '../../dist/node.js';
const html = pathToFileURL(resolve('dist/snapseal-codec.html')).href;
const vectors = JSON.parse(readFileSync('tests/fixtures/vectors/manifest.json', 'utf8'));
test('opens from disk, decodes both password formats, and makes no HTTP requests', async ({ page }) => {
  const network: string[] = []; page.on('request', request => { if (/^https?:/.test(request.url())) network.push(request.url()); });
  await page.goto(html);
  for (const vector of vectors) {
    const bytes = [...readFileSync(`tests/fixtures/vectors/${vector.file}`)];
    const result = await page.evaluate(async ({ bytes, password }) => { const r = await (window as any).SnapSealCodec.decodeFile(new Uint8Array(bytes), password); return { bytes: Array.from(r.bytes), filename: r.filename }; }, { bytes, password: vector.password });
    expect(Buffer.from(result.bytes as number[]).toString('base64')).toBe(vector.originalBase64);
  }
  await expect(page.locator('#language option')).toHaveCount(51);
  await page.selectOption('#language', 'uk'); await expect(page.locator('html')).toHaveAttribute('lang', 'uk');
  await page.selectOption('#language', 'ar'); await expect(page.locator('html')).toHaveAttribute('dir', 'rtl');
  expect(network).toEqual([]);
});
test('same encoder creates recoverable decorated PNG; Q60 and Q85→Q60 restore exact bytes', async ({ page }) => {
  await page.goto(html);
  const result = await page.evaluate(async () => {
    const c = (window as any).SnapSealCodec, original = new TextEncoder().encode('Anti-compression compatibility: original bytes 🌍\r\n');
    const password = 'Public recovery testing password';
    const envelope = await c.protectFile(original, 'note.txt', password, { contentKind: 'text' });
    const encoded = await c.encodeProtectedPNGWithInfo(envelope, undefined, { recoveryMode: 'auto', visual: { branding: true, label: 'Public test' } });
    const checks: number[][] = [];
    for (const qualities of [[], [.6], [.85,.6]]) {
      let bytes = encoded.bytes;
      for (const quality of qualities) {
        const bitmap = await createImageBitmap(new Blob([bytes])); const canvas = document.createElement('canvas'); canvas.width = bitmap.width; canvas.height = bitmap.height; const context = canvas.getContext('2d')!; context.drawImage(bitmap,0,0); bitmap.close();
        const blob = await new Promise<Blob>(resolve => canvas.toBlob(b => resolve(b!), 'image/jpeg', quality)); bytes = new Uint8Array(await blob.arrayBuffer());
      }
      checks.push(Array.from((await c.decodeFile(bytes, password)).bytes));
    }
    const zipped = await c.decodeFile(c.protectedImageZIP(encoded.bytes), password);
    return { recovery: encoded.jpegRecovery, original: Array.from(original), checks, zip: Array.from(zipped.bytes) };
  });
  expect(result.recovery).toBe(true); for (const check of result.checks) expect(check).toEqual(result.original); expect(result.zip).toEqual(result.original);
});
test('offline UI unlocks a real file and retains no password after success', async ({ page }) => {
  await page.goto(html); await page.selectOption('#language','en');
  await page.locator('#input').setInputFiles('tests/fixtures/vectors/v2.snapseal');
  await page.locator('#password').fill(vectors[1].password);
  await page.locator('#submit').click(); await expect(page.locator('#downloads a')).toHaveCount(1);
  await expect(page.locator('#password')).toHaveValue('');
  const download = page.waitForEvent('download'); await page.locator('#downloads a').click(); const saved = await download;
  expect(saved.suggestedFilename()).toBe('note.txt');
  expect(readFileSync((await saved.path())!).toString('base64')).toBe(vectors[1].originalBase64);
});
test('cover SSJ2/SSJ3, legacy recovery and HD outputs interoperate with the Node reader', async ({ page }) => {
  await page.goto(html);
  for (const scenario of [
    { bytes: 30, branding: false, recoveryMode: 'auto', cover: false },
    { bytes: 12_000, branding: false, recoveryMode: 'auto', cover: true },
    { bytes: 12_000, branding: true, recoveryMode: 'auto', cover: true },
    { bytes: 100, branding: true, recoveryMode: 'hd', cover: false },
    { bytes: 100, branding: true, recoveryMode: 'file', cover: true },
  ]) {
    const password = 'Public browser-to-node password';
    const result = await page.evaluate(async ({ scenario, password }) => {
      const c = (window as any).SnapSealCodec, original = new Uint8Array(scenario.bytes).fill(101);
      const envelope = await c.protectFile(original,'test.bin',password);
      let cover: Uint8Array | undefined;
      if (scenario.cover) { const canvas = document.createElement('canvas'); canvas.width = canvas.height = 1024; const ctx = canvas.getContext('2d')!; ctx.fillStyle = '#808080'; ctx.fillRect(0,0,1024,1024); const blob = await new Promise<Blob>(resolve => canvas.toBlob(b => resolve(b!))); cover = new Uint8Array(await blob.arrayBuffer()); }
      const encoded = await c.encodeProtectedPNGWithInfo(envelope,cover,{ recoveryMode: scenario.recoveryMode, visual: { branding: scenario.branding } });
      let jpeg: number[] | undefined;
      if (encoded.jpegRecovery) { const bitmap = await createImageBitmap(new Blob([encoded.bytes])); const canvas = document.createElement('canvas'); canvas.width = bitmap.width; canvas.height = bitmap.height; canvas.getContext('2d')!.drawImage(bitmap,0,0); bitmap.close(); const blob = await new Promise<Blob>(resolve => canvas.toBlob(b => resolve(b!),'image/jpeg',.6)); const bytes = new Uint8Array(await blob.arrayBuffer()); const restored = await c.decodeFile(bytes,password); if (!restored.bytes.every((b: number) => b === 101)) throw new Error('browser mismatch'); jpeg = Array.from(bytes); }
      return { png: Array.from(encoded.bytes) as number[], jpeg, recovery: encoded.jpegRecovery };
    }, { scenario, password });
    expect(result.recovery).toBe(scenario.recoveryMode !== 'file');
    for (const bytes of [result.png, result.jpeg].filter(Boolean) as number[][]) {
      const restored = await decodeNode(new Uint8Array(bytes),password);
      expect(restored.bytes).toEqual(new Uint8Array(scenario.bytes).fill(101));
    }
  }
});
