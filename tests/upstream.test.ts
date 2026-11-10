import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
const manifest = JSON.parse(readFileSync(new URL('../UPSTREAM.json', import.meta.url), 'utf8'));
it('preserves every extracted source/fixture hash and all 51 locale catalogs', () => {
  for (const file of manifest.files) {
    expect(createHash('sha256').update(readFileSync(new URL(`../${file.path}`, import.meta.url))).digest('hex'), file.path).toBe(file.sha256);
  }
  const locales = JSON.parse(readFileSync(new URL('../offline/locales.json', import.meta.url), 'utf8'));
  expect(Object.keys(locales)).toHaveLength(51);
  for (const catalog of Object.values(locales) as Record<string, unknown>[]) {
    expect(Object.keys(catalog).sort()).toEqual(Object.keys(locales.en).sort());
    for (const value of Object.values(catalog)) expect(value).toBeTruthy();
  }
});
