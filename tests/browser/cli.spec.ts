import { test, expect } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
test('CLI creates anti-compression PNG, restores exact bytes, and refuses overwriting', async ({}, info) => {
  const folder = info.outputPath('cli'); mkdirSync(folder,{recursive:true});
  const source = resolve(folder,'note.txt'), protectedPNG = resolve(folder,'protected.png'), restored = resolve(folder,'restored');
  const original = Buffer.from('CLI exact bytes 🌍\r\n\0'); writeFileSync(source,original);
  const run = (args: string[]) => spawnSync(process.execPath,['bin/snapseal.mjs',...args,'--password-stdin'],{ input:'Public CLI password\n',encoding:'utf8',timeout:120_000 });
  const encoded = run(['encode',source,'--out',protectedPNG]); expect(encoded.status,encoded.stderr).toBe(0); expect(encoded.stdout).toContain('Photo recovery: on');
  const decoded = run(['decode',protectedPNG,'--out',restored]); expect(decoded.status,decoded.stderr).toBe(0);
  expect(readFileSync(resolve(restored,'note.txt'))).toEqual(original);
  const again = run(['decode',protectedPNG,'--out',restored]); expect(again.status).toBe(1); expect(again.stderr).toContain('EEXIST');
});
