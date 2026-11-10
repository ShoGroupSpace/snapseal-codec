#!/usr/bin/env node
import { readFileSync, writeFileSync, statSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { emitKeypressEvents } from 'node:readline';
import { decodeFile, MAX_CONTAINER_FILE_BYTES, MAX_FILE_BYTES } from '../dist/node.js';
const help = `SnapSeal encoder and decoder
  snapseal decode FILE --out DIRECTORY [--password-stdin]
  snapseal encode FILE --out FILE.png [--recovery auto|standard|hd|file]
      [--cover COVER] [--no-branding] [--label LABEL] [--password-stdin]

Decode: protected PNG, supported JPEG, SnapSeal ZIP or raw .snapseal envelope.
Encode uses the same browser implementation, including JPEG recovery checks.
Install its browser once: npx playwright install chromium
Passwords are prompted without echo; use --password-stdin for automation.
The password is never accepted in command-line arguments or put in a URL.
`;
const args = process.argv.slice(2);
function option(name) { const i = args.indexOf(name); if (i < 0) return undefined; if (!args[i + 1] || args[i + 1].startsWith('--')) throw new Error(`Missing value for ${name}`); return args[i + 1]; }
async function promptPassword(label) {
  if (!process.stdin.isTTY) throw new Error('Use --password-stdin when piping a password.');
  process.stderr.write(label); emitKeypressEvents(process.stdin); process.stdin.setRawMode(true); process.stdin.resume();
  return new Promise((resolve, reject) => {
    const chars = [];
    const finish = error => { process.stdin.off('keypress', onKey); process.stdin.setRawMode(false); process.stdin.pause(); process.stderr.write('\n'); error ? reject(error) : resolve(chars.join('')); };
    const onKey = (text, key = {}) => { if (key.ctrl && key.name === 'c') finish(new Error('Cancelled')); else if (key.name === 'return' || key.name === 'enter') finish(); else if (key.name === 'backspace') chars.pop(); else if (text && !key.ctrl && !key.meta && !/[\u0000-\u001f\u007f]/.test(text)) chars.push(text); };
    process.stdin.on('keypress', onKey);
  });
}
async function main() {
  if (!args.length || args.includes('--help') || args.includes('-h')) { console.log(help); return; }
  const [command, input] = args, out = option('--out');
  if (!['encode', 'decode'].includes(command) || !input || !out) throw new Error(help);
  const allowed = new Set(['--out', '--cover', '--recovery', '--label', '--password-stdin', '--no-branding']);
  for (let i = 2; i < args.length; i++) { if (!allowed.has(args[i])) throw new Error(`Unknown option: ${args[i]}`); if (!['--password-stdin', '--no-branding'].includes(args[i])) i++; }
  const info = statSync(input), bound = command === 'decode' ? MAX_CONTAINER_FILE_BYTES : MAX_FILE_BYTES;
  if (!info.isFile() || info.size > bound) throw new Error('Input exceeds the supported size limit.');
  let password = args.includes('--password-stdin') ? readFileSync(0, 'utf8').replace(/\r?\n$/, '') : await promptPassword('Password: ');
  if (command === 'encode' && !args.includes('--password-stdin') && password !== await promptPassword('Confirm password: ')) throw new Error('Passwords do not match.');
  try {
    if (command === 'decode') {
      const result = await decodeFile(new Uint8Array(readFileSync(input)), password);
      mkdirSync(resolve(out), { recursive: true });
      const target = resolve(out, result.filename); writeFileSync(target, result.bytes, { flag: 'wx', mode: 0o600 }); result.bytes.fill(0);
      console.log(`Restored ${result.filename}`);
    } else {
      const recovery = option('--recovery') ?? 'auto'; if (!['auto', 'standard', 'hd', 'file'].includes(recovery)) throw new Error('Unsupported recovery mode.');
      const coverPath = option('--cover'); if (coverPath && statSync(coverPath).size > 8 * 1024 * 1024) throw new Error('Cover exceeds 8 MiB.');
      const { chromium } = await import('playwright');
      const browser = await chromium.launch({ headless: true });
      try {
        const page = await browser.newPage();
        await page.route(/^https?:/, route => route.abort());
        await page.goto(pathToFileURL(resolve(import.meta.dirname, '../dist/snapseal-codec.html')).href);
        const filename = input.split(/[/\\]/).pop();
        const result = await page.evaluate(async values => {
          const c = window.SnapSealCodec, bytes = new Uint8Array(values.bytes);
          const envelope = c.imagePreviewMime(bytes) ? await c.protectImageFile(bytes, values.filename, values.password) : await c.protectFile(bytes, values.filename, values.password);
          const result = await c.encodeProtectedPNGWithInfo(envelope, values.cover ? new Uint8Array(values.cover) : undefined, { recoveryMode: values.recovery, visual: { branding: values.branding, label: values.label } });
          return { bytes: Array.from(result.bytes), jpegRecovery: result.jpegRecovery };
        }, { bytes: [...readFileSync(input)], filename, password, cover: coverPath ? [...readFileSync(coverPath)] : undefined, recovery, branding: !args.includes('--no-branding'), label: option('--label') });
        writeFileSync(resolve(out), new Uint8Array(result.bytes), { flag: 'wx' });
        console.log(`Protected PNG saved. Photo recovery: ${result.jpegRecovery ? 'on' : 'off'}.`);
      } finally { await browser.close(); }
    }
  } finally { password = ''; }
}
main().catch(error => { console.error(error.code ?? error.message); process.exitCode = 1; });
