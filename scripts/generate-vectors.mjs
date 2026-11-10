// Independent Node crypto, fixed public test salts/IVs/passwords. Never use these
// deterministic values to protect real data. Normal creation uses secure RNG.
import { argon2Sync, pbkdf2Sync, createCipheriv, createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
mkdirSync(new URL('../tests/fixtures/vectors/', import.meta.url), { recursive: true });
const image = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==', 'base64');
const vectors = [];
for (const version of [1, 2, 3]) {
  const password = version === 1 ? 'x' : 'Public compatibility password 🔐';
  const metadata = version === 1 ? { filename: 'legacy.png', mimeType: 'image/png' } : { filename: 'note.txt', contentKind: 'text' };
  const bytes = version === 1 ? image : Buffer.from('  Public note 🌍\r\n\0end\n');
  const header = Buffer.alloc(version === 3 ? 48 : 41); header.write('SNAPSEAL'); header[8] = version;
  const salt = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'), iv = Buffer.from('101112131415161718191a1b', 'hex');
  if (version === 3) { header[9] = 1; header[10] = 0x13; header[11] = 1; header.writeUInt32BE(65536, 12); header.writeUInt32BE(3, 16); salt.copy(header, 20); iv.copy(header, 36); }
  else { header.writeUInt32BE(600000, 9); salt.copy(header, 13); iv.copy(header, 29); }
  const key = version === 3 ? argon2Sync('argon2id', { message: Buffer.from(password), nonce: salt, memory: 65536, passes: 3, parallelism: 1, tagLength: 32 }) : pbkdf2Sync(password, salt, 600000, 32, 'sha256');
  const meta = Buffer.from(JSON.stringify(metadata)), length = Buffer.alloc(4); length.writeUInt32BE(meta.length);
  const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(header);
  const envelope = Buffer.concat([header, cipher.update(Buffer.concat([length, meta, bytes])), cipher.final(), cipher.getAuthTag()]);
  const filename = `v${version}.snapseal`;
  writeFileSync(new URL(`../tests/fixtures/vectors/${filename}`, import.meta.url), envelope);
  vectors.push({ file: filename, password, metadata, originalBase64: bytes.toString('base64'), envelopeSHA256: createHash('sha256').update(envelope).digest('hex') }); key.fill(0);
}
writeFileSync(new URL('../tests/fixtures/vectors/manifest.json', import.meta.url), JSON.stringify(vectors, null, 2) + '\n');
console.log('Generated v1/v2 PBKDF2 and v3 Argon2id vectors with independent Node crypto.');
