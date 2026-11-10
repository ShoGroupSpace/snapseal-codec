// @vitest-environment node
import { argon2Sync, createCipheriv, pbkdf2Sync } from 'node:crypto';
import { argon2id } from 'hash-wasm';
import { expect, it, vi, afterEach } from 'vitest';
import { protectFile, inspectProtectedFile, unlockProtectedFile } from '../src/index';
import * as argonKDF from '../src/crypto/argon2-client';

afterEach(() => vi.restoreAllMocks());
it('cross-checks the RFC 9106 reference vector and independent native Argon2id output', async () => {
  const message = Buffer.alloc(32, 1), nonce = Buffer.alloc(16, 2);
  const parameters = { message, nonce, parallelism: 4, tagLength: 32, memory: 32, passes: 3 };
  expect(argon2Sync('argon2id', { ...parameters, secret: Buffer.alloc(8, 3), associatedData: Buffer.alloc(12, 4) }).toString('hex')).toBe('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
  // The application uses empty optional secret/associated-data inputs. GCM
  // authenticates the full envelope header separately as its additionalData.
  const wasm = await argon2id({ password: message, salt: nonce, memorySize: 32, parallelism: 4, iterations: 3, hashLength: 32, outputType: 'binary' });
  expect(Buffer.from(wasm)).toEqual(argon2Sync('argon2id', parameters));
});

it.each([1, 2])('keeps independent PBKDF2 v%i files readable, including short historical passwords', async version => {
  const password = 'x', bytes = version === 1 ? Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==', 'base64') : Buffer.from('  Old text 🌍\r\n');
  const metadata = Buffer.from(JSON.stringify(version === 1 ? { filename: 'old.png', mimeType: 'image/png' } : { filename: 'old.txt', contentKind: 'text' }));
  const header = Buffer.alloc(41); header.write('SNAPSEAL'); header[8] = version; header.writeUInt32BE(600_000, 9);
  crypto.getRandomValues(header.subarray(13, 29)); crypto.getRandomValues(header.subarray(29));
  const length = Buffer.alloc(4); length.writeUInt32BE(metadata.length);
  const cipher = createCipheriv('aes-256-gcm', pbkdf2Sync(password, header.subarray(13, 29), 600_000, 32, 'sha256'), header.subarray(29)); cipher.setAAD(header);
  const envelope = Buffer.concat([header, cipher.update(Buffer.concat([length, metadata, bytes])), cipher.final(), cipher.getAuthTag()]);
  expect(() => inspectProtectedFile(envelope)).not.toThrow();
  expect((await unlockProtectedFile(envelope, password)).bytes).toEqual(new Uint8Array(bytes));
});

it('rejects altered algorithms, memory, lanes and passes before either KDF or AES import', async () => {
  const envelope = await protectFile(new Uint8Array([1]), 'one.bin', 'Strong KDF boundary password');
  const argon = vi.spyOn(argonKDF, 'deriveArgon2'), pbkdf = vi.spyOn(crypto.subtle, 'deriveKey'), imported = vi.spyOn(crypto.subtle, 'importKey');
  for (const offset of [9, 10, 11, 12, 16]) {
    const hostile = envelope.slice(); hostile[offset] ^= 128;
    expect(() => inspectProtectedFile(hostile)).toThrow();
    await expect(unlockProtectedFile(hostile, 'Strong KDF boundary password')).rejects.toMatchObject({ code: 'invalid-file' });
  }
  expect(argon).not.toHaveBeenCalled(); expect(pbkdf).not.toHaveBeenCalled(); expect(imported).not.toHaveBeenCalled();
});

it('fails closed without silently creating PBKDF2 output if Argon2 is unavailable', async () => {
  vi.spyOn(argonKDF, 'deriveArgon2').mockRejectedValue(new Error('WASM blocked'));
  const pbkdf = vi.spyOn(crypto.subtle, 'deriveKey');
  await expect(protectFile(new Uint8Array([1]), 'one.bin', 'Strong KDF boundary password')).rejects.toMatchObject({ code: 'unsupported-browser' });
  expect(pbkdf).not.toHaveBeenCalled();
});

it('honors cancellation before starting a KDF', async () => {
  const controller = new AbortController(); controller.abort();
  const derive = vi.spyOn(argonKDF, 'deriveArgon2');
  await expect(protectFile(new Uint8Array([1]), 'one.bin', 'Strong KDF boundary password', { signal: controller.signal })).rejects.toMatchObject({ name: 'AbortError' });
  expect(derive).not.toHaveBeenCalled();
});
