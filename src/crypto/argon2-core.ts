import { argon2id } from 'hash-wasm';

// One fixed, authenticated profile. Untrusted headers cannot choose allocations.
export const ARGON2_MEMORY_KIB = 65_536;
export const ARGON2_PASSES = 3;
export const ARGON2_LANES = 1;
export const ARGON2_VERSION = 0x13;

export function argon2KeyBytes(password: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  if (!password.length || password.length > 1024 || salt.length !== 16) return Promise.reject(new Error('Invalid KDF input.'));
  return argon2id({ password, salt, memorySize: ARGON2_MEMORY_KIB, iterations: ARGON2_PASSES, parallelism: ARGON2_LANES, hashLength: 32, outputType: 'binary' });
}
