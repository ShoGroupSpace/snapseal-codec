import { EFF_WORDS } from './eff-words';
/** Eight independent words: about 103 bits. Rejection sampling prevents bias. */
export function generatePassphrase(): string {
  if (typeof globalThis.crypto?.getRandomValues !== 'function') throw new Error('secure-random-unavailable');
  const limit = Math.floor(2 ** 32 / EFF_WORDS.length) * EFF_WORDS.length;
  const random = new Uint32Array(16), words: string[] = [];
  try {
    while (words.length < 8) {
      globalThis.crypto.getRandomValues(random);
      for (const value of random) { if (value < limit) words.push(EFF_WORDS[value % EFF_WORDS.length]); if (words.length === 8) break; }
    }
    return words.join(' ');
  } finally { random.fill(0); }
}
/** 24 uniformly sampled base64url characters: 144 bits from the browser CSPRNG. */
export function generateImagePassword(): string {
  if (typeof globalThis.crypto?.getRandomValues !== 'function') throw new Error('secure-random-unavailable');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const random = globalThis.crypto.getRandomValues(new Uint8Array(24));
  try { return Array.from(random, byte => alphabet[byte & 63]).join(''); }
  finally { random.fill(0); }
}
