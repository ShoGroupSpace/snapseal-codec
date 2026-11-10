import { argon2KeyBytes } from './argon2-core';

let queue: Promise<unknown> = Promise.resolve();
const abortError = () => new DOMException('Cancelled', 'AbortError');

/** Serialize KDFs within one context and release the worker's 64 MiB on every
 * completion, failure, timeout or cancellation. Never fall back to PBKDF2. */
export function deriveArgon2(password: Uint8Array, salt: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
  const run = async () => {
    if (signal?.aborted) throw abortError();
    // Node/tests and extension service workers have no nested Worker API. Browser
    // window flows always use the disposable worker; worker startup errors fail.
    if (typeof Worker === 'undefined') {
      if (typeof window !== 'undefined' && typeof process === 'undefined') throw new Error('Argon2 worker unavailable.');
      const result = await argon2KeyBytes(password, salt);
      if (signal?.aborted) { result.fill(0); throw abortError(); }
      return result;
    }
    return new Promise<Uint8Array>((resolve, reject) => {
      let worker: Worker;
      try { worker = new Worker(new URL('./argon2.worker.ts', import.meta.url), { type: 'module' }); }
      catch { reject(new Error('Argon2 worker unavailable.')); return; }
      let finished = false;
      const finish = (key: Uint8Array | null, aborted = false) => {
        if (finished) return;
        finished = true; clearTimeout(timer); signal?.removeEventListener('abort', abort); worker.terminate();
        if (key?.length === 32) resolve(key);
        else reject(aborted ? abortError() : new Error('Argon2 unavailable.'));
      };
      const abort = () => finish(null, true);
      const timer = setTimeout(() => finish(null), 30_000);
      signal?.addEventListener('abort', abort, { once: true });
      worker.onmessage = (event: MessageEvent<unknown>) => finish(event.data instanceof Uint8Array ? event.data : null);
      worker.onerror = event => { event.preventDefault(); finish(null); };
      worker.onmessageerror = () => finish(null);
      const secret = Uint8Array.from(password), nonce = Uint8Array.from(salt);
      try { worker.postMessage({ password: secret, salt: nonce }, [secret.buffer, nonce.buffer]); }
      catch { if (secret.byteLength) secret.fill(0); if (nonce.byteLength) nonce.fill(0); finish(null); }
      if (signal?.aborted) abort();
    });
  };
  const result = queue.then(run, run);
  queue = result.then(() => {}, () => {});
  return result;
}
