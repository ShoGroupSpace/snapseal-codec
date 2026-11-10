/** One bounded, disposable parser per request. No password or plaintext enters
 * this worker; it returns an envelope that still needs AES-GCM authentication. */
export function readJPEGFile(bytes: Uint8Array, signal?: AbortSignal): Promise<Uint8Array | null> {
  if (signal?.aborted) return Promise.reject(new DOMException('Aborted', 'AbortError'));
  return new Promise((resolve, reject) => {
    let worker: Worker;
    try { worker = new Worker(new URL('./jpeg-file.worker.ts', import.meta.url), { type: 'module' }); }
    catch { resolve(null); return; } // Native pixel reader remains available.
    let finished = false;
    const finish = (value: Uint8Array | null, aborted = false) => {
      if (finished) return;
      finished = true; clearTimeout(timer); signal?.removeEventListener('abort', abort); worker.terminate();
      if (aborted) reject(new DOMException('Aborted', 'AbortError')); else resolve(value);
    };
    const abort = () => finish(null, true);
    const timer = setTimeout(() => finish(null), 20_000);
    signal?.addEventListener('abort', abort, { once: true });
    worker.onmessage = (event: MessageEvent<unknown>) => {
      const value = event.data;
      finish(value instanceof Uint8Array && value.length >= 62 && value.length <= 1_229_622 ? value : null);
    };
    worker.onerror = event => { event.preventDefault(); finish(null); };
    worker.onmessageerror = () => finish(null);
    try {
      // Keep caller bytes intact for native fallback and cancellation/retry.
      const input = Uint8Array.from(bytes);
      worker.postMessage(input, [input.buffer]);
    } catch { finish(null); }
  });
}
