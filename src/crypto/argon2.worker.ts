import { argon2KeyBytes } from './argon2-core';

// Only password bytes and a public salt enter this disposable worker. No files,
// decrypted content, URLs, persistent storage or network access are needed.
self.onmessage = async (event: MessageEvent<{ password: Uint8Array; salt: Uint8Array }>) => {
  const { password, salt } = event.data;
  if (!(password instanceof Uint8Array) || !(salt instanceof Uint8Array)) { self.postMessage(null); self.close(); return; }
  try {
    const key = await argon2KeyBytes(password, salt);
    self.postMessage(key, { transfer: [key.buffer] });
  } catch { self.postMessage(null); }
  finally { password.fill(0); salt.fill(0); self.close(); }
};
