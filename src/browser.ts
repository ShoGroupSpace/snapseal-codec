/** Browser encoder/decoder, copied from the same implementation as SnapSeal. */
export * from './index';
export * from './image/png-container';
export * from './image/image-compression';
import { decodeProtectedPNG } from './image/png-container';
import { unlockProtectedFile } from './crypto/protected-image';
export async function decodeFile(input: Uint8Array, password: string, signal?: AbortSignal) {
  const envelope = await decodeProtectedPNG(input, signal);
  return unlockProtectedFile(envelope, password, { signal });
}
