import { extractJPEGFile } from './jpeg-file';

self.onmessage = (event: MessageEvent<Uint8Array>) => {
  try {
    const { envelope } = extractJPEGFile(event.data);
    self.postMessage(envelope, { transfer: [envelope.buffer as ArrayBuffer] });
  } catch { self.postMessage(null); }
};
