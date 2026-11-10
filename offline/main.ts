import * as codec from '../src/browser';
import translations from './locales.json';
import languageNames from './languages.json';
// CLI and compatibility tests use the exact same bundled browser APIs.
(window as any).SnapSealCodec = codec;
const el = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const input = el<HTMLInputElement>('input'), cover = el<HTMLInputElement>('cover'), password = el<HTMLInputElement>('password');
const language = el<HTMLSelectElement>('language'), recovery = el<HTMLSelectElement>('recovery');
let mode: 'protect' | 'unlock' = 'unlock', busy = false;
let locale: keyof typeof translations = 'en';
const requested = navigator.language.toLowerCase();
if (Object.hasOwn(translations, requested)) locale = requested as typeof locale;
else if (Object.hasOwn(translations, requested.split('-')[0])) locale = requested.split('-')[0] as typeof locale;
for (const [code, name] of Object.entries(languageNames)) { const option = document.createElement('option'); option.value = code; option.textContent = name; language.append(option); }
language.value = locale;
const urls: string[] = [];
function clearDownloads() { for (const url of urls) URL.revokeObjectURL(url); urls.length = 0; el('downloads').replaceChildren(); }
function refresh() {
  const t = translations[locale];
  document.documentElement.lang = locale; document.documentElement.dir = ['ar', 'fa', 'he'].includes(locale) ? 'rtl' : 'ltr';
  document.title = `${t.title} · SnapSeal`;
  const labels = { heading: t.title, intro: t.intro, 'language-label': t.language, 'mode-unlock': t.unlock, 'mode-protect': t.protect, 'file-label': mode === 'unlock' ? t.protectedFile : t.choose, 'cover-label': t.cover, 'delivery-label': t.delivery, 'password-label': t.password, 'show-label': t.show, 'recovery-hint': t.recovery, submit: busy ? t.working : t[mode], clear: t.clear };
  for (const [id, text] of Object.entries(labels)) el(id).textContent = text;
  recovery.options[0].textContent = t.auto; recovery.options[1].textContent = t.standard; recovery.options[2].textContent = t.hd; recovery.options[3].textContent = t.fileOnly;
  el('encode-options').hidden = mode !== 'protect';
  el<HTMLButtonElement>('submit').disabled = busy; el<HTMLButtonElement>('mode-unlock').disabled = busy; el<HTMLButtonElement>('mode-protect').disabled = busy;
  input.disabled = cover.disabled = password.disabled = recovery.disabled = busy;
  el('mode-unlock').setAttribute('aria-pressed', String(mode === 'unlock')); el('mode-protect').setAttribute('aria-pressed', String(mode === 'protect'));
}
function changeMode(next: typeof mode) { mode = next; input.value = ''; password.value = ''; el('status').textContent = ''; clearDownloads(); refresh(); }
el('mode-unlock').onclick = () => changeMode('unlock'); el('mode-protect').onclick = () => changeMode('protect');
language.onchange = () => { locale = language.value as typeof locale; refresh(); };
el<HTMLInputElement>('show').onchange = event => { password.type = (event.target as HTMLInputElement).checked ? 'text' : 'password'; };
el('clear').onclick = () => { if (busy) return; changeMode(mode); cover.value = ''; password.type = 'password'; el<HTMLInputElement>('show').checked = false; };
function download(bytes: Uint8Array, filename: string, label: string) {
  const url = URL.createObjectURL(new Blob([Uint8Array.from(bytes)], { type: 'application/octet-stream' })); urls.push(url);
  const link = document.createElement('a'); link.href = url; link.download = filename; link.className = 'download'; link.textContent = label; el('downloads').append(link);
}
el('form').onsubmit = async event => {
  event.preventDefault(); if (busy || !input.files?.[0]) return;
  const file = input.files[0], t = translations[locale];
  clearDownloads(); el('status').textContent = ''; el('status').dataset.error = 'false';
  busy = true; refresh();
  try {
    // Bound file selection before reading into JS memory, as in the product.
    const max = mode === 'unlock' ? codec.MAX_CONTAINER_FILE_BYTES : codec.MAX_FILE_BYTES;
    if (file.size > max) throw new codec.ProtectedImageError('too-large');
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (mode === 'unlock') {
      const result = await codec.decodeFile(bytes, password.value);
      download(result.bytes, result.filename, `${t.download} · ${result.filename}`); result.bytes.fill(0);
      el('status').textContent = t.ready;
    } else {
      const envelope = codec.imagePreviewMime(bytes) ? await codec.protectImageFile(bytes, file.name, password.value) : await codec.protectFile(bytes, file.name, password.value);
      const coverFile = cover.files?.[0]; if (coverFile && coverFile.size > codec.MAX_COVER_IMAGE_BYTES) throw new codec.ProtectedImageError('too-large');
      const coverBytes = coverFile ? new Uint8Array(await coverFile.arrayBuffer()) : undefined;
      const result = await codec.encodeProtectedPNGWithInfo(envelope, coverBytes, { recoveryMode: recovery.value as codec.JPEGRecoveryMode, visual: { branding: true } });
      download(codec.protectedImageZIP(result.bytes), 'protected-image.zip', t.zip); download(result.bytes, 'protected-image.png', t.png);
      el('status').textContent = `${t.protectedReady}. ${result.jpegRecovery ? t.recovery : t.fileOnly}`;
    }
    password.value = '';
  } catch (error) {
    el('status').dataset.error = 'true'; el('status').textContent = error instanceof codec.ProtectedImageError ? t.errors[error.code] : t.error;
  } finally { busy = false; refresh(); }
};
refresh();
