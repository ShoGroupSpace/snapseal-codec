import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
const root = resolve(import.meta.dirname, '..');
process.chdir(root);
mkdirSync('dist', { recursive: true });
const bundle = async entry => (await build({ entryPoints: [entry], bundle: true, write: false, format: 'iife', platform: 'browser', target: 'es2022', minify: true, legalComments: 'inline' })).outputFiles[0].text;
const kdf = await bundle('src/crypto/argon2.worker.ts');
const jpeg = await bundle('src/image/jpeg-file.worker.ts');
const logo = 'data:image/png;base64,' + readFileSync('src/assets/brand-mark.png').toString('base64');
const workerFactory = `function __inlineWorker(source){const url=URL.createObjectURL(new Blob([source],{type:'text/javascript'}));let worker;try{worker=new Worker(url);}catch(e){URL.revokeObjectURL(url);throw e;}const stop=worker.terminate.bind(worker);worker.terminate=()=>{stop();URL.revokeObjectURL(url);};return worker;}\n`;
const inlineAssets = {
  name: 'inline-local-workers-and-logo',
  setup(builder) {
    builder.onLoad({ filter: /(?:argon2-client|jpeg-worker-client|visual-overlay)\.ts$/ }, args => {
      let contents = readFileSync(args.path, 'utf8');
      if (args.path.endsWith('argon2-client.ts')) contents = workerFactory + contents.replace("new Worker(new URL('./argon2.worker.ts', import.meta.url), { type: 'module' })", `__inlineWorker(${JSON.stringify(kdf)})`);
      if (args.path.endsWith('jpeg-worker-client.ts')) contents = workerFactory + contents.replace("new Worker(new URL('./jpeg-file.worker.ts', import.meta.url), { type: 'module' })", `__inlineWorker(${JSON.stringify(jpeg)})`);
      if (args.path.endsWith('visual-overlay.ts')) contents = contents.replace("new URL('../assets/brand-mark.png',import.meta.url).href", JSON.stringify(logo));
      return { contents, loader: 'ts', resolveDir: dirname(args.path) };
    });
  }
};
for (const [name, platform] of [['index', 'neutral'], ['browser', 'browser'], ['node', 'node']]) {
  await build({ entryPoints: [`src/${name}.ts`], outfile: `dist/${name}.js`, bundle: true, platform, format: 'esm', target: 'es2022', mainFields: ['module', 'main'], plugins: [inlineAssets], external: ['pngjs'], sourcemap: true, legalComments: 'inline' });
}
const app = (await build({ entryPoints: ['offline/main.ts'], bundle: true, write: false, platform: 'browser', format: 'iife', target: 'es2022', minify: true, plugins: [inlineAssets], legalComments: 'inline' })).outputFiles[0].text;
const html = readFileSync('offline/index.html', 'utf8').replace('<!--LOGO-->', readFileSync('assets/logo.png').toString('base64')).replace('<!--APP-->', app.replaceAll('</script', '<\\/script'));
writeFileSync('dist/snapseal-codec.html', html);
mkdirSync('dist/licenses', { recursive: true });
const require = createRequire(import.meta.url);
for (const [name, filename] of [['hash-wasm', 'LICENSE'], ['@zxing/library', 'LICENSE'], ['pngjs', 'LICENSE']]) {
  const packagePath = require.resolve(`${name}/package.json`);
  copyFileSync(resolve(dirname(packagePath), filename), `dist/licenses/${name.replace('/', '-')}-LICENSE.txt`);
}
for (const file of ['LICENSE.apache-2.0', 'LICENSE.jpeg-js', 'NOTICE.md']) copyFileSync(`src/image/vendor/${file}`, `dist/licenses/jpeg-decoder-${file}`);
copyFileSync('licenses/EFF-WORDLIST-LICENSE.txt', 'dist/licenses/EFF-WORDLIST-LICENSE.txt');
// The downloadable HTML is independently redistributable with all notices inside it.
const notices = ['LICENSE', 'THIRD-PARTY-NOTICES.md', ...['hash-wasm', '@zxing-library', 'pngjs'].map(name => `dist/licenses/${name}-LICENSE.txt`), ...['LICENSE.apache-2.0', 'LICENSE.jpeg-js', 'NOTICE.md'].map(name => `dist/licenses/jpeg-decoder-${name}`), 'licenses/EFF-WORDLIST-LICENSE.txt'].map(file => `\n${file}\n${readFileSync(file, 'utf8')}`).join('\n');
writeFileSync('dist/snapseal-codec.html', html.replace('</body>', `<details class="licenses"><summary>MIT · Apache-2.0 · BSD-3-Clause · CC BY 3.0</summary><pre>${notices.replaceAll('&', '&amp;').replaceAll('<', '&lt;')}</pre></details></body>`));
console.log('Built ESM APIs, embedded workers and standalone offline HTML.');
