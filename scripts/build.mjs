import { build } from 'esbuild';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
await mkdir('public', { recursive: true });
await mkdir('dist', { recursive: true });
await writeFile('public/index.html', (await readFile('index.html', 'utf8')).replace(/\r\n/g, '\n'));
await build({ entryPoints: ['src/client.js'], bundle: true, format: 'esm', platform: 'browser', target: 'es2022', outfile: 'public/app.js', legalComments: 'eof' });
await build({ entryPoints: ['src/entry.js'], bundle: true, format: 'esm', platform: 'neutral', mainFields: ['browser', 'module', 'main'], conditions: ['workerd', 'browser'], target: 'es2022', external: ['node:crypto'], outfile: 'dist/worker.js', legalComments: 'eof' });
console.log('브라우저와 Worker 빌드 완료');
