import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
export async function runtime() {
  const ORIGIN = 'https://t08.example.test';
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const mf = new Miniflare(convertV4MiniflareOptions({
    modules: true, scriptPath: fileURLToPath(new URL('../dist/worker.js', import.meta.url)),
    compatibilityDate: '2026-10-27', compatibilityFlags: ['nodejs_compat'],
    bindings: { ORIGIN, RP_ID: 't08.example.test' }, d1Databases: ['DB'],
    serviceBindings: { ASSETS: async () => new Response(html, { headers: { 'Content-Type': 'text/html' } }) },
  }));
  try {
    const db = await mf.getD1Database('DB');
    const sql = await readFile(new URL('../schema.sql', import.meta.url), 'utf8');
    await db.batch(sql.split(';').map(s => s.trim()).filter(Boolean).map(s => db.prepare(s)));
    const records = [];
    function browser() {
      const jar = new Map();
      return { jar, async api(path, method = 'GET', value, { cookieOverride, origin = ORIGIN, headers = {} } = {}) {
        const requestHeaders = new Headers(headers);
        requestHeaders.set('Cookie', cookieOverride ?? [...jar].map(([k, v]) => k + '=' + v).join('; '));
        if (method !== 'GET') { requestHeaders.set('Origin', origin); requestHeaders.set('Content-Type', 'application/json'); }
        const response = await mf.dispatchFetch(ORIGIN + path, { method, headers: requestHeaders, body: value === undefined ? undefined : JSON.stringify(value) });
        const cookies = response.headers.getSetCookie();
        for (const c of cookies) {
          const [pair] = c.split(';'), at = pair.indexOf('='), k = pair.slice(0, at), v = pair.slice(at + 1);
          if (!v || /Max-Age=0(?:;|$)/.test(c)) jar.delete(k); else jar.set(k, v);
        }
        const content = await response.text(); let data;
        try { data = JSON.parse(content); } catch { data = content; }
        records.push({ request: { method, path, body: value ?? null, cookie: requestHeaders.get('Cookie') ? '[REDACTED]' : null },
          response: { status: response.status, body: data, setCookie: cookies.length ? '[REDACTED]' : null } });
        return { status: response.status, data, headers: response.headers };
      } };
    }
    return { browser, records, db, origin: ORIGIN, dispose: () => mf.dispose() };
  } catch (e) { await mf.dispose(); throw e; }
}
