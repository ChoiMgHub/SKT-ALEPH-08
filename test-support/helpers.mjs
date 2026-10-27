import { DatabaseSync } from 'node:sqlite';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { handle } from '../src/worker.js';
const b64 = b => Buffer.from(b).toString('base64url');
const digest = b => createHash('sha256').update(b).digest();

// 테스트용 최소 CBOR 인코더. 실제 서버의 WebAuthn 검증을 대체하지 않는다.
function head(type, n) {
  if (n < 24) return Buffer.from([(type << 5) | n]);
  if (n < 256) return Buffer.from([(type << 5) | 24, n]);
  const b = Buffer.alloc(3); b[0] = (type << 5) | 25; b.writeUInt16BE(n, 1); return b;
}
function cbor(v) {
  if (typeof v === 'number') return head(v < 0 ? 1 : 0, v < 0 ? -1 - v : v);
  if (typeof v === 'string') { const b = Buffer.from(v); return Buffer.concat([head(3, b.length), b]); }
  if (v instanceof Uint8Array) return Buffer.concat([head(2, v.length), v]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  throw new Error('Unsupported test CBOR');
}
export class SoftwareAuthenticator {
  constructor() {
    const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    this.privateKey = pair.privateKey; this.jwk = pair.publicKey.export({ format: 'jwk' });
    this.id = crypto.getRandomValues(new Uint8Array(32)); this.counter = 0;
  }
  register(options, origin, { uv = true, rpID = options.rp.id } = {}) {
    this.userHandle = options.user.id;
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(this.jwk.x, 'base64url')], [-3, Buffer.from(this.jwk.y, 'base64url')]]));
    const length = Buffer.alloc(2); length.writeUInt16BE(this.id.length);
    const authData = Buffer.concat([digest(rpID), Buffer.from([0x41 | (uv ? 4 : 0)]), Buffer.alloc(4), Buffer.alloc(16), length, Buffer.from(this.id), cose]);
    const attestation = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
    return { id: b64(this.id), rawId: b64(this.id), type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: {},
      response: { clientDataJSON: b64(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false })),
        attestationObject: b64(attestation), transports: ['internal'] } };
  }
  login(options, origin, { badSignature = false, uv = true, rpID = options.rpId, handle = this.userHandle, challenge = options.challenge } = {}) {
    const count = Buffer.alloc(4); count.writeUInt32BE(++this.counter);
    const authenticatorData = Buffer.concat([digest(rpID), Buffer.from([1 | (uv ? 4 : 0)]), count]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }));
    const signature = sign('sha256', Buffer.concat([authenticatorData, digest(clientData)]), this.privateKey);
    if (badSignature) signature[signature.length - 1] ^= 1;
    return { id: b64(this.id), rawId: b64(this.id), type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: {},
      response: { clientDataJSON: b64(clientData), authenticatorData: b64(authenticatorData), signature: b64(signature), userHandle: handle } };
  }
}
class Statement {
  constructor(db, sql, args = []) { this.db = db; this.sql = sql; this.args = args; }
  bind(...args) { return new Statement(this.db, this.sql, args); }
  async first() { return this.db.prepare(this.sql).get(...this.args) || null; }
  async all() { return { results: this.db.prepare(this.sql).all(...this.args) }; }
  async run() { const r = this.db.prepare(this.sql).run(...this.args); return { meta: { changes: Number(r.changes) } }; }
}
export async function context() {
  const raw = new DatabaseSync(':memory:'); raw.exec(await readFile(new URL('../schema.sql', import.meta.url), 'utf8'));
  const DB = { prepare: sql => new Statement(raw, sql), async batch(statements) {
    raw.exec('BEGIN');
    try { const out = []; for (const s of statements) out.push(await s.run()); raw.exec('COMMIT'); return out; }
    catch (e) { raw.exec('ROLLBACK'); throw e; }
  } };
  const env = { DB, ORIGIN: 'https://t08.example.test', RP_ID: 't08.example.test', ASSETS: { async fetch() {
    return new Response(await readFile(new URL('../index.html', import.meta.url), 'utf8'), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  } } };
  const clock = { now: Date.now() }, records = [];
  function browser() {
    const jar = new Map();
    return {
      jar,
      async api(path, method = 'GET', value, { cookieOverride, origin = env.ORIGIN, headers = {}, record = true } = {}) {
        const requestHeaders = new Headers(headers);
        requestHeaders.set('Cookie', cookieOverride ?? [...jar].map(([k, v]) => k + '=' + v).join('; '));
        if (method !== 'GET') { requestHeaders.set('Origin', origin); requestHeaders.set('Content-Type', 'application/json'); }
        const req = new Request(env.ORIGIN + path, { method, headers: requestHeaders, body: value === undefined ? undefined : JSON.stringify(value) });
        const response = await handle(req, env, clock.now);
        const cookies = response.headers.getSetCookie();
        for (const c of cookies) {
          const [pair] = c.split(';'), idx = pair.indexOf('='), k = pair.slice(0, idx), v = pair.slice(idx + 1);
          if (!v || c.includes('Max-Age=0;') || c.endsWith('Max-Age=0')) jar.delete(k); else jar.set(k, v);
        }
        const content = await response.text(); let data;
        try { data = JSON.parse(content); } catch { data = content; }
        const result = { status: response.status, data, headers: response.headers };
        if (record) records.push({ request: { method, path, body: value ?? null, cookie: requestHeaders.get('Cookie') ? '[REDACTED]' : null },
          response: { status: response.status, body: data, setCookie: cookies.length ? '[REDACTED]' : null } });
        return result;
      },
    };
  }
  return { env, raw, browser, clock, records, close: () => raw.close() };
}
export async function signup(c, username, key = new SoftwareAuthenticator()) {
  const pending = await c.api('/api/auth/registration/options', 'POST', { mode: 'signup', username, name: '자동 시험 기본 키', provider: '기타·확인 필요' });
  if (pending.status !== 200) throw new Error(JSON.stringify(pending.data));
  const response = key.register(pending.data.options, c.origin || 'https://t08.example.test');
  const result = await c.api('/api/auth/registration/verify', 'POST', { mode: 'signup', ceremonyId: pending.data.ceremonyId, response });
  if (result.status !== 201) throw new Error(JSON.stringify(result.data));
  return { key, result, pending };
}
export async function login(c, key, opts = {}) {
  const pending = await c.api('/api/auth/login/options', 'POST', {});
  const response = key.login(pending.data.options, opts.origin || c.origin || 'https://t08.example.test', opts);
  const payload = { ceremonyId: pending.data.ceremonyId, response };
  return { result: await c.api('/api/auth/login/verify', 'POST', payload), payload, pending };
}
