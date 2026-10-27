import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from '@simplewebauthn/server';

export const CHALLENGE_MS = 5 * 60_000;
export const SESSION_MS = 60 * 60_000;
const RECENT_MS = 5 * 60_000;
const PROVIDERS = ['Google 비밀번호 관리자', 'Samsung Pass', 'Windows Hello', '보안 키', '기타·확인 필요'];
const enc = new TextEncoder();
export const to64 = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const from64 = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const random = () => to64(crypto.getRandomValues(new Uint8Array(32)));
const hash = async text => to64(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text))));
class Problem extends Error { constructor(status, message) { super(message); this.status = status; } }
const fail = (status, message) => { throw new Problem(status, message); };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
const all = async (db, sql, ...args) => (await db.prepare(sql).bind(...args).all()).results;
const first = (db, sql, ...args) => db.prepare(sql).bind(...args).first();
const run = (db, sql, ...args) => db.prepare(sql).bind(...args).run();
const stmt = (db, sql, ...args) => db.prepare(sql).bind(...args);

function config(env) {
  let u;
  try { u = new URL(env.ORIGIN); } catch { fail(503, '서버 주소 설정이 필요합니다.'); }
  const local = u.hostname === 'localhost' && u.protocol === 'http:';
  if (!env.DB || env.RP_ID !== u.hostname || u.origin !== env.ORIGIN || (!local && u.protocol !== 'https:')) fail(503, '서버 주소 설정이 올바르지 않습니다.');
  return { origin: u.origin, rpID: env.RP_ID, secure: !local,
    sessionName: local ? 't08_session' : '__Host-t08_session', flowName: local ? 't08_flow' : '__Host-t08_flow' };
}
function cookie(req, name) {
  const entries = (req.headers.get('Cookie') || '').split(';').map(s => s.trim().split('='));
  const value = entries.find(([k]) => k === name)?.[1];
  return value && /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
}
function setCookie(name, value, maxAge, cfg) {
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${cfg.secure ? '; Secure' : ''}`;
}
async function body(req) {
  if (!/^application\/json(?:\s*;|$)/i.test(req.headers.get('Content-Type') || '')) fail(415, 'JSON 요청만 받습니다.');
  const reader = req.body?.getReader();
  if (!reader) fail(400, '요청 내용이 없습니다.');
  let size = 0, chunks = [];
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > 65_536) { await reader.cancel(); fail(413, '요청 내용이 너무 큽니다.'); }
    chunks.push(value);
  }
  const data = new Uint8Array(size); let at = 0;
  for (const chunk of chunks) { data.set(chunk, at); at += chunk.length; }
  try { const v = JSON.parse(new TextDecoder().decode(data)); if (!v || Array.isArray(v) || typeof v !== 'object') throw 0; return v; }
  catch { fail(400, '올바른 JSON 객체가 필요합니다.'); }
}
function text(value, min, max, message) {
  if (typeof value !== 'string' || value.trim().length < min || value.trim().length > max) fail(400, message);
  return value.trim();
}
function keyMeta(input) {
  const name = text(input.name, 1, 60, '패스키 이름을 1~60자로 입력하세요.');
  if (!PROVIDERS.includes(input.provider)) fail(400, '패스키를 저장할 곳을 선택하세요.');
  return { name, provider: input.provider };
}
async function session(req, db, cfg, now, required = true) {
  const token = cookie(req, cfg.sessionName);
  const tokenHash = token ? await hash(token) : '';
  const value = tokenHash && await first(db, `SELECT s.*, u.username, c.name AS credential_name FROM sessions s
    JOIN users u ON u.id=s.user_id JOIN credentials c ON c.id=s.credential_id AND c.user_id=s.user_id
    WHERE s.token_hash=? AND s.expires_at>?`, tokenHash, now);
  if (!value && required) fail(401, '패스키로 로그인하세요.');
  return value || null;
}
function recent(s, now) { if (now - s.created_at >= RECENT_MS) fail(403, '안전을 위해 로그아웃 후 패스키로 다시 로그인하고 5분 안에 시도하세요.'); }
async function createSession(db, userID, credentialID, now) {
  const token = random();
  const result = await run(db, `INSERT INTO sessions(token_hash,user_id,credential_id,created_at,expires_at)
    SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM credentials WHERE id=? AND user_id=?)`,
  await hash(token), userID, credentialID, now, now + SESSION_MS, credentialID, userID);
  if (result.meta.changes !== 1) fail(401, '사용할 수 없는 패스키입니다.');
  return token;
}
async function rateLimit(req, db, now) {
  const bucket = await hash((req.headers.get('CF-Connecting-IP') || 'local-development') + ':' + Math.floor(now / 300_000));
  const result = await first(db, `INSERT INTO rate_limits(bucket,count,expires_at) VALUES(?,1,?)
    ON CONFLICT(bucket) DO UPDATE SET count=count+1 RETURNING count`, bucket, now + 300_000);
  if (result.count > 120) fail(429, '시도가 너무 많습니다. 잠시 후 다시 시도하세요.');
  await db.batch([
    stmt(db, 'DELETE FROM challenges WHERE expires_at<=?', now),
    stmt(db, 'DELETE FROM sessions WHERE expires_at<=?', now),
    stmt(db, 'DELETE FROM rate_limits WHERE expires_at<=?', now),
  ]);
}
async function issueChallenge(req, db, cfg, now, info, challenge) {
  let flow = cookie(req, cfg.flowName);
  if (!flow) flow = random();
  const flowHash = await hash(flow);
  const { n } = await first(db, 'SELECT COUNT(*) AS n FROM challenges WHERE flow_hash=?', flowHash);
  if (n >= 20) fail(429, '진행 중인 인증 창이 너무 많습니다. 5분 후 다시 시도하세요.');
  const id = crypto.randomUUID();
  await run(db, `INSERT INTO challenges(id,challenge,kind,flow_hash,session_hash,user_id,username,key_name,provider,created_at,expires_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, challenge, info.kind, flowHash, info.sessionHash || null,
  info.userID || null, info.username || null, info.name || null, info.provider || null, now, now + CHALLENGE_MS);
  return { id, flow };
}
async function consumeChallenge(req, db, cfg, now, id, kind) {
  if (typeof id !== 'string' || id.length > 64) fail(400, '인증 요청 번호가 필요합니다.');
  const flow = cookie(req, cfg.flowName);
  if (!flow) fail(401, '인증 창이 만료됐습니다. 다시 시작하세요.');
  // DELETE ... RETURNING은 읽기와 소모가 한 번의 SQL로 일어난다. 동시 재전송도 한 번만 처리한다.
  const value = await first(db, 'DELETE FROM challenges WHERE id=? AND flow_hash=? AND kind=? RETURNING *', id, await hash(flow), kind);
  if (!value || value.expires_at <= now) fail(401, '이미 사용했거나 만료된 인증 질문입니다. 다시 시작하세요.');
  return value;
}
function verifiedResponse(input) {
  const v = input.response;
  if (!v || typeof v.id !== 'string' || v.id.length > 2048 || v.type !== 'public-key') fail(400, '패스키 응답이 올바르지 않습니다.');
  return v;
}
function publicCredential(row) {
  return { id: row.id, name: row.name, provider: row.provider, providerSource: '사용자가 저장 화면을 보고 직접 선택한 값',
    registeredAt: new Date(row.created_at).toISOString(), lastUsedAt: row.last_used_at ? new Date(row.last_used_at).toISOString() : null,
    publicKey: row.public_key, publicKeyFormat: 'base64url encoded COSE public key',
    deviceType: row.device_type, backedUp: Boolean(row.backed_up) };
}
async function api(req, env, cfg, now) {
  const db = env.DB, url = new URL(req.url), path = url.pathname;
  if (req.method !== 'GET') {
    if (!['POST', 'PATCH', 'DELETE'].includes(req.method)) fail(405, '지원하지 않는 요청입니다.');
    if (req.headers.get('Origin') !== cfg.origin) fail(403, '다른 사이트에서 보낸 변경 요청은 받지 않습니다.');
  }
  if (path === '/api/auth/me' && req.method === 'GET') {
    const s = await session(req, db, cfg, now);
    return json({ user: { id: s.user_id, username: s.username },
      credential: { id: s.credential_id, name: s.credential_name },
      expiresAt: new Date(s.expires_at).toISOString() });
  }
  if (path === '/api/auth/registration/options' && req.method === 'POST') {
    const input = await body(req), meta = keyMeta(input);
    await rateLimit(req, db, now);
    let info, exclude = [];
    if (input.mode === 'signup') {
      if (await session(req, db, cfg, now, false)) fail(409, '새 계정은 로그아웃 후 만드세요.');
      const username = text(input.username, 3, 32, '가상 아이디를 3~32자로 입력하세요.').normalize('NFKC').toLowerCase();
      if (!/^[a-z0-9_-]{3,32}$/.test(username)) fail(400, '아이디에는 영문 소문자·숫자·밑줄·하이픈을 사용하세요.');
      if (await first(db, 'SELECT id FROM users WHERE username=?', username)) fail(409, '이미 등록된 아이디입니다. 기존 패스키로 로그인하세요.');
      info = { kind: 'signup', userID: crypto.randomUUID(), username, ...meta };
    } else if (input.mode === 'add') {
      const s = await session(req, db, cfg, now); recent(s, now);
      exclude = await all(db, 'SELECT id,transports FROM credentials WHERE user_id=?', s.user_id);
      if (exclude.length >= 10) fail(409, '패스키는 계정당 10개까지 등록할 수 있습니다.');
      info = { kind: 'add', userID: s.user_id, username: s.username, sessionHash: s.token_hash, ...meta };
    } else fail(400, '등록 종류가 올바르지 않습니다.');
    const options = await generateRegistrationOptions({
      rpName: 'SKT ALEPH 08 · 내 소개와 비공개 메모', rpID: cfg.rpID,
      userID: enc.encode(info.userID), userName: info.username, userDisplayName: info.username,
      attestationType: 'none', timeout: CHALLENGE_MS,
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      supportedAlgorithmIDs: [-7, -257],
      excludeCredentials: exclude.map(r => ({ id: r.id, transports: JSON.parse(r.transports) })),
    });
    const issued = await issueChallenge(req, db, cfg, now, info, options.challenge);
    const out = json({ ceremonyId: issued.id, options });
    out.headers.append('Set-Cookie', setCookie(cfg.flowName, issued.flow, 600, cfg)); return out;
  }
  if (path === '/api/auth/registration/verify' && req.method === 'POST') {
    const input = await body(req);
    const kind = input.mode === 'signup' ? 'signup' : input.mode === 'add' ? 'add' : fail(400, '등록 종류가 올바르지 않습니다.');
    const c = await consumeChallenge(req, db, cfg, now, input.ceremonyId, kind);
    if (kind === 'add') { const s = await session(req, db, cfg, now); recent(s, now); if (s.token_hash !== c.session_hash || s.user_id !== c.user_id) fail(403, '등록을 시작한 로그인 상태가 아닙니다.'); }
    else if (await session(req, db, cfg, now, false)) fail(409, '로그아웃 후 다시 등록하세요.');
    let verification;
    try { verification = await verifyRegistrationResponse({ response: verifiedResponse(input), expectedChallenge: c.challenge,
      expectedOrigin: cfg.origin, expectedRPID: cfg.rpID, requireUserVerification: true, supportedAlgorithmIDs: [-7, -257] }); }
    catch { fail(401, '패스키 등록 확인에 실패했습니다. 다시 시작하세요.'); }
    if (!verification.verified) fail(401, '패스키 등록 확인에 실패했습니다.');
    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    const publicKey = to64(credential.publicKey);
    const sql = [];
    if (kind === 'signup') sql.push(stmt(db, 'INSERT INTO users(id,username,created_at) VALUES(?,?,?)', c.user_id, c.username, now));
    sql.push(stmt(db, `INSERT INTO credentials(id,user_id,public_key,counter,transports,device_type,backed_up,name,provider,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?)`, credential.id, c.user_id, publicKey, credential.counter, JSON.stringify(credential.transports || []),
    credentialDeviceType, Number(credentialBackedUp), c.key_name, c.provider, now));
    if (kind === 'signup') {
      const fictional = [
        ['가상 프로젝트 메모', `${c.username}의 연습 자료입니다. 가상 서버 점검 도구의 화면 구성을 정리합니다.`],
        ['가상 지원 목록', `${c.username}의 연습 자료입니다. 예시 기업 A·B의 공개 채용 안내를 비교할 계획입니다.`],
        ['가상 학습 회고', `${c.username}의 연습 자료입니다. 패스키의 공개키와 개인키 역할을 다시 설명해 봅니다.`],
      ];
      for (const [title, content] of fictional) sql.push(stmt(db, 'INSERT INTO private_items(id,user_id,title,body,updated_at) VALUES(?,?,?,?,?)', crypto.randomUUID(), c.user_id, title, content, now));
    }
    try { await db.batch(sql); } catch { fail(409, '이미 등록된 아이디 또는 패스키입니다. 목록을 확인하고 다시 시도하세요.'); }
    const out = json({ verified: true, user: { id: c.user_id, username: c.username }, credential: { id: credential.id, name: c.key_name, publicKey } }, 201);
    if (kind === 'signup') out.headers.append('Set-Cookie', setCookie(cfg.sessionName, await createSession(db, c.user_id, credential.id, now), SESSION_MS / 1000, cfg));
    return out;
  }
  if (path === '/api/auth/login/options' && req.method === 'POST') {
    await body(req); await rateLimit(req, db, now);
    // Discoverable credential: 공개 API에서 아이디별 패스키 목록을 노출하지 않는다.
    const options = await generateAuthenticationOptions({ rpID: cfg.rpID, timeout: CHALLENGE_MS, userVerification: 'required' });
    const issued = await issueChallenge(req, db, cfg, now, { kind: 'login' }, options.challenge);
    const out = json({ ceremonyId: issued.id, options });
    out.headers.append('Set-Cookie', setCookie(cfg.flowName, issued.flow, 600, cfg)); return out;
  }
  if (path === '/api/auth/login/verify' && req.method === 'POST') {
    const input = await body(req), c = await consumeChallenge(req, db, cfg, now, input.ceremonyId, 'login');
    const response = verifiedResponse(input);
    const stored = await first(db, 'SELECT c.*,u.username FROM credentials c JOIN users u ON u.id=c.user_id WHERE c.id=?', response.id);
    if (!stored) fail(401, '패스키 로그인 확인에 실패했습니다.');
    if (response.response?.userHandle && response.response.userHandle !== to64(enc.encode(stored.user_id))) fail(401, '패스키 로그인 확인에 실패했습니다.');
    let verification;
    try { verification = await verifyAuthenticationResponse({ response, expectedChallenge: c.challenge, expectedOrigin: cfg.origin,
      expectedRPID: cfg.rpID, requireUserVerification: true,
      credential: { id: stored.id, publicKey: from64(stored.public_key), counter: stored.counter, transports: JSON.parse(stored.transports) } }); }
    catch { fail(401, '패스키 로그인 확인에 실패했습니다.'); }
    if (!verification.verified) fail(401, '패스키 로그인 확인에 실패했습니다.');
    const updated = await run(db, 'UPDATE credentials SET counter=?,backed_up=?,last_used_at=? WHERE id=? AND counter=?', verification.authenticationInfo.newCounter,
      Number(verification.authenticationInfo.credentialBackedUp), now, stored.id, stored.counter);
    if (updated.meta.changes !== 1) fail(401, '패스키 상태가 변경됐습니다. 다시 로그인하세요.');
    const old = cookie(req, cfg.sessionName); if (old) await run(db, 'DELETE FROM sessions WHERE token_hash=?', await hash(old));
    const token = await createSession(db, stored.user_id, stored.id, now);
    const out = json({ verified: true, user: { id: stored.user_id, username: stored.username } });
    out.headers.append('Set-Cookie', setCookie(cfg.sessionName, token, SESSION_MS / 1000, cfg)); return out;
  }
  if (path === '/api/auth/cancel' && req.method === 'POST') {
    const input = await body(req), flow = cookie(req, cfg.flowName);
    if (flow && typeof input.ceremonyId === 'string') await run(db, 'DELETE FROM challenges WHERE id=? AND flow_hash=?', input.ceremonyId, await hash(flow));
    return json({ cancelled: true, message: '등록을 취소했습니다. 패스키를 저장하지 않았습니다.' });
  }
  if (path === '/api/auth/logout' && req.method === 'POST') {
    const token = cookie(req, cfg.sessionName);
    if (token) await run(db, 'DELETE FROM sessions WHERE token_hash=?', await hash(token));
    const flow = cookie(req, cfg.flowName);
    if (flow) await run(db, 'DELETE FROM challenges WHERE flow_hash=?', await hash(flow));
    const out = json({ loggedOut: true });
    out.headers.append('Set-Cookie', setCookie(cfg.sessionName, '', 0, cfg));
    out.headers.append('Set-Cookie', setCookie(cfg.flowName, '', 0, cfg)); return out;
  }
  // 아래부터는 모든 경로에서 서버가 세션의 user_id를 소유자로 결정한다.
  const s = await session(req, db, cfg, now);
  if (path === '/api/credentials' && req.method === 'GET') {
    return json({ credentials: (await all(db, 'SELECT * FROM credentials WHERE user_id=? ORDER BY created_at,id', s.user_id)).map(publicCredential),
      lastKeyPolicy: '마지막 패스키 삭제는 차단합니다. 모든 저장 기기·복구 수단을 잃으면 이 앱은 계정을 복구해 주지 못합니다. 다른 사람에게 자료를 넘기지 않습니다.' });
  }
  if (path.startsWith('/api/credentials/') && req.method === 'DELETE') {
    recent(s, now);
    const id = decodeURIComponent(path.slice('/api/credentials/'.length));
    const row = await first(db, 'SELECT id FROM credentials WHERE id=? AND user_id=?', id, s.user_id);
    if (!row) fail(403, '본인 패스키만 삭제할 수 있습니다.');
    // 동시에 두 키를 지워도 마지막 한 개는 남긴다.
    const deleted = await first(db, `DELETE FROM credentials WHERE id=? AND user_id=?
      AND (SELECT COUNT(*) FROM credentials WHERE user_id=?)>1 RETURNING id`, id, s.user_id, s.user_id);
    if (!deleted) fail(409, '마지막 패스키는 삭제할 수 없습니다. 먼저 다른 저장소에 패스키를 추가하세요.');
    const out = json({ deleted: true, loggedOut: s.credential_id === id });
    if (s.credential_id === id) out.headers.append('Set-Cookie', setCookie(cfg.sessionName, '', 0, cfg));
    return out;
  }
  if (path === '/api/private' && req.method === 'GET') {
    return json({ user: { id: s.user_id, username: s.username }, items: await all(db, 'SELECT id,user_id,title,body,updated_at FROM private_items WHERE user_id=? ORDER BY title,id', s.user_id) });
  }
  if (path === '/api/private' && req.method === 'POST') {
    const input = await body(req), id = crypto.randomUUID();
    const title = text(input.title, 1, 100, '제목을 1~100자로 입력하세요.'), content = text(input.body, 1, 2000, '내용을 1~2000자로 입력하세요.');
    await run(db, 'INSERT INTO private_items(id,user_id,title,body,updated_at) VALUES(?,?,?,?,?)', id, s.user_id, title, content, now);
    return json({ id, owner: s.user_id }, 201);
  }
  if (path.startsWith('/api/private/')) {
    const id = decodeURIComponent(path.slice('/api/private/'.length));
    const item = await first(db, 'SELECT id,user_id,title,body,updated_at FROM private_items WHERE id=? AND user_id=?', id, s.user_id);
    if (!item) fail(403, '본인 자료만 접근할 수 있습니다.');
    if (req.method === 'GET') return json({ item });
    if (req.method === 'PATCH') {
      const input = await body(req), title = text(input.title, 1, 100, '제목을 1~100자로 입력하세요.'), content = text(input.body, 1, 2000, '내용을 1~2000자로 입력하세요.');
      await run(db, 'UPDATE private_items SET title=?,body=?,updated_at=? WHERE id=? AND user_id=?', title, content, now, id, s.user_id);
      return json({ updated: true, owner: s.user_id });
    }
    if (req.method === 'DELETE') { await run(db, 'DELETE FROM private_items WHERE id=? AND user_id=?', id, s.user_id); return json({ deleted: true }); }
  }
  if (path === '/api/account' && req.method === 'DELETE') {
    recent(s, now); const input = await body(req);
    if (input.confirmUsername !== s.username) fail(400, '삭제할 본인 가상 아이디를 확인하세요.');
    await db.batch([stmt(db, 'DELETE FROM challenges WHERE user_id=?', s.user_id), stmt(db, 'DELETE FROM users WHERE id=?', s.user_id)]);
    const out = json({ deleted: true }); out.headers.append('Set-Cookie', setCookie(cfg.sessionName, '', 0, cfg)); return out;
  }
  fail(404, '없는 API입니다.');
}
function protect(response) {
  const out = new Response(response.body, response);
  out.headers.set('Cache-Control', 'no-store');
  out.headers.set('X-Content-Type-Options', 'nosniff');
  out.headers.set('Referrer-Policy', 'same-origin');
  out.headers.set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  out.headers.set('Permissions-Policy', 'publickey-credentials-create=(self), publickey-credentials-get=(self)');
  return out;
}
export async function handle(req, env, now = Date.now()) {
  try {
    const url = new URL(req.url), cfg = config(env);
    if (url.origin !== cfg.origin) fail(421, '설정된 사이트 주소로 접속하세요.');
    if (url.pathname.startsWith('/api/')) return protect(await api(req, env, cfg, now));
    if (url.pathname === '/private' && !await session(req, env.DB, cfg, now, false)) return protect(Response.redirect(cfg.origin + '/#passkey-area', 302));
    if (url.pathname === '/favicon.ico') return protect(new Response(null, { status: 204 }));
    if (!['GET', 'HEAD'].includes(req.method)) fail(405, '지원하지 않는 요청입니다.');
    if (url.pathname === '/private') return protect(await env.ASSETS.fetch(new Request(cfg.origin + '/', req)));
    return protect(await env.ASSETS.fetch(req));
  } catch (e) {
    if (e instanceof Problem) return protect(json({ error: e.message }, e.status));
    // 자격 증명·쿠키·원문 요청·내부 SQL을 로그나 오류 응답에 출력하지 않는다.
    return protect(json({ error: '처리하지 못했습니다. 잠시 후 다시 시도하세요.' }, 500));
  }
}
// Workers의 세 번째 인자는 ExecutionContext이다. 시험용 now 인자에 전달하지 않는다.
export default { fetch: (req, env) => handle(req, env) };
