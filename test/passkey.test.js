import test from 'node:test';
import assert from 'node:assert/strict';
import { context, signup, login, SoftwareAuthenticator } from '../test-support/helpers.mjs';
import { handle, CHALLENGE_MS, SESSION_MS } from '../src/worker.js';

test('C10-C18: public source has no private items; anonymous API and direct page deny', async () => {
  const x = await context();
  try {
    const a = x.browser(); await signup(a, 'fixture_a');
    const anon = x.browser(), home = await anon.api('/');
    assert.equal(home.status, 200); assert.match(home.data, /AI 인프라/); assert.doesNotMatch(home.data, /fixture_a의 연습 자료/);
    assert.doesNotMatch(home.data, /가상 서버 점검 도구의 화면/);
    assert.equal((await anon.api('/api/private')).status, 401);
    const redirect = await anon.api('/private'); assert.equal(redirect.status, 302); assert.match(redirect.headers.get('location'), /#passkey-area$/);
  } finally { x.close(); }
});
test('C19-C26: fresh server challenges, verified COSE public key storage, cancel saves no account/key', async () => {
  const x = await context();
  try {
    const a = x.browser(), input = { mode: 'signup', username: 'fixture_a', name: '갤럭시 연습', provider: 'Google 비밀번호 관리자' };
    const p = await a.api('/api/auth/registration/options', 'POST', input), q = await a.api('/api/auth/registration/options', 'POST', input);
    assert.notEqual(p.data.options.challenge, q.data.options.challenge);
    assert.equal(x.raw.prepare('SELECT challenge FROM challenges WHERE id=?').get(p.data.ceremonyId).challenge, p.data.options.challenge);
    assert.equal((await a.api('/api/auth/cancel', 'POST', { ceremonyId: p.data.ceremonyId })).status, 200);
    assert.equal(x.raw.prepare('SELECT COUNT(*) n FROM users').get().n, 0);
    assert.equal(x.raw.prepare('SELECT COUNT(*) n FROM credentials').get().n, 0);
    const key = new SoftwareAuthenticator();
    const resp = key.register(q.data.options, x.env.ORIGIN);
    const result = await a.api('/api/auth/registration/verify', 'POST', { mode: 'signup', ceremonyId: q.data.ceremonyId, response: resp });
    assert.equal(result.status, 201); assert.ok(result.data.credential.publicKey.length > 50);
    const stored = x.raw.prepare('SELECT * FROM credentials').get(); assert.equal(stored.public_key, result.data.credential.publicKey);
    assert.equal(stored.name, '갤럭시 연습'); assert.doesNotMatch(JSON.stringify(resp), /privateKey|password|pepper/);
    assert.equal((await a.api('/api/private')).data.items.length, 3);
    assert.match((await a.api('/api/credentials')).data.credentials[0].registeredAt, /T/);
  } finally { x.close(); }
});
test('C27-C34: real signature validation, replay rejection, cookie flags and logout replay', async () => {
  const x = await context();
  try {
    const a = x.browser(), { key } = await signup(a, 'fixture_a');
    await a.api('/api/auth/logout', 'POST', {});
    const bad = await login(a, key, { badSignature: true }); assert.equal(bad.result.status, 401);
    const ok = await login(a, key); assert.equal(ok.result.status, 200);
    assert.notEqual(bad.pending.data.options.challenge, ok.pending.data.options.challenge);
    assert.equal((await a.api('/api/auth/login/verify', 'POST', ok.payload)).status, 401);
    assert.equal((await a.api('/api/private')).status, 200);
    const cookie = [...a.jar].map(([k, v]) => k + '=' + v).join('; ');
    const set = ok.result.headers.get('set-cookie');
    for (const flag of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/']) assert.ok(set.includes(flag));
    const sessionRow = x.raw.prepare('SELECT * FROM sessions').get();
    assert.ok(!cookie.includes(sessionRow.token_hash));
    await a.api('/api/auth/logout', 'POST', {});
    assert.equal((await a.api('/api/private', 'GET', undefined, { cookieOverride: cookie })).status, 401);
  } finally { x.close(); }
});
test('C29: wrong origin, RP ID, challenge, user handle and missing user verification deny', async () => {
  const x = await context();
  try {
    const a = x.browser(), { key } = await signup(a, 'fixture_a'); await a.api('/api/auth/logout', 'POST', {});
    for (const opts of [{ origin: 'https://evil.example' }, { rpID: 'evil.example' }, { challenge: 'bad_challenge' }, { handle: 'ZmFrZQ' }, { uv: false }]) {
      assert.equal((await login(a, key, opts)).result.status, 401);
      assert.equal((await a.api('/api/private')).status, 401);
    }
    assert.equal((await login(a, key)).result.status, 200);
  } finally { x.close(); }
});
test('registration rejects wrong origin, missing UV, expired and consumed challenge', async () => {
  const x = await context();
  try {
    const a = x.browser(), key = new SoftwareAuthenticator();
    const begin = () => a.api('/api/auth/registration/options', 'POST', { mode: 'signup', username: 'fixture_a', name: '키', provider: '기타·확인 필요' });
    for (const [origin, uv] of [['https://evil.example', true], [x.env.ORIGIN, false]]) {
      const p = await begin(); const payload = { mode: 'signup', ceremonyId: p.data.ceremonyId, response: key.register(p.data.options, origin, { uv }) };
      assert.equal((await a.api('/api/auth/registration/verify', 'POST', payload)).status, 401);
      assert.equal((await a.api('/api/auth/registration/verify', 'POST', payload)).status, 401);
    }
    const p = await begin(); x.clock.now += CHALLENGE_MS;
    assert.equal((await a.api('/api/auth/registration/verify', 'POST', { mode: 'signup', ceremonyId: p.data.ceremonyId, response: key.register(p.data.options, x.env.ORIGIN) })).status, 401);
    assert.equal(x.raw.prepare('SELECT COUNT(*) n FROM users').get().n, 0);
  } finally { x.close(); }
});
test('C36-C41: both directions deny read/update/delete; spoofing cannot change owner or victim data', async () => {
  const x = await context();
  try {
    const a = x.browser(), b = x.browser(); await signup(a, 'fixture_a'); await signup(b, 'fixture_b');
    for (const [attacker, victim] of [[a, b], [b, a]]) {
      const before = (await victim.api('/api/private')).data, id = before.items[0].id;
      assert.equal((await victim.api('/api/private/' + id)).status, 200);
      for (const method of ['GET', 'PATCH', 'DELETE']) assert.equal((await attacker.api('/api/private/' + id, method, method === 'PATCH' ? { title: '공격', body: '공격' } : undefined)).status, 403);
      const spoof = (await attacker.api('/api/private?user_id=' + before.user.id, 'GET', undefined, { headers: { 'X-User-ID': before.user.id } })).data;
      assert.notEqual(spoof.user.id, before.user.id); assert.ok(spoof.items.every(i => i.user_id === spoof.user.id));
      const created = await attacker.api('/api/private', 'POST', { user_id: before.user.id, title: '소유자 위조 시험', body: '가상 자료' });
      assert.equal(created.data.owner, spoof.user.id);
      assert.deepEqual((await victim.api('/api/private')).data, before);
    }
  } finally { x.close(); }
});
test('C42-C46: two credentials, deleted key denied, remaining key works; last-key deletion blocked', async () => {
  const x = await context();
  try {
    const a = x.browser(), { key: one } = await signup(a, 'fixture_a'), two = new SoftwareAuthenticator();
    const options = await a.api('/api/auth/registration/options', 'POST', { mode: 'add', name: '예비 키', provider: '기타·확인 필요' });
    assert.equal(options.data.options.excludeCredentials.length, 1);
    const add = await a.api('/api/auth/registration/verify', 'POST', { mode: 'add', ceremonyId: options.data.ceremonyId, response: two.register(options.data.options, x.env.ORIGIN) });
    assert.equal(add.status, 201); assert.equal((await a.api('/api/credentials')).data.credentials.length, 2);
    const firstID = Buffer.from(one.id).toString('base64url');
    const secondID = Buffer.from(two.id).toString('base64url');
    const oldCookie = [...a.jar].map(([k, v]) => k + '=' + v).join('; ');
    assert.equal((await a.api('/api/credentials/' + firstID, 'DELETE')).status, 200);
    assert.equal((await a.api('/api/private')).status, 401); // 현재 인증에 쓴 키를 지우면 그 세션도 회수한다.
    assert.equal((await a.api('/api/private', 'GET', undefined, { cookieOverride: oldCookie })).status, 401);
    assert.equal((await login(a, one)).result.status, 401);
    assert.equal((await login(a, two)).result.status, 200);
    assert.equal((await a.api('/api/credentials/' + secondID, 'DELETE')).status, 409);
    assert.equal((await a.api('/api/private')).status, 200);
  } finally { x.close(); }
});
test('concurrent key deletion preserves one usable key and an add ceremony cannot outlive logout', async () => {
  const x = await context();
  try {
    const a = x.browser(), { key: one } = await signup(a, 'fixture_a'), two = new SoftwareAuthenticator();
    const p = await a.api('/api/auth/registration/options', 'POST', { mode: 'add', name: '두 번째', provider: '기타·확인 필요' });
    assert.equal((await a.api('/api/auth/registration/verify', 'POST', { mode: 'add', ceremonyId: p.data.ceremonyId, response: two.register(p.data.options, x.env.ORIGIN) })).status, 201);
    const ids = (await a.api('/api/credentials')).data.credentials.map(k => k.id);
    const r = await Promise.all(ids.map(id => a.api('/api/credentials/' + id, 'DELETE')));
    assert.equal(r.filter(v => v.status === 200).length, 1);
    assert.equal(x.raw.prepare('SELECT COUNT(*) n FROM credentials').get().n, 1);
    const remaining = x.raw.prepare('SELECT id FROM credentials').get().id;
    assert.equal((await login(a, remaining === Buffer.from(one.id).toString('base64url') ? one : two)).result.status, 200);
    const q = await a.api('/api/auth/registration/options', 'POST', { mode: 'add', name: '중단된 등록', provider: '기타·확인 필요' });
    const three = new SoftwareAuthenticator(), response = three.register(q.data.options, x.env.ORIGIN);
    await a.api('/api/auth/logout', 'POST', {});
    assert.equal((await a.api('/api/auth/registration/verify', 'POST', { mode: 'add', ceremonyId: q.data.ceremonyId, response })).status, 401);
    assert.equal(x.raw.prepare('SELECT COUNT(*) n FROM credentials').get().n, 1);
  } finally { x.close(); }
});
test('challenge consumption is atomic across concurrent identical requests and bound to browser flow', async () => {
  const x = await context();
  try {
    const a = x.browser(), { key } = await signup(a, 'fixture_a'), other = x.browser();
    const p = await a.api('/api/auth/login/options', 'POST', {}), payload = { ceremonyId: p.data.ceremonyId, response: key.login(p.data.options, x.env.ORIGIN) };
    assert.equal((await other.api('/api/auth/login/verify', 'POST', payload)).status, 401);
    const results = await Promise.all([a.api('/api/auth/login/verify', 'POST', payload), a.api('/api/auth/login/verify', 'POST', payload)]);
    assert.deepEqual(results.map(r => r.status).sort(), [200, 401]);
  } finally { x.close(); }
});
test('exact session expiry, CSRF, missing config and bounded JSON fail closed', async () => {
  const x = await context();
  try {
    const a = x.browser(); await signup(a, 'fixture_a');
    assert.equal((await a.api('/api/private', 'POST', { title: 'a', body: 'a' }, { origin: 'https://evil.example' })).status, 403);
    assert.equal((await a.api('/api/private', 'POST', { title: 'a', body: 'x'.repeat(70_000) })).status, 413);
    assert.equal((await handle(new Request(x.env.ORIGIN + '/api/private'), { ...x.env, RP_ID: undefined })).status, 503);
    x.clock.now += SESSION_MS; assert.equal((await a.api('/api/private')).status, 401);
  } finally { x.close(); }
});
test('credential management needs fresh authentication and cannot delete another account key', async () => {
  const x = await context();
  try {
    const a = x.browser(), b = x.browser(); await signup(a, 'fixture_a'); await signup(b, 'fixture_b');
    const id = (await b.api('/api/credentials')).data.credentials[0].id;
    assert.equal((await a.api('/api/credentials/' + id, 'DELETE')).status, 403);
    x.clock.now += 5 * 60_000;
    assert.equal((await a.api('/api/auth/registration/options', 'POST', { mode: 'add', name: '추가', provider: '기타·확인 필요' })).status, 403);
  } finally { x.close(); }
});
test('migrations repeat without data loss; deletion is confined to authenticated account', async () => {
  const x = await context();
  try {
    const a = x.browser(), b = x.browser(); await signup(a, 'fixture_a'); await signup(b, 'fixture_b');
    const before = (await b.api('/api/private')).data;
    const { readFile } = await import('node:fs/promises'); x.raw.exec(await readFile(new URL('../schema.sql', import.meta.url), 'utf8'));
    assert.equal((await a.api('/api/account', 'DELETE', { confirmUsername: 'fixture_a' })).status, 200);
    assert.equal((await a.api('/api/private')).status, 401);
    assert.deepEqual((await b.api('/api/private')).data, before);
    assert.equal(x.raw.prepare('SELECT COUNT(*) n FROM credentials').get().n, 1);
  } finally { x.close(); }
});
test('session reports the credential that authenticated it, not the latest-added key or client-supplied selection', async () => {
  const x = await context();
  try {
    const a = x.browser(), { key: one, result } = await signup(a, 'fixture_a'), two = new SoftwareAuthenticator();
    const firstID = result.data.credential.id;
    assert.equal((await a.api('/api/auth/me')).data.credential.id, firstID);
    const p = await a.api('/api/auth/registration/options', 'POST', { mode: 'add', name: '내 예비 키', provider: '기타·확인 필요' });
    const add = await a.api('/api/auth/registration/verify', 'POST', { mode: 'add', ceremonyId: p.data.ceremonyId, response: two.register(p.data.options, x.env.ORIGIN) });
    assert.equal(add.status, 201);
    assert.equal((await a.api('/api/auth/me')).data.credential.id, firstID, 'adding a key is not logging in with it');
    await a.api('/api/auth/logout', 'POST', {});
    assert.equal((await a.api('/api/auth/me')).status, 401);
    assert.equal((await login(a, two)).result.status, 200);
    const me = await a.api('/api/auth/me?credential_id=' + firstID, 'GET', undefined, { headers: { 'X-Credential-ID': firstID } });
    assert.deepEqual(me.data.credential, { id: add.data.credential.id, name: '내 예비 키' });
    assert.equal((await login(a, one)).result.status, 200);
    assert.equal((await a.api('/api/auth/me')).data.credential.id, firstID);
  } finally { x.close(); }
});
