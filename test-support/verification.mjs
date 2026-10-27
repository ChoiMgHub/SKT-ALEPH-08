import assert from 'node:assert/strict';
import { signup, login, SoftwareAuthenticator } from './helpers.mjs';
export async function verify(x, { usernameA = 'fixture_a', usernameB = 'fixture_b', fixtures = [] } = {}) {
  const checks = [], pairs = [];
  function check(label, actual, expected) { assert.deepEqual(actual, expected, label); checks.push({ label, passed: true }); }
  const a = x.browser(), b = x.browser(), anon = x.browser();
  const beforeRegistration = await a.api('/api/auth/registration/options', 'POST', { mode: 'signup', username: usernameA, name: '취소할 자동 시험 키', provider: '기타·확인 필요' });
  check('취소할 등록 질문 발급', beforeRegistration.status, 200);
  check('등록 취소', (await a.api('/api/auth/cancel', 'POST', { ceremonyId: beforeRegistration.data.ceremonyId })).status, 200);
  const A = await signup(a, usernameA);
  const fixtureA = { actor: a, username: usernameA, keys: [A.key] }; fixtures.push(fixtureA);
  check('A 등록 검증 성공', A.result.status, 201);
  check('A 세션에 실제 등록 인증 키 표시', (await a.api('/api/auth/me')).data.credential.id, A.result.data.credential.id);
  const B = await signup(b, usernameB); fixtures.push({ actor: b, username: usernameB, keys: [B.key] }); check('B 등록 검증 성공', B.result.status, 201);
  check('등록마다 새 질문', A.pending.data.options.challenge === B.pending.data.options.challenge, false);
  const aData = (await a.api('/api/private')).data, bData = (await b.api('/api/private')).data;
  check('A 가상 메모 세 개', aData.items.length, 3); check('B 가상 메모 세 개', bData.items.length, 3);
  const allowed = await a.api('/api/private'), denied = await anon.api('/api/private');
  check('본인 로그인 조회 허용', allowed.status, 200); check('익명 조회 거부', denied.status, 401);
  pairs.push({ category: '로그인 없이 열기', allowStatus: allowed.status, denyStatus: denied.status,
    allow: 'A 세션으로 /api/private 조회', deny: '쿠키 없이 같은 API 조회' });
  for (const [label, actor, victim, data] of [['A → B', a, b, bData], ['B → A', b, a, aData]]) {
    const own = await victim.api('/api/private/' + data.items[0].id);
    const statuses = [];
    for (const method of ['GET', 'PATCH', 'DELETE']) {
      const result = await actor.api('/api/private/' + data.items[0].id, method, method === 'PATCH' ? { title: '거부되어야 할 변경', body: '가상 공격 자료' } : undefined);
      check(label + ' ' + method + ' 거부', result.status, 403); statuses.push(result.status);
    }
    check(label + ' 피해자 건수·원문 불변', (await victim.api('/api/private')).data, data);
    const spoof = await actor.api('/api/private?user_id=' + data.user.id, 'GET', undefined, { headers: { 'X-User-ID': data.user.id } });
    check(label + ' URL·헤더 위조해도 본인 자료만', spoof.data.items.every(i => i.user_id === spoof.data.user.id) && spoof.data.user.id !== data.user.id, true);
    const forged = await actor.api('/api/private', 'POST', { title: '가상 소유자 위조 시험', body: '입력한 소유자를 믿지 않아야 합니다.', user_id: data.user.id });
    check(label + ' 본문 소유자 위조 무시', forged.data.owner === spoof.data.user.id, true);
    await actor.api('/api/private/' + forged.data.id, 'DELETE');
    check(label + ' 위조 후 피해자 원문 불변', (await victim.api('/api/private')).data, data);
    pairs.push({ category: '남의 패스키 계정으로 열기 · ' + label, allowStatus: own.status, denyStatus: statuses[0], allow: '자료 소유자의 정상 조회', deny: label + ' 조회·수정·삭제 거부, 피해자 원문과 건수 불변' });
  }
  const bad = await login(a, A.key, { badSignature: true }); check('잘못된 서명 거부', bad.result.status, 401);
  const good = await login(a, A.key); check('올바른 서명 허용', good.result.status, 200);
  check('로그인마다 새 질문', bad.pending.data.options.challenge === good.pending.data.options.challenge, false);
  const replay = await a.api('/api/auth/login/verify', 'POST', good.payload); check('이미 사용한 질문 재전송 거부', replay.status, 401);
  pairs.push({ category: '이미 쓴 질문 재사용', allowStatus: good.result.status, denyStatus: replay.status, allow: '새 질문과 올바른 서명', deny: '동일 요청 본문 재전송' });
  const oldCookie = [...a.jar].map(([k, v]) => k + '=' + v).join('; ');
  check('로그아웃 성공', (await a.api('/api/auth/logout', 'POST', {})).status, 200);
  check('로그아웃 뒤 옛 쿠키 재전송 거부', (await a.api('/api/private', 'GET', undefined, { cookieOverride: oldCookie })).status, 401);
  check('기존 키 재로그인', (await login(a, A.key)).result.status, 200);
  const second = new SoftwareAuthenticator();
  fixtureA.keys.push(second);
  const options = await a.api('/api/auth/registration/options', 'POST', { mode: 'add', name: '자동 시험 예비 키', provider: '기타·확인 필요' });
  const add = await a.api('/api/auth/registration/verify', 'POST', { mode: 'add', ceremonyId: options.data.ceremonyId, response: second.register(options.data.options, x.origin) });
  check('두 번째 키 등록', add.status, 201);
  const keys = (await a.api('/api/credentials')).data.credentials;
  check('같은 계정 패스키 두 개', keys.length, 2);
  check('패스키 이름·날짜·공개키 있음', keys.every(k => Boolean(k.name && k.registeredAt && k.publicKey)), true);
  const firstID = Buffer.from(A.key.id).toString('base64url');
  const secondID = Buffer.from(second.id).toString('base64url');
  check('첫 번째 키 삭제', (await a.api('/api/credentials/' + firstID, 'DELETE')).status, 200);
  const directed = x.browser();
  const requestA = () => directed.api('/api/auth/login/options', 'POST', { username: usernameA });
  const requestWrong = await requestA();
  check('아이디 지정 로그인은 삭제 키를 제외하고 남은 키만 요청', requestWrong.data.options.allowCredentials.map(k => k.id), [secondID]);
  check('A 지정 질문에 B의 정상 서명도 거부', (await directed.api('/api/auth/login/verify', 'POST', { ceremonyId: requestWrong.data.ceremonyId, response: B.key.login(requestWrong.data.options, x.origin) })).status, 401);
  const requestGood = await requestA();
  check('아이디 지정 후 남은 예비 키로 로그인 허용', (await directed.api('/api/auth/login/verify', 'POST', { ceremonyId: requestGood.data.ceremonyId, response: second.login(requestGood.data.options, x.origin) })).status, 200);
  check('아이디 지정 로그인은 지정한 A 계정으로만 연결', (await directed.api('/api/auth/me')).data.user.username, usernameA);
  const removed = await login(a, A.key); check('삭제한 키 로그인 거부', removed.result.status, 401);
  const remains = await login(a, second); check('남은 키 로그인 허용', remains.result.status, 200);
  check('예비 키 로그인 뒤 실제 인증 키 표시', (await a.api('/api/auth/me')).data.credential.id, add.data.credential.id);
  pairs.push({ category: '패스키 삭제 뒤 로그인', allowStatus: remains.result.status, denyStatus: removed.result.status,
    allow: '같은 계정에 남아 있는 예비 키', deny: '서버에서 삭제한 이전 키' });
  check('마지막 키 삭제 차단', (await a.api('/api/credentials/' + secondID, 'DELETE')).status, 409);
  const invalidKey = await a.api('/api/credentials/' + Buffer.from(B.key.id).toString('base64url'), 'DELETE');
  check('다른 계정 키 삭제 차단', invalidKey.status, 403);
  check('A 시험 계정 정리', (await a.api('/api/account', 'DELETE', { confirmUsername: usernameA })).status, 200);
  check('B 시험 계정 정리', (await b.api('/api/account', 'DELETE', { confirmUsername: usernameB })).status, 200);
  return { checks, pairs, keys };
}
