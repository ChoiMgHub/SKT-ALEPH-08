import { writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { verify } from '../test-support/verification.mjs';
import { httpContext } from '../test-support/http-client.mjs';
import { login } from '../test-support/helpers.mjs';

const origin = 'https://skt-aleph-08.mingi85308530.workers.dev';
const prefix = 'audit_' + randomBytes(6).toString('hex');
const usernameA = prefix + '_a', usernameB = prefix + '_b';
const x = httpContext(origin), fixtures = [];
let result, error;
try { result = await verify(x, { usernameA, usernameB, fixtures }); }
catch (e) { error = e.message || '검증 실패'; }
const cleanup = [];
for (const fixture of fixtures) {
  if (![usernameA,usernameB].includes(fixture.username)) throw new Error('이 실행에서 만든 시험 계정만 정리합니다.');
  if (!fixture.actor.accountDeleted) {
    try {
      let me = await fixture.actor.api('/api/auth/me');
      if (me.status !== 200) {
        for (const key of [...fixture.keys].reverse()) {
          if ((await login(fixture.actor, key)).result.status === 200) break;
        }
        me = await fixture.actor.api('/api/auth/me');
      }
      if (me.status === 200 && me.data.user.username === fixture.username) await fixture.actor.api('/api/account', 'DELETE', { confirmUsername: fixture.username });
    } catch { /* 결과에 미정리 상태를 남긴다. 기존 사용자 계정에는 접근하지 않는다. */ }
  }
  cleanup.push({ account: fixture.username, deleted: fixture.actor.accountDeleted });
}
const report = {
  kind: 't08-production-http-verification', generatedAt: new Date().toISOString(), origin,
  environment: '실제 배포된 HTTPS Worker·원격 D1. 이 실행에서만 만든 임시 A/B 계정과 소프트웨어 인증기의 P-256 실제 서명으로 검사.',
  limitation: '소프트웨어 인증기 기반 운영 HTTP 검사이며 갤럭시 지문 센서 시험이 아니다. 사용자 learner_a·learner_b에는 접근하지 않았다.',
  sensitiveData: 'Cookie·Set-Cookie 값은 가림. 개인키·비밀번호·API 키·사용자 원문은 저장하지 않음. 공개키·서명·메모는 삭제한 임시 계정의 시험 자료.',
  passed: !error && cleanup.length === 2 && cleanup.every(c=>c.deleted),
  ...(result || {}), error: error || null, cleanup, records: x.records,
};
await writeFile('docs/production-evidence.json', JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({ passed:report.passed, checks:result?.checks.length || 0, cleanup, file:'docs/production-evidence.json', error:report.error },null,2));
if (!report.passed) process.exitCode=1;
