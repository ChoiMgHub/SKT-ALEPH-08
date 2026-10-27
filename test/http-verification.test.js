import test from 'node:test';
import assert from 'node:assert/strict';
import { context } from '../test-support/helpers.mjs';
import { httpContext } from '../test-support/http-client.mjs';
import { verify } from '../test-support/verification.mjs';
import { handle } from '../src/worker.js';
test('HTTP verification uses unique named fixtures, real signatures, redacted cookies and removes only its own accounts', async () => {
  const local = await context();
  try {
    const x = httpContext(local.env.ORIGIN, (url, init) => handle(new Request(url,init),local.env,local.clock.now));
    const fixtures=[];
    const result=await verify(x,{usernameA:'audit_unit_a',usernameB:'audit_unit_b',fixtures});
    assert.equal(result.checks.length,46); assert.ok(result.checks.every(c=>c.passed));
    assert.ok(fixtures.every(f=>f.actor.accountDeleted));
    assert.equal(local.raw.prepare('SELECT COUNT(*) n FROM users').get().n,0);
    for(const r of x.records){
      assert.ok(r.request.cookie===null||r.request.cookie==='[REDACTED]');
      assert.ok(r.response.setCookie===null||r.response.setCookie==='[REDACTED]');
      assert.ok(r.response.cookieAttributes.flat().every(a=>!/__Host-t08_session=/.test(a)));
    }
    await assert.rejects(x.browser().api('https://evil.example/api/private'),/다른 서버/);
    const encoded=JSON.stringify(x.records);
    assert.ok(!encoded.includes(fixtures[0].actor.jar.get('__Host-t08_session')||'NO_CURRENT_TOKEN'));
  } finally {local.close();}
});
