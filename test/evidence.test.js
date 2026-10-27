import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
test('public evidence distinguishes isolated signatures from physical-device use and redacts sessions', async () => {
  const report = JSON.parse(await readFile(new URL('../public/verification.json', import.meta.url), 'utf8'));
  assert.equal(report.kind, 't08-isolated-workerd-verification');
  assert.match(report.limitation, /실제 기기 두 패스키/);
  assert.ok(report.checks.length >= 40); assert.ok(report.checks.every(c => c.passed));
  for (const phrase of ['로그인 없이', '남의 패스키', '이미 쓴 질문', '패스키 삭제']) assert.ok(report.pairs.some(p => p.category.includes(phrase)));
  for (const p of report.pairs) { assert.equal(p.allowStatus, 200); assert.ok([401, 403].includes(p.denyStatus)); }
  for (const record of report.records) {
    assert.ok(record.request.cookie === null || record.request.cookie === '[REDACTED]');
    assert.ok(record.response.setCookie === null || record.response.setCookie === '[REDACTED]');
  }
  assert.ok(report.keys.length === 2 && report.keys.every(k => k.publicKey));
  const encoded = JSON.stringify(report); assert.doesNotMatch(encoded, /PRIVATE KEY|"privateKey"|"token_hash"|"password"/);
});
