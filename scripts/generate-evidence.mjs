import { writeFile } from 'node:fs/promises';
import { runtime } from '../test-support/runtime.mjs';
import { verify } from '../test-support/verification.mjs';
const x = await runtime();
try {
  const result = await verify(x);
  const evidence = {
    kind: 't08-isolated-workerd-verification', generatedAt: new Date().toISOString(),
    environment: '로컬 격리 workerd + D1 SQLite. 배포할 동일 Worker 번들을 실행. 소프트웨어 인증기가 시험용 P-256 키로 실제 서명을 생성하고 SimpleWebAuthn이 검증함.',
    limitation: '갤럭시 실기기·운영 배포 시험이 아닙니다. 실제 기기 두 패스키 등록과 삭제 후 로그인은 별도 확인해야 합니다.',
    sensitiveData: '실제 계정·비밀번호·토큰·개인키·API 키 없음. Cookie와 Set-Cookie는 가림. 공개키와 서명은 폐기한 가상 시험 키의 공개 증거.',
    ...result, records: x.records,
  };
  await writeFile('public/verification.json', JSON.stringify(evidence, null, 2) + '\n');
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const html = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>과제 8 · 공개 자동 검증 기록</title><link rel="stylesheet" href="/passkey.css"></head><body><main class="passkey-wrap"><h1>과제 8 · 공개 자동 검증 기록</h1><p>${esc(evidence.environment)}</p><p class="notice">${esc(evidence.limitation)}</p><p>생성: ${esc(evidence.generatedAt)} · ${result.checks.length}개 확인 통과</p><p>${esc(evidence.sensitiveData)}</p><p><a href="/">공개 소개로</a> · <a href="/verification.json">원문 JSON</a> · <a href="https://github.com/ChoiMgHub/SKT-ALEPH-08/blob/task-08/docs/auth.md">구현 설명</a></p><h2>허용·거부 짝</h2>${result.pairs.map(p => `<article><h3>${esc(p.category)}</h3><p>허용 ${p.allowStatus}: ${esc(p.allow)}</p><p>거부 ${p.denyStatus}: ${esc(p.deny)}</p></article>`).join('')}<h2>서버 저장 공개키 · 격리 시험 계정</h2>${result.keys.map(k => `<article><h3>${esc(k.name)}</h3><p>${esc(k.registeredAt)} · ${esc(k.provider)}</p><pre>${esc(k.publicKey)}</pre></article>`).join('')}<h2>검사 결과</h2><ul>${result.checks.map(c => `<li>통과: ${esc(c.label)}</li>`).join('')}</ul><details><summary>요청·응답 원문 (쿠키 제외)</summary><pre>${esc(JSON.stringify(x.records, null, 2))}</pre></details></main></body></html>`;
  await writeFile('public/verification.html', html + '\n');
  console.log(`격리 workerd 검증 ${result.checks.length}개 통과. public/verification.json과 HTML 생성 완료.`);
} finally { await x.dispose(); }
