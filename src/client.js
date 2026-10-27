import { startRegistration, startAuthentication, browserSupportsWebAuthn } from '@simplewebauthn/browser';

export function mount({ doc = document, fetcher = fetch, register = startRegistration, authenticate = startAuthentication,
  supported = browserSupportsWebAuthn, download } = {}) {
  const $ = id => doc.getElementById(id);
  let currentUser = null, evidence = [], busy = false, generation = 0, timer;
  const status = message => { $('status').textContent = message; };
  const journal = (path, method, request, response, code) => {
    evidence.push({ at: new Date().toISOString(), request: { path, method, body: request ?? null }, response: { status: code, body: response } });
    if (evidence.length > 150) evidence.shift();
  };
  function clearPrivate(clearJournal = true) {
    generation++; currentUser = null; doc.defaultView.clearTimeout(timer);
    $('items').replaceChildren(); $('credentials').replaceChildren(); $('account-label').textContent = '';
    $('private-panel').hidden = true; $('anonymous-panel').hidden = false;
    $('item-form').reset(); $('add-key-form').reset();
    if (clearJournal) evidence = [];
  }
  async function api(path, method = 'GET', value, record = true) {
    const response = await fetcher(path, { method, credentials: 'same-origin', cache: 'no-store',
      headers: method === 'GET' ? {} : { 'Content-Type': 'application/json' }, body: value === undefined ? undefined : JSON.stringify(value) });
    const result = await response.json();
    if (record) journal(path, method, value, result, response.status);
    if (!response.ok) {
      if (response.status === 401 && !path.includes('/registration/verify') && !path.includes('/login/verify')) clearPrivate();
      throw new Error(result.error || '요청을 처리하지 못했습니다.');
    }
    return result;
  }
  function element(tag, content, parent) {
    const node = doc.createElement(tag); if (content !== undefined) node.textContent = content; if (parent) parent.append(node); return node;
  }
  function action(label, callback, parent) {
    const button = element('button', label, parent); button.type = 'button';
    button.addEventListener('click', () => perform(callback)); return button;
  }
  async function perform(task) {
    if (busy) return; busy = true;
    doc.querySelectorAll('.passkey-wrap button').forEach(b => { b.disabled = true; });
    try { await task(); } catch (e) { status(e.message || '작업에 실패했습니다.'); }
    finally { busy = false; doc.querySelectorAll('.passkey-wrap button').forEach(b => { b.disabled = false; }); }
  }
  function showItems(items) {
    $('items').replaceChildren();
    for (const item of items) {
      const card = element('article', undefined, $('items'));
      element('h4', item.title, card); element('p', item.body, card);
      element('small', `원문 번호: ${item.id}`, card);
      const row = element('div', undefined, card); row.className = 'row';
      action('이 메모 삭제', async () => {
        if (!doc.defaultView.confirm('이 가상 메모를 삭제할까요?')) return;
        await api('/api/private/' + encodeURIComponent(item.id), 'DELETE'); await refresh(); status('본인 메모를 삭제했습니다.');
      }, row);
    }
  }
  function showCredentials(credentials) {
    $('credentials').replaceChildren();
    for (const key of credentials) {
      const card = element('article', undefined, $('credentials'));
      element('h4', key.name, card);
      element('p', `등록: ${new Date(key.registeredAt).toLocaleString('ko-KR')} · 저장소(직접 선택): ${key.provider}`, card);
      const details = element('details', undefined, card); element('summary', '서버에 저장된 공개키 보기', details);
      element('pre', key.publicKey, details); element('p', 'base64url 형식의 COSE 공개키입니다. 개인키·비밀번호가 아닙니다.', details);
      action('이 패스키 삭제', async () => {
        if (!doc.defaultView.confirm('이 키로 더 이상 로그인할 수 없게 됩니다. 삭제할까요?')) return;
        const result = await api('/api/credentials/' + encodeURIComponent(key.id), 'DELETE');
        if (result.loggedOut) { clearPrivate(); status('현재 키를 삭제하여 로그아웃했습니다. 남은 패스키로 로그인하세요.'); }
        else { await refresh(); status('패스키를 삭제했습니다. 남은 패스키로 다시 로그인해 확인하세요.'); }
      }, card);
    }
  }
  async function refresh() {
    const snapshot = generation;
    const me = await api('/api/auth/me', 'GET', undefined, false);
    if (snapshot !== generation) return;
    if (currentUser && currentUser !== me.user.id) clearPrivate();
    currentUser = me.user.id;
    const ticket = generation;
    const [data, keys] = await Promise.all([api('/api/private'), api('/api/credentials')]);
    if (ticket !== generation) return;
    $('account-label').textContent = `비공개 공간 · ${me.user.username}`;
    showItems(data.items); showCredentials(keys.credentials);
    $('anonymous-panel').hidden = true; $('private-panel').hidden = false;
    doc.defaultView.clearTimeout(timer);
    timer = doc.defaultView.setTimeout(() => { clearPrivate(); status('로그인 시간이 지났습니다. 패스키로 다시 로그인하세요.'); }, Math.max(0, Date.parse(me.expiresAt) - Date.now()));
  }
  async function registration(form, mode) {
    if (!supported()) throw new Error('이 브라우저에서 패스키를 지원하지 않습니다. 갤럭시 Chrome의 HTTPS 주소로 접속하세요.');
    const values = Object.fromEntries(new doc.defaultView.FormData(form));
    status('기기의 패스키 등록 창에서 저장할 곳을 선택하세요.');
    const pending = await api('/api/auth/registration/options', 'POST', { mode, ...values });
    let response;
    try { response = await register({ optionsJSON: pending.options }); }
    catch (e) {
      await api('/api/auth/cancel', 'POST', { ceremonyId: pending.ceremonyId }).catch(() => {});
      if (e.name === 'InvalidStateError') throw new Error('이 저장소에 이미 등록된 패스키가 있습니다. 다른 지원 저장소·개인 기기를 선택하세요.');
      if (e.name === 'NotAllowedError' || e.name === 'AbortError') throw new Error('패스키 등록이 완료되지 않았습니다. 취소·시간 초과·기기 제한일 수 있으며 서버에 패스키를 저장하지 않았습니다.');
      throw new Error('패스키를 등록하지 못했습니다. HTTPS 주소와 기기 지원 여부를 확인하세요.');
    }
    if (mode === 'signup') { clearPrivate(); journal('/api/auth/registration/options', 'POST', { mode, ...values }, pending, 200); }
    await api('/api/auth/registration/verify', 'POST', { mode, ceremonyId: pending.ceremonyId, response });
    form.reset(); await refresh(); status(mode === 'signup' ? '패스키 등록과 로그인을 완료했습니다. 아래 가상 메모를 확인하세요.' : '현재 계정에 새 패스키를 추가했습니다.');
  }
  $('signup-form').addEventListener('submit', e => { e.preventDefault(); perform(() => registration(e.currentTarget, 'signup')); });
  $('add-key-form').addEventListener('submit', e => { e.preventDefault(); perform(() => registration(e.currentTarget, 'add')); });
  $('login-btn').addEventListener('click', () => perform(async () => {
    if (!supported()) throw new Error('패스키를 지원하는 브라우저에서 HTTPS 주소로 접속하세요.');
    clearPrivate(); status('기기에서 로그인할 패스키를 선택하세요.');
    const pending = await api('/api/auth/login/options', 'POST', {});
    let response;
    try { response = await authenticate({ optionsJSON: pending.options }); }
    catch { await api('/api/auth/cancel', 'POST', { ceremonyId: pending.ceremonyId }).catch(() => {}); throw new Error('로그인을 완료하지 않았습니다. 기기의 선택 창을 확인하고 다시 시도하세요.'); }
    await api('/api/auth/login/verify', 'POST', { ceremonyId: pending.ceremonyId, response });
    await refresh(); status('패스키로 로그인했습니다.');
  }));
  $('logout-btn').addEventListener('click', () => perform(async () => {
    // 요청 실패여도 먼저 표시와 메모리를 비운다. 성공을 가장하지는 않는다.
    clearPrivate();
    try { await api('/api/auth/logout', 'POST', {}, false); status('로그아웃했습니다. 비공개 화면과 확인 기록을 지웠습니다.'); }
    catch { status('화면은 비웠지만 서버 로그아웃 확인에 실패했습니다. 연결을 복구한 뒤 새로고침해 상태를 확인하고 다시 로그아웃하세요.'); }
  }));
  $('item-form').addEventListener('submit', e => {
    e.preventDefault(); const form = e.currentTarget;
    perform(async () => { await api('/api/private', 'POST', Object.fromEntries(new doc.defaultView.FormData(form))); form.reset(); await refresh(); status('본인 메모를 저장했습니다.'); });
  });
  $('download-evidence').addEventListener('click', () => {
    const report = { kind: 't08-browser-api-evidence', generatedAt: new Date().toISOString(),
      note: '이 브라우저의 실제 API 기록. 쿠키·세션 토큰·개인키·지문 원본은 수집하지 않음. 계정 별칭·입력 내용은 공개 전 확인하세요.', records: evidence };
    if (download) { download(report); return; }
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
    const link = element('a'); link.href = url; link.download = 't08-browser-evidence.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  doc.defaultView.addEventListener('pageshow', e => { if (e.persisted) { clearPrivate(); refresh().catch(() => status('패스키로 로그인하세요.')); } });
  doc.addEventListener('visibilitychange', () => {
    if (doc.visibilityState === 'hidden') {
      // 공유 PC의 탭 미리보기와 재표시에서도 오래된 비공개 DOM을 남기지 않는다.
      clearPrivate();
    } else if (!busy) refresh().then(() => status('로그인 상태를 확인했습니다.')).catch(() => status('패스키로 로그인하세요.'));
  });
  const copyBtn = $('copy-btn');
  copyBtn.addEventListener('click', async () => {
    try { await doc.defaultView.navigator.clipboard.writeText($('email-val').textContent); $('btn-msg').textContent = '복사 완료!'; }
    catch { $('btn-msg').textContent = '복사 실패'; }
  });
  const ready = refresh().then(() => status('패스키로 로그인된 상태입니다.')).catch(() => { clearPrivate(); status('공개 소개는 누구나 볼 수 있습니다. 비공개 메모는 패스키로 로그인하세요.'); });
  return { ready, refresh, clearPrivate };
}
if (typeof document !== 'undefined') mount();
