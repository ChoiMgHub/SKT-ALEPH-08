export function httpContext(origin, fetcher = fetch) {
  const url = new URL(origin);
  if (url.protocol !== 'https:' || url.origin !== origin) throw new Error('정확한 HTTPS origin이 필요합니다.');
  const records = [];
  function browser() {
    const jar = new Map();
    const actor = { origin, jar, accountDeleted: false, async api(path, method = 'GET', value, { cookieOverride, origin: requestOrigin = origin, headers = {} } = {}) {
      const target = new URL(path, origin);
      if (target.origin !== origin) throw new Error('다른 서버에 인증 정보를 보내지 않습니다.');
      const h = new Headers(headers);
      h.set('Cookie', cookieOverride ?? [...jar].map(([k,v]) => k + '=' + v).join('; '));
      if (method !== 'GET') { h.set('Origin', requestOrigin); h.set('Content-Type', 'application/json'); }
      const response = await fetcher(target.href, { method, headers: h, body: value === undefined ? undefined : JSON.stringify(value), redirect: 'manual', signal: AbortSignal.timeout(25_000) });
      const cookies = response.headers.getSetCookie();
      for (const c of cookies) {
        const pair = c.split(';')[0], at = pair.indexOf('='), k = pair.slice(0, at), v = pair.slice(at + 1);
        if (!v || /Max-Age=0(?:;|$)/.test(c)) jar.delete(k); else jar.set(k,v);
      }
      const raw = await response.text(); let data;
      try { data = JSON.parse(raw); } catch { data = raw; }
      records.push({ at: new Date().toISOString(), request: { method, path, body: value ?? null, cookie: h.get('Cookie') ? '[REDACTED]' : null },
        response: { status: response.status, body: data, setCookie: cookies.length ? '[REDACTED]' : null,
          cookieAttributes: cookies.map(c => c.split(';').slice(1).map(s => s.trim())) } });
      if (path === '/api/account' && method === 'DELETE' && response.status === 200) actor.accountDeleted = true;
      return { status: response.status, data, headers: response.headers };
    } };
    return actor;
  }
  return { origin, browser, records };
}
