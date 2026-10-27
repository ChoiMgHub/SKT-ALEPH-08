import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { JSDOM } from 'jsdom';
import { mount } from '../src/client.js';
import { context, SoftwareAuthenticator, signup } from '../test-support/helpers.mjs';
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
async function settled(doc) { for (let n = 0; n < 100; n++) { await tick(); if (![...doc.querySelectorAll('button')].some(b => b.disabled)) return; } throw new Error('UI did not settle'); }
async function app(x, browser, options = {}) {
  const dom = new JSDOM(await readFile(new URL('../index.html', import.meta.url), 'utf8'), { url: x.env.ORIGIN });
  dom.window.confirm = () => true;
  const fetcher = async (path, req) => {
    const r = await browser.api(path, req.method, req.body ? JSON.parse(req.body) : undefined);
    return { status: r.status, ok: r.status >= 200 && r.status < 300, json: async () => r.data };
  };
  const api = mount({ doc: dom.window.document, fetcher, supported: () => true, ...options });
  await api.ready; return { dom, doc: dom.window.document, api };
}
test('public-first UI has no password inputs and cancelled registration saves no account or key', async () => {
  const x = await context(); let ui;
  try {
    ui = await app(x, x.browser(), { register: async () => { throw Object.assign(new Error('cancel'), { name: 'NotAllowedError' }); } });
    const { doc, dom } = ui;
    assert.equal(doc.getElementById('private-panel').hidden, true);
    assert.equal(doc.querySelectorAll('input[type=password]').length, 0);
    const form = doc.getElementById('signup-form'); form.elements.username.value = 'fixture_a'; form.elements.name.value = '취소 시험'; form.elements.provider.value = '기타·확인 필요';
    form.dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true })); await settled(doc);
    assert.match(doc.getElementById('status').textContent, /서버에 패스키를 저장하지 않았/);
    assert.equal(x.raw.prepare('SELECT COUNT(*) n FROM users').get().n, 0);
    assert.equal(x.raw.prepare('SELECT COUNT(*) n FROM credentials').get().n, 0);
    assert.equal(x.raw.prepare('SELECT COUNT(*) n FROM challenges').get().n, 0);
  } finally { ui?.dom.window.close(); x.close(); }
});
test('UI signup/login, text-only memo rendering, public key list and logout clearing use the real API', async () => {
  const x = await context(); let ui;
  try {
    const browser = x.browser(), key = new SoftwareAuthenticator(); let report;
    ui = await app(x, browser, { register: async ({ optionsJSON }) => key.register(optionsJSON, x.env.ORIGIN),
      authenticate: async ({ optionsJSON }) => key.login(optionsJSON, x.env.ORIGIN), download: data => { report = data; } });
    const { doc, dom } = ui;
    const form = doc.getElementById('signup-form'); form.elements.username.value = 'fixture_a'; form.elements.name.value = '시험 기본'; form.elements.provider.value = '기타·확인 필요';
    form.dispatchEvent(new dom.window.Event('submit', { cancelable: true })); await settled(doc);
    assert.equal(doc.getElementById('private-panel').hidden, false); assert.equal(doc.querySelectorAll('#items article').length, 3);
    assert.match(doc.getElementById('credentials').textContent, /시험 기본/); assert.ok(doc.querySelector('#credentials pre').textContent.length > 50);
    const note = doc.getElementById('item-form'); note.elements.title.value = '<img src=x onerror=alert(1)>'; note.elements.body.value = '<script>alert(1)</script>';
    note.dispatchEvent(new dom.window.Event('submit', { cancelable: true })); await settled(doc);
    assert.equal(doc.querySelectorAll('#items img, #items script').length, 0); assert.match(doc.getElementById('items').textContent, /<script>/);
    doc.getElementById('download-evidence').click(); assert.ok(report.records.length > 0);
    assert.doesNotMatch(JSON.stringify(report), /__Host-t08_session|privateKey/);
    doc.getElementById('logout-btn').click(); await settled(doc);
    assert.equal(doc.getElementById('items').textContent, ''); assert.equal(doc.getElementById('credentials').textContent, '');
    doc.getElementById('download-evidence').click(); assert.equal(report.records.length, 0);
    doc.getElementById('login-btn').click(); await settled(doc);
    assert.equal(doc.querySelectorAll('#items article').length, 4);
  } finally { ui?.dom.window.close(); x.close(); }
});
test('backgrounding a shared PC tab clears private DOM; no pending response may restore it', async () => {
  const x = await context(); let ui;
  try {
    const browser = x.browser(); await signup(browser, 'fixture_a'); ui = await app(x, browser);
    assert.ok(ui.doc.getElementById('items').children.length > 0);
    Object.defineProperty(ui.doc, 'visibilityState', { configurable: true, value: 'hidden' });
    ui.doc.dispatchEvent(new ui.dom.window.Event('visibilitychange'));
    assert.equal(ui.doc.getElementById('items').children.length, 0); assert.equal(ui.doc.getElementById('private-panel').hidden, true);
  } finally { ui?.dom.window.close(); x.close(); }
});
test('expired recent authentication displays the reason next to the add-key button without calling the authenticator', async () => {
  const x = await context(); let ui;
  try {
    const browser = x.browser(); await signup(browser, 'fixture_a'); x.clock.now += 5 * 60_000;
    let called = false;
    ui = await app(x, browser, { register: async () => { called = true; throw new Error('must not open'); } });
    const form = ui.doc.getElementById('add-key-form'); form.elements.name.value = '예비 키'; form.elements.provider.value = '기타·확인 필요';
    form.dispatchEvent(new ui.dom.window.Event('submit', { cancelable: true })); await settled(ui.doc);
    assert.equal(called, false);
    const inline = ui.doc.getElementById('add-key-status');
    assert.ok(inline, 'the error must be visible beside the button, not only above all private notes');
    assert.match(inline.textContent, /다시 로그인.*5분/);
    assert.equal(ui.doc.getElementById('private-panel').hidden, false);
  } finally { ui?.dom.window.close(); x.close(); }
});
test('fresh add-key UI calls the authenticator and lists two distinct credentials', async () => {
  const x = await context(); let ui;
  try {
    const browser = x.browser(); await signup(browser, 'fixture_a'); const two = new SoftwareAuthenticator();
    ui = await app(x, browser, { register: async ({ optionsJSON }) => two.register(optionsJSON, x.env.ORIGIN) });
    const form = ui.doc.getElementById('add-key-form'); form.elements.name.value = '예비 키'; form.elements.provider.value = '기타·확인 필요';
    form.dispatchEvent(new ui.dom.window.Event('submit', { cancelable: true })); await settled(ui.doc);
    assert.equal(ui.doc.querySelectorAll('#credentials article').length, 2);
    assert.match(ui.doc.getElementById('add-key-status').textContent, /새 패스키를 추가했습니다/);
    assert.equal(ui.doc.getElementById('add-key-status').dataset.state, 'info');
  } finally { ui?.dom.window.close(); x.close(); }
});
test('device window rejection displays inline and restores private UI after visibility changes', async () => {
  const x = await context(); let ui;
  try {
    const browser = x.browser(); await signup(browser, 'fixture_a');
    ui = await app(x, browser, { register: async () => {
      Object.defineProperty(ui.doc, 'visibilityState', { configurable: true, value: 'hidden' });
      ui.doc.dispatchEvent(new ui.dom.window.Event('visibilitychange'));
      Object.defineProperty(ui.doc, 'visibilityState', { configurable: true, value: 'visible' });
      ui.doc.dispatchEvent(new ui.dom.window.Event('visibilitychange'));
      throw Object.assign(new Error('duplicate'), { name: 'InvalidStateError' });
    } });
    const form = ui.doc.getElementById('add-key-form'); form.elements.name.value = '예비 키'; form.elements.provider.value = '기타·확인 필요';
    form.dispatchEvent(new ui.dom.window.Event('submit', { cancelable: true })); await settled(ui.doc);
    assert.match(ui.doc.getElementById('add-key-status').textContent, /이미 등록된 패스키/);
    assert.equal(ui.doc.getElementById('add-key-status').dataset.state, 'error');
    assert.equal(ui.doc.getElementById('private-panel').hidden, false);
    assert.equal(ui.doc.querySelectorAll('#credentials article').length, 1);
  } finally { ui?.dom.window.close(); x.close(); }
});
