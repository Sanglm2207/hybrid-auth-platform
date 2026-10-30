const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');
const source = readFileSync(require('node:path').join(__dirname, '../../main/resources/account-pages/account-actions.js'), 'utf8');

function page(mode, proof = 'a'.repeat(43), response = { status: 200, success: true }) {
  const elements = new Map();
  const requests = [];
  let submit;
  let cleanUrl;
  const document = { getElementById(id) {
    if (!elements.has(id)) elements.set(id, {
      hidden: ['action-form', 'email-fields', 'password-fields', 'recovery'].includes(id),
      value: '', dataset: {}, focus() {}, reset() {},
      addEventListener(event, handler) { if (event === 'submit') submit = handler; }
    });
    return elements.get(id);
  }};
  vm.runInNewContext(source, {
    document, location: { pathname: `/api/v1/auth/${mode}`, hash: proof ? `#token=${proof}` : '' },
    history: { replaceState(_state, _title, url) { cleanUrl = url; } }, URLSearchParams, TextEncoder,
    fetch: async (url, options) => {
      requests.push({ url, options, body: JSON.parse(options.body) });
      if (response.error) throw Error('offline');
      return { ok: response.status === 200, json: async () => response };
    }
  });
  return {
    elements, requests, cleanUrl,
    el: id => document.getElementById(id),
    submit: () => submit({ preventDefault() {} })
  };
}

test('opening either email link never posts or consumes the proof; removes fragment from history', () => {
  for (const mode of ['reset-password', 'confirm-email-change']) {
    const p = page(mode);
    assert.equal(p.requests.length, 0);
    assert.equal(p.cleanUrl, `/api/v1/auth/${mode}`);
    assert.equal(p.el('action-form').hidden, false);
    assert.equal(p.el('password-fields').hidden, mode !== 'reset-password');
  }
});

test('missing/malformed link displays recovery instructions and no form', () => {
  for (const proof of ['', 'bad-proof']) {
    const p = page('reset-password', proof);
    assert.equal(p.el('action-form').hidden, true);
    assert.equal(p.el('recovery').hidden, false);
    assert.equal(p.requests.length, 0);
  }
});

test('forgot page sends email only and gives a generic account-independent response', async () => {
  const p = page('forgot-password', '');
  p.el('email').value = ' owner@example.com ';
  await p.submit();
  assert.deepEqual(p.requests[0].body, { email: 'owner@example.com' });
  assert.match(p.el('message').textContent, /If an account uses this email/);
});

test('reset validates confirmation and UTF-8 limits before sending, then submits proof automatically', async () => {
  const p = page('reset-password');
  p.el('password').value = 'NewPassword123!';
  p.el('confirm-password').value = 'different';
  await p.submit();
  assert.equal(p.requests.length, 0);
  assert.match(p.el('message').textContent, /do not match/);
  p.el('password').value = p.el('confirm-password').value = '😀'.repeat(20);
  await p.submit();
  assert.equal(p.requests.length, 0);
  p.el('password').value = p.el('confirm-password').value = 'NewPassword123!';
  await p.submit();
  assert.deepEqual(p.requests[0].body, { token: 'a'.repeat(43), newPassword: 'NewPassword123!' });
  assert.equal(p.requests[0].options.credentials, 'omit');
  assert.equal(p.el('action-form').hidden, true);
  assert.match(p.el('message').textContent, /password has been reset/);
  await p.submit();
  assert.equal(p.requests.length, 1);
});

test('email confirmation submits exactly once after explicit confirmation', async () => {
  const p = page('confirm-email-change');
  assert.equal(p.requests.length, 0);
  await p.submit();
  await p.submit();
  assert.deepEqual(p.requests[0].body, { token: 'a'.repeat(43) });
  assert.equal(p.requests.length, 1);
  assert.match(p.el('message').textContent, /email address has been updated/);
});

test('expired proof gives an actionable message; network failure permits a retry', async () => {
  const expired = page('reset-password', 'a'.repeat(43), { status: 400, success: false, code: 'INVALID_ACCOUNT_TOKEN' });
  expired.el('password').value = expired.el('confirm-password').value = 'NewPassword123!';
  await expired.submit();
  assert.equal(expired.el('action-form').hidden, true);
  assert.equal(expired.el('recovery').hidden, false);
  assert.match(expired.el('message').textContent, /expired or has already been used/);
  const offline = page('confirm-email-change', 'a'.repeat(43), { error: true });
  await offline.submit();
  assert.equal(offline.el('submit').disabled, false);
  assert.equal(offline.el('action-form').hidden, false);
  assert.match(offline.el('message').textContent, /check your connection/);
});
