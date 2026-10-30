'use strict';
(() => {
  const base = '/api/v1/auth';
  const mode = location.pathname.split('/').pop();
  let token = new URLSearchParams(location.hash.slice(1)).get('token');
  // Keep the proof in memory only; remove it before the user navigates elsewhere.
  history.replaceState(null, '', location.pathname);
  const el = id => document.getElementById(id);
  const form = el('action-form');
  const button = el('submit');
  const reset = mode === 'reset-password';
  const forgot = mode === 'forgot-password';
  const message = (text, error = false) => {
    el('message').textContent = text;
    el('message').dataset.error = String(error);
    el('message').focus();
  };
  document.title = el('title').textContent = forgot ? 'Forgot your password?' : reset ? 'Choose a new password' : 'Confirm your new email';
  el('description').textContent = forgot
    ? 'Enter your account email. We will send you a link to reset your password.'
    : reset ? 'Enter your new password below to recover access to your account.'
    : 'Confirm that you want to use this email address for your account. You will need to sign in again after the change.';
  if (!forgot && !/^[A-Za-z0-9_-]{43}$/.test(token || '')) {
    el('description').textContent = 'This link is incomplete. Please open the latest link from your email.';
    message(reset ? 'You can also request a new reset link.' : 'To receive a new link, request the email change again in your account settings.', true);
    el('recovery').hidden = !reset;
    return;
  }
  el('email-fields').hidden = !forgot;
  el('email').required = forgot;
  el('password-fields').hidden = !reset;
  el('password').required = el('confirm-password').required = reset;
  const label = forgot ? 'Send reset link' : reset ? 'Reset password' : 'Confirm email address';
  button.textContent = label;
  form.hidden = false;
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (button.disabled) return;
    const password = el('password').value;
    if (reset) {
      if (Array.from(password).length < 12 || !password.trim()) {
        message('Use at least 12 characters for your new password.', true);
        return;
      }
      if (new TextEncoder().encode(password).length > 72) {
        message('This password is too long. Please choose a shorter password.', true);
        return;
      }
      if (password !== el('confirm-password').value) {
        message('Your passwords do not match. Please try again.', true);
        return;
      }
    }
    button.disabled = true;
    button.textContent = 'Please wait…';
    let completed = false;
    try {
      const body = forgot ? { email: el('email').value.trim() } : reset ? { token, newPassword: password } : { token };
      const response = await fetch(`${base}/${mode}`, {
        method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      });
      const data = await response.json();
      if (!response.ok || !data.success) {
        const errors = {
          INVALID_ACCOUNT_TOKEN: reset ? 'This reset link has expired or has already been used. Please request a new one.' : 'This confirmation link has expired or has already been used. Request the email change again in your account settings.',
          PASSWORD_UNCHANGED: 'Choose a password different from your current password.',
          EMAIL_EXISTS: 'This email address is already in use. Choose another address in your account settings.',
          VALIDATION_FAILED: forgot ? 'Please enter a valid email address.' : 'Please check that your new password meets the requirements.',
          RATE_LIMITED: 'Too many attempts. Please wait a moment before trying again.'
        };
        message(errors[data.code] || 'We could not complete your request. Please try again later.', true);
        if (data.code === 'INVALID_ACCOUNT_TOKEN') {
          token = null;
          form.hidden = true;
          el('recovery').hidden = !reset;
        }
        return;
      }
      completed = true;
      form.reset();
      form.hidden = true;
      token = null;
      message(forgot
        ? 'If an account uses this email, you will receive a reset link shortly. Check your inbox and spam folder. The link is valid for 15 minutes.'
        : reset ? 'Your password has been reset. You can now return to the app and sign in with your new password.'
        : 'Your email address has been updated. Return to the app and sign in with your new email address.');
    } catch {
      message('Unable to connect. Please check your connection and try again.', true);
    } finally {
      if (!completed) { button.disabled = false; button.textContent = label; }
    }
  });
})();
