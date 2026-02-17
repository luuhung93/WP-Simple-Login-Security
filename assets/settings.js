(function () {
  'use strict';

  if (typeof SimpleLoginSecuritySettings === 'undefined') {
    return;
  }

  const openBtn = document.getElementById('simple-login-security-test-turnstile');
  const modal = document.getElementById('simple-login-security-turnstile-modal');
  const closeBtn = document.getElementById('simple-login-security-turnstile-close');
  const message = document.getElementById('simple-login-security-turnstile-message');
  const widgetRoot = document.getElementById('simple-login-security-turnstile-widget');
  const siteKeyInput = document.getElementById('simple-login-security-turnstile-site-key');
  const secretKeyInput = document.getElementById('simple-login-security-turnstile-secret-key');

  if (!openBtn || !modal || !closeBtn || !message || !widgetRoot || !siteKeyInput || !secretKeyInput) {
    return;
  }

  let widgetId = null;

  function setMessage(text, isError, isSuccess) {
    message.textContent = text || '';
    message.classList.toggle('is-error', !!isError);
    message.classList.toggle('is-success', !!isSuccess);
  }

  function openModal() {
    modal.hidden = false;
  }

  function closeModal() {
    modal.hidden = true;
    setMessage('', false, false);
    widgetRoot.innerHTML = '';
    widgetId = null;
  }

  async function postVerify(token, secretKey) {
    const body = new URLSearchParams();
    body.set('action', 'simple_login_security_test_turnstile');
    body.set('nonce', SimpleLoginSecuritySettings.nonce);
    body.set('token', token);
    body.set('secretKey', secretKey);

    const res = await fetch(SimpleLoginSecuritySettings.ajaxUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
      body: body.toString()
    });

    const data = await res.json();
    if (!data || !data.success) {
      throw new Error((data && data.data && data.data.message) || SimpleLoginSecuritySettings.i18n.error);
    }
  }

  async function waitForTurnstile() {
    if (window.turnstile && typeof window.turnstile.render === 'function') {
      return true;
    }

    for (let i = 0; i < 20; i++) {
      await new Promise(function (resolve) {
        window.setTimeout(resolve, 250);
      });

      if (window.turnstile && typeof window.turnstile.render === 'function') {
        return true;
      }
    }

    return false;
  }

  async function renderWidget() {
    const siteKey = (siteKeyInput.value || '').trim();
    const secretKey = (secretKeyInput.value || '').trim();

    if (!siteKey || !secretKey) {
      setMessage(SimpleLoginSecuritySettings.i18n.missingKeys, true, false);
      return;
    }

    openModal();
    widgetRoot.innerHTML = '';
    setMessage(SimpleLoginSecuritySettings.i18n.loading, false, false);

    const ready = await waitForTurnstile();
    if (!ready) {
      setMessage(SimpleLoginSecuritySettings.i18n.loadError, true, false);
      return;
    }

    widgetId = window.turnstile.render(widgetRoot, {
      sitekey: siteKey,
      callback: async function (token) {
        try {
          setMessage(SimpleLoginSecuritySettings.i18n.verifying, false, false);
          await postVerify(token, secretKey);
          setMessage(SimpleLoginSecuritySettings.i18n.success, false, true);
        } catch (err) {
          setMessage(err.message, true, false);
        }
      },
      'error-callback': function () {
        setMessage(SimpleLoginSecuritySettings.i18n.error, true, false);
      },
      'expired-callback': function () {
        setMessage(SimpleLoginSecuritySettings.i18n.expired, true, false);
      }
    });
  }

  openBtn.addEventListener('click', function () {
    renderWidget();
  });

  closeBtn.addEventListener('click', function () {
    closeModal();
  });

  modal.addEventListener('click', function (event) {
    if (event.target && event.target.getAttribute('data-close') === '1') {
      closeModal();
    }
  });
})();
