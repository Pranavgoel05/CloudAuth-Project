(() => {
  'use strict';
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const state = {
    accessToken: localStorage.getItem('cloudauth_access') || '',
    refreshToken: localStorage.getItem('cloudauth_refresh') || '',
    user: null,
    view: 'overview',
    mfaSetup: null,
    cloudStatus: null,
    resetToken: new URLSearchParams(window.location.hash.slice(1)).get('reset_token') || ''
  };
  if (state.resetToken) {
    // Reset tokens are carried in the URL fragment, which browsers don't send to the server.
    // Remove the fragment from the address bar immediately and keep it only in page memory.
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[char]);
  }

  let toastTimer;
  function toast(message, type = 'success') {
    const element = $('#toast');
    element.textContent = message;
    element.className = `toast show ${type}`;
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => { element.className = 'toast'; }, 4200);
  }

  async function api(path, options = {}, authorized = true) {
    const headers = new Headers(options.headers || {});
    if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    if (authorized && state.accessToken) headers.set('Authorization', `Bearer ${state.accessToken}`);
    let response;
    try {
      response = await fetch(path, { ...options, headers });
    } catch (_error) {
      throw new Error('Cannot reach the API. Check the network connection and try again.');
    }
    let body = {};
    const raw = await response.text();
    if (raw) {
      try { body = JSON.parse(raw); } catch { body = { detail: raw }; }
    }
    if (!response.ok) {
      const detail = Array.isArray(body.detail)
        ? body.detail.map((item) => item.msg || 'Invalid input').join('; ')
        : (body.detail || body.message || `Request failed (${response.status})`);
      const error = new Error(detail);
      error.status = response.status;
      error.body = body;
      throw error;
    }
    return body;
  }

  function saveTokens(tokens) {
    state.accessToken = tokens.access_token;
    state.refreshToken = tokens.refresh_token;
    localStorage.setItem('cloudauth_access', state.accessToken);
    localStorage.setItem('cloudauth_refresh', state.refreshToken);
    if (tokens.user) state.user = tokens.user;
  }

  function clearSession() {
    state.accessToken = '';
    state.refreshToken = '';
    state.user = null;
    state.mfaSetup = null;
    localStorage.removeItem('cloudauth_access');
    localStorage.removeItem('cloudauth_refresh');
    $('#app-view').classList.add('hidden');
    $('#auth-view').classList.remove('hidden');
    setAuthMode('login');
  }

  function setAuthMode(mode) {
    const titles = {
      login: ['Welcome back', 'Sign in to your security workspace.'],
      register: ['Create your account', 'Set up a secure account in a few steps.'],
      forgot: ['Forgot password?', 'We’ll help you recover access securely.'],
      reset: ['Choose a new password', 'Use a strong password you have not used before.']
    };
    ['login', 'register', 'forgot', 'reset'].forEach((name) => {
      const id = ({ login: 'login-form', register: 'register-form', forgot: 'forgot-password-form', reset: 'reset-password-form' })[name];
      $(`#${id}`).classList.toggle('hidden', mode !== name);
    });
    const showTabs = mode === 'login' || mode === 'register';
    $('#auth-tabs').classList.toggle('hidden', !showTabs);
    $('#forgot-password-action').classList.toggle('hidden', mode !== 'login');
    $('#show-login').classList.toggle('active', mode === 'login');
    $('#show-register').classList.toggle('active', mode === 'register');
    $('#auth-title').textContent = (titles[mode] || titles.login)[0];
    $('#auth-subtitle').textContent = (titles[mode] || titles.login)[1];
  }

  function roleLabel(role) {
    return ({ admin: 'Administrator', auditor: 'Auditor', user: 'Standard user' })[role] || role || 'User';
  }

  function setRoleVisibility() {
    const role = state.user?.role || 'user';
    $$('[data-roles]').forEach((element) => {
      const allowed = element.dataset.roles.split(',').includes(role);
      element.classList.toggle('hidden', !allowed);
    });
  }

  function showApp() {
    $('#auth-view').classList.add('hidden');
    $('#app-view').classList.remove('hidden');
    setRoleVisibility();
    renderUserChrome();
    showPage('overview');
  }

  function renderUserChrome() {
    const user = state.user || {};
    const email = user.email || 'Signed-in user';
    const initial = email.charAt(0).toUpperCase() || 'U';
    $('#sidebar-email').textContent = email;
    $('#sidebar-role').textContent = (user.role || 'user').toUpperCase();
    $('#sidebar-avatar').textContent = initial;
    $('#profile-avatar').textContent = initial;
    $('#welcome-name').textContent = email.split('@')[0] || 'there';
    $('#metric-role').textContent = roleLabel(user.role);
    $('#profile-email').textContent = email;
    $('#profile-id').textContent = user.id ?? '—';
    $('#profile-role').textContent = roleLabel(user.role);
    const mfaOn = Boolean(user.mfa_enabled);
    $('#metric-mfa').textContent = mfaOn ? 'Enabled' : 'Not enabled';
    $('#metric-mfa-foot').textContent = mfaOn ? 'Second factor is active' : 'Add an extra layer of protection';
    $('#profile-mfa').textContent = mfaOn ? 'Enabled' : 'Not enabled';
    $('#mfa-nav-badge').classList.toggle('hidden', mfaOn);
    if (mfaOn) $('#mfa-nav-badge').textContent = 'ON';
    else $('#mfa-nav-badge').textContent = 'SETUP';
  }

  async function loadProfile() {
    const profile = await api('/auth/me');
    state.user = profile;
    renderUserChrome();
    return profile;
  }

  async function handleLogin(payload) {
    const tokens = await api('/auth/login', { method: 'POST', body: JSON.stringify(payload) }, false);
    saveTokens(tokens);
    try {
      await loadProfile();
    } catch (error) {
      clearSession();
      throw error;
    }
    showApp();
    toast(`Signed in as ${roleLabel(state.user.role)}.`, 'success');
  }

  async function handleRegister(payload) {
    const result = await api('/auth/register', { method: 'POST', body: JSON.stringify(payload) }, false);
    setAuthMode('login');
    $('#login-email').value = payload.email;
    $('#login-form input[name="password"]').focus();
    toast(result.message || 'Account created. Sign in to continue.', 'success');
  }

  function showPage(view) {
    const role = state.user?.role || 'user';
    const access = {
      overview: true, mfa: true,
      audit: ['admin', 'auditor'].includes(role),
      users: role === 'admin',
      cloud: role === 'admin'
    };
    if (!access[view]) {
      toast('Your role does not have permission to access this section.', 'error');
      view = 'overview';
    }
    state.view = view;
    $$('.page-view').forEach((page) => page.classList.toggle('hidden', page.id !== `page-${view}`));
    $$('.nav-item[data-view]').forEach((button) => button.classList.toggle('active', button.dataset.view === view));
    const title = ({ overview: 'Overview', mfa: 'Multi-factor authentication', audit: 'Audit logs', users: 'User management', cloud: 'Cloud security' })[view];
    $('#page-title').textContent = title;
    $('#breadcrumb-title').textContent = title;
    if (view === 'overview') refreshOverview();
    if (view === 'mfa') renderMfaPage();
    if (view === 'audit') loadAudit();
    if (view === 'users') loadUsers();
    if (view === 'cloud') loadCloudStatus();
  }

  async function refreshOverview() {
    try {
      await loadProfile();
      const health = await api('/health', {}, false);
      $('#metric-cloud').textContent = health.cloud_simulation ? 'Simulated' : 'Local mode';
      $('#metric-cloud-foot').textContent = health.cloud_simulation ? 'Moto-backed AWS simulation' : 'Cloud simulation is off';
    } catch (error) {
      if (error.status === 401) clearSession();
      else console.error(error);
    }
  }

  function renderMfaPage() {
    const enabled = Boolean(state.user?.mfa_enabled);
    $('#mfa-status-title').textContent = enabled ? 'MFA is enabled' : 'Set up an authenticator';
    $('#mfa-status-pill').textContent = enabled ? 'Enabled' : 'Not enabled';
    $('#mfa-status-pill').className = `pill ${enabled ? 'pill-green' : 'pill-amber'}`;
    $('#mfa-status-description').textContent = enabled
      ? 'Your account requires a valid authenticator code in addition to your password at login.'
      : 'Start enrollment, add the secret to an authenticator app, then verify a current six-digit code.';
    $('#mfa-setup-btn').classList.toggle('hidden', enabled || Boolean(state.mfaSetup));
    $('#mfa-secret-area').classList.toggle('hidden', !state.mfaSetup || enabled);
    if (state.mfaSetup) {
      $('#mfa-secret').textContent = state.mfaSetup.secret;
      $('#mfa-uri').textContent = state.mfaSetup.provisioning_uri;
      const qrArea = $('#mfa-qr-area');
      if (state.mfaSetup.qr_code_data_uri) { $('#mfa-qr').src = state.mfaSetup.qr_code_data_uri; qrArea.classList.remove('hidden'); }
      else { $('#mfa-qr').removeAttribute('src'); qrArea.classList.add('hidden'); }
    }
  }

  async function startMfaSetup() {
    try {
      const result = await api('/auth/mfa/setup', { method: 'POST' });
      state.mfaSetup = result;
      renderMfaPage();
      toast('MFA setup started. Add the secret to your authenticator app.', 'success');
    } catch (error) { toast(error.message, 'error'); }
  }

  async function enableMfa(event) {
    event.preventDefault();
    const code = new FormData(event.currentTarget).get('code').trim();
    try {
      const result = await api('/auth/mfa/enable', { method: 'POST', body: JSON.stringify({ code }) });
      state.mfaSetup = null;
      await loadProfile();
      renderMfaPage();
      toast(result.message || 'MFA enabled.', 'success');
      event.currentTarget.reset();
    } catch (error) { toast(error.message, 'error'); }
  }

  async function loadAudit() {
    const target = $('#audit-table');
    target.innerHTML = '<div class="loading-state">Loading security events…</div>';
    try {
      const rows = await api('/audit/events?limit=50');
      if (!rows.length) {
        target.innerHTML = '<div class="empty-state">No audit events yet. Register or sign in to generate events.</div>';
        return;
      }
      target.innerHTML = `<table class="data-table"><thead><tr><th>TIME</th><th>EVENT</th><th>ACCOUNT</th><th>RESULT</th><th>IP ADDRESS</th></tr></thead><tbody>${rows.map((row) => `<tr><td>${escapeHtml(formatDate(row.at))}</td><td class="mono">${escapeHtml(row.event)}</td><td>${escapeHtml(row.email)}</td><td><span class="${row.success ? 'result-success' : 'result-fail'}">${row.success ? 'SUCCESS' : 'BLOCKED'}</span></td><td class="mono">${escapeHtml(row.ip)}</td></tr>`).join('')}</tbody></table>`;
    } catch (error) {
      target.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
      if (error.status === 401) clearSession();
    }
  }

  async function loadUsers() {
    const target = $('#users-table');
    target.innerHTML = '<div class="loading-state">Loading users…</div>';
    try {
      const users = await api('/admin/users');
      target.innerHTML = `<table class="data-table"><thead><tr><th>ID</th><th>EMAIL</th><th>ROLE</th><th>STATUS</th><th>MFA</th><th>CREATED</th></tr></thead><tbody>${users.map((user) => `<tr><td class="mono">#${escapeHtml(user.id)}</td><td class="table-email">${escapeHtml(user.email)}</td><td><span class="role-pill ${user.role === 'admin' ? 'role-admin' : user.role === 'auditor' ? 'role-auditor' : ''}">${escapeHtml(user.role.toUpperCase())}</span></td><td><span class="${user.is_active ? 'result-success' : 'result-fail'}">${user.is_active ? 'ACTIVE' : 'DISABLED'}</span></td><td>${user.mfa_enabled ? 'Enabled' : '—'}</td><td>${escapeHtml(formatDate(user.created_at))}</td></tr>`).join('')}</tbody></table>`;
    } catch (error) {
      target.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
      if (error.status === 401) clearSession();
    }
  }

  async function loadCloudStatus() {
    const target = $('#cloud-resource-list');
    target.innerHTML = '<div class="loading-state">Checking cloud resources…</div>';
    try {
      const data = await api('/admin/cloud-status');
      state.cloudStatus = data;
      const resources = [
        ['secrets_manager', 'Secrets Manager', 'JWT signing key retrieval', '♢'],
        ['kms', 'Key Management Service', 'Sensitive-value encryption', '⌑'],
        ['cloudwatch_logs', 'CloudWatch Logs', 'Audit event export', '≋'],
        ['s3_archive', 'S3 audit archive', 'JSON event archive', '▤'],
        ['iam_role', 'IAM demo role', 'Example least-privilege policy', '♙']
      ];
      const healthy = resources.filter(([key]) => data[key]).length;
      $('#cloud-mode').textContent = data.simulation_mode ? 'Moto simulation' : 'Local only';
      $('#cloud-count').textContent = `${healthy} / ${resources.length}`;
      $('#metric-cloud').textContent = data.simulation_mode ? 'Simulated' : 'Local mode';
      $('#metric-cloud-foot').textContent = data.simulation_mode ? 'Moto-backed AWS simulation' : 'Cloud simulation is off';
      target.innerHTML = resources.map(([key, name, description, icon]) => `<div class="resource-row"><span class="resource-icon">${icon}</span><div class="resource-info"><b>${name}</b><small>${description}</small></div><span class="resource-state ${data[key] ? 'ok' : ''}">${data[key] ? 'READY' : 'OFFLINE'}</span></div>`).join('');
    } catch (error) {
      target.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
      if (error.status === 401) clearSession();
    }
  }

  function formatDate(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  }

  async function refreshSession() {
    if (!state.refreshToken) { toast('No refresh token is available. Sign in again.', 'error'); return; }
    try {
      const tokens = await api('/auth/refresh', { method: 'POST', body: JSON.stringify({ refresh_token: state.refreshToken }) }, false);
      saveTokens(tokens);
      await loadProfile();
      toast('Session rotated successfully. Old refresh token revoked.', 'success');
    } catch (error) {
      toast(error.message, 'error');
    }
  }

  async function logout() {
    try {
      if (state.accessToken && state.refreshToken) {
        await api('/auth/logout', { method: 'POST', body: JSON.stringify({ refresh_token: state.refreshToken }) });
      }
    } catch (_error) {
      // Clear the browser session even if the server cannot be reached.
    }
    clearSession();
    toast('You have signed out.', 'success');
  }

  $('#show-login').addEventListener('click', () => setAuthMode('login'));
  $('#show-register').addEventListener('click', () => setAuthMode('register'));
  $('#forgot-password-link').addEventListener('click', () => {
    $('#forgot-email').value = $('#login-email').value.trim();
    $('#reset-dev-link').classList.add('hidden');
    setAuthMode('forgot');
  });
  $('#back-to-login-from-forgot').addEventListener('click', () => setAuthMode('login'));
  $('#back-to-login-from-reset').addEventListener('click', () => {
    state.resetToken = '';
    $('#reset-password-form').reset();
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
    setAuthMode('login');
  });
  $('#login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const payload = { email: form.get('email').trim(), password: form.get('password') };
    const totp = form.get('totp_code').trim();
    if (totp) payload.totp_code = totp;
    const button = event.currentTarget.querySelector('button[type="submit"]');
    button.disabled = true;
    try { await handleLogin(payload); }
    catch (error) { toast(error.message, 'error'); }
    finally { button.disabled = false; }
  });
  $('#register-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const payload = { email: form.get('email').trim(), password: form.get('password') };
    const button = event.currentTarget.querySelector('button[type="submit"]');
    button.disabled = true;
    try { await handleRegister(payload); event.currentTarget.reset(); }
    catch (error) { toast(error.message, 'error'); }
    finally { button.disabled = false; }
  });
  $('#forgot-password-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const button = event.currentTarget.querySelector('button[type="submit"]');
    const devLink = $('#reset-dev-link');
    devLink.classList.add('hidden');
    button.disabled = true;
    try {
      const result = await api('/auth/password/forgot', {
        method: 'POST', body: JSON.stringify({ email: form.get('email').trim() })
      }, false);
      toast(result.message || 'If an account matches that email, reset instructions will be sent.', 'success');
      // API exposes a reset URL only in local development; production sends email instead.
      if (result.reset_url) {
        const link = document.createElement('a');
        link.href = result.reset_url;
        link.textContent = 'Open local development reset link';
        link.rel = 'noreferrer';
        devLink.replaceChildren(document.createTextNode('Development only: '), link);
        devLink.classList.remove('hidden');
      }
    } catch (error) {
      toast(error.message, 'error');
    } finally { button.disabled = false; }
  });
  $('#reset-password-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    // Save the form element before awaiting: event.currentTarget becomes null
    // once this async event handler yields control back to the browser.
    const resetForm = event.currentTarget;
    const form = new FormData(resetForm);
    const newPassword = form.get('new_password');
    if (newPassword !== form.get('confirm_password')) {
      toast('The passwords do not match.', 'error');
      return;
    }
    const button = event.currentTarget.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const result = await api('/auth/password/reset', {
        method: 'POST',
        body: JSON.stringify({ token: form.get('token') || state.resetToken, new_password: newPassword })
      }, false);
      state.resetToken = '';
      resetForm.reset();
      window.history.replaceState(null, '', window.location.pathname + window.location.search);

      // Clear credentials from this browser immediately after a successful reset.
      state.accessToken = '';
      state.refreshToken = '';
      state.user = null;
      state.mfaSetup = null;
      localStorage.removeItem('cloudauth_access');
      localStorage.removeItem('cloudauth_refresh');

      // Show success on the reset screen first, then return to the main login form.
      toast('Password changed successfully. Redirecting to sign in...', 'success');
      window.setTimeout(() => {
        clearSession();
        $('#login-email').focus();
      }, 2500);
    } catch (error) {
      toast(error.message, 'error');
    } finally { button.disabled = false; }
  });
  $$('.nav-item[data-view]').forEach((button) => button.addEventListener('click', () => showPage(button.dataset.view)));
  $$('[data-go]').forEach((button) => button.addEventListener('click', () => showPage(button.dataset.go)));
  $('#logout-btn').addEventListener('click', logout);
  $('#refresh-profile').addEventListener('click', async () => {
    try { await loadProfile(); toast('Profile refreshed.', 'success'); }
    catch (error) { toast(error.message, 'error'); }
  });
  $('#mfa-setup-btn').addEventListener('click', startMfaSetup);
  $('#mfa-enable-form').addEventListener('submit', enableMfa);
  $('#copy-mfa-secret').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText($('#mfa-secret').textContent); toast('Authenticator secret copied. Keep it private.', 'success'); }
    catch (_error) { toast('Clipboard is unavailable. Select and copy the secret manually.', 'error'); }
  });
  $('#reload-audit').addEventListener('click', loadAudit);
  $('#reload-users').addEventListener('click', loadUsers);
  $('#reload-cloud').addEventListener('click', loadCloudStatus);

  // Expose the session rotation action without cluttering the overview.
  const rotateButton = document.createElement('button');
  rotateButton.className = 'btn btn-secondary';
  rotateButton.textContent = 'Rotate session token ↻';
  rotateButton.type = 'button';
  rotateButton.addEventListener('click', refreshSession);
  $('#refresh-profile').insertAdjacentElement('afterend', rotateButton);
  rotateButton.style.marginTop = '8px';
  rotateButton.style.width = '100%';

  async function boot() {
    if (state.resetToken) {
      $('#reset-password-token').value = state.resetToken;
      setAuthMode('reset');
      return;
    }
    try {
      const health = await api('/health', {}, false);
      const badge = $('.env-chip');
      if (badge) badge.title = health.cloud_simulation ? 'Moto-backed AWS simulation active' : 'Cloud simulation disabled; local fallback mode';
    } catch (_error) { /* The login screen explains how to start the server. */ }
    if (state.accessToken) {
      try {
        await loadProfile();
        showApp();
      } catch (_error) {
        clearSession();
      }
    }
  }
  boot();
})();
