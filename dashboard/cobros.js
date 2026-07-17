(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const controllers = new Set();
  let csrfToken = null;
  let expiryTimer = null;
  let authenticated = false;

  function abortRequests() {
    for (const controller of controllers) controller.abort();
    controllers.clear();
  }

  function clearExpiryTimer() {
    if (expiryTimer) clearTimeout(expiryTimer);
    expiryTimer = null;
  }

  function clearPrivateDom() {
    abortRequests();
    clearExpiryTimer();
    csrfToken = null;
    authenticated = false;
    $('private-view').replaceChildren();
    $('private-root').hidden = true;
    $('gate').hidden = false;
    $('pin').value = '';
    history.replaceState(null, '', location.pathname);
  }

  function setError(message = '') {
    $('auth-error').textContent = message;
  }

  async function request(url, options = {}) {
    const controller = new AbortController();
    controllers.add(controller);
    try {
      const response = await fetch(url, {
        ...options,
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
          Accept: 'application/json',
          ...(options.headers || {}),
        },
        signal: controller.signal,
      });
      let payload = null;
      try {
        payload = await response.json();
      } catch (_) {
        payload = null;
      }
      if (!response.ok) {
        const error = new Error('private_request_denied');
        error.status = response.status;
        throw error;
      }
      return payload;
    } finally {
      controllers.delete(controller);
    }
  }

  function appendText(parent, tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = typeof value === 'string' ? value : '';
    parent.appendChild(node);
    return node;
  }

  function renderPrivatePayload(payload) {
    const root = $('private-view');
    root.replaceChildren();

    const title = payload && payload.view && typeof payload.view.title === 'string'
      ? payload.view.title
      : 'Área privada';
    const emptyMessage = payload && payload.view && typeof payload.view.empty_message === 'string'
      ? payload.view.empty_message
      : 'No hay datos privados disponibles.';

    appendText(root, 'h1', 'private-view-title', title);
    const sections = Array.isArray(payload && payload.sections) ? payload.sections : [];
    if (sections.length === 0) {
      appendText(root, 'p', 'private-empty', emptyMessage);
      return;
    }

    for (const section of sections) {
      if (!section || typeof section !== 'object') continue;
      const wrapper = document.createElement('section');
      wrapper.className = 'private-section';
      appendText(wrapper, 'h2', '', typeof section.label === 'string' ? section.label : 'Sección');
      const items = Array.isArray(section.items) ? section.items : [];
      if (items.length === 0) {
        appendText(wrapper, 'p', 'private-empty', emptyMessage);
      } else {
        const list = document.createElement('ul');
        list.className = 'private-list';
        for (const item of items) {
          const text = typeof item === 'string'
            ? item
            : item && typeof item.label === 'string'
              ? item.label
              : '';
          if (!text) continue;
          appendText(list, 'li', '', text);
        }
        wrapper.appendChild(list);
      }
      root.appendChild(wrapper);
    }
  }

  function scheduleExpiry(expiresAt) {
    clearExpiryTimer();
    const expiresMs = Date.parse(expiresAt);
    if (!Number.isFinite(expiresMs)) return;
    const delay = Math.max(0, Math.min(expiresMs - Date.now(), 2_147_483_647));
    expiryTimer = setTimeout(() => {
      clearPrivateDom();
      setError('La sesión finalizó. Volvé a autorizar el acceso.');
    }, delay);
  }

  async function loadPrivateSession() {
    const session = await request('/api/private/billing/session');
    if (!session || session.authenticated !== true || typeof session.csrf_token !== 'string') {
      throw new Error('invalid_private_session');
    }
    csrfToken = session.csrf_token;
    authenticated = true;
    scheduleExpiry(session.expires_at);
    const payload = await request('/api/private/billing/data');
    renderPrivatePayload(payload);
    $('gate').hidden = true;
    $('private-root').hidden = false;
    $('session-state').textContent = 'Sesión privada activa';
  }

  async function restoreSession() {
    try {
      await loadPrivateSession();
    } catch (_) {
      clearPrivateDom();
    }
  }

  $('access-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    setError('');
    const pin = $('pin').value;
    if (!pin || pin.length > 128) {
      setError('No fue posible autorizar el acceso.');
      return;
    }

    try {
      const result = await request('/api/private/billing/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin }),
      });
      $('pin').value = '';
      if (!result || result.authenticated !== true) throw new Error('auth_failed');
      await loadPrivateSession();
    } catch (_) {
      clearPrivateDom();
      setError('No fue posible autorizar el acceso.');
    }
  });

  $('logout').addEventListener('click', async () => {
    try {
      if (authenticated && csrfToken) {
        await request('/api/private/billing/logout', {
          method: 'POST',
          headers: { 'X-CSRF-Token': csrfToken },
        });
      }
    } catch (_) {
      // Local state is cleared even when the network is unavailable.
    } finally {
      clearPrivateDom();
    }
  });

  addEventListener('pagehide', () => {
    abortRequests();
    $('private-view').replaceChildren();
    $('private-root').hidden = true;
  });

  addEventListener('pageshow', (event) => {
    if (event.persisted) restoreSession();
  });

  restoreSession();
})();
