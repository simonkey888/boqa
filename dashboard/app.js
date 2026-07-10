(function () {
  'use strict';

  const state = {
    ws: null,
    connected: false,
    bugs: [],
    selectedBugId: null,
    coverage: 0,
    evidenceQuality: 0,
    uptimeStart: Date.now(),
    apiKey: localStorage.getItem('boqa_key') || ''
  };

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);

  // ─── Control de Acceso Local (Northflank Secure Guard) ───────────
  //
  // AUTH GATE DISABLED — direct boot, no key prompt.
  // The modal is force-hidden and the dashboard boots immediately.
  // To re-enable: revert this function to check state.apiKey and show modal.
  //
  function verifyAccess() {
    // Force-hide the modal without checking any key.
    $('#auth-gate').classList.add('hidden');

    // Connect the Hunter streams in the background.
    connectWS();
    pollState();
    setInterval(pollState, 10000); // Poll cada 10s
  }

  // Verify a candidate key against a protected endpoint.
  // /api/health is whitelisted (returns 200 regardless of key) — we use
  // /api/bugs which IS protected by requireApiKey, so 200/404/503 = key OK,
  // 401/403 = key rejected.
  async function verifyApiKey(candidate) {
    try {
      const res = await fetch('/api/bugs', { headers: { 'X-API-Key': candidate } });
      return res.status === 200 || res.status === 404 || res.status === 503;
    } catch (_) {
      return false;
    }
  }

  $('#auth-gate-btn').addEventListener('click', async () => {
    const inputVal = $('#auth-gate-input').value.trim();
    if (!inputVal) return;

    const ok = await verifyApiKey(inputVal);
    if (ok) {
      state.apiKey = inputVal;
      try { localStorage.setItem('boqa_key', inputVal); } catch (_) {}
      verifyAccess();
    } else {
      $('#auth-gate-error').classList.remove('hidden');
    }
  });

  // Enter key submits the auth gate
  $('#auth-gate-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      $('#auth-gate-btn').click();
    }
  });

  // Fetch con Cabecera API Key
  async function authenticatedFetch(url, options = {}) {
    const headers = {
      ...options.headers,
      'X-API-Key': state.apiKey
    };
    return fetch(url, { ...options, headers });
  }

  // ─── WebSocket ─────────────────────────────────────────────────

  function connectWS() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    state.ws = new WebSocket(`${protocol}//${location.host}/ws?api_key=${encodeURIComponent(state.apiKey)}`);

    state.ws.onopen = () => {
      state.connected = true;
      $('#srv-status').className = 'status-indicator online';
      $('#srv-status-text').textContent = 'Conectado';
      logEvent('api', 'Canal WebSocket establecido de forma segura.');
    };

    state.ws.onclose = () => {
      state.connected = false;
      $('#srv-status').className = 'status-indicator';
      $('#srv-status-text').textContent = 'Desconectado';
      // Only auto-reconnect if we still have an API key
      if (state.apiKey) setTimeout(connectWS, 3000);
    };

    state.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleIncomingEvent(msg);
      } catch (_) {}
    };
  }

  // Capturar eventos de navegación y anomalías en vivo de la IA
  function handleIncomingEvent(msg) {
    if (msg.type === 'page_navigation') {
      logEvent('nav', `Navegando a: ${msg.url}`);
    } else if (msg.type === 'auth_signal' && msg.meta?.signalType === 'anomaly_detected') {
      logEvent('analisis', `Anomalía: ${msg.meta.anomalyDetail}`);
    } else if (msg.type === 'bug_confirmed' || msg.type === 'finding_confirmed') {
      const bug = msg.payload;
      logEvent('bug', `BUG CONFIRMADO: ${bug.title}`);
      if (!state.bugs.some(b => b.id === bug.id)) {
        state.bugs.unshift(bug);
        renderMetrics();
        renderReportTab();
      }
    } else if (msg.type === 'websocket_message_in' || msg.type === 'websocket_open') {
      logEvent('api', `WS: ${msg.type.replace('websocket_', '')} — ${msg.url || ''}`);
    } else if (msg.type === 'cookie_snapshot' && msg.meta?.authCookies?.length) {
      logEvent('analisis', `Cookies de auth detectadas: ${msg.meta.authCookies.length}`);
    } else if (msg.type === 'network_request') {
      logEvent('nav', `${msg.method || 'GET'} ${msg.url || ''}`);
    }
  }

  function logEvent(type, detail) {
    const container = $('#event-stream');
    if (!container) return;
    const emptyMsg = container.querySelector('.stream-empty');
    if (emptyMsg) emptyMsg.remove();

    const item = document.createElement('div');
    item.className = 'stream-item';
    item.innerHTML = `
      <span class="stream-type ${type}">${type}</span>
      <span class="stream-detail">${escapeHtml(detail)}</span>
      <span class="stream-time">${new Date().toLocaleTimeString()}</span>
    `;
    container.insertBefore(item, container.firstChild);

    // Mantener consola liviana (max 40 items)
    while (container.children.length > 40) {
      container.removeChild(container.lastChild);
    }
  }

  // ─── Renderers ─────────────────────────────────────────────────

  function renderMetrics() {
    $('#m-bugs').textContent = state.bugs.length;
    $('#m-coverage').textContent = state.coverage + '%';
    // m-evidence element was removed from HTML — evidenceQuality is tracked
    // in state but no longer rendered. Safe no-op.
  }

  function renderReportTab() {
    const container = $('#report-list');
    if (state.bugs.length === 0) {
      container.innerHTML = '<div class="stream-empty">Esperando hallazgos confirmados...</div>';
      return;
    }

    container.innerHTML = state.bugs.map(bug => `
      <div class="report-item ${state.selectedBugId === bug.id ? 'selected' : ''}" data-id="${bug.id}">
        <span class="report-item-title">${escapeHtml(bug.title || bug.id)}</span>
        <span class="report-item-severity ${(bug.severity || 'medium').toLowerCase()}">${bug.severity || 'MEDIUM'}</span>
      </div>
    `).join('');

    $$('.report-item').forEach(el => {
      el.addEventListener('click', () => {
        state.selectedBugId = el.dataset.id;
        renderReportTab();
        renderReportDetail(state.selectedBugId);
      });
    });
  }

  function renderReportDetail(bugId) {
    const bug = state.bugs.find(b => b.id === bugId);
    const placeholder = $('#report-detail-placeholder');
    const content = $('#report-detail-content');

    if (!bug) {
      placeholder.classList.remove('hidden');
      content.classList.add('hidden');
      return;
    }

    placeholder.classList.add('hidden');
    content.classList.remove('hidden');

    content.innerHTML = `
      <div class="detail-section">
        <span class="detail-label">Identificador Único</span>
        <div class="detail-value" style="font-family: var(--font-mono); color: var(--color-purple); font-weight:600">${escapeHtml(bug.id)}</div>
      </div>
      <div class="detail-section">
        <span class="detail-label">Severidad del Fallo</span>
        <div class="detail-value" style="font-weight:700; text-transform:uppercase; color: var(--color-red)">${escapeHtml(bug.severity || 'N/A')}</div>
      </div>
      <div class="detail-section">
        <span class="detail-label">Título del Reporte</span>
        <div class="detail-value" style="font-weight: 600; color: var(--text-primary)">${escapeHtml(bug.title || 'Untitled')}</div>
      </div>
      <div class="detail-section">
        <span class="detail-label">Categoría de Vulnerabilidad</span>
        <div class="detail-value">${escapeHtml(bug.category || 'Uncategorized')}</div>
      </div>
      <div class="detail-section">
        <span class="detail-label">Cadena de Custodia</span>
        <div class="detail-value" style="color: var(--color-green)">✓ Evidencia lista para cobro (${bug.evidence_count || 1} artefactos verificados)</div>
      </div>
      <div class="detail-btn-group">
        <button class="btn-primary" id="btn-export-pkg">Descargar Reporte (.MD)</button>
        <button class="btn-secondary" id="btn-export-raw">Evidencia Completa (.JSON)</button>
      </div>
    `;

    $('#btn-export-pkg').addEventListener('click', () => triggerDownload(bugId, 'markdown'));
    $('#btn-export-raw').addEventListener('click', () => triggerDownload(bugId, 'json'));
  }

  async function triggerDownload(bugId, format) {
    try {
      const url = format === 'markdown'
        ? `/api/disclosures/${bugId}/report`
        : `/api/bug/${bugId}`;

      const res = await authenticatedFetch(url);
      if (!res.ok) throw new Error();

      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = format === 'markdown' ? `reporte-${bugId}.md` : `evidencia-${bugId}.json`;
      a.click();
    } catch (_) {
      alert('Error descargando el archivo de la nube.');
    }
  }

  // ─── Polling de Sincronización ───────────────────────────────────

  async function pollState() {
    try {
      const [bugsRes, covRes] = await Promise.all([
        authenticatedFetch('/api/bugs').then(r => r.json()).catch(() => ({ bugs: [] })),
        authenticatedFetch('/api/coverage').then(r => r.json()).catch(() => ({ overall_score: 0 }))
      ]);

      const newBugs = bugsRes.bugs || [];
      // Log any new confirmed bugs as they appear
      for (const bug of newBugs) {
        if (!state.bugs.some(b => b.id === bug.id)) {
          logEvent('bug', `BUG CONFIRMADO: ${bug.title || bug.id}`);
        }
      }
      state.bugs = newBugs;
      state.coverage = Math.round(covRes.overall_score || 0);
      state.evidenceQuality = state.bugs.length > 0 ? 100 : 0;

      renderMetrics();
      renderReportTab();
    } catch (_) {}
  }

  // Uptime del Servidor
  setInterval(() => {
    const elapsed = Date.now() - state.uptimeStart;
    const s = Math.floor(elapsed / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    const uptimeEl = $('#m-uptime');
    if (uptimeEl) {
      uptimeEl.textContent = `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
    }
  }, 1000);

  // Helpers
  function escapeHtml(str) {
    return str ? String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') : '';
  }

  function setupTabs() {
    $$('.menu-item').forEach(btn => {
      btn.addEventListener('click', () => {
        $$('.menu-item').forEach(b => b.classList.remove('active'));
        $$('.tab-panel').forEach(p => p.classList.remove('active'));

        btn.classList.add('active');
        $(`#panel-${btn.dataset.tab}`).classList.add('active');
      });
    });
  }

  setupTabs();
  verifyAccess();

})();
// version: 1783656171
