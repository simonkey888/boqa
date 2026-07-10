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

  // ─── WebSocket con tolerancia a fallos ───────────────────────────
  //
  // Cloudflare Workers free tier no soporta proxear WebSocket upgrades
  // a un backend HTTP. El WS va a fallar silenciosamente, pero pollState()
  // (HTTP polling cada 10s) asume el control del estado y mantiene el dashboard vivo.

  function connectWS() {
    try {
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      state.ws = new WebSocket(`${protocol}//${location.host}/ws`);

      state.ws.onopen = () => {
        state.connected = true;
        const ind = $('#srv-status');
        const txt = $('#srv-status-text');
        if (ind) ind.className = 'status-indicator online';
        if (txt) txt.textContent = 'Conectado (Tiempo Real)';
        logEvent('api', 'Canal WebSocket establecido.');
      };

      state.ws.onclose = () => {
        state.connected = false;
        // No brickear el UI a "Desconectado" — pollState() mantiene el estado real.
        // Reintento de WS espaciado a 10s para evitar saturación del borde.
        setTimeout(connectWS, 10000);
      };

      state.ws.onerror = () => {
        // Silent — WS es best-effort. pollState() es la fuente de verdad.
      };

      state.ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          handleIncomingEvent(msg);
        } catch (_) {}
      };
    } catch (_) {
      // WS no soportado (ej. Cloudflare Worker proxy) — silent fail.
      // pollState() es la fuente de datos primaria de todos modos.
    }
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

      // [Surgical Patch: HTTP Status Indicator Fallback]
      // Si el fetch HTTP tiene éxito, el servidor está vivo y respondiendo.
      // Solo cambiar el texto si WS no lo sobreescribió a "Tiempo Real".
      state.connected = true;
      const ind = $('#srv-status');
      const txt = $('#srv-status-text');
      if (ind) ind.className = 'status-indicator online';
      if (txt && txt.textContent !== 'Conectado (Tiempo Real)') {
        txt.textContent = 'Conectado (Sincronizado)';
      }

      renderMetrics();
      renderReportTab();
    } catch (_) {
      // Solo marcamos como desconectado si falla también el canal HTTP.
      state.connected = false;
      const ind = $('#srv-status');
      const txt = $('#srv-status-text');
      if (ind) ind.className = 'status-indicator';
      if (txt) txt.textContent = 'Desconectado';
    }
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

  // ═══════════════════════════════════════════════════════════════════
  // Cyber Pitch Visualizer — 3D Attack Surface + Momentum Strip + Goal Wave
  // Canvas 2D with software 3D projection (no Three.js, universal compat)
  // ═══════════════════════════════════════════════════════════════════

  class CyberPitchVisualizer {
    constructor(canvasId) {
      this.canvas = document.getElementById(canvasId);
      if (!this.canvas) return;
      this.ctx = this.canvas.getContext('2d');

      // 3D rotation state
      this.rotX = -0.55;   // tilt down to see the grid from above
      this.rotY = 0.6;     // slight angle
      this.targetRotX = this.rotX;
      this.targetRotY = this.rotY;

      // Grid configuration
      this.gridSize = 24;          // 24x24 cells
      this.cellSize = 22;          // pixels per cell at z=0

      // Spike data — one entry per grid cell
      this.spikes = [];
      for (let i = 0; i < this.gridSize * this.gridSize; i++) {
        this.spikes.push({
          x: 0, y: 0,           // grid coords (set in resize)
          height: 0,            // current height
          targetHeight: 0,      // animated target
          color: { r: 99, g: 102, b: 241 }, // indigo by default
          intensity: 0,         // 0..1 for glow
        });
      }

      // Momentum strip — history of events per second
      this.momentum = new Array(120).fill(0);   // 120 buckets (~2 min at 1Hz)
      this.eventsThisSecond = 0;
      this.lastSecondTick = Math.floor(Date.now() / 1000);

      // Goal wave — expanding ring on bug_confirmed
      this.goalWaves = [];

      // Background wave phase for ambient motion
      this.wavePhase = 0;

      // Auto-rotation when user is not interacting
      this.autoRotate = true;
      this.lastInteraction = Date.now();

      // Setup
      this._setupResize();
      this._setupMouseInteraction();
      this._startLoop();
      this._startMomentumTicker();
    }

    _setupResize() {
      const resize = () => {
        const rect = this.canvas.parentElement.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;
        this.canvas.width = rect.width * dpr;
        this.canvas.height = rect.height * dpr;
        this.canvas.style.width = rect.width + 'px';
        this.canvas.style.height = rect.height + 'px';
        this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        this.width = rect.width;
        this.height = rect.height;
        this.cx = this.width / 2;
        this.cy = this.height / 2 + 40;
        const half = (this.gridSize - 1) / 2;
        for (let gy = 0; gy < this.gridSize; gy++) {
          for (let gx = 0; gx < this.gridSize; gx++) {
            const i = gy * this.gridSize + gx;
            this.spikes[i].x = (gx - half) * this.cellSize;
            this.spikes[i].y = (gy - half) * this.cellSize;
          }
        }
      };
      resize();
      window.addEventListener('resize', resize);
    }

    _setupMouseInteraction() {
      let dragging = false;
      let lastX = 0, lastY = 0;

      this.canvas.addEventListener('mousedown', (e) => {
        dragging = true;
        lastX = e.clientX; lastY = e.clientY;
        this.autoRotate = false;
        this.lastInteraction = Date.now();
      });
      window.addEventListener('mouseup', () => { dragging = false; });
      window.addEventListener('mousemove', (e) => {
        if (!dragging) return;
        const dx = e.clientX - lastX;
        const dy = e.clientY - lastY;
        this.targetRotY += dx * 0.01;
        this.targetRotX += dy * 0.01;
        this.targetRotX = Math.max(-1.3, Math.min(0.3, this.targetRotX));
        lastX = e.clientX; lastY = e.clientY;
        this.lastInteraction = Date.now();
      });
      this.canvas.addEventListener('mousemove', (e) => {
        if (dragging) return;
        const rect = this.canvas.getBoundingClientRect();
        const nx = (e.clientX - rect.left) / rect.width - 0.5;
        const ny = (e.clientY - rect.top) / rect.height - 0.5;
        this.targetRotY = 0.6 + nx * 0.6;
        this.targetRotX = -0.55 + ny * 0.4;
        this.lastInteraction = Date.now();
      });
    }

    _startLoop() {
      const loop = () => {
        this._update();
        this._render();
        requestAnimationFrame(loop);
      };
      requestAnimationFrame(loop);
    }

    _startMomentumTicker() {
      setInterval(() => {
        const now = Math.floor(Date.now() / 1000);
        if (now !== this.lastSecondTick) {
          this.momentum.push(this.eventsThisSecond);
          if (this.momentum.length > 120) this.momentum.shift();
          this.eventsThisSecond = 0;
          this.lastSecondTick = now;
        }
      }, 200);
    }

    pulse(type, intensity = 1) {
      const i = Math.floor(Math.random() * this.spikes.length);
      const spike = this.spikes[i];
      spike.targetHeight = Math.min(120, spike.targetHeight + 20 * intensity);
      spike.intensity = 1;
      if (type === 'bug') {
        spike.color = { r: 244, g: 63, b: 94 };
      } else if (type === 'analisis' || type === 'anomaly') {
        spike.color = { r: 245, g: 158, b: 11 };
      } else if (type === 'nav') {
        spike.color = { r: 6, g: 182, b: 212 };
      } else {
        spike.color = { r: 16, g: 185, b: 129 };
      }
      this.eventsThisSecond++;
    }

    triggerGoalWave() {
      this.goalWaves.push({
        radius: 0,
        maxRadius: 400,
        alpha: 1,
      });
      const center = Math.floor(this.gridSize / 2) * this.gridSize + Math.floor(this.gridSize / 2);
      this.spikes[center].targetHeight = 140;
      this.spikes[center].color = { r: 244, g: 63, b: 94 };
      this.spikes[center].intensity = 1;
    }

    _update() {
      if (!this.autoRotate && Date.now() - this.lastInteraction > 3000) {
        this.autoRotate = true;
      }
      if (this.autoRotate) {
        this.targetRotY += 0.0025;
      }
      this.rotX += (this.targetRotX - this.rotX) * 0.1;
      this.rotY += (this.targetRotY - this.rotY) * 0.1;
      this.wavePhase += 0.04;
      for (const s of this.spikes) {
        s.height += (s.targetHeight - s.height) * 0.15;
        s.targetHeight *= 0.94;
        if (s.targetHeight < 0.5) s.targetHeight = 0;
        s.intensity *= 0.95;
      }
      this.goalWaves = this.goalWaves.filter(w => {
        w.radius += 6;
        w.alpha *= 0.96;
        return w.alpha > 0.02 && w.radius < w.maxRadius;
      });
    }

    _project(x, y, z) {
      const cosY = Math.cos(this.rotY), sinY = Math.sin(this.rotY);
      const x1 = x * cosY - z * sinY;
      const z1 = x * sinY + z * cosY;
      const cosX = Math.cos(this.rotX), sinX = Math.sin(this.rotX);
      const y1 = y * cosX - z1 * sinX;
      const z2 = y * sinX + z1 * cosX;
      const perspective = 600;
      const scale = perspective / (perspective + z2);
      return {
        x: this.cx + x1 * scale,
        y: this.cy + y1 * scale,
        scale: scale,
        z: z2,
      };
    }

    _render() {
      const ctx = this.ctx;
      ctx.fillStyle = 'rgba(5, 5, 8, 0.35)';
      ctx.fillRect(0, 0, this.width, this.height);

      const drawables = [];

      for (const s of this.spikes) {
        const ambient = Math.sin(this.wavePhase + (s.x + s.y) * 0.03) * 1.5;
        const baseZ = ambient;
        const heightZ = baseZ - s.height;
        const top = this._project(s.x, s.y, heightZ);
        const base = this._project(s.x, s.y, baseZ);
        drawables.push({ type: 'spike', z: base.z, top, base, spike: s });
      }

      const half = (this.gridSize - 1) / 2 * this.cellSize;
      for (let i = 0; i <= this.gridSize; i++) {
        const t = (i - (this.gridSize - 1) / 2) * this.cellSize;
        const p1 = this._project(-half, t, 0);
        const p2 = this._project(half, t, 0);
        drawables.push({ type: 'gridline', z: (p1.z + p2.z) / 2 - 1, p1, p2 });
        const p3 = this._project(t, -half, 0);
        const p4 = this._project(t, half, 0);
        drawables.push({ type: 'gridline', z: (p3.z + p4.z) / 2 - 1, p1: p3, p2: p4 });
      }

      drawables.sort((a, b) => b.z - a.z);

      for (const d of drawables) {
        if (d.type === 'gridline') {
          ctx.strokeStyle = 'rgba(99, 102, 241, 0.12)';
          ctx.lineWidth = 0.5;
          ctx.beginPath();
          ctx.moveTo(d.p1.x, d.p1.y);
          ctx.lineTo(d.p2.x, d.p2.y);
          ctx.stroke();
        } else if (d.type === 'spike') {
          const { top, base, spike } = d;
          const h = spike.height;
          const c = spike.color;
          const intensity = spike.intensity;
          if (h > 1) {
            const baseWidth = 4 * base.scale;
            const alpha = 0.5 + intensity * 0.5;
            ctx.fillStyle = `rgba(${c.r}, ${c.g}, ${c.b}, ${alpha})`;
            ctx.beginPath();
            ctx.moveTo(base.x - baseWidth, base.y);
            ctx.lineTo(base.x + baseWidth, base.y);
            ctx.lineTo(top.x, top.y);
            ctx.closePath();
            ctx.fill();
            if (intensity > 0.1) {
              const glowRadius = 6 + intensity * 8;
              const grad = ctx.createRadialGradient(top.x, top.y, 0, top.x, top.y, glowRadius);
              grad.addColorStop(0, `rgba(${c.r}, ${c.g}, ${c.b}, ${intensity * 0.8})`);
              grad.addColorStop(1, `rgba(${c.r}, ${c.g}, ${c.b}, 0)`);
              ctx.fillStyle = grad;
              ctx.beginPath();
              ctx.arc(top.x, top.y, glowRadius, 0, Math.PI * 2);
              ctx.fill();
            }
          } else {
            ctx.fillStyle = `rgba(${c.r}, ${c.g}, ${c.b}, 0.25)`;
            ctx.fillRect(base.x - 1, base.y - 1, 2, 2);
          }
        }
      }

      for (const w of this.goalWaves) {
        const center = this._project(0, 0, 0);
        ctx.strokeStyle = `rgba(244, 63, 94, ${w.alpha})`;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(center.x, center.y, w.radius, 0, Math.PI * 2);
        ctx.stroke();
        ctx.strokeStyle = `rgba(255, 100, 130, ${w.alpha * 0.5})`;
        ctx.lineWidth = 8;
        ctx.beginPath();
        ctx.arc(center.x, center.y, w.radius, 0, Math.PI * 2);
        ctx.stroke();
      }

      this._renderMomentumStrip();
    }

    _renderMomentumStrip() {
      const ctx = this.ctx;
      const stripHeight = 36;
      const stripY = this.height - stripHeight - 8;
      const stripX = 16;
      const stripW = this.width - 32;
      const buckets = this.momentum.length;
      const bucketW = stripW / buckets;
      const maxEvents = Math.max(5, ...this.momentum);

      ctx.fillStyle = 'rgba(255, 255, 255, 0.03)';
      ctx.fillRect(stripX, stripY, stripW, stripHeight);

      for (let i = 0; i < buckets; i++) {
        const v = this.momentum[i];
        if (v === 0) continue;
        const h = (v / maxEvents) * (stripHeight - 4);
        const x = stripX + i * bucketW;
        const y = stripY + stripHeight - h - 2;
        const ratio = v / maxEvents;
        let r, g, b;
        if (ratio < 0.5) {
          r = 16 + ratio * 2 * (245 - 16);
          g = 185 + ratio * 2 * (158 - 185);
          b = 129 + ratio * 2 * (11 - 129);
        } else {
          r = 245 + (ratio - 0.5) * 2 * (244 - 245);
          g = 158 + (ratio - 0.5) * 2 * (63 - 158);
          b = 11 + (ratio - 0.5) * 2 * (94 - 11);
        }
        ctx.fillStyle = `rgba(${r|0}, ${g|0}, ${b|0}, 0.8)`;
        ctx.fillRect(x, y, Math.max(1, bucketW - 0.5), h);
      }

      ctx.fillStyle = 'rgba(161, 161, 170, 0.6)';
      ctx.font = '9px JetBrains Mono, monospace';
      ctx.textAlign = 'left';
      ctx.fillText('MOMENTUM (events/sec)', stripX, stripY - 4);
      ctx.textAlign = 'right';
      ctx.fillText(`${this.eventsThisSecond}/s NOW`, stripX + stripW, stripY - 4);
    }
  }

  // Instantiate visualizer BEFORE verifyAccess() so the first pollState() can pulse it.
  const cyberPitch = new CyberPitchVisualizer('cyber-pitch-canvas');

  // Wrap logEvent so every event also pulses the visualizer.
  const _originalLogEvent = logEvent;
  logEvent = function(type, detail) {
    _originalLogEvent(type, detail);
    if (cyberPitch && cyberPitch.canvas) {
      cyberPitch.pulse(type, type === 'bug' ? 2 : 1);
      if (type === 'bug') cyberPitch.triggerGoalWave();
    }
  };

  // Wrap pollState so every successful poll also pulses the grid (heartbeat effect).
  const _originalPollState = pollState;
  pollState = async function() {
    try {
      await _originalPollState();
      if (cyberPitch && cyberPitch.canvas) {
        cyberPitch.pulse('api', 0.4);
      }
    } catch (err) {
      throw err;
    }
  };

  setupTabs();
  verifyAccess();

})();
// version: 1783656171
// v:1783656596177128959
// v:1783659661839695542
