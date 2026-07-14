/**
 * BOQA agent.js — Playwright instrumentation + auth intelligence + anomaly engine
 *
 * v0.3: Integrated HypothesisEngine for real-time hypothesis generation.
 *       AnomalyEngine seeded from baseline when in compare/baseline mode.
 *       Events feed into hypothesis engine for incremental finding detection.
 *
 * Observability only. No bypass. No modification.
 */

const { AnomalyEngine } = require('./anomaly');
const { HypothesisEngine } = require('./finder');

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');
const executionGuard = require('./lib/execution-authorization-guard');
const { BrowserEgressGuard } = require('./lib/browser-egress-guard');

// ─── Auth Pattern Definitions ──────────────────────────────────────────

const AUTH_URL_PATTERNS = [
  /\/api\/users\/me\/?/, /\/auth\//, /\/login/, /\/logout/, /\/token/,
  /\/oauth/, /\/session/, /\/2fa/, /\/verify/, /\/refresh/,
];

const AUTH_COOKIE_NAMES = new Set([
  'ripio_access', 'sessionid', 'csrftoken',
  'access_token', 'refresh_token', 'auth_token',
  'id_token', '_jwt', '_session',
]);

const AUTH_HEADER_KEYS = new Set([
  'authorization', 'x-csrftoken', 'x-auth-token',
  'x-access-token', 'x-refresh-token',
]);

// ─── Document-Start Injection Script (inline) ──────────────────────────

const INSTRUMENTATION_SCRIPT = `
(function BOQA_INSTRUMENTATION() {
  'use strict';
  var PREFIX = '__BOQA__';

  function emit(type, data) {
    try {
      if (window.__boqaEmit) {
        window.__boqaEmit(type, data);
      }
    } catch(_) {}
  }

  function isAuthURL(url) {
    return /\\/auth\\/|\\/login|\\/logout|\\/token|\\/session|\\/2fa|\\/verify|\\/api\\/users\\/me/.test(url);
  }

  function extractAuth(headers) {
    var auth = {};
    var keys = ['authorization','x-csrftoken','x-auth-token','x-access-token'];
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      if (headers[k] || headers[k.toLowerCase()]) {
        auth[k] = (headers[k] || headers[k.toLowerCase()]).substring(0, 50);
      }
    }
    return Object.keys(auth).length > 0 ? auth : null;
  }

  // Fetch hook
  var origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function() {
      var input = arguments[0];
      var init = arguments[1] || {};
      var url = typeof input === 'string' ? input : (input instanceof Request ? input.url : String(input));
      var method = (init.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
      var headers = {};
      if (init.headers) {
        if (init.headers instanceof Headers) { init.headers.forEach(function(v,k){ headers[k.toLowerCase()]=v; }); }
        else { for (var k in init.headers) { headers[k.toLowerCase()] = init.headers[k]; } }
      }
      var authH = extractAuth(headers);
      emit('fetch_request', { url: url, method: method, hasAuthHeaders: !!authH, authHeaders: authH, isAuthURL: isAuthURL(url) });
      if (isAuthURL(url) && init.body) {
        try { emit('fetch_body', { url: url, method: method, bodyPreview: String(init.body).substring(0,2000) }); } catch(_) {}
      }
      return origFetch.apply(this, arguments).then(function(res) {
        var rh = {};
        res.headers.forEach(function(v,k){ rh[k.toLowerCase()]=v; });
        if (isAuthURL(url) || rh['set-cookie'] || extractAuth(rh)) {
          emit('fetch_response', { url: url, method: method, status: res.status, hasSetCookie: !!rh['set-cookie'], authHeaders: extractAuth(rh) });
        }
        return res;
      });
    };
    window.fetch.toString = function(){ return 'function fetch() { [native code] }'; };
  }

  // XHR hook
  var XHR = window.XMLHttpRequest;
  var origOpen = XHR.prototype.open;
  var origSend = XHR.prototype.send;
  var origSetHeader = XHR.prototype.setRequestHeader;
  var xhrMeta = new WeakMap();

  XHR.prototype.open = function(m, u) { xhrMeta.set(this, { method: (m||'GET').toUpperCase(), url: String(u), headers: {} }); return origOpen.apply(this, arguments); };
  XHR.prototype.setRequestHeader = function(n, v) { var meta = xhrMeta.get(this); if (meta) meta.headers[n.toLowerCase()] = v; return origSetHeader.apply(this, arguments); };
  XHR.prototype.send = function(body) {
    var meta = xhrMeta.get(this);
    if (meta) {
      var authH = extractAuth(meta.headers);
      emit('xhr_request', { url: meta.url, method: meta.method, hasAuthHeaders: !!authH, authHeaders: authH, isAuthURL: isAuthURL(meta.url) });
      if (isAuthURL(meta.url) && body) { try { emit('xhr_body', { url: meta.url, method: meta.method, bodyPreview: String(body).substring(0,2000) }); } catch(_) {} }
      this.addEventListener('load', function() {
        if (isAuthURL(meta.url) || authH) emit('xhr_response', { url: meta.url, method: meta.method, status: this.status });
      });
    }
    return origSend.apply(this, arguments);
  };

  // WebSocket hook
  var OrigWS = window.WebSocket;
  var wsId = 0;
  window.WebSocket = function(url, protocols) {
    var id = ++wsId;
    var ws = protocols ? new OrigWS(url, protocols) : new OrigWS(url);
    emit('ws_open', { url: url, wsId: id });
    ws.addEventListener('open', function() { emit('ws_connected', { url: url, wsId: id }); });
    var origSend = ws.send.bind(ws);
    ws.send = function(data) {
      emit('ws_out', { url: url, wsId: id, preview: typeof data === 'string' ? data.substring(0,2000) : '[binary]' });
      return origSend(data);
    };
    ws.addEventListener('message', function(e) {
      emit('ws_in', { url: url, wsId: id, preview: typeof e.data === 'string' ? e.data.substring(0,2000) : '[binary]' });
    });
    ws.addEventListener('close', function(e) { emit('ws_close', { url: url, wsId: id, code: e.code }); });
    return ws;
  };
  window.WebSocket.prototype = OrigWS.prototype;
  window.WebSocket.CONNECTING = OrigWS.CONNECTING;
  window.WebSocket.OPEN = OrigWS.OPEN;
  window.WebSocket.CLOSING = OrigWS.CLOSING;
  window.WebSocket.CLOSED = OrigWS.CLOSED;
  window.WebSocket.toString = function(){ return 'function WebSocket() { [native code] }'; };

  // Cookie write monitor
  var cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
  if (cookieDesc && cookieDesc.set) {
    var origSet = cookieDesc.set;
    Object.defineProperty(Document.prototype, 'cookie', {
      get: cookieDesc.get,
      set: function(v) {
        var name = v.split('=')[0].trim();
        if (['ripio_access','sessionid','csrftoken','access_token','refresh_token'].indexOf(name) !== -1) {
          emit('cookie_write', { name: name, preview: v.substring(0,100) });
        }
        return origSet.call(this, v);
      },
      configurable: true
    });
  }

  // CryptoJS decrypt detection
  var cjMonitored = false;
  function monitorCJ() {
    if (cjMonitored || !window.CryptoJS || !window.CryptoJS.AES) return;
    cjMonitored = true;
    var origDec = window.CryptoJS.AES.decrypt;
    window.CryptoJS.AES.decrypt = function() {
      emit('cryptojs_decrypt', { ciphertextPreview: typeof arguments[0] === 'string' ? arguments[0].substring(0,50) : '[object]', passphraseType: typeof arguments[1] });
      return origDec.apply(this, arguments);
    };
  }
  setInterval(monitorCJ, 3000);

  // Storage monitor
  var origSetItem = Storage.prototype.setItem;
  Storage.prototype.setItem = function(key, value) {
    if (/token|jwt|auth|access|refresh|csrf|session/i.test(key)) {
      emit('storage_write', { storage: this === localStorage ? 'localStorage' : 'sessionStorage', key: key, preview: String(value).substring(0,100) });
    }
    return origSetItem.apply(this, arguments);
  };
  Storage.prototype.setItem.toString = function(){ return 'function setItem() { [native code] }'; };

  emit('init', { url: location.href, ts: Date.now() });
})();
`;

// ─── Auth Intelligence Engine ───────────────────────────────────────────

class AuthIntelligence {
  constructor() {
    this.authCookies = new Map();        // name → { httpOnly, secure, sameSite, domain }
    this.bearerDetected = false;
    this.csrfHeaderDetected = false;
    this.authEndpoints = new Set();
    this.wsChannels = new Map();         // url → { authRelated, messages }
    this.errorCodes = [];                // { url, status, ts }
    this.timeline = [];                  // ordered auth events
    this.cryptoJSDetected = false;
    this.jwtInJSMemory = false;          // inferred from bearer + !httpOnly
    this.sessionRotations = [];          // cookie value changes
    this._prevCookieValues = new Map();  // name → last value prefix
  }

  /**
   * Ingest an event and update auth state
   */
  ingest(event) {
    if (event.type !== 'auth_signal' && event.type !== 'cookie_snapshot' &&
        event.type !== 'websocket_open' && event.type !== 'websocket_message_in' &&
        event.type !== 'console_error' && event.type !== 'network_response') {
      return;
    }

    const meta = event.meta || {};

    switch (meta.signalType || event.type) {
      // --- Auth cookie set via Set-Cookie header ---
      case 'auth_cookie_set':
        if (meta.cookies) {
          for (const c of meta.cookies) {
            const prev = this._prevCookieValues.get(c.name);
            if (prev && prev !== c.valuePreview) {
              this.sessionRotations.push({ name: c.name, ts: event.ts });
            }
            this._prevCookieValues.set(c.name, c.valuePreview);
            this.authCookies.set(c.name, {
              httpOnly: c.httpOnly,
              secure: c.secure,
              sameSite: c.sameSite,
              domain: c.domain,
              path: c.path,
              firstSeen: event.ts,
            });
          }
        }
        this.timeline.push({ ts: event.ts, signal: 'auth_cookie_set', detail: meta.cookies?.map(c => c.name).join(',') });
        break;

      // --- Bearer token in request header ---
      case 'bearer_token':
        this.bearerDetected = true;
        this.timeline.push({ ts: event.ts, signal: 'bearer_token', detail: meta.headerPreview });
        break;

      // --- CSRF header in request ---
      case 'csrf_header':
        this.csrfHeaderDetected = true;
        this.timeline.push({ ts: event.ts, signal: 'csrf_header', detail: meta.headerPreview });
        break;

      // --- Auth endpoint request ---
      case 'auth_endpoint_request':
        this.authEndpoints.add(event.url);
        this.timeline.push({ ts: event.ts, signal: 'auth_endpoint', detail: `${event.method} ${event.url}` });
        break;

      // --- Auth page navigation ---
      case 'auth_page_navigation':
        this.authEndpoints.add(event.url);
        this.timeline.push({ ts: event.ts, signal: 'auth_page', detail: event.url });
        break;

      // --- Auth WS connection ---
      case 'auth_related_ws':
        this.wsChannels.set(event.url, { authRelated: true, messages: 0 });
        this.timeline.push({ ts: event.ts, signal: 'auth_ws', detail: event.url });
        break;

      // --- 401/403 ---
      case 'unauthorized':
      case 'forbidden':
        this.errorCodes.push({ url: event.url, status: event.status || (meta.signalType === 'unauthorized' ? 401 : 403), ts: event.ts });
        this.timeline.push({ ts: event.ts, signal: meta.signalType, detail: `${event.status} ${event.url}` });
        break;

      // --- Auth cookies present (from cookie poll) ---
      case 'auth_cookies_present':
        if (meta.cookies) {
          for (const c of meta.cookies) {
            if (!this.authCookies.has(c.name)) {
              this.authCookies.set(c.name, {
                httpOnly: c.httpOnly,
                secure: c.secure,
                sameSite: c.sameSite,
                domain: c.domain,
                firstSeen: event.ts,
              });
            }
          }
        }
        break;

      // --- Cookie snapshot ---
      case 'cookie_snapshot':
        if (meta.authCookies) {
          for (const c of meta.authCookies) {
            if (!this.authCookies.has(c.name)) {
              this.authCookies.set(c.name, {
                httpOnly: c.httpOnly,
                secure: c.secure,
                sameSite: c.sameSite,
                domain: c.domain,
                path: c.path,
                firstSeen: event.ts,
              });
            }
          }
        }
        break;

      // --- WS messages ---
      case 'websocket_open':
        if (!this.wsChannels.has(event.url)) {
          this.wsChannels.set(event.url, { authRelated: false, messages: 0 });
        }
        break;

      case 'websocket_message_in':
        if (event.url && this.wsChannels.has(event.url)) {
          this.wsChannels.get(event.url).messages++;
        }
        break;

      // --- CryptoJS decrypt detected ---
      case 'cryptojs_decrypt':
      case 'cryptojs_decrypt': // from instrumentation bridge
        this.cryptoJSDetected = true;
        this.timeline.push({ ts: event.ts, signal: 'cryptojs_decrypt', detail: 'CryptoJS.AES.decrypt called' });
        break;
    }

    // Infer jwt_in_js_memory: bearer detected + cookie NOT httpOnly
    if (this.bearerDetected) {
      for (const [name, attrs] of this.authCookies) {
        if (name.includes('access') || name.includes('jwt') || name.includes('token')) {
          if (!attrs.httpOnly) {
            this.jwtInJSMemory = true;
          }
        }
      }
    }
  }

  /**
   * Determine auth model
   */
  getModel() {
    const hasBearer = this.bearerDetected;
    const hasAuthCookies = this.authCookies.size > 0;

    if (hasBearer && hasAuthCookies) return 'hybrid';
    if (hasBearer && !hasAuthCookies) return 'bearer';
    if (!hasBearer && hasAuthCookies) return 'cookie';
    return 'unknown';
  }

  /**
   * Generate risk flags
   */
  getRiskFlags() {
    const flags = [];

    if (this.jwtInJSMemory) {
      flags.push({ flag: 'jwt_in_js_memory', severity: 'high', detail: 'Bearer token detected + auth cookie lacks HttpOnly — JWT accessible to XSS' });
    }

    for (const [name, attrs] of this.authCookies) {
      if (!attrs.httpOnly && AUTH_COOKIE_NAMES.has(name)) {
        flags.push({ flag: 'missing_httpOnly', severity: 'high', detail: `Cookie "${name}" lacks HttpOnly — readable by document.cookie` });
      }
      if (!attrs.secure && AUTH_COOKIE_NAMES.has(name)) {
        flags.push({ flag: 'missing_secure', severity: 'medium', detail: `Cookie "${name}" lacks Secure flag — sent over HTTP` });
      }
      if (!attrs.sameSite || attrs.sameSite === 'None') {
        flags.push({ flag: 'csrf_missing', severity: 'medium', detail: `Cookie "${name}" has SameSite=${attrs.sameSite || 'unset'} — vulnerable to CSRF` });
      }
    }

    if (!this.csrfHeaderDetected && this.authCookies.size > 0) {
      flags.push({ flag: 'csrf_missing', severity: 'medium', detail: 'No CSRF header detected — cookie auth without double-submit CSRF protection' });
    }

    if (this.sessionRotations.length > 3) {
      flags.push({ flag: 'session_rotation_detected', severity: 'low', detail: `${this.sessionRotations.length} cookie rotations observed — possible session fixation concern` });
    }

    if (this.cryptoJSDetected) {
      flags.push({ flag: 'client_side_encryption', severity: 'info', detail: 'CryptoJS.AES.decrypt detected — client-side decryption is obfuscation, not security' });
    }

    return flags;
  }

  /**
   * Generate final report
   */
  getReport() {
    return {
      auth_flow_detected: this.getModel() !== 'unknown',
      auth_model: this.getModel(),
      risk_flags: this.getRiskFlags(),
      endpoints: [...this.authEndpoints],
      ws_channels: [...this.wsChannels.entries()].map(([url, info]) => ({ url, authRelated: info.authRelated, messages: info.messages })),
      cookies: [...this.authCookies.entries()].map(([name, attrs]) => ({ name, ...attrs })),
      errors: this.errorCodes,
      timeline: this.timeline,
      cryptojs_detected: this.cryptoJSDetected,
      jwt_in_js_memory: this.jwtInJSMemory,
      bearer_detected: this.bearerDetected,
      csrf_header_detected: this.csrfHeaderDetected,
    };
  }
}

// ─── Playwright Agent ───────────────────────────────────────────────────

class Agent {
  constructor(bus, options = {}) {
    this.bus = bus;
    this.intel = new AuthIntelligence();
    this.anomaly = new AnomalyEngine(options.baseline || null);
    this.options = {
      target: options.target || null,
      targetId: options.targetId || null,
      headless: options.headless || false,
      devtools: options.devtools !== false,
      cdpEndpoint: options.cdpEndpoint || null,
      cookiePollMs: options.cookiePollMs || 3000,
      perfPollMs: options.perfPollMs || 5000,
      recordHar: options.recordHar || false,
      harPath: options.harPath || path.join(__dirname, 'output', 'session.har'),
      viewport: options.viewport || { width: 1440, height: 900 },
      slowMo: options.slowMo || 0,
      baseline: options.baseline || null,
    };
    this.registry = options.registry || null;
    this.resolver = options.resolver;
    this.executionGuard = options.executionGuard || executionGuard;
    this.telemetry = options.telemetry || null;
    this.browserEgressGuard = options.browserEgressGuard || new BrowserEgressGuard({
      registry: this.registry,
      targetId: this.options.targetId,
      resolver: this.resolver,
      telemetry: this.telemetry,
    });

    this.browser = null;
    this.context = null;
    this.page = null;
    this.cdpSession = null;
    this.activeWs = new Map();
    this.wsCounter = 0;
    this._timers = [];

    // v0.3: Hypothesis engine for real-time finding detection
    this.hypothesisEngine = new HypothesisEngine();

    // Wire: every event → intelligence engine + anomaly engine + hypothesis engine
    this.bus.on('event', (event) => {
      this.intel.ingest(event);
      const anomalies = this.anomaly.ingest(event);
      // Re-emit anomalies as auth_signals for dashboard visibility
      for (const a of anomalies) {
        this.bus.emit({
          type: 'auth_signal',
          url: a.context || null,
          source: 'anomaly_engine',
          meta: {
            signalType: 'anomaly_detected',
            anomalyRule: a.rule,
            anomalySeverity: a.severity,
            anomalyDetail: a.detail,
          },
        });
      }

      // v0.3: Feed events to hypothesis engine for incremental detection
      try {
        const newHypotheses = this.hypothesisEngine.ingestEvent(event, {
          report: this.intel.getReport(),
          anomalies: this.anomaly.getAnomalies(),
          baseline: this.options.baseline,
        });
        // Stream new hypotheses as auth_signals for real-time visibility
        for (const h of newHypotheses) {
          this.bus.emit({
            type: 'auth_signal',
            url: null,
            source: 'hypothesis_engine',
            meta: {
              signalType: 'hypothesis_generated',
              hypothesisId: h.id,
              hypothesisCategory: h.category,
              hypothesisTitle: h.title,
              hypothesisConfidence: h.confidence,
              hypothesisSeverity: h.severity_hint,
            },
          });
        }
      } catch (_) {}
    });
  }

  async start() {
    console.log(`[Agent] Target: ${this.options.target}`);

    if (this.options.cdpEndpoint) {
      throw new Error('CDP_ENDPOINT_DISABLED_BY_EGRESS_POLICY');
    }

    const startupTask = {
      action: 'navigation',
      target_id: this.options.targetId,
      params: { url: this.options.target },
    };
    const startupAuthorization = await this.executionGuard.validateTaskAsync(startupTask, this.registry, {
      resolver: this.resolver,
      telemetry: this.telemetry,
      phase: 'agent_startup',
    });
    if (!startupAuthorization.allowed) {
      throw new Error(`${startupAuthorization.code}: ${startupAuthorization.reason}`);
    }

    // Wrap entire start() in try/catch — if anything fails after _launchBrowser(),
    // call this.stop() immediately to release Chromium resources and avoid OOM leaks.
    try {
      if (this.options.cdpEndpoint) {
        await this._connectCDP();
      } else {
        await this._launchBrowser();
      }

      // CDP session for deep access
      if (!this.cdpSession) {
        try {
          this.cdpSession = await this.page.context().newCDPSession(this.page);
          console.log('[Agent] CDP session attached');
        } catch (e) {
          console.warn('[Agent] CDP session unavailable:', e.message);
        }
      }

      // Expose function for instrumentation bridge
      try {
        await this.page.exposeFunction('__boqaEmit', (type, data) => {
          const typeMap = {
            'fetch_request': 'network_request', 'xhr_request': 'network_request',
            'fetch_response': 'network_response', 'xhr_response': 'network_response',
            'fetch_body': 'network_request', 'xhr_body': 'network_request',
            'ws_open': 'websocket_open', 'ws_connected': 'websocket_open',
            'ws_in': 'websocket_message_in', 'ws_out': 'websocket_message_out',
            'ws_close': 'websocket_close',
            'cookie_write': 'auth_signal', 'storage_write': 'auth_signal',
            'cryptojs_decrypt': 'auth_signal', 'init': 'console_log',
          };
          const mapped = typeMap[type];
          if (mapped) {
            const signalTypeMap = {
              'cookie_write': 'cookie_write',
              'storage_write': 'storage_auth_write',
              'cryptojs_decrypt': 'cryptojs_decrypt',
            };
            this.bus.emit({
              type: mapped,
              url: data?.url || null,
              method: data?.method || null,
              source: 'browser',
              meta: {
                instrumentType: type,
                signalType: signalTypeMap[type] || undefined,
                ...data,
              },
            });
          }
        });
      } catch (_) {}

      // Inject document-start hooks
      await this.page.addInitScript(INSTRUMENTATION_SCRIPT);
      // Also inject __boqaEmit reference for instrumentation script
      await this.page.addInitScript(() => {
        window.__boqaEmit = window.__boqaEmit || null;
      });

      // Attach Playwright-level hooks
      this._hookNetwork();
      this._hookWebSocket();
      this._hookConsole();
      this._hookNavigation();
      this._startCookiePoll();
      this._startPerfPoll();

      // Navigate
      console.log(`[Agent] Navigating to ${this.options.target}`);
      const navigationAuthorization = await this.executionGuard.validateUrlAsync(
        this.options.targetId,
        this.options.target,
        this.registry,
        { resolver: this.resolver, method: 'GET' },
      );
      if (!navigationAuthorization.allowed) {
        throw new Error(`${navigationAuthorization.code}: ${navigationAuthorization.reason}`);
      }
      await this.page.goto(this.options.target, { waitUntil: 'domcontentloaded', timeout: 60000 });
      console.log('[Agent] Page loaded — instrumentation active');

      return this.page;
    } catch (err) {
      // If anything failed AFTER _launchBrowser()/_connectCDP() opened Chromium,
      // we MUST close the browser to avoid orphan Chromium processes leaking RAM.
      console.error('[Agent] start() failed — releasing browser:', err.message);
      try {
        await this.stop();
      } catch (stopErr) {
        console.error('[Agent] stop() also failed during cleanup:', stopErr.message);
      }
      throw err; // re-throw so server.js can mark degraded mode
    }
  }

  async _launchBrowser() {
    const ctxOpts = {
      viewport: this.options.viewport,
      ignoreHTTPSErrors: true,
      serviceWorkers: 'block',
    };
    if (this.options.recordHar) {
      ctxOpts.recordHar = { path: this.options.harPath };
    }

    // ─── Surgical Patch: Memory Optimization for Free Containers ───────
    // Northflank free tier typically gives 512 MB – 1 GB RAM per container.
    // Playwright Chromium easily OOMs at that footprint with default flags.
    // These args cut RAM usage ~60% by disabling GPU, zygote, 2D canvas
    // acceleration, shared memory, and forcing a single-process model.
    // `headless: true` is forced (this.options.headless ignored) so headed
    // mode can never accidentally ship to a container without X server.
    this.browser = await chromium.launch({
      headless: true, // FORCED — headed mode is unsafe in Docker/Northflank
      slowMo: this.options.slowMo,
      args: [
        '--disable-blink-features=AutomationControlled',
        '--no-sandbox',                       // Required inside Docker
        '--disable-setuid-sandbox',           // Defense in depth
        '--disable-dev-shm-usage',            // Avoids /dev/shm crashes in shared containers
        '--disable-accelerated-2d-canvas',    // No GPU in containers
        '--disable-gpu',                      // Disables GPU compositing entirely
        '--no-first-run',                     // Skip first-run profile setup
        '--no-zygote',                        // No zygote process — saves ~30MB
        '--single-process',                   // Run everything in one process — saves ~50MB
      ],
    });

    this.context = await this.browser.newContext(ctxOpts);
    await this.browserEgressGuard.install(this.context);
    this.page = await this.context.newPage();
    console.log('[Agent] Browser launched (Headless & RAM-Optimized)');
  }

  async _connectCDP() {
    throw new Error('CDP_ENDPOINT_DISABLED_BY_EGRESS_POLICY');
  }

  // ─── Network Hooks ─────────────────────────────────────────────

  _hookNetwork() {
    this.page.on('request', (req) => {
      const url = req.url();
      const method = req.method();

      const event = {
        type: 'network_request',
        url, method,
        source: 'playwright',
        meta: {
          resourceType: req.resourceType(),
          isNavigation: req.isNavigationRequest(),
        },
      };

      try {
        const headers = req.headers();
        event.headers = headers;
        const lower = {};
        for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;

        if (lower['authorization']) {
          this.bus.emit({ type: 'auth_signal', url, method, headers, source: 'request_header', meta: { signalType: 'bearer_token', headerPreview: lower['authorization'].substring(0, 40) + '...' } });
        }
        if (lower['x-csrftoken']) {
          this.bus.emit({ type: 'auth_signal', url, method, headers, source: 'request_header', meta: { signalType: 'csrf_header', headerPreview: lower['x-csrftoken'].substring(0, 12) + '...' } });
        }
      } catch (_) {}

      if (['POST', 'PUT', 'PATCH'].includes(method)) {
        try {
          const body = req.postData();
          if (body) event.payload = body.length > 5000 ? body.substring(0, 5000) + '…' : body;
        } catch (_) {}

        if (AUTH_URL_PATTERNS.some(p => p.test(url))) {
          this.bus.emit({ type: 'auth_signal', url, method, source: 'request_url', meta: { signalType: 'auth_endpoint_request' } });
        }
      }

      this.bus.emit(event);
    });

    this.page.on('response', async (res) => {
      const url = res.url();
      const status = res.status();
      const event = {
        type: 'network_response',
        url,
        method: res.request()?.method() || 'GET',
        status,
        source: 'playwright',
        meta: { resourceType: res.request()?.resourceType() || 'unknown', fromCache: (() => { try { return typeof res.fromCache === 'function' ? res.fromCache() : false; } catch(_) { return false; } })() },
      };

      try {
        const allHeaders = await res.allHeaders();
        event.headers = allHeaders;

        // Auth signal: Set-Cookie with auth names
        const setCookies = Object.entries(allHeaders).filter(([k]) => k.toLowerCase() === 'set-cookie');
        const authSetCookies = setCookies.filter(([_, v]) => [...AUTH_COOKIE_NAMES].some(n => v.toLowerCase().startsWith(n.toLowerCase() + '=')));

        if (authSetCookies.length > 0) {
          this.bus.emit({
            type: 'auth_signal', url, status,
            headers: Object.fromEntries(authSetCookies),
            source: 'response_set_cookie',
            meta: {
              signalType: 'auth_cookie_set',
              cookies: authSetCookies.map(([_, v]) => {
                const parts = v.split(';');
                const [name, ...rest] = parts[0].split('=');
                const attrs = {};
                for (const p of parts.slice(1)) {
                  const [k, ...r] = p.trim().split('=');
                  attrs[k.toLowerCase()] = r.join('=') || true;
                }
                return {
                  name: name,
                  valuePreview: rest.join('=').substring(0, 25) + '…',
                  httpOnly: 'httponly' in attrs,
                  secure: 'secure' in attrs,
                  sameSite: attrs.samesite || null,
                  domain: attrs.domain || null,
                  path: attrs.path || null,
                };
              }),
            },
          });
        }
      } catch (_) {}

      // Auth endpoint response body
      if (AUTH_URL_PATTERNS.some(p => p.test(url)) && status < 400) {
        try {
          const ct = event.headers?.['content-type'] || '';
          if (ct.includes('json')) {
            const body = await res.text();
            if (body && body.length < 10000) event.payload = body;
          }
        } catch (_) {}
      }

      // 401/403
      if (status === 401 || status === 403) {
        this.bus.emit({ type: 'auth_signal', url, status, source: 'response_status', meta: { signalType: status === 401 ? 'unauthorized' : 'forbidden' } });
      }

      this.bus.emit(event);
    });

    this.page.on('requestfailed', (req) => {
      this.bus.emit({ type: 'network_failure', url: req.url(), method: req.method(), source: 'playwright', meta: { failure: req.failure()?.errorText || 'unknown' } });
    });
  }

  // ─── WebSocket Hooks ───────────────────────────────────────────

  _hookWebSocket() {
    this.page.on('websocket', (ws) => {
      const wsId = ++this.wsCounter;
      const wsUrl = ws.url();
      this.activeWs.set(wsId, { url: wsUrl, openedAt: Date.now() });

      this.bus.emit({ type: 'websocket_open', url: wsUrl, source: 'playwright', meta: { wsId } });

      if (/nexus|socket|ws|push|realtime/i.test(wsUrl)) {
        this.bus.emit({ type: 'auth_signal', url: wsUrl, source: 'websocket_connect', meta: { signalType: 'auth_related_ws', wsId } });
      }

      ws.on('framereceived', (frame) => {
        const p = frame.payload;
        this.bus.emit({
          type: 'websocket_message_in', url: wsUrl,
          payload: typeof p === 'string' ? (p.length > 5000 ? p.substring(0, 5000) + '…' : p) : `[binary ${p.byteLength}B]`,
          source: 'playwright', meta: { wsId, opcode: frame.opcode },
        });
      });

      ws.on('framesent', (frame) => {
        const p = frame.payload;
        this.bus.emit({
          type: 'websocket_message_out', url: wsUrl,
          payload: typeof p === 'string' ? (p.length > 5000 ? p.substring(0, 5000) + '…' : p) : `[binary ${p.byteLength}B]`,
          source: 'playwright', meta: { wsId, opcode: frame.opcode },
        });
      });

      ws.on('close', () => {
        const info = this.activeWs.get(wsId);
        this.activeWs.delete(wsId);
        this.bus.emit({ type: 'websocket_close', url: wsUrl, source: 'playwright', meta: { wsId, lifetime: info ? Date.now() - info.openedAt : 0 } });
      });
    });
  }

  // ─── Console / Error Hooks ─────────────────────────────────────

  _hookConsole() {
    this.page.on('console', (msg) => {
      const t = msg.type();
      const text = msg.text();
      const isAuth = /auth|token|jwt|session|cookie|csrf/i.test(text);

      if (t === 'warning' || t === 'error' || t === 'assert') {
        this.bus.emit({ type: 'console_error', payload: text.substring(0, 3000), source: 'playwright', meta: { consoleType: t } });
      } else if (isAuth) {
        this.bus.emit({ type: 'console_log', payload: text.substring(0, 3000), source: 'playwright', meta: { consoleType: t, authRelated: true } });
      }
    });

    this.page.on('pageerror', (err) => {
      this.bus.emit({ type: 'console_error', payload: err.message, source: 'playwright', meta: { consoleType: 'pageerror', stack: err.stack?.substring(0, 2000) } });
    });
  }

  // ─── Navigation Hooks ──────────────────────────────────────────

  _hookNavigation() {
    this.page.on('framenavigated', (frame) => {
      const url = frame.url();
      if (!url || url === 'about:blank') return;
      this.bus.emit({ type: 'page_navigation', url, source: 'playwright', meta: { isMain: frame === this.page.mainFrame() } });

      if (AUTH_URL_PATTERNS.some(p => p.test(url))) {
        this.bus.emit({ type: 'auth_signal', url, source: 'navigation', meta: { signalType: 'auth_page_navigation' } });
      }
    });
  }

  // ─── Cookie Polling ────────────────────────────────────────────

  _startCookiePoll() {
    const timer = setInterval(async () => {
      try {
        const cookies = await this.context.cookies();
        const authCookies = cookies.filter(c => AUTH_COOKIE_NAMES.has(c.name));

        this.bus.emit({
          type: 'cookie_snapshot', source: 'playwright',
          meta: {
            totalCookies: cookies.length,
            authCookies: authCookies.map(c => ({
              name: c.name, domain: c.domain, path: c.path,
              httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite,
              expires: c.expires, valuePreview: c.value?.substring(0, 30) + '…',
            })),
          },
        });

        if (authCookies.length > 0) {
          this.bus.emit({
            type: 'auth_signal', source: 'cookie_poll',
            meta: {
              signalType: 'auth_cookies_present',
              cookies: authCookies.map(c => ({ name: c.name, domain: c.domain, httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite, valuePrefix: c.value?.substring(0, 15) })),
            },
          });
        }
      } catch (_) {}
    }, this.options.cookiePollMs);
    this._timers.push(timer);
  }

  // ─── Performance Polling ───────────────────────────────────────

  _startPerfPoll() {
    const timer = setInterval(async () => {
      try {
        const entries = await this.page.evaluate(() => {
          return performance.getEntriesByType('resource').map(r => ({
            name: r.name, type: r.initiatorType,
            duration: Math.round(r.duration), size: r.transferSize,
          }));
        });
        if (entries.length > 0) {
          this.bus.emit({
            type: 'performance_resource', source: 'playwright',
            meta: {
              entries: entries.slice(-60),
              summary: {
                totalSize: entries.reduce((s, e) => s + (e.size || 0), 0),
                avgDuration: Math.round(entries.reduce((s, e) => s + e.duration, 0) / entries.length),
                byType: entries.reduce((a, e) => { a[e.type] = (a[e.type] || 0) + 1; return a; }, {}),
              },
            },
          });
        }
      } catch (_) {}
    }, this.options.perfPollMs);
    this._timers.push(timer);
  }

  // ─── Shutdown ──────────────────────────────────────────────────

  async stop() {
    console.log('[Agent] Shutting down...');
    this._timers.forEach(t => clearInterval(t));
    try {
      if (this.context && this.options.recordHar) await this.context.close();
      if (this.browser) await this.browser.close();
    } catch (_) {}
    console.log('[Agent] Stopped');
  }

  getReport() {
    const intelReport = this.intel.getReport();
    const anomalySummary = this.anomaly.getSummary();
    return {
      ...intelReport,
      anomalies: this.anomaly.getAnomalies(),
      anomaly_summary: anomalySummary,
    };
  }
}

module.exports = { Agent, AuthIntelligence, INSTRUMENTATION_SCRIPT, AUTH_URL_PATTERNS, AUTH_COOKIE_NAMES };
