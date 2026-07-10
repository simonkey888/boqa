/**
 * BOQA asset-mapper.js — Asset Mapper v0.5
 *
 * Builds endpoint, cookie, auth, and websocket asset graphs for the
 * BOQA security observability system. Ingests events from the EventBus,
 * cross-references assets, computes risk flags, and persists graphs
 * to disk for dashboard consumption.
 *
 * Asset types:
 *   - Endpoints: HTTP request/response pairs with auth mechanism detection
 *   - Cookies: Auth/session cookie tracking with sensitivity classification
 *   - Auth Flows: Login/logout/token-refresh/2FA/session-rotation sequences
 *   - WebSockets: Live socket connections with message accounting
 *
 * Observability only. No bypass. No modification.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Constants ──────────────────────────────────────────────────────────

const ASSETS_DIR = path.join(__dirname, 'output', 'assets');

const COOKIE_SENSITIVITY = {
  ripio_access:  'critical',
  sessionid:     'critical',
  access_token:  'critical',
  refresh_token: 'high',
  id_token:      'high',
  csrftoken:     'medium',
  auth_token:    'critical',
  _jwt:          'critical',
  _session:      'high',
};

const AUTH_COOKIE_NAMES = new Set([
  'ripio_access', 'sessionid', 'csrftoken',
  'access_token', 'refresh_token', 'auth_token',
  'id_token', '_jwt', '_session',
]);

const AUTH_HEADER_KEYS = new Set([
  'authorization', 'x-csrftoken', 'x-auth-token',
  'x-access-token', 'x-refresh-token',
]);

const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const AUTH_FLOW_WINDOW_MS = 5000; // 5-second window for grouping auth_signal events

// ─── ID Generators ─────────────────────────────────────────────────────

function generateId(prefix) {
  const raw = crypto.randomUUID
    ? crypto.randomUUID()
    : Date.now().toString(36) + Math.random().toString(36).substring(2, 10);
  return `${prefix}-${raw.replace(/-/g, '').substring(0, 8).toUpperCase()}`;
}

// ─── AssetMapper ────────────────────────────────────────────────────────

class AssetMapper {
  constructor() {
    // target_id → { endpoints, cookies, authFlows, websockets, meta }
    this._graphs = new Map();

    // Temporal buffers for auth flow grouping (target_id → auth_signal events)
    this._authSignalBuffers = new Map();

    // Response buffer: endpoint key → { status, headers, contentType } for pairing
    this._responseBuffer = new Map();

    // Ensure output directory exists
    fs.mkdirSync(ASSETS_DIR, { recursive: true });
  }

  // ─── Core Ingestion ───────────────────────────────────────────────

  /**
   * Process an array of BOQA events and build/update the asset graph
   * for the given target.
   *
   * @param {Array} events  - Array of normalized EventBus events
   * @param {string} targetId - Target identifier (e.g. "TGT-XXXX")
   * @returns {object} The updated asset graph for the target
   */
  ingestEvents(events, targetId) {
    this._ensureGraph(targetId);

    for (const event of events) {
      switch (event.type) {
        case 'network_request':
          this.addEndpoint(event, targetId);
          break;

        case 'network_response':
          this._pairResponse(event, targetId);
          break;

        case 'cookie_snapshot':
          this._processCookieSnapshot(event, targetId);
          break;

        case 'auth_signal':
          this.addAuthFlow(event, targetId);
          break;

        case 'websocket_open':
          this.addWebSocket(event, targetId);
          break;

        case 'websocket_message_in':
          this._processWsMessageIn(event, targetId);
          break;

        case 'websocket_message_out':
          this._processWsMessageOut(event, targetId);
          break;

        case 'websocket_close':
          this._processWsClose(event, targetId);
          break;
      }
    }

    // After ingestion, compute cross-references and risk flags
    this.linkAssets();
    this.computeRiskFlags();

    return this.getGraph(targetId);
  }

  // ─── Endpoint Management ──────────────────────────────────────────

  /**
   * Extract endpoint info from a network_request event.
   * Merge if endpoint already exists (update counts, status codes, last_seen).
   *
   * @param {object} event - Normalized network_request event
   * @param {string} [targetId] - Target identifier
   * @returns {object} The endpoint asset
   */
  addEndpoint(event, targetId) {
    const tid = targetId || this._resolveTargetId(event);
    this._ensureGraph(tid);

    const url = event.url || '';
    const method = (event.method || 'GET').toUpperCase();

    let pathname = '';
    try {
      pathname = new URL(url).pathname;
    } catch (_) {
      pathname = url;
    }

    const endpointKey = `${method} ${pathname}`;

    // Extract cookies sent and headers sent
    const cookiesSent = this._extractCookieNames(event);
    const headersSent = this._extractAuthHeaders(event);

    // Detect auth mechanism
    const authMechanism = this._detectAuthMechanism(cookiesSent, headersSent);

    // Determine if endpoint is auth-related
    const isAuth = this._isAuthEndpoint(pathname) ||
                   cookiesSent.some(c => AUTH_COOKIE_NAMES.has(c)) ||
                   headersSent.length > 0;

    const contentType = this._extractContentType(event) || '';

    const graph = this._graphs.get(tid);
    const existing = graph.endpoints.get(endpointKey);

    const now = Date.now();

    if (existing) {
      // Merge: update counts, last_seen, accumulate data
      existing.request_count++;
      existing.last_seen = now;

      // Merge cookies_sent
      for (const ck of cookiesSent) {
        if (!existing.cookies_sent.includes(ck)) {
          existing.cookies_sent.push(ck);
        }
      }

      // Merge headers_sent
      for (const hdr of headersSent) {
        if (!existing.headers_sent.includes(hdr)) {
          existing.headers_sent.push(hdr);
        }
      }

      // Re-evaluate auth mechanism (may upgrade from none → cookie → mixed)
      existing.auth_mechanism = this._detectAuthMechanism(existing.cookies_sent, existing.headers_sent);
      existing.is_auth = existing.is_auth || isAuth;

      // Update content_type if discovered
      if (contentType && !existing.content_type) {
        existing.content_type = contentType;
      }
    } else {
      // Create new endpoint asset
      const endpoint = {
        id: generateId('EP'),
        url,
        method,
        path: pathname,
        is_auth: isAuth,
        auth_mechanism: authMechanism,
        content_type: contentType,
        status_codes: [],
        request_count: 1,
        cookies_sent: cookiesSent,
        headers_sent: headersSent,
        risk_flags: [],
        first_seen: now,
        last_seen: now,
      };

      graph.endpoints.set(endpointKey, endpoint);
    }

    return graph.endpoints.get(endpointKey);
  }

  /**
   * Pair a network_response with an existing endpoint.
   * Updates status_codes and content_type on the matched endpoint.
   *
   * @param {object} event - Normalized network_response event
   * @param {string} targetId - Target identifier
   */
  _pairResponse(event, targetId) {
    const tid = targetId || this._resolveTargetId(event);
    const graph = this._graphs.get(tid);
    if (!graph) return;

    const url = event.url || '';
    const method = (event.method || 'GET').toUpperCase();

    let pathname = '';
    try {
      pathname = new URL(url).pathname;
    } catch (_) {
      pathname = url;
    }

    const endpointKey = `${method} ${pathname}`;
    const endpoint = graph.endpoints.get(endpointKey);

    if (endpoint && event.status) {
      if (!endpoint.status_codes.includes(event.status)) {
        endpoint.status_codes.push(event.status);
      }

      // Update content_type from response headers
      const ct = this._extractContentType(event);
      if (ct) {
        endpoint.content_type = ct;
      }
    }

    // Buffer response for potential later pairing
    this._responseBuffer.set(endpointKey, {
      status: event.status,
      headers: event.headers,
      ts: event.ts,
    });
  }

  // ─── Cookie Management ────────────────────────────────────────────

  /**
   * Add or update a cookie asset from cookie_snapshot events.
   *
   * @param {object} cookieData - Cookie data object
   * @param {string} [targetId] - Target identifier
   * @returns {object} The cookie asset
   */
  addCookie(cookieData, targetId) {
    const tid = targetId;
    if (!tid) return null;

    this._ensureGraph(tid);
    const graph = this._graphs.get(tid);

    const name = cookieData.name || '';
    const domain = cookieData.domain || '';
    const cookieKey = `${name}@${domain}`;

    // Determine sensitivity
    const sensitivity = this._classifyCookieSensitivity(name);

    // Determine if auth cookie
    const isAuth = AUTH_COOKIE_NAMES.has(name);

    const existing = graph.cookies.get(cookieKey);

    if (existing) {
      // Update mutable fields
      existing.path = cookieData.path || existing.path;
      existing.httpOnly = cookieData.httpOnly !== undefined ? cookieData.httpOnly : existing.httpOnly;
      existing.secure = cookieData.secure !== undefined ? cookieData.secure : existing.secure;
      existing.sameSite = cookieData.sameSite || existing.sameSite;
      existing.is_auth = existing.is_auth || isAuth;

      // Promote sensitivity if higher
      existing.sensitivity = this._higherSensitivity(existing.sensitivity, sensitivity);
    } else {
      const cookie = {
        id: generateId('CK'),
        name,
        domain,
        path: cookieData.path || '/',
        httpOnly: !!cookieData.httpOnly,
        secure: !!cookieData.secure,
        sameSite: cookieData.sameSite || 'Lax',
        is_auth: isAuth,
        used_by_endpoints: [],
        sensitivity,
        risk_flags: [],
      };

      graph.cookies.set(cookieKey, cookie);
    }

    return graph.cookies.get(cookieKey);
  }

  /**
   * Process a cookie_snapshot event from the EventBus.
   *
   * @param {object} event - cookie_snapshot event
   * @param {string} targetId - Target identifier
   */
  _processCookieSnapshot(event, targetId) {
    const tid = targetId || this._resolveTargetId(event);

    // cookie_snapshot may carry cookies in payload or meta
    // Real agent format: { type: 'cookie_snapshot', meta: { authCookies: [...] } }
    // Also handle: { type: 'cookie_snapshot', payload: { name, domain, ... } } (single cookie)
    // And: { type: 'cookie_snapshot', payload: { cookies: [...] } } (array wrapper)
    let cookies = event.payload?.cookies ||
                  event.meta?.cookies ||
                  event.meta?.authCookies ||
                  null;

    // Handle single cookie object in payload (not wrapped in array)
    if (!cookies && event.payload?.name && typeof event.payload.name === 'string') {
      cookies = [event.payload];
    }

    if (!cookies) return;

    for (const ck of cookies) {
      this.addCookie(ck, tid);
    }
  }

  // ─── Auth Flow Management ─────────────────────────────────────────

  /**
   * Build an auth flow from an auth_signal event.
   * Groups auth_signal events that occur within 5 seconds of each other
   * and share cookies into the same flow.
   *
   * @param {object} authSignalEvent - auth_signal event from EventBus
   * @param {string} [targetId] - Target identifier
   * @returns {object} The auth flow asset
   */
  addAuthFlow(authSignalEvent, targetId) {
    const tid = targetId || this._resolveTargetId(authSignalEvent);
    this._ensureGraph(tid);

    const graph = this._graphs.get(tid);
    const meta = authSignalEvent.meta || {};
    const payload = authSignalEvent.payload || {};
    const signalType = meta.signalType || payload.signalType || 'login';
    const ts = authSignalEvent.ts || Date.now();

    // Normalize signal type to flow type
    const flowType = this._normalizeFlowType(signalType);

    // Extract endpoint references
    const endpointIds = [];
    if (authSignalEvent.url) {
      const method = (authSignalEvent.method || 'GET').toUpperCase();
      let pathname = '';
      try { pathname = new URL(authSignalEvent.url).pathname; } catch (_) { pathname = authSignalEvent.url; }
      const epKey = `${method} ${pathname}`;
      const ep = graph.endpoints.get(epKey);
      if (ep) endpointIds.push(ep.id);
    }

    // Extract cookie references
    const cookieNames = meta.cookies || payload.cookies || [];
    const cookieIds = [];
    for (const ck of cookieNames) {
      const ckName = typeof ck === 'string' ? ck : ck.name;
      const ckDomain = typeof ck === 'string' ? '' : (ck.domain || '');
      const ckKey = `${ckName}@${ckDomain}`;
      const cookieAsset = graph.cookies.get(ckKey);
      if (cookieAsset) cookieIds.push(cookieAsset.id);
    }

    // Determine cookies set vs cleared based on signal type
    const cookiesSet = [];
    const cookiesCleared = [];

    if (flowType === 'login' || flowType === 'token_refresh' || flowType === '2fa') {
      for (const cid of cookieIds) cookiesSet.push(cid);
    } else if (flowType === 'logout') {
      for (const cid of cookieIds) cookiesCleared.push(cid);
    } else if (flowType === 'session_rotation') {
      // Session rotation: old cleared, new set
      for (const cid of cookieIds) {
        cookiesCleared.push(cid);
        cookiesSet.push(cid);
      }
    }

    // Tokens observed
    const tokensObserved = [];
    if (meta.tokenType) tokensObserved.push(meta.tokenType);
    if (payload.tokenType && !tokensObserved.includes(payload.tokenType)) {
      tokensObserved.push(payload.tokenType);
    }
    // Infer from headers
    if (authSignalEvent.headers) {
      const lower = {};
      for (const [k, v] of Object.entries(authSignalEvent.headers)) lower[k.toLowerCase()] = v;
      if (lower['authorization']) tokensObserved.push('bearer');
      if (lower['x-csrftoken']) tokensObserved.push('csrf');
    }
    if (tokensObserved.length === 0 && cookieNames.some(c => {
      const n = typeof c === 'string' ? c : c.name;
      return n === 'access_token' || n === 'auth_token' || n === '_jwt';
    })) {
      tokensObserved.push('bearer');
    }

    // Try to merge with an existing flow in the temporal window
    const buffer = this._authSignalBuffers.get(tid) || [];
    let merged = false;

    for (const pending of buffer) {
      if (
        ts - pending.ts <= AUTH_FLOW_WINDOW_MS &&
        this._flowsShareCookies(cookieIds, pending.cookieIds)
      ) {
        // Merge into existing flow
        const flow = graph.authFlows.get(pending.flowId);
        if (flow) {
          // Add new endpoints
          for (const eid of endpointIds) {
            if (!flow.endpoints.includes(eid)) flow.endpoints.push(eid);
          }
          // Add new cookies set
          for (const cid of cookiesSet) {
            if (!flow.cookies_set.includes(cid)) flow.cookies_set.push(cid);
          }
          // Add new cookies cleared
          for (const cid of cookiesCleared) {
            if (!flow.cookies_cleared.includes(cid)) flow.cookies_cleared.push(cid);
          }
          // Add new tokens
          for (const tok of tokensObserved) {
            if (!flow.tokens_observed.includes(tok)) flow.tokens_observed.push(tok);
          }
          // Update timing
          flow.timing_ms = ts - flow._startTs;
          // Upgrade flow type if needed (e.g., login + 2fa → 2fa)
          if (flowType === '2fa' && flow.type === 'login') {
            flow.type = '2fa';
          }
        }
        merged = true;
        break;
      }
    }

    if (!merged) {
      // Create new auth flow
      const flowId = generateId('AF');
      const flow = {
        id: flowId,
        type: flowType,
        endpoints: endpointIds,
        cookies_set: cookiesSet,
        cookies_cleared: cookiesCleared,
        tokens_observed: tokensObserved,
        timing_ms: 0,
        _startTs: ts, // internal: for timing calculation
      };

      graph.authFlows.set(flowId, flow);

      buffer.push({ flowId, ts, cookieIds });
    }

    this._authSignalBuffers.set(tid, buffer);

    // Return the last created or merged flow
    const lastEntry = buffer[buffer.length - 1];
    return lastEntry ? graph.authFlows.get(lastEntry.flowId) : null;
  }

  /**
   * Normalize auth signal types to flow types
   */
  _normalizeFlowType(signalType) {
    const mapping = {
      login: 'login',
      auth_cookie_set: 'login',
      auth_cookies_present: 'login',
      logout: 'logout',
      auth_cookies_cleared: 'logout',
      token_refresh: 'token_refresh',
      token_rotated: 'token_refresh',
      '2fa': '2fa',
      two_factor: '2fa',
      mfa_challenge: '2fa',
      session_rotation: 'session_rotation',
      session_rotated: 'session_rotation',
    };
    return mapping[signalType] || 'login';
  }

  /**
   * Check if two sets of cookie IDs share at least one cookie
   */
  _flowsShareCookies(idsA, idsB) {
    if (idsA.length === 0 || idsB.length === 0) return true; // no cookies to compare, group by time
    return idsA.some(id => idsB.includes(id));
  }

  // ─── WebSocket Management ─────────────────────────────────────────

  /**
   * Track a websocket connection and its messages.
   *
   * @param {object} wsEvent - websocket_open event
   * @param {string} [targetId] - Target identifier
   * @returns {object} The websocket asset
   */
  addWebSocket(wsEvent, targetId) {
    const tid = targetId || this._resolveTargetId(wsEvent);
    this._ensureGraph(tid);

    const graph = this._graphs.get(tid);
    const url = wsEvent.url || '';
    const protocol = wsEvent.meta?.protocol || wsEvent.payload?.protocol || '';

    // Determine auth mechanism for the WS
    const authMechanism = this._detectWsAuthMechanism(wsEvent);

    // Extract channel name from URL pathname
    let channel = '';
    try {
      channel = new URL(url).pathname;
    } catch (_) {
      channel = url;
    }

    const now = Date.now();

    // Check for existing websocket at the same URL
    const existing = graph.websockets.get(url);

    if (existing) {
      existing.messages_in = 0;
      existing.messages_out = 0;
      existing.last_seen = now;
      if (protocol && !existing.protocol) existing.protocol = protocol;
      if (channel && !existing.channels.includes(channel)) {
        existing.channels.push(channel);
      }
    } else {
      const ws = {
        id: generateId('WS'),
        url,
        protocol,
        auth_mechanism: authMechanism,
        messages_in: 0,
        messages_out: 0,
        channels: channel ? [channel] : [],
        first_seen: now,
        last_seen: now,
      };

      graph.websockets.set(url, ws);
    }

    return graph.websockets.get(url);
  }

  /**
   * Process a websocket_message_in event
   */
  _processWsMessageIn(event, targetId) {
    const tid = targetId || this._resolveTargetId(event);
    const graph = this._graphs.get(tid);
    if (!graph) return;

    const url = event.url || '';
    const ws = graph.websockets.get(url);

    if (ws) {
      ws.messages_in++;
      ws.last_seen = Date.now();

      // Extract channel from message payload
      const channel = event.payload?.channel || event.meta?.channel;
      if (channel && !ws.channels.includes(channel)) {
        ws.channels.push(channel);
      }
    }
  }

  /**
   * Process a websocket_message_out event
   */
  _processWsMessageOut(event, targetId) {
    const tid = targetId || this._resolveTargetId(event);
    const graph = this._graphs.get(tid);
    if (!graph) return;

    const url = event.url || '';
    const ws = graph.websockets.get(url);

    if (ws) {
      ws.messages_out++;
      ws.last_seen = Date.now();

      const channel = event.payload?.channel || event.meta?.channel;
      if (channel && !ws.channels.includes(channel)) {
        ws.channels.push(channel);
      }
    }
  }

  /**
   * Process a websocket_close event
   */
  _processWsClose(event, targetId) {
    const tid = targetId || this._resolveTargetId(event);
    const graph = this._graphs.get(tid);
    if (!graph) return;

    const url = event.url || '';
    const ws = graph.websockets.get(url);
    if (ws) {
      ws.last_seen = Date.now();
    }
  }

  // ─── Cross-Reference Linking ──────────────────────────────────────

  /**
   * After ingestion, compute cross-references:
   *   - Which cookies are sent to which endpoints
   *   - Which auth flows set which cookies
   *   - Which endpoints use which auth mechanisms
   */
  linkAssets() {
    for (const [targetId, graph] of this._graphs) {
      // Build cookie → endpoint mapping
      const cookieToEndpoints = new Map(); // cookieKey → [endpointId, ...]

      for (const [epKey, endpoint] of graph.endpoints) {
        // Re-evaluate auth mechanism with full context
        endpoint.auth_mechanism = this._detectAuthMechanism(
          endpoint.cookies_sent,
          endpoint.headers_sent
        );

        // Link cookies to endpoints
        for (const cookieName of endpoint.cookies_sent) {
          // Find cookie asset by name (may have multiple domains)
          for (const [ckKey, cookie] of graph.cookies) {
            if (cookie.name === cookieName) {
              if (!cookie.used_by_endpoints.includes(endpoint.id)) {
                cookie.used_by_endpoints.push(endpoint.id);
              }
              if (!cookieToEndpoints.has(ckKey)) {
                cookieToEndpoints.set(ckKey, []);
              }
              if (!cookieToEndpoints.get(ckKey).includes(endpoint.id)) {
                cookieToEndpoints.get(ckKey).push(endpoint.id);
              }
            }
          }
        }

        // Determine is_auth more precisely
        if (endpoint.cookies_sent.some(c => AUTH_COOKIE_NAMES.has(c))) {
          endpoint.is_auth = true;
        }
        if (endpoint.headers_sent.length > 0) {
          endpoint.is_auth = true;
        }
      }

      // Link auth flows to cookies they set
      for (const [flowId, flow] of graph.authFlows) {
        // Resolve cookie IDs back to cookie assets for cross-reference
        for (const ckId of flow.cookies_set) {
          for (const [ckKey, cookie] of graph.cookies) {
            if (cookie.id === ckId) {
              // Cookie was set in this flow — already captured
              break;
            }
          }
        }
      }

      // Link websockets to cookies/endpoints
      for (const [wsUrl, ws] of graph.websockets) {
        // Find endpoints that share the same origin
        try {
          const wsOrigin = new URL(wsUrl).origin;
          for (const [epKey, endpoint] of graph.endpoints) {
            try {
              const epOrigin = new URL(endpoint.url).origin;
              if (epOrigin === wsOrigin && endpoint.is_auth) {
                // WebSocket shares origin with authenticated endpoint
                // If WS has no auth, this is notable
                if (ws.auth_mechanism === 'none') {
                  // Flag will be set in computeRiskFlags
                }
              }
            } catch (_) {}
          }
        } catch (_) {}
      }
    }
  }

  // ─── Risk Flag Computation ────────────────────────────────────────

  /**
   * Compute risk flags for each asset:
   *   - missing_httpOnly on auth cookies
   *   - no_auth on sensitive endpoints
   *   - missing_csrf on state-changing endpoints
   *   - auth_desync on websockets without auth
   *   - missing_secure on auth cookies
   *   - weak_samesite on auth cookies
   *   - insecure_cookie_transport on non-secure cookies
   */
  computeRiskFlags() {
    for (const [targetId, graph] of this._graphs) {
      // ── Endpoint risk flags ──
      for (const [epKey, endpoint] of graph.endpoints) {
        endpoint.risk_flags = [];

        // no_auth: endpoint has no auth mechanism
        if (endpoint.auth_mechanism === 'none' && this._isSensitivePath(endpoint.path)) {
          endpoint.risk_flags.push('no_auth');
        }

        // missing_csrf: state-changing endpoint without CSRF protection
        if (
          STATE_CHANGING_METHODS.has(endpoint.method) &&
          !endpoint.cookies_sent.includes('csrftoken') &&
          !endpoint.headers_sent.includes('x-csrftoken') &&
          endpoint.auth_mechanism !== 'none'
        ) {
          endpoint.risk_flags.push('missing_csrf');
        }

        // idor_pattern: endpoint path contains identifiable segments
        if (this._hasIdorPattern(endpoint.path)) {
          endpoint.risk_flags.push('idor_pattern');
        }

        // sensitive_data_exposure: GET to auth/session endpoints
        if (
          endpoint.method === 'GET' &&
          this._isAuthEndpoint(endpoint.path) &&
          endpoint.status_codes.some(c => c >= 200 && c < 300)
        ) {
          endpoint.risk_flags.push('sensitive_data_exposure');
        }
      }

      // ── Cookie risk flags ──
      for (const [ckKey, cookie] of graph.cookies) {
        cookie.risk_flags = [];

        if (cookie.is_auth) {
          // missing_httpOnly: auth cookie without HttpOnly
          if (!cookie.httpOnly) {
            cookie.risk_flags.push('missing_httpOnly');
          }

          // missing_secure: auth cookie without Secure flag
          if (!cookie.secure) {
            cookie.risk_flags.push('missing_secure');
          }

          // weak_samesite: auth cookie with SameSite=None or missing
          if (!cookie.sameSite || cookie.sameSite === 'None') {
            cookie.risk_flags.push('weak_samesite');
          }
        }

        // insecure_cookie_transport: cookie with sensitivity high/critical but not secure
        if (
          (cookie.sensitivity === 'critical' || cookie.sensitivity === 'high') &&
          !cookie.secure
        ) {
          cookie.risk_flags.push('insecure_transport');
        }

        // overly_broad_path: cookie path is /
        if (cookie.path === '/' && cookie.is_auth) {
          cookie.risk_flags.push('overly_broad_path');
        }

        // cross_origin_usage: cookie used by endpoints on different domains
        if (cookie.used_by_endpoints.length > 5) {
          cookie.risk_flags.push('excessive_endpoint_usage');
        }
      }

      // ── WebSocket risk flags ──
      for (const [wsUrl, ws] of graph.websockets) {
        // We store risk_flags directly on the ws object
        ws.risk_flags = [];

        // auth_desync: WebSocket without auth on same origin as auth endpoints
        if (ws.auth_mechanism === 'none') {
          const hasAuthEndpoint = this._hasAuthEndpointsOnSameOrigin(graph, wsUrl);
          if (hasAuthEndpoint) {
            ws.risk_flags.push('auth_desync');
          }
        }

        // unencrypted_ws: WebSocket over ws:// instead of wss://
        if (wsUrl.startsWith('ws://') && !wsUrl.startsWith('wss://')) {
          ws.risk_flags.push('unencrypted_ws');
        }

        // high_message_volume: potential data exfiltration
        if (ws.messages_out > ws.messages_in * 10 && ws.messages_out > 50) {
          ws.risk_flags.push('high_message_volume');
        }
      }
    }
  }

  /**
   * Check if path looks sensitive enough to warrant auth
   */
  _isSensitivePath(pathname) {
    const sensitivePatterns = [
      /\/api\//i,
      /\/auth\//i,
      /\/user/i,
      /\/admin/i,
      /\/account/i,
      /\/profile/i,
      /\/settings/i,
      /\/dashboard/i,
      /\/private/i,
      /\/internal/i,
      /\/session/i,
      /\/token/i,
    ];
    return sensitivePatterns.some(p => p.test(pathname));
  }

  /**
   * Check if path contains IDOR-like patterns (UUIDs, numeric IDs)
   */
  _hasIdorPattern(pathname) {
    return /\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(pathname) ||
           /\/\d{2,}(?:\/|$)/.test(pathname);
  }

  /**
   * Check if there are authenticated endpoints on the same origin as a WS URL
   */
  _hasAuthEndpointsOnSameOrigin(graph, wsUrl) {
    try {
      const wsParsed = new URL(wsUrl);
      // Normalize: wss:// and https:// share the same origin for security analysis
      const wsHost = wsParsed.hostname;
      const wsPort = wsParsed.port || (wsParsed.protocol === 'wss:' ? '443' : '80');
      for (const [epKey, endpoint] of graph.endpoints) {
        if (endpoint.is_auth) {
          try {
            const epParsed = new URL(endpoint.url);
            const epHost = epParsed.hostname;
            const epPort = epParsed.port || (epParsed.protocol === 'https:' ? '443' : '80');
            // Same host + same effective port → same origin (cross-protocol ws/https)
            if (wsHost === epHost && wsPort === epPort) return true;
          } catch (_) {}
        }
      }
    } catch (_) {}
    return false;
  }

  // ─── Graph Accessors ──────────────────────────────────────────────

  /**
   * Get the full asset graph for a target
   *
   * @param {string} targetId - Target identifier
   * @returns {object} Complete asset graph following schema
   */
  getGraph(targetId) {
    const graph = this._graphs.get(targetId);
    if (!graph) return null;

    const endpoints = [...graph.endpoints.values()];
    const cookies = [...graph.cookies.values()];
    const authFlows = [...graph.authFlows.values()].map(f => {
      // Remove internal fields
      const { _startTs, ...rest } = f;
      return rest;
    });
    const websockets = [...graph.websockets.values()];

    const riskSummary = this._computeRiskSummary(endpoints, cookies, websockets);

    return {
      target_id: targetId,
      generated_at: Date.now(),
      endpoints,
      cookies,
      auth_flows: authFlows,
      websockets,
      risk_summary: riskSummary,
    };
  }

  /**
   * Get endpoints for a target
   *
   * @param {string} targetId - Target identifier
   * @returns {Array} Endpoint assets
   */
  getEndpoints(targetId) {
    const graph = this._graphs.get(targetId);
    if (!graph) return [];
    return [...graph.endpoints.values()];
  }

  /**
   * Get cookies for a target
   *
   * @param {string} targetId - Target identifier
   * @returns {Array} Cookie assets
   */
  getCookies(targetId) {
    const graph = this._graphs.get(targetId);
    if (!graph) return [];
    return [...graph.cookies.values()];
  }

  /**
   * Get auth flows for a target
   *
   * @param {string} targetId - Target identifier
   * @returns {Array} Auth flow assets
   */
  getAuthFlows(targetId) {
    const graph = this._graphs.get(targetId);
    if (!graph) return [];
    return [...graph.authFlows.values()].map(f => {
      const { _startTs, ...rest } = f;
      return rest;
    });
  }

  /**
   * Get websockets for a target
   *
   * @param {string} targetId - Target identifier
   * @returns {Array} WebSocket assets
   */
  getWebSockets(targetId) {
    const graph = this._graphs.get(targetId);
    if (!graph) return [];
    return [...graph.websockets.values()];
  }

  /**
   * Get risk summary for a target
   *
   * @param {string} targetId - Target identifier
   * @returns {object} Risk summary
   */
  getRiskSummary(targetId) {
    const graph = this._graphs.get(targetId);
    if (!graph) return this._emptyRiskSummary();

    const endpoints = [...graph.endpoints.values()];
    const cookies = [...graph.cookies.values()];
    const websockets = [...graph.websockets.values()];

    return this._computeRiskSummary(endpoints, cookies, websockets);
  }

  /**
   * Get all target graphs
   *
   * @returns {object} Map of targetId → asset graph
   */
  getAllGraphs() {
    const all = {};
    for (const targetId of this._graphs.keys()) {
      all[targetId] = this.getGraph(targetId);
    }
    return all;
  }

  // ─── Persistence ──────────────────────────────────────────────────

  /**
   * Persist graph to disk
   *
   * @param {string} targetId - Target identifier
   * @returns {string} File path of saved graph
   */
  save(targetId) {
    const graph = this.getGraph(targetId);
    if (!graph) {
      throw new Error(`No graph found for target: ${targetId}`);
    }

    fs.mkdirSync(ASSETS_DIR, { recursive: true });
    const filePath = path.join(ASSETS_DIR, `graph-${targetId}.json`);
    fs.writeFileSync(filePath, JSON.stringify(graph, null, 2));
    return filePath;
  }

  /**
   * Load graph from disk
   *
   * @param {string} targetId - Target identifier
   * @returns {object} Loaded asset graph
   */
  load(targetId) {
    const filePath = path.join(ASSETS_DIR, `graph-${targetId}.json`);

    if (!fs.existsSync(filePath)) {
      throw new Error(`Graph file not found: ${filePath}`);
    }

    const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    // Reconstruct internal maps from the loaded graph
    this._ensureGraph(targetId);
    const graph = this._graphs.get(targetId);

    // Restore endpoints
    graph.endpoints.clear();
    for (const ep of (raw.endpoints || [])) {
      const epKey = `${ep.method} ${ep.path}`;
      graph.endpoints.set(epKey, ep);
    }

    // Restore cookies
    graph.cookies.clear();
    for (const ck of (raw.cookies || [])) {
      const ckKey = `${ck.name}@${ck.domain}`;
      graph.cookies.set(ckKey, ck);
    }

    // Restore auth flows
    graph.authFlows.clear();
    for (const af of (raw.auth_flows || [])) {
      graph.authFlows.set(af.id, { ...af, _startTs: Date.now() - (af.timing_ms || 0) });
    }

    // Restore websockets
    graph.websockets.clear();
    for (const ws of (raw.websockets || [])) {
      graph.websockets.set(ws.url, ws);
    }

    return this.getGraph(targetId);
  }

  // ─── Export for Dashboard ─────────────────────────────────────────

  /**
   * Export graph in a format suitable for dashboard rendering (nodes + edges).
   *
   * Node types: endpoint, cookie, auth_flow, websocket
   * Edge types: sends_cookie, uses_auth, flow_sets_cookie, flow_clears_cookie,
   *             ws_auth_desync, endpoint_to_ws
   *
   * @param {string} targetId - Target identifier
   * @returns {object} { nodes, edges, metadata }
   */
  exportGraph(targetId) {
    const graph = this.getGraph(targetId);
    if (!graph) return { nodes: [], edges: [], metadata: {} };

    const nodes = [];
    const edges = [];

    // ── Endpoint nodes ──
    for (const ep of graph.endpoints) {
      nodes.push({
        id: ep.id,
        type: 'endpoint',
        label: `${ep.method} ${ep.path}`,
        data: {
          method: ep.method,
          path: ep.path,
          is_auth: ep.is_auth,
          auth_mechanism: ep.auth_mechanism,
          request_count: ep.request_count,
          risk_flags: ep.risk_flags,
          status_codes: ep.status_codes,
        },
      });

      // Edge: endpoint ← cookie (sends_cookie)
      for (const ckName of ep.cookies_sent) {
        const cookieAsset = graph.cookies.find(c => c.name === ckName);
        if (cookieAsset) {
          edges.push({
            source: cookieAsset.id,
            target: ep.id,
            type: 'sends_cookie',
            label: ckName,
          });
        }
      }
    }

    // ── Cookie nodes ──
    for (const ck of graph.cookies) {
      nodes.push({
        id: ck.id,
        type: 'cookie',
        label: ck.name,
        data: {
          domain: ck.domain,
          sensitivity: ck.sensitivity,
          is_auth: ck.is_auth,
          httpOnly: ck.httpOnly,
          secure: ck.secure,
          sameSite: ck.sameSite,
          risk_flags: ck.risk_flags,
          used_by_endpoint_count: ck.used_by_endpoints.length,
        },
      });
    }

    // ── Auth flow nodes ──
    for (const af of graph.auth_flows) {
      nodes.push({
        id: af.id,
        type: 'auth_flow',
        label: af.type,
        data: {
          type: af.type,
          tokens_observed: af.tokens_observed,
          timing_ms: af.timing_ms,
        },
      });

      // Edge: flow → endpoint (uses_auth)
      for (const epId of af.endpoints) {
        edges.push({
          source: af.id,
          target: epId,
          type: 'uses_auth',
          label: af.type,
        });
      }

      // Edge: flow → cookie (flow_sets_cookie)
      for (const ckId of af.cookies_set) {
        edges.push({
          source: af.id,
          target: ckId,
          type: 'flow_sets_cookie',
        });
      }

      // Edge: flow → cookie (flow_clears_cookie)
      for (const ckId of af.cookies_cleared) {
        edges.push({
          source: af.id,
          target: ckId,
          type: 'flow_clears_cookie',
        });
      }
    }

    // ── WebSocket nodes ──
    for (const ws of graph.websockets) {
      nodes.push({
        id: ws.id,
        type: 'websocket',
        label: ws.url,
        data: {
          url: ws.url,
          protocol: ws.protocol,
          auth_mechanism: ws.auth_mechanism,
          messages_in: ws.messages_in,
          messages_out: ws.messages_out,
          channels: ws.channels,
          risk_flags: ws.risk_flags || [],
        },
      });

      // Edge: ws → endpoint on same origin (endpoint_to_ws)
      for (const ep of graph.endpoints) {
        try {
          const wsOrigin = new URL(ws.url).origin;
          const epOrigin = new URL(ep.url).origin;
          if (wsOrigin === epOrigin) {
            edges.push({
              source: ws.id,
              target: ep.id,
              type: 'endpoint_to_ws',
              label: 'same_origin',
            });
          }
        } catch (_) {}
      }
    }

    return {
      nodes,
      edges,
      metadata: {
        target_id: targetId,
        generated_at: graph.generated_at,
        node_count: nodes.length,
        edge_count: edges.length,
        risk_summary: graph.risk_summary,
      },
    };
  }

  // ─── Internal Helpers ─────────────────────────────────────────────

  /**
   * Ensure a graph structure exists for a target
   */
  _ensureGraph(targetId) {
    if (!this._graphs.has(targetId)) {
      this._graphs.set(targetId, {
        endpoints: new Map(),    // "METHOD /path" → endpoint
        cookies: new Map(),      // "name@domain" → cookie
        authFlows: new Map(),    // "AF-XXXX" → authFlow
        websockets: new Map(),   // url → websocket
        meta: {
          created_at: Date.now(),
          last_updated: Date.now(),
        },
      });
    }
  }

  /**
   * Try to resolve targetId from an event
   */
  _resolveTargetId(event) {
    return event.meta?.targetId || event.meta?.target || 'TGT-UNKNOWN';
  }

  /**
   * Extract cookie names from a request event
   */
  _extractCookieNames(event) {
    const names = [];

    // From Cookie header
    if (event.headers) {
      const lower = {};
      for (const [k, v] of Object.entries(event.headers)) lower[k.toLowerCase()] = v;

      if (lower['cookie']) {
        const parsed = lower['cookie'].split(';').map(c => c.trim().split('=')[0].trim());
        names.push(...parsed.filter(Boolean));
      }
    }

    // From meta.cookies (if Playwright provides them)
    if (event.meta?.cookies) {
      for (const c of event.meta.cookies) {
        const name = typeof c === 'string' ? c : c.name;
        if (name && !names.includes(name)) names.push(name);
      }
    }

    // From payload.cookies
    if (event.payload?.cookies) {
      for (const c of event.payload.cookies) {
        const name = typeof c === 'string' ? c : c.name;
        if (name && !names.includes(name)) names.push(name);
      }
    }

    return names;
  }

  /**
   * Extract auth-related header names from a request event
   */
  _extractAuthHeaders(event) {
    const headers = [];
    if (event.headers) {
      for (const key of Object.keys(event.headers)) {
        const lower = key.toLowerCase();
        if (AUTH_HEADER_KEYS.has(lower)) {
          headers.push(lower);
        }
      }
    }
    return headers;
  }

  /**
   * Detect auth mechanism for an endpoint based on cookies and headers
   * Returns: 'cookie' | 'bearer' | 'csrf' | 'mixed' | 'none'
   */
  _detectAuthMechanism(cookiesSent, headersSent) {
    const hasBearer = headersSent.includes('authorization') ||
                      headersSent.includes('x-auth-token') ||
                      headersSent.includes('x-access-token');
    const hasCookie = cookiesSent.some(c => AUTH_COOKIE_NAMES.has(c));
    const hasCsrf = headersSent.includes('x-csrftoken') ||
                    headersSent.includes('x-refresh-token') ||
                    cookiesSent.includes('csrftoken');

    const mechanisms = [];
    if (hasBearer) mechanisms.push('bearer');
    if (hasCookie) mechanisms.push('cookie');
    if (hasCsrf) mechanisms.push('csrf');

    if (mechanisms.length === 0) return 'none';
    if (mechanisms.length === 1) return mechanisms[0];
    return 'mixed';
  }

  /**
   * Detect auth mechanism for a WebSocket connection
   */
  _detectWsAuthMechanism(wsEvent) {
    // Check headers
    const headers = wsEvent.headers || wsEvent.meta?.headers || {};
    const lower = {};
    for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;

    if (lower['authorization'] || lower['x-auth-token']) return 'token';
    if (lower['cookie']) {
      // Check if auth cookies are present
      const cookieNames = lower['cookie'].split(';').map(c => c.trim().split('=')[0].trim());
      if (cookieNames.some(n => AUTH_COOKIE_NAMES.has(n))) return 'cookie';
    }

    // Check for custom auth in query params
    try {
      const u = new URL(wsEvent.url || '');
      if (u.searchParams.has('token') || u.searchParams.has('access_token')) return 'custom';
    } catch (_) {}

    // Check meta
    if (wsEvent.meta?.authMechanism) return wsEvent.meta.authMechanism;

    return 'none';
  }

  /**
   * Extract content-type from event headers
   */
  _extractContentType(event) {
    if (!event.headers) return null;
    const lower = {};
    for (const [k, v] of Object.entries(event.headers)) lower[k.toLowerCase()] = v;
    return lower['content-type'] || null;
  }

  /**
   * Check if a path corresponds to an auth endpoint
   */
  _isAuthEndpoint(pathname) {
    const authPatterns = [
      /\/api\/users\/me\/?/,
      /\/auth\//,
      /\/login/,
      /\/logout/,
      /\/token/,
      /\/oauth/,
      /\/session/,
      /\/2fa/,
      /\/verify/,
      /\/refresh/,
    ];
    return authPatterns.some(p => p.test(pathname));
  }

  /**
   * Classify cookie sensitivity based on name
   */
  _classifyCookieSensitivity(name) {
    // Direct match
    if (COOKIE_SENSITIVITY[name]) return COOKIE_SENSITIVITY[name];

    // Partial match (suffix/prefix patterns)
    const lower = name.toLowerCase();
    if (lower.includes('access') || lower.includes('auth')) return 'critical';
    if (lower.includes('session') || lower.includes('jwt')) return 'high';
    if (lower.includes('csrf') || lower.includes('xsrf')) return 'medium';
    if (lower.includes('refresh') || lower.includes('id_token')) return 'high';
    if (lower.includes('track') || lower.includes('analytics') || lower.includes('_ga')) return 'low';

    return 'low';
  }

  /**
   * Return the higher of two sensitivity levels
   */
  _higherSensitivity(a, b) {
    const order = { critical: 4, high: 3, medium: 2, low: 1 };
    return (order[a] || 0) >= (order[b] || 0) ? a : b;
  }

  /**
   * Compute risk summary from assets
   */
  _computeRiskSummary(endpoints, cookies, websockets) {
    let unauthenticatedEndpoints = 0;
    let missingCsrfEndpoints = 0;
    let insecureCookies = 0;
    let authDesyncSockets = 0;
    let totalRiskFlags = 0;

    for (const ep of endpoints) {
      if (ep.risk_flags.includes('no_auth')) unauthenticatedEndpoints++;
      if (ep.risk_flags.includes('missing_csrf')) missingCsrfEndpoints++;
      totalRiskFlags += ep.risk_flags.length;
    }

    for (const ck of cookies) {
      if (ck.risk_flags.length > 0 && ck.is_auth) insecureCookies++;
      totalRiskFlags += ck.risk_flags.length;
    }

    for (const ws of websockets) {
      if ((ws.risk_flags || []).includes('auth_desync')) authDesyncSockets++;
      totalRiskFlags += (ws.risk_flags || []).length;
    }

    return {
      unauthenticated_endpoints: unauthenticatedEndpoints,
      missing_csrf_endpoints: missingCsrfEndpoints,
      insecure_cookies: insecureCookies,
      auth_desync_sockets: authDesyncSockets,
      total_risk_flags: totalRiskFlags,
    };
  }

  /**
   * Return empty risk summary
   */
  _emptyRiskSummary() {
    return {
      unauthenticated_endpoints: 0,
      missing_csrf_endpoints: 0,
      insecure_cookies: 0,
      auth_desync_sockets: 0,
      total_risk_flags: 0,
    };
  }
}

module.exports = { AssetMapper };

