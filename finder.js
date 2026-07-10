/**
 * BOQA finder.js — Hypothesis Engine
 *
 * Scans observability data (events, anomalies, risk flags, auth report,
 * baseline, diff) and generates candidate findings across 19 categories.
 *
 * Pipeline: observations → hypotheses → (validator) → (evidence) → (risk) → findings
 *
 * Safe mode: observations only, no exploitation, no privilege escalation.
 */

const crypto = require('crypto');

// ─── Finding Categories ─────────────────────────────────────────────

const CATEGORIES = [
  'missing_httpOnly',
  'missing_secure',
  'weak_samesite',
  'bearer_token_exposure',
  'jwt_in_browser_memory',
  'session_fixation_indicators',
  'session_rotation_failure',
  'cache_control_misconfiguration',
  'csrf_signal_anomaly',
  'cors_misconfiguration',
  'cookie_scope_oversharing',
  'cross_subdomain_trust_expansion',
  'unexpected_auth_model_change',
  'sensitive_data_exposure',
  'excessive_client_side_secrets',
  'auth_state_desynchronization',
  'ws_auth_inconsistency',
  'permission_boundary_anomaly',
  'regression_security_change',
];

// ─── Hypothesis Schema ──────────────────────────────────────────────

// {
//   id: string,
//   category: string,
//   title: string,
//   description: string,
//   observed: object,       // raw observations that triggered this hypothesis
//   affected_cookies: [],
//   affected_endpoints: [],
//   confidence: 0-100,     // initial confidence before validation
//   severity_hint: string,  // info|low|medium|high|critical
//   created_at: number,
//   source: string,         // which detector generated this
// }

class HypothesisEngine {
  constructor() {
    this.hypotheses = [];
    this._detectors = [
      this._detectMissingHttpOnly,
      this._detectMissingSecure,
      this._detectWeakSameSite,
      this._detectBearerTokenExposure,
      this._detectJwtInBrowserMemory,
      this._detectSessionFixation,
      this._detectSessionRotationFailure,
      this._detectCacheControlMisconfiguration,
      this._detectCsrfSignalAnomaly,
      this._detectCorsMisconfiguration,
      this._detectCookieScopeOversharing,
      this._detectCrossSubdomainTrust,
      this._detectAuthModelChange,
      this._detectSensitiveDataExposure,
      this._detectExcessiveClientSideSecrets,
      this._detectAuthStateDesync,
      this._detectWsAuthInconsistency,
      this._detectPermissionBoundaryAnomaly,
      this._detectRegressionSecurityChange,
    ];
  }

  /**
   * Run all detectors against a complete observation set
   * @param {object} observations - { events, report, anomalies, baseline, diff }
   * @returns {array} hypotheses
   */
  analyze(observations) {
    const { events = [], report = {}, anomalies = [], baseline = null, diff = null } = observations;

    this.hypotheses = [];

    for (const detector of this._detectors) {
      try {
        const results = detector.call(this, { events, report, anomalies, baseline, diff });
        if (Array.isArray(results)) {
          for (const h of results) {
            this.hypotheses.push(this._normalizeHypothesis(h));
          }
        }
      } catch (err) {
        // Detector failure must not break the pipeline
        console.warn(`[Finder] Detector error: ${err.message}`);
      }
    }

    return this.hypotheses;
  }

  /**
   * Run a single incremental check on a new event (for real-time streaming)
   * @param {object} event - single normalized event
   * @param {object} context - { report, anomalies, baseline }
   * @returns {array} new hypotheses from this event
   */
  ingestEvent(event, context = {}) {
    const newHypotheses = [];

    // Real-time checks that can fire on individual events
    if (event.type === 'network_response') {
      // Cache-Control check
      const h = this._checkCacheControlOnResponse(event);
      if (h) newHypotheses.push(this._normalizeHypothesis(h));

      // CORS check
      const corsH = this._checkCorsOnResponse(event);
      if (corsH) newHypotheses.push(this._normalizeHypothesis(corsH));
    }

    if (event.type === 'auth_signal') {
      // Session fixation check
      const fixH = this._checkSessionFixationOnAuth(event, context);
      if (fixH) newHypotheses.push(this._normalizeHypothesis(fixH));

      // Auth state desync check
      const desyncH = this._checkAuthDesyncOnAuth(event, context);
      if (desyncH) newHypotheses.push(this._normalizeHypothesis(desyncH));
    }

    if (event.type === 'websocket_open' || event.type === 'websocket_message_in') {
      const wsH = this._checkWsAuthOnMessage(event, context);
      if (wsH) newHypotheses.push(this._normalizeHypothesis(wsH));
    }

    if (event.type === 'cookie_snapshot') {
      const cookieH = this._checkCookieAttributesOnSnapshot(event);
      if (cookieH) newHypotheses.push(cookieH.map(h => this._normalizeHypothesis(h)));
    }

    const flat = newHypotheses.flat();
    this.hypotheses.push(...flat);
    return flat;
  }

  // ─── Detectors ────────────────────────────────────────────────

  /**
   * MISSING_HTTPONLY: Auth cookies lacking HttpOnly flag
   */
  _detectMissingHttpOnly({ report }) {
    const hypotheses = [];
    const cookies = report.cookies || [];
    const authCookieNames = new Set([
      'ripio_access', 'sessionid', 'csrftoken',
      'access_token', 'refresh_token', 'auth_token',
      'id_token', '_jwt', '_session',
    ]);

    for (const c of cookies) {
      if (authCookieNames.has(c.name) && !c.httpOnly) {
        hypotheses.push({
          category: 'missing_httpOnly',
          title: `Auth cookie "${c.name}" missing HttpOnly flag`,
          description: `The authentication cookie "${c.name}" is accessible to JavaScript because the HttpOnly flag is not set. This allows XSS attacks to steal session credentials. Cookie domain: ${c.domain || 'unknown'}.`,
          observed: { cookie_name: c.name, domain: c.domain, httpOnly: c.httpOnly, secure: c.secure },
          affected_cookies: [c.name],
          affected_endpoints: [],
          confidence: 92,
          severity_hint: 'high',
          source: 'cookie_attribute_scanner',
        });
      }
    }

    return hypotheses;
  }

  /**
   * MISSING_SECURE: Auth cookies lacking Secure flag
   */
  _detectMissingSecure({ report }) {
    const hypotheses = [];
    const cookies = report.cookies || [];
    const authCookieNames = new Set([
      'ripio_access', 'sessionid', 'csrftoken',
      'access_token', 'refresh_token', 'auth_token',
    ]);

    for (const c of cookies) {
      if (authCookieNames.has(c.name) && !c.secure) {
        hypotheses.push({
          category: 'missing_secure',
          title: `Auth cookie "${c.name}" missing Secure flag`,
          description: `The authentication cookie "${c.name}" is transmitted over unencrypted connections because the Secure flag is not set. An active network attacker can intercept this cookie via HTTP. Domain: ${c.domain || 'unknown'}.`,
          observed: { cookie_name: c.name, domain: c.domain, httpOnly: c.httpOnly, secure: c.secure },
          affected_cookies: [c.name],
          affected_endpoints: [],
          confidence: 90,
          severity_hint: 'high',
          source: 'cookie_attribute_scanner',
        });
      }
    }

    return hypotheses;
  }

  /**
   * WEAK_SAMESITE: Auth cookies with None or missing SameSite
   */
  _detectWeakSameSite({ report }) {
    const hypotheses = [];
    const cookies = report.cookies || [];
    const authCookieNames = new Set([
      'ripio_access', 'sessionid', 'csrftoken',
      'access_token', 'refresh_token', 'auth_token',
    ]);

    for (const c of cookies) {
      if (authCookieNames.has(c.name) && (!c.sameSite || c.sameSite === 'None' || c.sameSite === 'none')) {
        hypotheses.push({
          category: 'weak_samesite',
          title: `Auth cookie "${c.name}" has weak SameSite attribute`,
          description: `The authentication cookie "${c.name}" has SameSite=${c.sameSite || '(unset)'}, making it vulnerable to CSRF attacks. Browsers will send this cookie with cross-site requests. Recommended: SameSite=Strict or SameSite=Lax.`,
          observed: { cookie_name: c.name, sameSite: c.sameSite, domain: c.domain },
          affected_cookies: [c.name],
          affected_endpoints: [],
          confidence: 85,
          severity_hint: 'medium',
          source: 'cookie_attribute_scanner',
        });
      }
    }

    return hypotheses;
  }

  /**
   * BEARER_TOKEN_EXPOSURE: Bearer tokens visible in request headers from JS
   */
  _detectBearerTokenExposure({ events, report }) {
    const hypotheses = [];
    const bearerUrls = new Set();

    // Check events for Authorization headers on non-API paths
    for (const e of events) {
      if (e.type === 'network_request' && e.headers) {
        const lower = {};
        for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;
        if (lower['authorization'] && e.url) {
          try {
            const u = new URL(e.url);
            // Bearer on static assets or cross-origin is suspicious
            const isStatic = /\.(js|css|png|jpg|svg|ico|woff|woff2)/.test(u.pathname);
            const isCrossOrigin = u.origin !== new URL(e.url).origin;
            if (isStatic || isCrossOrigin) {
              bearerUrls.add(u.pathname);
            }
          } catch (_) {}
        }
      }
    }

    if (bearerUrls.size > 0) {
      hypotheses.push({
        category: 'bearer_token_exposure',
        title: 'Bearer token sent to non-API endpoints',
        description: `Authorization header detected in requests to ${bearerUrls.size} non-API path(s): ${[...bearerUrls].slice(0, 5).join(', ')}. Sending tokens to static or cross-origin endpoints increases the risk of token leakage via referer headers, logs, or misconfigured CORS.`,
        observed: { bearer_on_paths: [...bearerUrls] },
        affected_cookies: [],
        affected_endpoints: [...bearerUrls],
        confidence: 75,
        severity_hint: 'medium',
        source: 'bearer_exposure_scanner',
      });
    }

    // Bearer in report + no HttpOnly = exposure
    if (report.bearer_detected) {
      const cookies = report.cookies || [];
      const nonHttpOnlyAuth = cookies.filter(c =>
        !c.httpOnly && ['ripio_access', 'access_token', 'id_token', '_jwt'].includes(c.name)
      );
      if (nonHttpOnlyAuth.length > 0) {
        hypotheses.push({
          category: 'bearer_token_exposure',
          title: 'Bearer token pattern in non-HttpOnly cookie',
          description: `Bearer token usage detected alongside non-HttpOnly auth cookies: ${nonHttpOnlyAuth.map(c => c.name).join(', ')}. JavaScript can read these cookies, enabling token theft via XSS.`,
          observed: { bearer_detected: true, non_httpOnly_cookies: nonHttpOnlyAuth.map(c => c.name) },
          affected_cookies: nonHttpOnlyAuth.map(c => c.name),
          affected_endpoints: [],
          confidence: 88,
          severity_hint: 'high',
          source: 'bearer_cookie_correlation',
        });
      }
    }

    return hypotheses;
  }

  /**
   * JWT_IN_BROWSER_MEMORY: JWT decode detected in browser JS
   */
  _detectJwtInBrowserMemory({ events, report }) {
    const hypotheses = [];

    // Check for CryptoJS.AES.decrypt events (Ripio-specific)
    const decryptEvents = events.filter(e =>
      e.type === 'console_log' && e.payload &&
      (e.payload.includes('CryptoJS.AES.decrypt') || e.payload.includes('__BOQA__aes_decrypt'))
    );

    if (decryptEvents.length > 0 || (report.risk_flags || []).some(f => f.flag === 'jwt_in_js_memory')) {
      hypotheses.push({
        category: 'jwt_in_browser_memory',
        title: 'JWT decrypted in browser JavaScript memory',
        description: `A JWT or encrypted token is being decrypted client-side using CryptoJS.AES.decrypt, making the plaintext token available in JavaScript memory. The encrypted cookie (prefix U2FsdGVkX1) is decrypted in the browser, meaning any XSS can access the raw token. ${decryptEvents.length} decrypt event(s) observed.`,
        observed: { decrypt_event_count: decryptEvents.length, risk_flag_present: true },
        affected_cookies: ['ripio_access'],
        affected_endpoints: [],
        confidence: 95,
        severity_hint: 'critical',
        source: 'client_side_decryption_scanner',
      });
    }

    return hypotheses;
  }

  /**
   * SESSION_FIXATION_INDICATORS: Session cookie not rotating after auth
   */
  _detectSessionFixation({ events, report }) {
    const hypotheses = [];
    const sessionCookieSnapshots = [];

    // Collect all cookie snapshots that contain sessionid
    for (const e of events) {
      if (e.type === 'cookie_snapshot' && e.meta?.authCookies) {
        const sessionid = e.meta.authCookies.find(c => c.name === 'sessionid');
        if (sessionid) {
          sessionCookieSnapshots.push({ ts: e.ts, value: sessionid.valuePreview || sessionid.value });
        }
      }
      if (e.type === 'auth_signal' && e.meta?.cookies) {
        const sessionid = e.meta.cookies.find(c => c.name === 'sessionid');
        if (sessionid) {
          sessionCookieSnapshots.push({ ts: e.ts, value: sessionid.valuePreview || sessionid.value });
        }
      }
    }

    // Check if sessionid remained the same across login events
    if (sessionCookieSnapshots.length >= 2) {
      const first = sessionCookieSnapshots[0].value;
      const last = sessionCookieSnapshots[sessionCookieSnapshots.length - 1].value;
      const authEvents = events.filter(e => e.type === 'auth_signal');
      const loginEvents = authEvents.filter(e =>
        e.meta?.signalType === 'auth_cookie_set' || (e.url && /\/login|\/auth\//.test(e.url))
      );

      if (first === last && loginEvents.length > 0 && first && first !== '(hidden)') {
        hypotheses.push({
          category: 'session_fixation_indicators',
          title: 'Session cookie not rotated after authentication',
          description: `The "sessionid" cookie remained unchanged (${first?.substring(0, 8)}...) across ${loginEvents.length} login/auth events. Session fixation is possible if the server does not issue a new session ID after authentication. ${sessionCookieSnapshots.length} snapshots observed.`,
          observed: { first_value: first?.substring(0, 16), last_value: last?.substring(0, 16), auth_events: loginEvents.length, unchanged: true },
          affected_cookies: ['sessionid'],
          affected_endpoints: loginEvents.map(e => e.url).filter(Boolean),
          confidence: 70,
          severity_hint: 'high',
          source: 'session_rotation_tracker',
        });
      }
    }

    return hypotheses;
  }

  /**
   * SESSION_ROTATION_FAILURE: Session cookies rotate too frequently or not at all
   */
  _detectSessionRotationFailure({ events, anomalies }) {
    const hypotheses = [];

    // Check anomaly-based rotation failure
    const rotationAnomalies = anomalies.filter(a =>
      a.rule === 'auth_model_change' || a.rule === 'cookie_httpOnly_downgrade'
    );

    // Check if sessionid appeared and disappeared rapidly
    const sessionAppearances = [];
    for (const e of events) {
      if (e.type === 'auth_signal' && e.meta?.cookies) {
        const hasSession = e.meta.cookies.some(c => c.name === 'sessionid');
        if (hasSession) sessionAppearances.push(e.ts);
      }
    }

    // Rapid rotation: > 3 different sessionid values in 60s
    if (sessionAppearances.length > 5) {
      const spans = [];
      for (let i = 1; i < sessionAppearances.length; i++) {
        spans.push(sessionAppearances[i] - sessionAppearances[i - 1]);
      }
      const avgSpan = spans.reduce((s, v) => s + v, 0) / spans.length;
      if (avgSpan < 10000 && sessionAppearances.length > 3) { // < 10s average
        hypotheses.push({
          category: 'session_rotation_failure',
          title: 'Excessive session rotation detected',
          description: `Session cookie changed ${sessionAppearances.length} times with an average interval of ${(avgSpan / 1000).toFixed(1)}s. Excessive rotation may indicate session management issues or could be exploited for session hijacking via race conditions.`,
          observed: { rotation_count: sessionAppearances.length, avg_interval_ms: Math.round(avgSpan) },
          affected_cookies: ['sessionid'],
          affected_endpoints: [],
          confidence: 60,
          severity_hint: 'medium',
          source: 'session_rotation_tracker',
        });
      }
    }

    return hypotheses;
  }

  /**
   * CACHE_CONTROL_MISCONFIGURATION: Sensitive responses missing cache headers
   */
  _detectCacheControlMisconfiguration({ events }) {
    const hypotheses = [];
    const sensitivePaths = new Set();

    for (const e of events) {
      if (e.type === 'network_response' && e.url && e.headers) {
        const lower = {};
        for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;

        // Check if this is a sensitive endpoint (auth, user data)
        const isSensitive = /\/api\/users|\/auth\/|\/session|\/me\/?|\/wallet|\/balance|\/account/.test(e.url);
        if (!isSensitive) continue;

        const cc = lower['cache-control'] || '';
        const pragma = lower['pragma'] || '';
        const hasNoStore = cc.includes('no-store') || cc.includes('no-cache') || pragma.includes('no-cache');

        if (!hasNoStore && e.status && e.status >= 200 && e.status < 400) {
          try {
            sensitivePaths.add(new URL(e.url).pathname);
          } catch (_) {}
        }
      }
    }

    if (sensitivePaths.size > 0) {
      hypotheses.push({
        category: 'cache_control_misconfiguration',
        title: 'Sensitive endpoints missing Cache-Control: no-store',
        description: `${sensitivePaths.size} sensitive endpoint(s) lack Cache-Control: no-store headers. Auth/user data responses may be cached by intermediate proxies or the browser, exposing sensitive data. Affected paths: ${[...sensitivePaths].slice(0, 5).join(', ')}.`,
        observed: { paths_missing_cache_control: [...sensitivePaths] },
        affected_cookies: [],
        affected_endpoints: [...sensitivePaths],
        confidence: 82,
        severity_hint: 'medium',
        source: 'cache_header_scanner',
      });
    }

    return hypotheses;
  }

  /**
   * CSRF_SIGNAL_ANOMALY: Cookie auth without CSRF protection
   */
  _detectCsrfSignalAnomaly({ report, events }) {
    const hypotheses = [];

    // Cookie auth but no CSRF header
    if (report.auth_model === 'cookie' || report.auth_model === 'hybrid') {
      const hasCsrf = (report.risk_flags || []).some(f => f.flag === 'csrf_present');
      const csrfMissing = (report.risk_flags || []).some(f => f.flag === 'csrf_missing');

      if (csrfMissing || (!hasCsrf && report.auth_model !== 'bearer')) {
        // Check if there are state-modifying requests without CSRF
        const stateChangingMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
        const unsafeRequests = events.filter(e =>
          e.type === 'network_request' && stateChangingMethods.has(e.method)
        );

        hypotheses.push({
          category: 'csrf_signal_anomaly',
          title: 'Cookie-based auth without CSRF protection on state-changing requests',
          description: `Auth model is "${report.auth_model}" (cookie-based) but no CSRF token header detected. ${unsafeRequests.length} state-changing request(s) (POST/PUT/PATCH/DELETE) were observed without CSRF protection. This enables cross-site request forgery attacks.`,
          observed: { auth_model: report.auth_model, unsafe_request_count: unsafeRequests.length, csrf_detected: hasCsrf },
          affected_cookies: ['sessionid', 'csrftoken'],
          affected_endpoints: unsafeRequests.map(e => {
            try { return `${e.method} ${new URL(e.url).pathname}`; } catch (_) { return null; }
          }).filter(Boolean).slice(0, 10),
          confidence: 85,
          severity_hint: 'high',
          source: 'csrf_protection_scanner',
        });
      }
    }

    return hypotheses;
  }

  /**
   * CORS_MISCONFIGURATION: Overly permissive CORS headers
   */
  _detectCorsMisconfiguration({ events }) {
    const hypotheses = [];
    const wildcardOrigins = new Set();
    const credentialedWildcard = new Set();

    for (const e of events) {
      if (e.type === 'network_response' && e.headers) {
        const lower = {};
        for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;

        const acao = lower['access-control-allow-origin'] || '';
        const acac = lower['access-control-allow-credentials'] || '';

        if (acao === '*') {
          try { wildcardOrigins.add(new URL(e.url).pathname); } catch (_) {}
        }

        // Wildcard + credentials = critical
        if (acao === '*' && acac === 'true') {
          try { credentialedWildcard.add(new URL(e.url).pathname); } catch (_) {}
        }

        // Reflect any origin
        if (acao && acao !== '*' && e.meta?.requestOrigin && acao === e.meta.requestOrigin) {
          try { wildcardOrigins.add(`${new URL(e.url).pathname} (reflects origin)`); } catch (_) {}
        }
      }
    }

    if (credentialedWildcard.size > 0) {
      hypotheses.push({
        category: 'cors_misconfiguration',
        title: 'CORS allows wildcard origin with credentials',
        description: `${credentialedWildcard.size} endpoint(s) return Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. This is explicitly forbidden by the CORS spec but some browsers may still allow it. Paths: ${[...credentialedWildcard].slice(0, 5).join(', ')}.`,
        observed: { credentialed_wildcard_paths: [...credentialedWildcard] },
        affected_cookies: [],
        affected_endpoints: [...credentialedWildcard],
        confidence: 95,
        severity_hint: 'critical',
        source: 'cors_header_scanner',
      });
    }

    if (wildcardOrigins.size > 0 && credentialedWildcard.size === 0) {
      hypotheses.push({
        category: 'cors_misconfiguration',
        title: 'CORS allows wildcard origin on API endpoints',
        description: `${wildcardOrigins.size} endpoint(s) return Access-Control-Allow-Origin: *. While credentials are not explicitly allowed, wildcard CORS on API endpoints may still expose data. Paths: ${[...wildcardOrigins].slice(0, 5).join(', ')}.`,
        observed: { wildcard_paths: [...wildcardOrigins] },
        affected_cookies: [],
        affected_endpoints: [...wildcardOrigins],
        confidence: 70,
        severity_hint: 'medium',
        source: 'cors_header_scanner',
      });
    }

    return hypotheses;
  }

  /**
   * COOKIE_SCOPE_OVERSHARING: Cookies with overly broad path or domain
   */
  _detectCookieScopeOversharing({ report }) {
    const hypotheses = [];
    const cookies = report.cookies || [];

    for (const c of cookies) {
      const isAuth = ['ripio_access', 'sessionid', 'csrftoken', 'access_token'].includes(c.name);
      if (!isAuth) continue;

      // Path = / means cookie is sent to every request
      if (c.path === '/' || !c.path) {
        // Domain starting with . means subdomains included
        const domain = c.domain || '';
        const isBroadDomain = domain.startsWith('.') && domain.split('.').length <= 3;

        if (isBroadDomain) {
          hypotheses.push({
            category: 'cookie_scope_oversharing',
            title: `Auth cookie "${c.name}" has overly broad scope`,
            description: `The auth cookie "${c.name}" is scoped to path "/" on domain "${domain}", meaning it is sent with every request to every subdomain. This increases the attack surface for session hijacking via any subdomain compromise.`,
            observed: { cookie_name: c.name, path: c.path, domain: c.domain },
            affected_cookies: [c.name],
            affected_endpoints: [],
            confidence: 80,
            severity_hint: 'medium',
            source: 'cookie_scope_scanner',
          });
        }
      }
    }

    return hypotheses;
  }

  /**
   * CROSS_SUBDOMAIN_TRUST_EXPANSION: New subdomains receiving auth cookies
   */
  _detectCrossSubdomainTrust({ events, baseline }) {
    const hypotheses = [];
    if (!baseline) return hypotheses;

    const blCookies = baseline.fingerprint?.cookie_schema || [];
    const currentCookieDomains = new Set();
    const baselineCookieDomains = new Set();

    // Collect current cookie domains from events
    for (const e of events) {
      if (e.type === 'cookie_snapshot' && e.meta?.authCookies) {
        for (const c of e.meta.authCookies) {
          if (c.domain) currentCookieDomains.add(c.domain);
        }
      }
    }

    for (const c of blCookies) {
      if (c.domain) baselineCookieDomains.add(c.domain);
    }

    // New domains not in baseline
    const newDomains = [...currentCookieDomains].filter(d => !baselineCookieDomains.has(d));
    if (newDomains.length > 0) {
      hypotheses.push({
        category: 'cross_subdomain_trust_expansion',
        title: 'Auth cookies now sent to new subdomains',
        description: `Auth cookies are now being sent to ${newDomains.length} domain(s) not present in the baseline: ${newDomains.join(', ')}. This may indicate a trust boundary expansion where auth state is shared with additional subdomains.`,
        observed: { new_domains: newDomains, baseline_domains: [...baselineCookieDomains] },
        affected_cookies: [],
        affected_endpoints: [],
        confidence: 72,
        severity_hint: 'medium',
        source: 'subdomain_trust_scanner',
      });
    }

    return hypotheses;
  }

  /**
   * UNEXPECTED_AUTH_MODEL_CHANGE: Auth model changed from baseline
   */
  _detectAuthModelChange({ report, baseline, anomalies }) {
    const hypotheses = [];
    if (!baseline) return hypotheses;

    const blModel = baseline.fingerprint?.auth_model;
    const currentModel = report.auth_model;

    if (blModel && currentModel && blModel !== 'unknown' && currentModel !== 'unknown' && blModel !== currentModel) {
      hypotheses.push({
        category: 'unexpected_auth_model_change',
        title: `Auth model changed: ${blModel} → ${currentModel}`,
        description: `The authentication model has shifted from "${blModel}" to "${currentModel}". This could indicate an architectural change, a misconfiguration, or an active attack. Anomaly detection also flagged this: ${anomalies.filter(a => a.rule === 'auth_model_change').length} related anomaly(ies).`,
        observed: { from: blModel, to: currentModel },
        affected_cookies: [],
        affected_endpoints: [],
        confidence: 90,
        severity_hint: 'high',
        source: 'auth_model_change_detector',
      });
    }

    return hypotheses;
  }

  /**
   * SENSITIVE_DATA_EXPOSURE: Sensitive data in URLs or client-visible responses
   */
  _detectSensitiveDataExposure({ events }) {
    const hypotheses = [];
    const sensitiveInUrls = new Set();
    const sensitivePatterns = [
      { pattern: /token=[^&]+/i, label: 'token in query string' },
      { pattern: /api_key=[^&]+/i, label: 'API key in query string' },
      { pattern: /password=[^&]+/i, label: 'password in query string' },
      { pattern: /secret=[^&]+/i, label: 'secret in query string' },
    ];

    for (const e of events) {
      if (e.type === 'network_request' && e.url) {
        for (const sp of sensitivePatterns) {
          if (sp.pattern.test(e.url)) {
            try {
              const u = new URL(e.url);
              sensitiveInUrls.add(`${sp.label}: ${u.pathname}`);
            } catch (_) {}
          }
        }
      }
    }

    if (sensitiveInUrls.size > 0) {
      hypotheses.push({
        category: 'sensitive_data_exposure',
        title: 'Sensitive data exposed in URL query strings',
        description: `${sensitiveInUrls.size} instance(s) of sensitive data in URL query parameters detected: ${[...sensitiveInUrls].slice(0, 5).join('; ')}. Query strings are logged in browser history, server access logs, and referer headers, making them unsafe for sensitive data.`,
        observed: { sensitive_url_patterns: [...sensitiveInUrls] },
        affected_cookies: [],
        affected_endpoints: [...sensitiveInUrls],
        confidence: 88,
        severity_hint: 'high',
        source: 'url_sensitive_data_scanner',
      });
    }

    return hypotheses;
  }

  /**
   * EXCESSIVE_CLIENT_SIDE_SECRETS: Too many secrets accessible from JS
   */
  _detectExcessiveClientSideSecrets({ events, report }) {
    const hypotheses = [];
    const jsAccessibleSecrets = [];

    // Non-HttpOnly auth cookies = JS-accessible
    const cookies = report.cookies || [];
    for (const c of cookies) {
      if (!c.httpOnly && ['ripio_access', 'sessionid', 'csrftoken', 'access_token', 'refresh_token', 'auth_token', 'id_token'].includes(c.name)) {
        jsAccessibleSecrets.push({ type: 'cookie', name: c.name });
      }
    }

    // LocalStorage secrets detected by instrumentation
    for (const e of events) {
      if (e.type === 'console_log' && e.payload && e.payload.includes('__BOQA__localStorage')) {
        jsAccessibleSecrets.push({ type: 'localStorage', name: 'detected_item' });
      }
    }

    if (jsAccessibleSecrets.length >= 3) {
      hypotheses.push({
        category: 'excessive_client_side_secrets',
        title: `${jsAccessibleSecrets.length} secrets accessible to client-side JavaScript`,
        description: `The browser has ${jsAccessibleSecrets.length} authentication-related secrets accessible to JavaScript: ${jsAccessibleSecrets.map(s => `${s.type}:${s.name}`).join(', ')}. Excessive client-side secrets amplify the impact of any XSS vulnerability. Each accessible secret is an additional attack vector.`,
        observed: { secret_count: jsAccessibleSecrets.length, secrets: jsAccessibleSecrets },
        affected_cookies: jsAccessibleSecrets.filter(s => s.type === 'cookie').map(s => s.name),
        affected_endpoints: [],
        confidence: 85,
        severity_hint: 'high',
        source: 'client_secret_counter',
      });
    }

    return hypotheses;
  }

  /**
   * AUTH_STATE_DESYNCHRONIZATION: Cookie and server auth states disagree
   */
  _detectAuthStateDesync({ events, report }) {
    const hypotheses = [];

    // Look for 401/403 after auth cookies are present
    const authCookieSet = [];
    const unauthorizedEvents = [];

    for (const e of events) {
      if (e.type === 'auth_signal' && e.meta?.signalType === 'auth_cookie_set') {
        authCookieSet.push(e.ts);
      }
      if (e.type === 'auth_signal' && (e.meta?.signalType === 'unauthorized' || e.meta?.signalType === 'forbidden')) {
        unauthorizedEvents.push({ ts: e.ts, url: e.url, status: e.meta?.signalType });
      }
    }

    // 401/403 after successful auth = desync
    if (authCookieSet.length > 0 && unauthorizedEvents.length > 0) {
      const lastAuth = Math.max(...authCookieSet);
      const postAuth401s = unauthorizedEvents.filter(e => e.ts > lastAuth);

      if (postAuth401s.length >= 2) {
        hypotheses.push({
          category: 'auth_state_desynchronization',
          title: 'Authentication state desynchronization detected',
          description: `${postAuth401s.length} unauthorized/forbidden response(s) occurred after auth cookies were set. This suggests the server-side session state does not match the client-side cookie state. Possible causes: session expiration mismatch, race condition in session creation, or server-side session invalidation not reflected in client cookies.`,
          observed: { post_auth_401_count: postAuth401s.length, last_auth_ts: lastAuth, failed_urls: postAuth401s.map(e => e.url).filter(Boolean).slice(0, 5) },
          affected_cookies: ['sessionid', 'ripio_access'],
          affected_endpoints: postAuth401s.map(e => e.url).filter(Boolean),
          confidence: 75,
          severity_hint: 'high',
          source: 'auth_desync_detector',
        });
      }
    }

    return hypotheses;
  }

  /**
   * WS_AUTH_INCONSISTENCY: WebSocket auth differs from HTTP auth
   */
  _detectWsAuthInconsistency({ events }) {
    const hypotheses = [];
    const wsAuthEvents = [];

    for (const e of events) {
      if (e.type === 'websocket_open' && e.meta) {
        const hasToken = e.meta.authToken || e.meta.token;
        const hasCookie = e.meta.cookies;
        wsAuthEvents.push({ ts: e.ts, url: e.url, hasToken, hasCookie, auth: e.meta.auth });
      }
    }

    // Check if some WS connections have auth and others don't
    const withAuth = wsAuthEvents.filter(e => e.hasToken || e.hasCookie || e.auth);
    const withoutAuth = wsAuthEvents.filter(e => !e.hasToken && !e.hasCookie && !e.auth);

    if (withAuth.length > 0 && withoutAuth.length > 0) {
      hypotheses.push({
        category: 'ws_auth_inconsistency',
        title: 'Inconsistent authentication across WebSocket connections',
        description: `${withAuth.length} WebSocket connection(s) have authentication while ${withoutAuth.length} do not. Inconsistent auth on WebSocket channels may allow unauthenticated access to authenticated data streams. URLs: ${wsAuthEvents.map(e => e.url).filter(Boolean).slice(0, 3).join(', ')}.`,
        observed: { ws_with_auth: withAuth.length, ws_without_auth: withoutAuth.length },
        affected_cookies: [],
        affected_endpoints: wsAuthEvents.map(e => e.url).filter(Boolean),
        confidence: 70,
        severity_hint: 'medium',
        source: 'ws_auth_scanner',
      });
    }

    return hypotheses;
  }

  /**
   * PERMISSION_BOUNDARY_ANOMALY: User accessing admin/privileged endpoints
   */
  _detectPermissionBoundaryAnomaly({ events }) {
    const hypotheses = [];
    const adminEndpoints = new Set();

    const adminPatterns = [
      /\/admin\//i, /\/manage\//i, /\/dashboard\/config/i,
      /\/api\/admin/i, /\/api\/config/i, /\/internal\//i,
      /\/debug\//i, /\/_debug/i, /\/graphql/i,
    ];

    for (const e of events) {
      if (e.type === 'network_response' && e.url && e.status) {
        if (e.status >= 200 && e.status < 300) {
          for (const p of adminPatterns) {
            if (p.test(e.url)) {
              try { adminEndpoints.add(new URL(e.url).pathname); } catch (_) {}
              break;
            }
          }
        }
      }
    }

    if (adminEndpoints.size > 0) {
      hypotheses.push({
        category: 'permission_boundary_anomaly',
        title: 'Potential permission boundary violation',
        description: `${adminEndpoints.size} admin/privileged endpoint(s) returned successful responses: ${[...adminEndpoints].slice(0, 5).join(', ')}. If this is a non-admin user, these endpoints should not be accessible. This may indicate missing authorization checks.`,
        observed: { admin_endpoints: [...adminEndpoints] },
        affected_cookies: [],
        affected_endpoints: [...adminEndpoints],
        confidence: 55,
        severity_hint: 'medium',
        source: 'permission_boundary_scanner',
      });
    }

    return hypotheses;
  }

  /**
   * REGRESSION_SECURITY_CHANGE: Security posture regressed from baseline
   */
  _detectRegressionSecurityChange({ diff, baseline }) {
    const hypotheses = [];
    if (!diff) return hypotheses;

    // Cookie attribute downgrades in diff
    const cookieDowngrades = (diff.cookie_diff || []).filter(cd =>
      cd.type === 'cookie_httpOnly_downgrade' || cd.type === 'cookie_secure_downgrade' || cd.type === 'cookie_sameSite_downgrade'
    );

    if (cookieDowngrades.length > 0) {
      hypotheses.push({
        category: 'regression_security_change',
        title: 'Security regression: cookie attributes downgraded',
        description: `${cookieDowngrades.length} cookie attribute downgrade(s) detected compared to baseline: ${cookieDowngrades.map(cd => `${cd.name}: ${cd.type}`).join(', ')}. This indicates a security regression where previously protected cookies are now less secure.`,
        observed: { downgrades: cookieDowngrades },
        affected_cookies: cookieDowngrades.map(cd => cd.name),
        affected_endpoints: [],
        confidence: 90,
        severity_hint: 'high',
        source: 'regression_detector',
      });
    }

    // Risk flag increase
    const addedRisks = (diff.risk_delta?.added || []);
    if (addedRisks.length > 0) {
      hypotheses.push({
        category: 'regression_security_change',
        title: 'Security regression: new risk flags introduced',
        description: `${addedRisks.length} new risk flag(s) appeared compared to baseline: ${addedRisks.join(', ')}. These represent a degradation in the application's security posture.`,
        observed: { added_risks: addedRisks },
        affected_cookies: [],
        affected_endpoints: [],
        confidence: 85,
        severity_hint: 'medium',
        source: 'regression_detector',
      });
    }

    // Severity score increase
    if (diff.severity_score >= 40) {
      hypotheses.push({
        category: 'regression_security_change',
        title: `Security regression: severity score ${diff.severity_score}/100`,
        description: `The diff between current session and baseline has a severity score of ${diff.severity_score}/100 (verdict: ${diff.verdict}). This indicates meaningful security regression. Added endpoints: ${diff.added_endpoints?.length || 0}. Auth changes: ${diff.auth_changes?.length || 0}.`,
        observed: { severity_score: diff.severity_score, verdict: diff.verdict },
        affected_cookies: [],
        affected_endpoints: diff.added_endpoints || [],
        confidence: 80,
        severity_hint: diff.severity_score >= 70 ? 'critical' : 'high',
        source: 'regression_detector',
      });
    }

    return hypotheses;
  }

  // ─── Real-time Incremental Checks ─────────────────────────────

  _checkCacheControlOnResponse(event) {
    if (!event.headers) return null;
    const lower = {};
    for (const [k, v] of Object.entries(event.headers)) lower[k.toLowerCase()] = v;

    const isSensitive = event.url && /\/api\/users|\/auth\/|\/session|\/me\/?|\/wallet/.test(event.url);
    if (!isSensitive) return null;

    const cc = lower['cache-control'] || '';
    if (!cc.includes('no-store') && !cc.includes('no-cache') && event.status >= 200 && event.status < 400) {
      try {
        const pathname = new URL(event.url).pathname;
        return {
          category: 'cache_control_misconfiguration',
          title: `Missing Cache-Control on ${pathname}`,
          description: `Sensitive response lacks cache-control headers.`,
          observed: { path: pathname, status: event.status },
          affected_cookies: [],
          affected_endpoints: [pathname],
          confidence: 78,
          severity_hint: 'medium',
          source: 'realtime_cache_scanner',
        };
      } catch (_) {}
    }
    return null;
  }

  _checkCorsOnResponse(event) {
    if (!event.headers) return null;
    const lower = {};
    for (const [k, v] of Object.entries(event.headers)) lower[k.toLowerCase()] = v;

    const acao = lower['access-control-allow-origin'] || '';
    const acac = lower['access-control-allow-credentials'] || '';
    if (acao === '*' && acac === 'true') {
      try {
        const pathname = new URL(event.url).pathname;
        return {
          category: 'cors_misconfiguration',
          title: `CORS wildcard+credentials on ${pathname}`,
          description: 'Response has Access-Control-Allow-Origin: * with credentials: true.',
          observed: { path: pathname },
          affected_cookies: [],
          affected_endpoints: [pathname],
          confidence: 93,
          severity_hint: 'critical',
          source: 'realtime_cors_scanner',
        };
      } catch (_) {}
    }
    return null;
  }

  _checkSessionFixationOnAuth(event, context) {
    // Will be accumulated over time in the validator
    return null;
  }

  _checkAuthDesyncOnAuth(event, context) {
    if (event.meta?.signalType === 'unauthorized' || event.meta?.signalType === 'forbidden') {
      return {
        category: 'auth_state_desynchronization',
        title: 'Auth desync: unauthorized after login',
        description: `Received ${event.meta.signalType} after auth cookies were set.`,
        observed: { signal: event.meta.signalType, url: event.url },
        affected_cookies: ['sessionid'],
        affected_endpoints: [event.url].filter(Boolean),
        confidence: 65,
        severity_hint: 'medium',
        source: 'realtime_desync_scanner',
      };
    }
    return null;
  }

  _checkWsAuthOnMessage(event, context) {
    // Track WS auth state for later correlation
    return null;
  }

  _checkCookieAttributesOnSnapshot(event) {
    const hypotheses = [];
    if (!event.meta?.authCookies) return hypotheses;

    const authNames = new Set(['ripio_access', 'sessionid', 'csrftoken', 'access_token', 'refresh_token']);
    for (const c of event.meta.authCookies) {
      if (authNames.has(c.name)) {
        if (!c.httpOnly) {
          hypotheses.push({
            category: 'missing_httpOnly',
            title: `Cookie "${c.name}" missing HttpOnly`,
            description: `Auth cookie lacks HttpOnly flag.`,
            observed: { cookie_name: c.name },
            affected_cookies: [c.name],
            affected_endpoints: [],
            confidence: 90,
            severity_hint: 'high',
            source: 'realtime_cookie_scanner',
          });
        }
      }
    }
    return hypotheses;
  }

  // ─── Helpers ──────────────────────────────────────────────────

  _normalizeHypothesis(h) {
    return {
      id: `hyp-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36) + Math.random().toString(36).substring(2, 6)}`,
      category: h.category || 'unknown',
      title: h.title || 'Untitled hypothesis',
      description: h.description || '',
      observed: h.observed || {},
      affected_cookies: h.affected_cookies || [],
      affected_endpoints: h.affected_endpoints || [],
      confidence: Math.max(0, Math.min(100, h.confidence || 50)),
      severity_hint: h.severity_hint || 'info',
      created_at: Date.now(),
      source: h.source || 'unknown',
    };
  }

  getHypotheses() {
    return this.hypotheses;
  }

  getHypothesesByCategory() {
    const byCategory = {};
    for (const h of this.hypotheses) {
      byCategory[h.category] = byCategory[h.category] || [];
      byCategory[h.category].push(h);
    }
    return byCategory;
  }
}

module.exports = { HypothesisEngine, CATEGORIES };

