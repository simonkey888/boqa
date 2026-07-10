/**
 * BOQA real-bug-detector.js — Real Bug Detection Engine (S6-2)
 *
 * Executes BOQA heuristics on real applications to discover genuine bugs.
 * Uses the existing Agent infrastructure (Playwright instrumentation,
 * AnomalyEngine, auth pattern detection) and adds dedicated detectors for:
 *
 *   - DOM anomalies (missing elements, broken layouts, invisible content)
 *   - Navigation failures (404s, unexpected redirects, SPA routing errors)
 *   - Console errors (uncaught exceptions, unhandled promise rejections)
 *   - Unexpected redirects (301/302 chains, meta refresh, JS redirects)
 *   - HTTP failures (5xx, timeout, mixed content)
 *   - Cookie anomalies (missing SameSite, HttpOnly downgrade, expired)
 *   - Storage anomalies (quota exceeded, inaccessible, corrupted)
 *   - Authentication inconsistencies (login state mismatch, session drift)
 *   - Race conditions (concurrent state mutations, double-submits)
 *   - State corruption (form state lost, cart emptied, CSRF mismatch)
 *
 * Each detected bug candidate includes:
 *   - bug_candidate: true
 *   - confidence: 0-100
 *   - reasoning: machine-generated explanation
 */

const crypto = require('crypto');

// ─── Bug Categories ──────────────────────────────────────────────────

const BUG_CATEGORIES = {
  DOM_ANOMALY: 'dom_anomaly',
  NAV_FAILURE: 'navigation_failure',
  CONSOLE_ERROR: 'console_error',
  UNEXPECTED_REDIRECT: 'unexpected_redirect',
  HTTP_FAILURE: 'http_failure',
  COOKIE_ANOMALY: 'cookie_anomaly',
  STORAGE_ANOMALY: 'storage_anomaly',
  AUTH_INCONSISTENCY: 'auth_inconsistency',
  RACE_CONDITION: 'race_condition',
  STATE_CORRUPTION: 'state_corruption',
};

// ─── Signal Strength Levels ──────────────────────────────────────────

const SIGNAL_STRENGTH = {
  WEAK: 'weak',
  MODERATE: 'moderate',
  STRONG: 'strong',
  VERY_STRONG: 'very_strong',
};

class RealBugDetector {
  /**
   * @param {object} opts
   * @param {object} opts.anomalyEngine    - AnomalyEngine for baseline-driven detection
   * @param {object} opts.knowledgeBase    - KnowledgeBase for cross-target patterns
   * @param {object} opts.memoryGraph      - MemoryGraph for relationship queries
   */
  constructor(opts = {}) {
    this.anomalyEngine = opts.anomalyEngine || null;
    this.knowledgeBase = opts.knowledgeBase || null;
    this.memoryGraph = opts.memoryGraph || null;

    this._detectionHistory = [];
    this._stats = {
      total_detections: 0,
      by_category: {},
      by_signal_strength: { weak: 0, moderate: 0, strong: 0, very_strong: 0 },
      total_candidates: 0,
      avg_initial_confidence: 0,
    };
  }

  /**
   * Run all detection heuristics against a live agent session.
   *
   * @param {object} agent - Active Agent instance
   * @param {object} ctx   - Full BOQA context
   * @returns {object} { findings: [], candidates: [] }
   */
  detect(agent, ctx) {
    const findings = [];
    const candidates = [];

    // Gather data sources
    const events = ctx.bus ? ctx.bus.eventLog : [];
    const report = agent && typeof agent.getReport === 'function' ? agent.getReport() : null;
    const anomalies = agent && agent.anomaly ? agent.anomaly.getAnomalies() : [];

    // Run each detector
    const domBugs = this._detectDOMAnomalies(events, report, ctx);
    const navBugs = this._detectNavigationFailures(events, report, ctx);
    const consoleBugs = this._detectConsoleErrors(events, report, ctx);
    const redirectBugs = this._detectUnexpectedRedirects(events, report, ctx);
    const httpBugs = this._detectHTTPFailures(events, report, ctx);
    const cookieBugs = this._detectCookieAnomalies(events, report, ctx);
    const storageBugs = this._detectStorageAnomalies(events, report, ctx);
    const authBugs = this._detectAuthInconsistencies(events, report, ctx);
    const raceBugs = this._detectRaceConditions(events, report, ctx);
    const stateBugs = this._detectStateCorruption(events, report, ctx);

    // Merge anomaly engine findings (baseline-driven)
    const anomalyBugs = this._convertAnomalies(anomalies, report);

    const allDetections = [
      ...domBugs, ...navBugs, ...consoleBugs, ...redirectBugs,
      ...httpBugs, ...cookieBugs, ...storageBugs, ...authBugs,
      ...raceBugs, ...stateBugs, ...anomalyBugs,
    ];

    // Deduplicate by category + context hash
    const seen = new Set();
    for (const det of allDetections) {
      const key = `${det.category}:${det.context_hash}`;
      if (!seen.has(key)) {
        seen.add(key);
        findings.push(det);

        // Promote to candidate if initial confidence >= 30
        if (det.initial_confidence >= 30) {
          candidates.push({
            ...det,
            bug_candidate: true,
          });
        }
      }
    }

    // Update stats
    this._stats.total_detections += findings.length;
    this._stats.total_candidates += candidates.length;
    for (const f of findings) {
      this._stats.by_category[f.category] = (this._stats.by_category[f.category] || 0) + 1;
      this._stats.by_signal_strength[f.signal_strength] = (this._stats.by_signal_strength[f.signal_strength] || 0) + 1;
    }
    if (findings.length > 0) {
      const totalConf = findings.reduce((s, f) => s + f.initial_confidence, 0);
      this._stats.avg_initial_confidence = Math.round(totalConf / findings.length);
    }

    this._detectionHistory.push({
      timestamp: Date.now(),
      findings_count: findings.length,
      candidates_count: candidates.length,
      target: report?.target || (ctx.CONFIG ? ctx.CONFIG.target : 'unknown'),
    });

    return { findings, candidates };
  }

  // ─── Individual Detectors ─────────────────────────────────────────

  /**
   * DOM Anomaly Detection
   * Detects: empty pages, missing critical elements, broken layouts,
   * invisible interactive elements, duplicate IDs, form field issues.
   */
  _detectDOMAnomalies(events, report, ctx) {
    const bugs = [];

    // Check for empty or near-empty page loads
    const navEvents = events.filter(e => e.type === 'navigation');
    for (const nav of navEvents) {
      if (nav.meta?.domSize !== undefined && nav.meta.domSize < 10) {
        bugs.push(this._makeDetection(
          BUG_CATEGORIES.DOM_ANOMALY,
          'Low DOM node count after navigation — possible blank page or render failure',
          70,
          nav.url,
          { dom_size: nav.meta.domSize, navigation_type: nav.meta.navigationType },
          SIGNAL_STRENGTH.STRONG,
          ctx
        ));
      }
    }

    // Check for console errors about missing DOM elements
    const consoleErrors = events.filter(e => e.type === 'console_error');
    const domRelatedErrors = consoleErrors.filter(e =>
      (e.text && /cannot read propert|null is not an object|undefined is not an object|element not found|no such element/i.test(e.text))
    );
    if (domRelatedErrors.length >= 2) {
      bugs.push(this._makeDetection(
        BUG_CATEGORIES.DOM_ANOMALY,
        `Multiple DOM-related console errors (${domRelatedErrors.length}) — likely broken element references`,
        60 + Math.min(domRelatedErrors.length * 5, 30),
        domRelatedErrors[0].url,
        { error_count: domRelatedErrors.length, sample_errors: domRelatedErrors.slice(0, 3).map(e => e.text?.substring(0, 100)) },
        SIGNAL_STRENGTH.STRONG,
        ctx
      ));
    }

    // Check for duplicate form submissions detected via events
    const formSubmits = events.filter(e =>
      e.type === 'interaction' && e.meta?.type === 'submit'
    );
    if (formSubmits.length > 0) {
      const rapidSubmits = formSubmits.filter((e, i) =>
        i > 0 && e.ts - formSubmits[i - 1].ts < 500
      );
      if (rapidSubmits.length > 0) {
        bugs.push(this._makeDetection(
          BUG_CATEGORIES.DOM_ANOMALY,
          `Rapid form double-submit detected (${rapidSubmits.length} within 500ms) — missing debounce protection`,
          55,
          formSubmits[0].url,
          { rapid_submit_count: rapidSubmits.length },
          SIGNAL_STRENGTH.MODERATE,
          ctx
        ));
      }
    }

    return bugs;
  }

  /**
   * Navigation Failure Detection
   * Detects: 404 responses, SPA routing errors, infinite redirects.
   */
  _detectNavigationFailures(events, report, ctx) {
    const bugs = [];

    // 404 responses
    const notFoundResponses = events.filter(e =>
      e.type === 'network_response' && e.status === 404
    );
    if (notFoundResponses.length >= 2) {
      bugs.push(this._makeDetection(
        BUG_CATEGORIES.NAV_FAILURE,
        `Multiple 404 responses (${notFoundResponses.length}) — broken navigation links`,
        65,
        notFoundResponses[0].url,
        { count: notFoundResponses.length, urls: notFoundResponses.slice(0, 5).map(e => e.url) },
        SIGNAL_STRENGTH.STRONG,
        ctx
      ));
    } else if (notFoundResponses.length === 1) {
      bugs.push(this._makeDetection(
        BUG_CATEGORIES.NAV_FAILURE,
        `404 response detected — possible broken link`,
        40,
        notFoundResponses[0].url,
        { url: notFoundResponses[0].url },
        SIGNAL_STRENGTH.MODERATE,
        ctx
      ));
    }

    // SPA hash/hashchange without corresponding network activity
    const hashChanges = events.filter(e => e.type === 'navigation' && e.meta?.navigationType === 'hashchange');
    const noNetHashes = hashChanges.filter(h => {
      const nearbyRequests = events.filter(e =>
        e.type === 'network_request' && Math.abs(e.ts - h.ts) < 2000
      );
      return nearbyRequests.length === 0;
    });
    if (noNetHashes.length >= 3) {
      bugs.push(this._makeDetection(
        BUG_CATEGORIES.NAV_FAILURE,
        `Multiple hash navigations without network requests (${noNetHashes.length}) — possible SPA routing error`,
        45,
        noNetHashes[0].url,
        { count: noNetHashes.length },
        SIGNAL_STRENGTH.MODERATE,
        ctx
      ));
    }

    return bugs;
  }

  /**
   * Console Error Detection
   * Detects: uncaught exceptions, unhandled rejections, repeated errors.
   */
  _detectConsoleErrors(events, report, ctx) {
    const bugs = [];

    const consoleErrors = events.filter(e => e.type === 'console_error');
    if (consoleErrors.length === 0) return bugs;

    // Group by error pattern
    const errorGroups = {};
    for (const err of consoleErrors) {
      const pattern = this._extractErrorPattern(err.text || '');
      errorGroups[pattern] = errorGroups[pattern] || [];
      errorGroups[pattern].push(err);
    }

    // Report groups with 3+ occurrences
    for (const [pattern, group] of Object.entries(errorGroups)) {
      if (group.length >= 3) {
        bugs.push(this._makeDetection(
          BUG_CATEGORIES.CONSOLE_ERROR,
          `Recurring console error pattern "${pattern}" (${group.length} occurrences) — likely unhandled exception`,
          55 + Math.min(group.length * 3, 30),
          group[0].url,
          { pattern, count: group.length, sample: group[0].text?.substring(0, 150) },
          SIGNAL_STRENGTH.STRONG,
          ctx
        ));
      }
    }

    // Unhandled promise rejections
    const rejectionErrors = consoleErrors.filter(e =>
      e.text && /unhandled.*promise.*rejection|uncaught.*error/i.test(e.text)
    );
    if (rejectionErrors.length >= 1) {
      bugs.push(this._makeDetection(
        BUG_CATEGORIES.CONSOLE_ERROR,
        `Unhandled promise rejection detected — application error boundary may be missing`,
        60,
        rejectionErrors[0].url,
        { count: rejectionErrors.length, sample: rejectionErrors[0].text?.substring(0, 150) },
        SIGNAL_STRENGTH.STRONG,
        ctx
      ));
    }

    return bugs;
  }

  /**
   * Unexpected Redirect Detection
   * Detects: 301/302 chains, meta refresh, JavaScript redirects.
   */
  _detectUnexpectedRedirects(events, report, ctx) {
    const bugs = [];

    // Redirect chains (3xx responses)
    const redirects = events.filter(e =>
      e.type === 'network_response' && e.status >= 300 && e.status < 400
    );

    // Check for long redirect chains
    if (redirects.length >= 3) {
      // Group by time proximity (within 5s windows)
      const chains = this._findRedirectChains(redirects, 5000);
      for (const chain of chains) {
        if (chain.length >= 3) {
          bugs.push(this._makeDetection(
            BUG_CATEGORIES.UNEXPECTED_REDIRECT,
            `Long redirect chain (${chain.length} hops) — possible redirect loop or misconfigured routing`,
            50 + chain.length * 5,
            chain[0].url,
            { chain_length: chain.length, status_codes: chain.map(r => r.status), urls: chain.map(r => r.url) },
            SIGNAL_STRENGTH.STRONG,
            ctx
          ));
        }
      }
    }

    // Navigation to different domain than target
    if (report && report.target) {
      let targetDomain;
      try { targetDomain = new URL(report.target).hostname; } catch (_) { targetDomain = report.target; }

      const crossDomainNavs = events.filter(e => {
        if (e.type !== 'navigation') return false;
        try {
          const navDomain = new URL(e.url).hostname;
          return navDomain !== targetDomain;
        } catch (_) { return false; }
      });

      if (crossDomainNavs.length >= 2) {
        const domains = new Set(crossDomainNavs.map(e => { try { return new URL(e.url).hostname; } catch(_) { return ''; } }));
        bugs.push(this._makeDetection(
          BUG_CATEGORIES.UNEXPECTED_REDIRECT,
          `Unexpected cross-domain navigation to ${domains.size} domain(s) — possible open redirect vulnerability`,
          55,
          crossDomainNavs[0].url,
          { domains: [...domains], count: crossDomainNavs.length },
          SIGNAL_STRENGTH.MODERATE,
          ctx
        ));
      }
    }

    return bugs;
  }

  /**
   * HTTP Failure Detection
   * Detects: 5xx errors, timeouts, mixed content, CORS failures.
   */
  _detectHTTPFailures(events, report, ctx) {
    const bugs = [];

    // 5xx errors
    const serverErrors = events.filter(e =>
      e.type === 'network_response' && e.status >= 500
    );
    if (serverErrors.length >= 1) {
      bugs.push(this._makeDetection(
        BUG_CATEGORIES.HTTP_FAILURE,
        `Server error response(s) detected (${serverErrors.length}) — backend may be malfunctioning`,
        70 + Math.min(serverErrors.length * 5, 25),
        serverErrors[0].url,
        {
          count: serverErrors.length,
          status_codes: [...new Set(serverErrors.map(e => e.status))],
          urls: serverErrors.slice(0, 5).map(e => e.url),
        },
        SIGNAL_STRENGTH.VERY_STRONG,
        ctx
      ));
    }

    // Network failures (no response)
    const networkFailures = events.filter(e => e.type === 'network_failure');
    if (networkFailures.length >= 2) {
      bugs.push(this._makeDetection(
        BUG_CATEGORIES.HTTP_FAILURE,
        `Network failures detected (${networkFailures.length}) — possible connectivity or CORS issues`,
        50 + Math.min(networkFailures.length * 5, 30),
        networkFailures[0].url,
        { count: networkFailures.length },
        SIGNAL_STRENGTH.STRONG,
        ctx
      ));
    }

    // Mixed content (HTTP requests from HTTPS page)
    const target = ctx.CONFIG ? ctx.CONFIG.target : '';
    if (target.startsWith('https://')) {
      const mixedContent = events.filter(e =>
        e.type === 'network_request' && e.url && e.url.startsWith('http://')
      );
      if (mixedContent.length >= 1) {
        bugs.push(this._makeDetection(
          BUG_CATEGORIES.HTTP_FAILURE,
          `Mixed content detected: HTTP requests from HTTPS page (${mixedContent.length}) — browser will block these`,
          65,
          mixedContent[0].url,
          { count: mixedContent.length, urls: mixedContent.slice(0, 3).map(e => e.url) },
          SIGNAL_STRENGTH.STRONG,
          ctx
        ));
      }
    }

    return bugs;
  }

  /**
   * Cookie Anomaly Detection
   * Detects: missing SameSite, HttpOnly downgrade, expired cookies, session fixation.
   */
  _detectCookieAnomalies(events, report, ctx) {
    const bugs = [];

    // From auth signal events that set cookies
    const cookieEvents = events.filter(e =>
      e.type === 'auth_signal' && e.meta?.cookies
    );

    for (const ce of cookieEvents) {
      for (const cookie of (ce.meta.cookies || [])) {
        // Missing SameSite
        if (cookie.name && cookie.name.toLowerCase().includes('session') && !cookie.sameSite) {
          bugs.push(this._makeDetection(
            BUG_CATEGORIES.COOKIE_ANOMALY,
            `Session cookie "${cookie.name}" missing SameSite attribute — vulnerable to CSRF`,
            55,
            ce.url || 'unknown',
            { cookie_name: cookie.name, missing_attribute: 'SameSite' },
            SIGNAL_STRENGTH.MODERATE,
            ctx
          ));
        }

        // Session cookie without HttpOnly
        if (cookie.name && cookie.name.toLowerCase().includes('session') && !cookie.httpOnly) {
          bugs.push(this._makeDetection(
            BUG_CATEGORIES.COOKIE_ANOMALY,
            `Session cookie "${cookie.name}" missing HttpOnly flag — accessible to JavaScript, XSS risk`,
            60,
            ce.url || 'unknown',
            { cookie_name: cookie.name, missing_attribute: 'HttpOnly' },
            SIGNAL_STRENGTH.STRONG,
            ctx
          ));
        }

        // Auth cookie without Secure flag
        if (cookie.name && (cookie.name.toLowerCase().includes('auth') || cookie.name.toLowerCase().includes('token')) && !cookie.secure) {
          bugs.push(this._makeDetection(
            BUG_CATEGORIES.COOKIE_ANOMALY,
            `Auth cookie "${cookie.name}" missing Secure flag — will be sent over HTTP`,
            50,
            ce.url || 'unknown',
            { cookie_name: cookie.name, missing_attribute: 'Secure' },
            SIGNAL_STRENGTH.MODERATE,
            ctx
          ));
        }
      }
    }

    // From cookie snapshot events
    const cookieSnapshots = events.filter(e => e.type === 'cookie_snapshot');
    for (const cs of cookieSnapshots) {
      const cookies = cs.meta?.authCookies || cs.meta?.cookies || [];
      for (const cookie of cookies) {
        if (!cookie.sameSite || cookie.sameSite === 'none') {
          bugs.push(this._makeDetection(
            BUG_CATEGORIES.COOKIE_ANOMALY,
            `Cookie "${cookie.name}" with SameSite=None or absent — third-party CSRF risk`,
            45,
            cs.url || 'unknown',
            { cookie_name: cookie.name, sameSite: cookie.sameSite || 'absent' },
            SIGNAL_STRENGTH.MODERATE,
            ctx
          ));
        }
      }
    }

    return bugs;
  }

  /**
   * Storage Anomaly Detection
   * Detects: quota exceeded, inaccessible storage, corrupted data.
   */
  _detectStorageAnomalies(events, report, ctx) {
    const bugs = [];

    // Console errors about storage
    const storageErrors = events.filter(e =>
      e.type === 'console_error' && e.text &&
      /quota.*exceeded|storage.*full|failed to execute.*storage|securityerror.*storage|access.*denied.*storage/i.test(e.text)
    );
    if (storageErrors.length >= 1) {
      bugs.push(this._makeDetection(
        BUG_CATEGORIES.STORAGE_ANOMALY,
        `Storage-related error detected — application may fail to persist state`,
        55,
        storageErrors[0].url,
        { error_count: storageErrors.length, sample: storageErrors[0].text?.substring(0, 100) },
        SIGNAL_STRENGTH.MODERATE,
        ctx
      ));
    }

    // Large number of storage writes (possible leak or abuse)
    const storageWrites = events.filter(e =>
      e.type === 'storage_write' || (e.type === 'interaction' && e.meta?.storageType)
    );
    if (storageWrites.length > 50) {
      bugs.push(this._makeDetection(
        BUG_CATEGORIES.STORAGE_ANOMALY,
        `Excessive storage writes (${storageWrites.length}) — possible memory leak or storage abuse`,
        40,
        storageWrites[0].url,
        { write_count: storageWrites.length },
        SIGNAL_STRENGTH.WEAK,
        ctx
      ));
    }

    return bugs;
  }

  /**
   * Authentication Inconsistency Detection
   * Detects: login state mismatch, session drift, token expiration.
   */
  _detectAuthInconsistencies(events, report, ctx) {
    const bugs = [];

    // Auth signals followed by 401/403
    const authSignals = events.filter(e => e.type === 'auth_signal');
    const unauthorizedResponses = events.filter(e =>
      e.type === 'network_response' && (e.status === 401 || e.status === 403)
    );

    for (const unauth of unauthorizedResponses) {
      // Check if there was an auth signal before this
      const priorAuth = authSignals.find(a => a.ts < unauth.ts && a.ts > unauth.ts - 30000);
      if (priorAuth) {
        bugs.push(this._makeDetection(
          BUG_CATEGORIES.AUTH_INCONSISTENCY,
          `Auth signal present but ${unauth.status} response received — possible session invalidation or permission error`,
          60,
          unauth.url,
          { status: unauth.status, auth_signal_type: priorAuth.meta?.signalType },
          SIGNAL_STRENGTH.STRONG,
          ctx
        ));
      }
    }

    // Standalone 401/403 (no auth signal at all — might be unauthenticated access issue)
    const unauthWithoutPriorAuth = unauthorizedResponses.filter(u => {
      const priorAuth = authSignals.find(a => a.ts < u.ts && a.ts > u.ts - 60000);
      return !priorAuth;
    });
    if (unauthWithoutPriorAuth.length >= 3) {
      bugs.push(this._makeDetection(
        BUG_CATEGORIES.AUTH_INCONSISTENCY,
        `Multiple ${unauthWithoutPriorAuth[0].status} responses without auth signal — possible auth configuration issue`,
        50,
        unauthWithoutPriorAuth[0].url,
        { count: unauthWithoutPriorAuth.length, status: unauthWithoutPriorAuth[0].status },
        SIGNAL_STRENGTH.MODERATE,
        ctx
      ));
    }

    // Auth model change detection (from anomaly engine)
    const authModelAnomalies = anomalies => anomalies.filter(a => a.rule === 'auth_model_change');
    if (this.anomalyEngine) {
      const anomalies = this.anomalyEngine.getAnomalies();
      const modelChanges = authModelAnomalies(anomalies);
      if (modelChanges.length > 0) {
        bugs.push(this._makeDetection(
          BUG_CATEGORIES.AUTH_INCONSISTENCY,
          `Authentication model change detected — ${modelChanges[0].detail}`,
          75,
          'auth_subsystem',
          { anomaly_rule: 'auth_model_change', detail: modelChanges[0].detail },
          SIGNAL_STRENGTH.VERY_STRONG,
          ctx
        ));
      }
    }

    return bugs;
  }

  /**
   * Race Condition Detection
   * Detects: concurrent state mutations, double-submits, overlapping requests.
   */
  _detectRaceConditions(events, report, ctx) {
    const bugs = [];

    // Overlapping requests to the same endpoint
    const requests = events.filter(e => e.type === 'network_request');
    const endpointMap = {};
    for (const req of requests) {
      try {
        const key = `${req.method || 'GET'} ${new URL(req.url).pathname}`;
        endpointMap[key] = endpointMap[key] || [];
        endpointMap[key].push(req);
      } catch (_) {}
    }

    for (const [endpoint, reqs] of Object.entries(endpointMap)) {
      // Check for overlapping requests (same endpoint, started before previous finished)
      const overlapping = [];
      for (let i = 1; i < reqs.length; i++) {
        if (reqs[i].ts - reqs[i - 1].ts < 100) { // < 100ms apart
          overlapping.push(reqs[i]);
        }
      }
      if (overlapping.length >= 2) {
        bugs.push(this._makeDetection(
          BUG_CATEGORIES.RACE_CONDITION,
          `Concurrent requests to ${endpoint} (${overlapping.length + 1} overlapping) — possible race condition or missing request deduplication`,
          45 + Math.min(overlapping.length * 5, 25),
          reqs[0].url,
          { endpoint, overlapping_count: overlapping.length + 1 },
          SIGNAL_STRENGTH.MODERATE,
          ctx
        ));
      }
    }

    // Mutations (POST/PUT/DELETE) to same resource within 200ms
    const mutations = requests.filter(e =>
      (e.method === 'POST' || e.method === 'PUT' || e.method === 'DELETE' || e.method === 'PATCH')
    );
    for (let i = 1; i < mutations.length; i++) {
      if (mutations[i].ts - mutations[i - 1].ts < 200) {
        try {
          const pathA = new URL(mutations[i - 1].url).pathname;
          const pathB = new URL(mutations[i].url).pathname;
          if (pathA === pathB) {
            bugs.push(this._makeDetection(
              BUG_CATEGORIES.RACE_CONDITION,
              `Rapid duplicate mutations to ${pathA} within 200ms — likely race condition`,
              55,
              mutations[i].url,
              { method: mutations[i].method, path: pathB, interval_ms: mutations[i].ts - mutations[i - 1].ts },
              SIGNAL_STRENGTH.STRONG,
              ctx
            ));
          }
        } catch (_) {}
      }
    }

    return bugs;
  }

  /**
   * State Corruption Detection
   * Detects: form state loss, CSRF token mismatch, cart/session emptying.
   */
  _detectStateCorruption(events, report, ctx) {
    const bugs = [];

    // Navigation away from form without submission (possible state loss)
    const formInteractions = events.filter(e =>
      e.type === 'interaction' && (e.meta?.type === 'input' || e.meta?.type === 'select')
    );
    const navEvents = events.filter(e => e.type === 'navigation');
    const formSubmissions = events.filter(e =>
      e.type === 'interaction' && e.meta?.type === 'submit'
    );

    for (const nav of navEvents) {
      const priorInputs = formInteractions.filter(f => f.ts < nav.ts && f.ts > nav.ts - 10000);
      const subsequentSubmits = formSubmissions.filter(s => s.ts > nav.ts && s.ts < nav.ts + 2000);
      if (priorInputs.length >= 3 && subsequentSubmits.length === 0) {
        bugs.push(this._makeDetection(
          BUG_CATEGORIES.STATE_CORRUPTION,
          `Navigation away from page with ${priorInputs.length} unsaved form inputs — possible state loss`,
          40,
          nav.url,
          { unsaved_inputs: priorInputs.length },
          SIGNAL_STRENGTH.WEAK,
          ctx
        ));
      }
    }

    // CSRF token in request but not in cookies
    const csrfRequests = events.filter(e =>
      e.type === 'network_request' && e.headers && e.headers['x-csrftoken']
    );
    for (const req of csrfRequests) {
      const nearbyCookieSnapshots = events.filter(e =>
        e.type === 'cookie_snapshot' && Math.abs(e.ts - req.ts) < 5000
      );
      const hasCsrfCookie = nearbyCookieSnapshots.some(cs =>
        cs.meta?.cookies?.some(c => c.name.toLowerCase().includes('csrf'))
      );
      if (!hasCsrfCookie && nearbyCookieSnapshots.length > 0) {
        bugs.push(this._makeDetection(
          BUG_CATEGORIES.STATE_CORRUPTION,
          `CSRF token in request header but no matching cookie found — possible CSRF protection mismatch`,
          50,
          req.url,
          { header_token_present: true, cookie_token_present: false },
          SIGNAL_STRENGTH.MODERATE,
          ctx
        ));
        break; // One report per session is enough
      }
    }

    return bugs;
  }

  // ─── Helpers ──────────────────────────────────────────────────────

  /**
   * Convert AnomalyEngine anomalies into BugDetector findings.
   */
  _convertAnomalies(anomalies, report) {
    const categoryMap = {
      'auth_model_change': BUG_CATEGORIES.AUTH_INCONSISTENCY,
      'new_bearer_usage_detected': BUG_CATEGORIES.AUTH_INCONSISTENCY,
      'cookie_httpOnly_downgrade': BUG_CATEGORIES.COOKIE_ANOMALY,
      'cookie_secure_downgrade': BUG_CATEGORIES.COOKIE_ANOMALY,
      'unexpected_ws_channel': BUG_CATEGORIES.NAV_FAILURE,
      'endpoint_entropy_spike': BUG_CATEGORIES.HTTP_FAILURE,
      'error_rate_spike': BUG_CATEGORIES.HTTP_FAILURE,
      'z_score_request_volume': BUG_CATEGORIES.RACE_CONDITION,
      'timing_deviation_detected': BUG_CATEGORIES.RACE_CONDITION,
    };

    const severityToConfidence = {
      high: 65,
      medium: 45,
      low: 25,
      info: 10,
    };

    return anomalies.map(a => ({
      ...this._makeDetection(
        categoryMap[a.rule] || BUG_CATEGORIES.HTTP_FAILURE,
        `[Baseline Anomaly] ${a.detail}`,
        severityToConfidence[a.severity] || 30,
        a.context || 'unknown',
        { anomaly_rule: a.rule, severity: a.severity },
        a.severity === 'high' ? SIGNAL_STRENGTH.STRONG : a.severity === 'medium' ? SIGNAL_STRENGTH.MODERATE : SIGNAL_STRENGTH.WEAK,
        null
      ),
    }));
  }

  /**
   * Create a detection record.
   */
  _makeDetection(category, reasoning, confidence, url, evidence, signalStrength, ctx) {
    const contextStr = `${category}:${url}:${JSON.stringify(evidence).substring(0, 100)}`;
    return {
      id: crypto.randomUUID(),
      category,
      reasoning,
      initial_confidence: Math.min(confidence, 100),
      signal_strength: signalStrength,
      url,
      evidence,
      context_hash: crypto.createHash('sha256').update(contextStr).digest('hex').substring(0, 16),
      detected_at: Date.now(),
      target: ctx && ctx.CONFIG ? ctx.CONFIG.target : 'unknown',
    };
  }

  /**
   * Extract an error pattern from console error text.
   */
  _extractErrorPattern(text) {
    if (!text) return 'unknown';
    // Normalize: remove specific values, keep structure
    return text
      .replace(/\d+/g, 'N')
      .replace(/https?:\/\/[^\s]+/g, 'URL')
      .replace(/0x[0-9a-f]+/gi, 'HEX')
      .substring(0, 80);
  }

  /**
   * Find redirect chains from a list of redirect responses.
   */
  _findRedirectChains(redirects, windowMs) {
    const chains = [];
    let current = [redirects[0]];
    for (let i = 1; i < redirects.length; i++) {
      if (redirects[i].ts - redirects[i - 1].ts < windowMs) {
        current.push(redirects[i]);
      } else {
        chains.push(current);
        current = [redirects[i]];
      }
    }
    chains.push(current);
    return chains;
  }

  /**
   * Get detection statistics.
   */
  getStats() {
    return { ...this._stats, history_size: this._detectionHistory.length };
  }

  /**
   * Get detection history.
   */
  getHistory(limit) {
    const h = [...this._detectionHistory];
    return limit ? h.slice(-limit) : h;
  }

  /**
   * Reset all state.
   */
  reset() {
    this._detectionHistory = [];
    this._stats = {
      total_detections: 0,
      by_category: {},
      by_signal_strength: { weak: 0, moderate: 0, strong: 0, very_strong: 0 },
      total_candidates: 0,
      avg_initial_confidence: 0,
    };
  }
}

module.exports = { RealBugDetector, BUG_CATEGORIES, SIGNAL_STRENGTH };

