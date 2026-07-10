/**
 * BOQA validator.js — Validator Engine
 *
 * Verifies hypotheses using passive replay and deterministic checks.
 * Does NOT exploit, modify, or escalate — only confirms observability evidence.
 *
 * Validation strategies:
 *   1. Evidence corroboration: multiple independent observations confirm the hypothesis
 *   2. Temporal consistency: the observed behavior is stable across the session
 *   3. Cross-signal validation: different event types agree on the finding
 *   4. Baseline comparison: deviation from baseline confirms regression
 *   5. Deterministic replay: re-reading NDJSON confirms the same signals
 *
 * Output: validated hypotheses with adjusted confidence and validation proof
 */

const crypto = require('crypto');

// ─── Validation Result Schema ───────────────────────────────────────

// {
//   hypothesis_id: string,
//   validated: boolean,
//   confidence_adjusted: number,  // 0-100, adjusted after validation
//   validation_method: string,
//   validation_proof: [],         // evidence items that confirmed
//   validation_notes: string,
//   validated_at: number,
// }

class ValidatorEngine {
  constructor() {
    this.validationResults = new Map(); // hypothesisId → validationResult
  }

  /**
   * Validate a batch of hypotheses against the full observation set
   * @param {array} hypotheses - from HypothesisEngine
   * @param {object} observations - { events, report, anomalies, baseline, diff }
   * @returns {array} validated hypotheses with adjusted confidence
   */
  validateAll(hypotheses, observations) {
    const { events = [], report = {}, anomalies = [], baseline = null, diff = null } = observations;
    const results = [];

    for (const hyp of hypotheses) {
      const result = this.validate(hyp, { events, report, anomalies, baseline, diff });
      this.validationResults.set(hyp.id, result);
      results.push(result);
    }

    return results;
  }

  /**
   * Validate a single hypothesis
   */
  validate(hypothesis, observations) {
    const { events, report, anomalies, baseline, diff } = observations;
    const category = hypothesis.category;

    // Route to category-specific validator
    let result;
    switch (category) {
      case 'missing_httpOnly':
        result = this._validateCookieAttribute(hypothesis, events, report, 'httpOnly', false);
        break;
      case 'missing_secure':
        result = this._validateCookieAttribute(hypothesis, events, report, 'secure', false);
        break;
      case 'weak_samesite':
        result = this._validateSameSite(hypothesis, events, report);
        break;
      case 'bearer_token_exposure':
        result = this._validateBearerExposure(hypothesis, events, report);
        break;
      case 'jwt_in_browser_memory':
        result = this._validateJwtInMemory(hypothesis, events, report);
        break;
      case 'session_fixation_indicators':
        result = this._validateSessionFixation(hypothesis, events, report);
        break;
      case 'session_rotation_failure':
        result = this._validateSessionRotation(hypothesis, events, report);
        break;
      case 'cache_control_misconfiguration':
        result = this._validateCacheControl(hypothesis, events);
        break;
      case 'csrf_signal_anomaly':
        result = this._validateCsrfAnomaly(hypothesis, events, report);
        break;
      case 'cors_misconfiguration':
        result = this._validateCors(hypothesis, events);
        break;
      case 'cookie_scope_oversharing':
        result = this._validateCookieScope(hypothesis, events, report);
        break;
      case 'cross_subdomain_trust_expansion':
        result = this._validateCrossSubdomainTrust(hypothesis, events, baseline);
        break;
      case 'unexpected_auth_model_change':
        result = this._validateAuthModelChange(hypothesis, report, baseline, anomalies);
        break;
      case 'sensitive_data_exposure':
        result = this._validateSensitiveDataExposure(hypothesis, events);
        break;
      case 'excessive_client_side_secrets':
        result = this._validateExcessiveClientSecrets(hypothesis, events, report);
        break;
      case 'auth_state_desynchronization':
        result = this._validateAuthDesync(hypothesis, events);
        break;
      case 'ws_auth_inconsistency':
        result = this._validateWsAuthInconsistency(hypothesis, events);
        break;
      case 'permission_boundary_anomaly':
        result = this._validatePermissionBoundary(hypothesis, events);
        break;
      case 'regression_security_change':
        result = this._validateRegression(hypothesis, diff, baseline);
        break;
      default:
        result = this._validateGeneric(hypothesis, events, report);
    }

    return result;
  }

  // ─── Category-Specific Validators ─────────────────────────────

  /**
   * Validate cookie attribute hypotheses (missing_httpOnly, missing_secure)
   * Strategy: Corroborate with multiple cookie snapshots + response headers
   */
  _validateCookieAttribute(hypothesis, events, report, attr, expectedValue) {
    const cookieName = hypothesis.affected_cookies[0];
    if (!cookieName) return this._fail(hypothesis, 'No cookie name specified');

    // Check 1: Multiple cookie snapshots agree
    const snapshots = events.filter(e =>
      e.type === 'cookie_snapshot' && e.meta?.authCookies
    );
    const relevantSnapshots = snapshots.filter(e =>
      e.meta.authCookies.some(c => c.name === cookieName)
    );

    // Check if attribute is consistently missing
    let missingCount = 0;
    let presentCount = 0;
    const proofItems = [];

    for (const snap of relevantSnapshots) {
      const cookie = snap.meta.authCookies.find(c => c.name === cookieName);
      if (cookie) {
        if (cookie[attr] === expectedValue) {
          missingCount++;
          proofItems.push({
            type: 'cookie_snapshot',
            ts: snap.ts,
            detail: `${cookieName}.${attr}=${cookie[attr]} at elapsed ${snap.elapsed}ms`,
          });
        } else {
          presentCount++;
        }
      }
    }

    // Check 2: Report also confirms
    const reportCookie = (report.cookies || []).find(c => c.name === cookieName);
    if (reportCookie && reportCookie[attr] === expectedValue) {
      proofItems.push({
        type: 'report_confirmation',
        ts: Date.now(),
        detail: `Auth report confirms ${cookieName}.${attr}=${reportCookie[attr]}`,
      });
    }

    // Check 3: Set-Cookie header analysis
    const setCookieEvents = events.filter(e =>
      e.type === 'network_response' && e.headers
    );
    for (const e of setCookieEvents) {
      const lower = {};
      for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;
      const sc = lower['set-cookie'] || '';
      if (sc.includes(cookieName)) {
        const hasAttr = sc.toLowerCase().includes(attr);
        if (!hasAttr && expectedValue === false) {
          proofItems.push({
            type: 'set_cookie_header',
            ts: e.ts,
            detail: `Set-Cookie for ${cookieName} lacks ${attr} flag`,
          });
        }
      }
    }

    const totalObservations = missingCount + presentCount;
    const consistency = totalObservations > 0 ? missingCount / totalObservations : 0;
    const validated = missingCount >= 2 || (missingCount >= 1 && reportCookie && reportCookie[attr] === expectedValue);
    const confidenceAdjust = validated ? Math.min(hypothesis.confidence + 5, 98) : Math.max(hypothesis.confidence - 20, 10);

    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: Math.round(confidenceAdjust),
      validation_method: 'multi_snapshot_corroboration',
      validation_proof: proofItems,
      validation_notes: validated
        ? `Confirmed: ${cookieName} consistently lacks ${attr} across ${missingCount}/${totalObservations} snapshots, report, and ${proofItems.filter(p => p.type === 'set_cookie_header').length} Set-Cookie headers`
        : `Insufficient evidence: only ${missingCount}/${totalObservations} snapshots show missing ${attr}`,
      validated_at: Date.now(),
    };
  }

  /**
   * Validate SameSite hypothesis
   */
  _validateSameSite(hypothesis, events, report) {
    const cookieName = hypothesis.affected_cookies[0];
    if (!cookieName) return this._fail(hypothesis, 'No cookie name');

    const proofItems = [];
    const reportCookie = (report.cookies || []).find(c => c.name === cookieName);

    if (reportCookie && (!reportCookie.sameSite || reportCookie.sameSite === 'None')) {
      proofItems.push({
        type: 'report_confirmation',
        detail: `Report confirms ${cookieName}.sameSite=${reportCookie.sameSite || '(unset)'}`,
      });
    }

    // Check Set-Cookie headers
    for (const e of events) {
      if (e.type === 'network_response' && e.headers) {
        const lower = {};
        for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;
        const sc = lower['set-cookie'] || '';
        if (sc.includes(cookieName) && !sc.toLowerCase().includes('samesite=')) {
          proofItems.push({
            type: 'set_cookie_header',
            ts: e.ts,
            detail: `Set-Cookie for ${cookieName} has no SameSite attribute`,
          });
        }
      }
    }

    const validated = proofItems.length >= 1;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? Math.min(hypothesis.confidence + 3, 95) : Math.max(hypothesis.confidence - 15, 10),
      validation_method: 'header_and_report_corroboration',
      validation_proof: proofItems,
      validation_notes: validated ? `Confirmed: ${proofItems.length} evidence items` : 'Insufficient evidence',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate Bearer token exposure
   */
  _validateBearerExposure(hypothesis, events, report) {
    const proofItems = [];

    // Corroborate: Authorization headers observed on requests
    let bearerRequestCount = 0;
    const bearerUrls = [];
    for (const e of events) {
      if (e.type === 'network_request' && e.headers) {
        const lower = {};
        for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;
        if (lower['authorization']) {
          bearerRequestCount++;
          if (e.url) bearerUrls.push(e.url);
        }
      }
    }

    if (bearerRequestCount > 0) {
      proofItems.push({
        type: 'request_header_evidence',
        detail: `Authorization header present in ${bearerRequestCount} requests`,
      });
    }

    // Check if bearer is on non-HttpOnly cookie
    if (report.bearer_detected) {
      const nonHttpOnlyAuth = (report.cookies || []).filter(c =>
        !c.httpOnly && ['ripio_access', 'access_token', 'id_token'].includes(c.name)
      );
      if (nonHttpOnlyAuth.length > 0) {
        proofItems.push({
          type: 'cookie_correlation',
          detail: `Bearer detected + non-HttpOnly cookies: ${nonHttpOnlyAuth.map(c => c.name).join(', ')}`,
        });
      }
    }

    const validated = proofItems.length >= 2 || (proofItems.length >= 1 && hypothesis.confidence >= 80);
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? Math.min(hypothesis.confidence + 5, 95) : hypothesis.confidence,
      validation_method: 'cross_signal_validation',
      validation_proof: proofItems,
      validation_notes: validated
        ? `Confirmed: Bearer exposure corroborated by ${proofItems.length} independent signals`
        : `Partial: ${proofItems.length} signal(s), needs more evidence`,
      validated_at: Date.now(),
    };
  }

  /**
   * Validate JWT in browser memory
   */
  _validateJwtInMemory(hypothesis, events, report) {
    const proofItems = [];

    // Check for CryptoJS.AES.decrypt in console logs
    const decryptEvents = events.filter(e =>
      e.type === 'console_log' && e.payload &&
      (e.payload.includes('CryptoJS.AES.decrypt') || e.payload.includes('__BOQA__aes_decrypt'))
    );
    if (decryptEvents.length > 0) {
      proofItems.push({
        type: 'console_log_evidence',
        detail: `${decryptEvents.length} CryptoJS.AES.decrypt event(s) captured`,
        events: decryptEvents.map(e => ({ ts: e.ts, elapsed: e.elapsed })),
      });
    }

    // Check for encrypted cookie prefix in cookie values
    const encryptedCookies = events.filter(e =>
      e.type === 'cookie_snapshot' && e.meta?.authCookies &&
      e.meta.authCookies.some(c => c.value && c.value.startsWith('U2FsdGVkX1'))
    );
    if (encryptedCookies.length > 0) {
      proofItems.push({
        type: 'encrypted_cookie_evidence',
        detail: `${encryptedCookies.length} snapshot(s) with U2FsdGVkX1 prefix (AES-CBC encrypted)`,
      });
    }

    // Risk flag from report
    const hasRiskFlag = (report.risk_flags || []).some(f => f.flag === 'jwt_in_js_memory');
    if (hasRiskFlag) {
      proofItems.push({ type: 'risk_flag', detail: 'jwt_in_js_memory risk flag present in report' });
    }

    const validated = proofItems.length >= 2;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? Math.min(hypothesis.confidence + 3, 98) : Math.max(hypothesis.confidence - 10, 30),
      validation_method: 'multi_signal_corroboration',
      validation_proof: proofItems,
      validation_notes: validated
        ? `Confirmed: ${proofItems.length} independent signals confirm client-side JWT decryption`
        : `Partial: ${proofItems.length} signal(s)`,
      validated_at: Date.now(),
    };
  }

  /**
   * Validate session fixation
   */
  _validateSessionFixation(hypothesis, events, report) {
    const proofItems = [];

    // Collect sessionid values over time
    const sessionValues = [];
    for (const e of events) {
      if (e.type === 'cookie_snapshot' && e.meta?.authCookies) {
        const sid = e.meta.authCookies.find(c => c.name === 'sessionid');
        if (sid && sid.valuePreview) sessionValues.push({ ts: e.ts, value: sid.valuePreview });
      }
      if (e.type === 'auth_signal' && e.meta?.cookies) {
        const sid = e.meta.cookies.find(c => c.name === 'sessionid');
        if (sid && sid.valuePreview) sessionValues.push({ ts: e.ts, value: sid.valuePreview });
      }
    }

    // Check for auth events (login) where sessionid doesn't change
    const authEvents = events.filter(e =>
      e.type === 'auth_signal' && (
        e.meta?.signalType === 'auth_cookie_set' ||
        (e.url && /\/login|\/auth\//.test(e.url))
      )
    );

    if (sessionValues.length >= 2) {
      const first = sessionValues[0].value;
      const last = sessionValues[sessionValues.length - 1].value;
      const unchanged = first === last;

      proofItems.push({
        type: 'session_value_tracking',
        detail: `${sessionValues.length} sessionid snapshots, first=${first?.substring(0, 8)}... last=${last?.substring(0, 8)}... unchanged=${unchanged}`,
      });

      if (unchanged && authEvents.length > 0) {
        proofItems.push({
          type: 'auth_event_without_rotation',
          detail: `${authEvents.length} auth event(s) without sessionid rotation`,
        });
      }
    }

    const validated = proofItems.length >= 2;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? Math.min(hypothesis.confidence + 5, 90) : Math.max(hypothesis.confidence - 15, 20),
      validation_method: 'temporal_session_tracking',
      validation_proof: proofItems,
      validation_notes: validated
        ? 'Session fixation pattern confirmed: sessionid unchanged across auth events'
        : 'Insufficient temporal data to confirm session fixation',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate session rotation failure
   */
  _validateSessionRotation(hypothesis, events, report) {
    const proofItems = [];
    const sessionAppearances = [];

    for (const e of events) {
      if (e.type === 'auth_signal' && e.meta?.cookies) {
        const hasSession = e.meta.cookies.some(c => c.name === 'sessionid');
        if (hasSession) sessionAppearances.push(e.ts);
      }
    }

    if (sessionAppearances.length > 5) {
      const spans = [];
      for (let i = 1; i < sessionAppearances.length; i++) {
        spans.push(sessionAppearances[i] - sessionAppearances[i - 1]);
      }
      const avgSpan = spans.reduce((s, v) => s + v, 0) / spans.length;
      proofItems.push({
        type: 'rotation_frequency',
        detail: `${sessionAppearances.length} session appearances, avg interval=${Math.round(avgSpan)}ms`,
      });
    }

    const validated = proofItems.length >= 1;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: hypothesis.confidence,
      validation_method: 'frequency_analysis',
      validation_proof: proofItems,
      validation_notes: validated ? 'Excessive rotation pattern confirmed' : 'Normal rotation pattern',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate cache control misconfiguration
   */
  _validateCacheControl(hypothesis, events) {
    const proofItems = [];
    const observedPaths = hypothesis.observed?.paths_missing_cache_control || [];

    // Re-verify each path from the hypothesis against raw events
    let confirmedPaths = 0;
    for (const e of events) {
      if (e.type === 'network_response' && e.url && e.headers) {
        try {
          const pathname = new URL(e.url).pathname;
          if (!observedPaths.includes(pathname)) continue;

          const lower = {};
          for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;
          const cc = lower['cache-control'] || '';
          if (!cc.includes('no-store') && !cc.includes('no-cache')) {
            confirmedPaths++;
            proofItems.push({
              type: 'response_header_evidence',
              ts: e.ts,
              detail: `${pathname} → Cache-Control: "${cc || '(missing)'}"`,
            });
          }
        } catch (_) {}
      }
    }

    const validated = confirmedPaths > 0;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? Math.min(hypothesis.confidence + 5, 92) : Math.max(hypothesis.confidence - 20, 10),
      validation_method: 'deterministic_replay',
      validation_proof: proofItems,
      validation_notes: validated
        ? `Confirmed: ${confirmedPaths}/${observedPaths.length} paths verified missing cache headers`
        : 'No paths verified — cache headers may have been added',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate CSRF signal anomaly
   */
  _validateCsrfAnomaly(hypothesis, events, report) {
    const proofItems = [];

    // Check for state-changing requests without CSRF header
    const stateChanging = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
    let unsafeWithoutCsrf = 0;
    const unsafeUrls = [];

    for (const e of events) {
      if (e.type === 'network_request' && stateChanging.has(e.method)) {
        const lower = {};
        if (e.headers) {
          for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;
        }
        const hasCsrf = lower['x-csrftoken'] || lower['x-csrf-token'] || lower['csrf-token'];
        if (!hasCsrf) {
          unsafeWithoutCsrf++;
          if (e.url) {
            try { unsafeUrls.push(`${e.method} ${new URL(e.url).pathname}`); } catch (_) {}
          }
        }
      }
    }

    if (unsafeWithoutCsrf > 0) {
      proofItems.push({
        type: 'request_header_evidence',
        detail: `${unsafeWithoutCsrf} state-changing requests without CSRF header: ${[...new Set(unsafeUrls)].slice(0, 5).join(', ')}`,
      });
    }

    // Double-submit pattern check: csrftoken cookie exists but not sent
    const hasCsrfCookie = (report.cookies || []).some(c => c.name === 'csrftoken');
    if (hasCsrfCookie && unsafeWithoutCsrf > 0) {
      proofItems.push({
        type: 'double_submit_failure',
        detail: 'csrftoken cookie exists but is not being sent as X-CSRFToken header (double-submit failure)',
      });
    }

    const validated = proofItems.length >= 1;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? Math.min(hypothesis.confidence + 8, 93) : Math.max(hypothesis.confidence - 15, 20),
      validation_method: 'request_header_analysis',
      validation_proof: proofItems,
      validation_notes: validated
        ? `Confirmed: CSRF protection gap on ${unsafeWithoutCsrf} requests`
        : 'All state-changing requests have CSRF protection',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate CORS misconfiguration
   */
  _validateCors(hypothesis, events) {
    const proofItems = [];

    for (const e of events) {
      if (e.type === 'network_response' && e.headers) {
        const lower = {};
        for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;

        const acao = lower['access-control-allow-origin'] || '';
        const acac = lower['access-control-allow-credentials'] || '';

        if (acao === '*' && acac === 'true') {
          proofItems.push({
            type: 'response_header_evidence',
            ts: e.ts,
            detail: `${e.url || 'unknown'} → ACAO:* + ACAC:true`,
          });
        }
      }
    }

    const validated = proofItems.length >= 1;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? Math.min(hypothesis.confidence + 5, 98) : Math.max(hypothesis.confidence - 25, 10),
      validation_method: 'deterministic_header_replay',
      validation_proof: proofItems,
      validation_notes: validated
        ? `Confirmed: ${proofItems.length} response(s) with CORS wildcard+credentials`
        : 'No CORS misconfiguration verified in raw events',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate cookie scope overshowing
   */
  _validateCookieScope(hypothesis, events, report) {
    const cookieName = hypothesis.affected_cookies[0];
    const proofItems = [];

    const cookie = (report.cookies || []).find(c => c.name === cookieName);
    if (cookie) {
      if (cookie.path === '/' || !cookie.path) {
        proofItems.push({ type: 'report_confirmation', detail: `${cookieName}.path="${cookie.path || '/'}" (broad)` });
      }
      if (cookie.domain && cookie.domain.startsWith('.')) {
        proofItems.push({ type: 'report_confirmation', detail: `${cookieName}.domain="${cookie.domain}" (subdomain-wide)` });
      }
    }

    const validated = proofItems.length >= 1;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? hypothesis.confidence : Math.max(hypothesis.confidence - 20, 10),
      validation_method: 'report_corroboration',
      validation_proof: proofItems,
      validation_notes: validated ? 'Cookie scope confirmed' : 'Cookie not found in report',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate cross-subdomain trust
   */
  _validateCrossSubdomainTrust(hypothesis, events, baseline) {
    const proofItems = [];
    if (!baseline) {
      return this._fail(hypothesis, 'No baseline available for comparison');
    }

    const blDomains = new Set((baseline.fingerprint?.cookie_schema || []).map(c => c.domain).filter(Boolean));
    const currentDomains = new Set();

    for (const e of events) {
      if (e.type === 'cookie_snapshot' && e.meta?.authCookies) {
        for (const c of e.meta.authCookies) {
          if (c.domain) currentDomains.add(c.domain);
        }
      }
    }

    const newDomains = [...currentDomains].filter(d => !blDomains.has(d));
    if (newDomains.length > 0) {
      proofItems.push({
        type: 'baseline_comparison',
        detail: `New domains: ${newDomains.join(', ')} vs baseline: ${[...blDomains].join(', ')}`,
      });
    }

    const validated = proofItems.length >= 1;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? hypothesis.confidence : Math.max(hypothesis.confidence - 15, 10),
      validation_method: 'baseline_diff',
      validation_proof: proofItems,
      validation_notes: validated ? `${newDomains.length} new domain(s) confirmed` : 'No new domains detected',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate auth model change
   */
  _validateAuthModelChange(hypothesis, report, baseline, anomalies) {
    const proofItems = [];

    if (!baseline) {
      return this._fail(hypothesis, 'No baseline available');
    }

    const blModel = baseline.fingerprint?.auth_model;
    const currentModel = report.auth_model;

    if (blModel && currentModel && blModel !== currentModel) {
      proofItems.push({
        type: 'baseline_comparison',
        detail: `Baseline auth_model=${blModel}, current=${currentModel}`,
      });
    }

    const relatedAnomalies = anomalies.filter(a => a.rule === 'auth_model_change');
    if (relatedAnomalies.length > 0) {
      proofItems.push({
        type: 'anomaly_corroboration',
        detail: `${relatedAnomalies.length} auth_model_change anomaly(ies) detected`,
      });
    }

    const validated = proofItems.length >= 1;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? Math.min(hypothesis.confidence + 5, 95) : Math.max(hypothesis.confidence - 20, 10),
      validation_method: 'baseline_and_anomaly_corroboration',
      validation_proof: proofItems,
      validation_notes: validated
        ? `Auth model change confirmed: ${blModel} → ${currentModel}`
        : 'No auth model change verified',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate sensitive data exposure
   */
  _validateSensitiveDataExposure(hypothesis, events) {
    const proofItems = [];
    const patterns = [
      { regex: /token=[^&]+/i, label: 'token' },
      { regex: /api_key=[^&]+/i, label: 'api_key' },
      { regex: /password=[^&]+/i, label: 'password' },
      { regex: /secret=[^&]+/i, label: 'secret' },
    ];

    let totalMatches = 0;
    for (const e of events) {
      if (e.type === 'network_request' && e.url) {
        for (const p of patterns) {
          if (p.regex.test(e.url)) {
            totalMatches++;
            proofItems.push({
              type: 'url_query_string',
              ts: e.ts,
              detail: `${p.label} found in URL query string`,
            });
          }
        }
      }
    }

    const validated = totalMatches > 0;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? Math.min(hypothesis.confidence + 3, 92) : Math.max(hypothesis.confidence - 25, 10),
      validation_method: 'deterministic_url_replay',
      validation_proof: proofItems,
      validation_notes: validated
        ? `Confirmed: ${totalMatches} sensitive parameter(s) in URLs`
        : 'No sensitive data in URL query strings verified',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate excessive client-side secrets
   */
  _validateExcessiveClientSecrets(hypothesis, events, report) {
    const proofItems = [];
    const jsSecrets = [];

    for (const c of (report.cookies || [])) {
      if (!c.httpOnly && ['ripio_access', 'sessionid', 'csrftoken', 'access_token', 'refresh_token'].includes(c.name)) {
        jsSecrets.push(c.name);
      }
    }

    if (jsSecrets.length >= 3) {
      proofItems.push({
        type: 'report_confirmation',
        detail: `${jsSecrets.length} non-HttpOnly auth cookies: ${jsSecrets.join(', ')}`,
      });
    }

    const validated = proofItems.length >= 1;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? Math.min(hypothesis.confidence + 3, 90) : Math.max(hypothesis.confidence - 15, 10),
      validation_method: 'report_and_cookie_corroboration',
      validation_proof: proofItems,
      validation_notes: validated
        ? `Confirmed: ${jsSecrets.length} JS-accessible auth secrets`
        : 'Insufficient JS-accessible secrets to confirm',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate auth state desynchronization
   */
  _validateAuthDesync(hypothesis, events) {
    const proofItems = [];
    const authTimestamps = [];
    const unauthorizedTimestamps = [];

    for (const e of events) {
      if (e.type === 'auth_signal') {
        if (e.meta?.signalType === 'auth_cookie_set' || e.meta?.signalType === 'auth_cookies_present') {
          authTimestamps.push(e.ts);
        }
        if (e.meta?.signalType === 'unauthorized' || e.meta?.signalType === 'forbidden') {
          unauthorizedTimestamps.push({ ts: e.ts, url: e.url, signal: e.meta.signalType });
        }
      }
    }

    // Check 401/403 after last auth
    if (authTimestamps.length > 0 && unauthorizedTimestamps.length > 0) {
      const lastAuth = Math.max(...authTimestamps);
      const postAuth401s = unauthorizedTimestamps.filter(e => e.ts > lastAuth);
      if (postAuth401s.length >= 2) {
        proofItems.push({
          type: 'temporal_corroboration',
          detail: `${postAuth401s.length} unauthorized events after last auth at ${lastAuth}`,
        });
      }
    }

    const validated = proofItems.length >= 1;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? Math.min(hypothesis.confidence + 5, 85) : Math.max(hypothesis.confidence - 20, 10),
      validation_method: 'temporal_auth_tracking',
      validation_proof: proofItems,
      validation_notes: validated
        ? 'Auth desync confirmed: unauthorized responses after authentication'
        : 'No auth desync pattern verified',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate WS auth inconsistency
   */
  _validateWsAuthInconsistency(hypothesis, events) {
    const proofItems = [];
    const wsEvents = events.filter(e =>
      e.type === 'websocket_open' && e.meta
    );

    const withAuth = wsEvents.filter(e => e.meta.authToken || e.meta.token || e.meta.cookies || e.meta.auth);
    const withoutAuth = wsEvents.filter(e => !e.meta.authToken && !e.meta.token && !e.meta.cookies && !e.meta.auth);

    if (withAuth.length > 0 && withoutAuth.length > 0) {
      proofItems.push({
        type: 'ws_auth_analysis',
        detail: `${withAuth.length} WS connections with auth, ${withoutAuth.length} without auth`,
      });
    }

    const validated = proofItems.length >= 1;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? hypothesis.confidence : Math.max(hypothesis.confidence - 15, 10),
      validation_method: 'ws_auth_state_analysis',
      validation_proof: proofItems,
      validation_notes: validated ? 'WS auth inconsistency confirmed' : 'All WS connections have consistent auth',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate permission boundary anomaly
   */
  _validatePermissionBoundary(hypothesis, events) {
    const proofItems = [];
    const adminEndpoints = hypothesis.observed?.admin_endpoints || [];

    // Re-verify: successful responses on admin paths
    let confirmed = 0;
    for (const e of events) {
      if (e.type === 'network_response' && e.url && e.status >= 200 && e.status < 300) {
        try {
          const pathname = new URL(e.url).pathname;
          if (adminEndpoints.includes(pathname)) {
            confirmed++;
            proofItems.push({
              type: 'response_confirmation',
              ts: e.ts,
              detail: `${pathname} → ${e.status} (accessible)`,
            });
          }
        } catch (_) {}
      }
    }

    const validated = confirmed > 0;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? Math.min(hypothesis.confidence + 5, 70) : Math.max(hypothesis.confidence - 25, 5),
      validation_method: 'deterministic_response_replay',
      validation_proof: proofItems,
      validation_notes: validated
        ? `Confirmed: ${confirmed} admin endpoint(s) returned successful responses`
        : 'No admin endpoints confirmed accessible',
      validated_at: Date.now(),
    };
  }

  /**
   * Validate regression security change
   */
  _validateRegression(hypothesis, diff, baseline) {
    const proofItems = [];
    if (!diff) return this._fail(hypothesis, 'No diff available');

    if (diff.severity_score >= 40) {
      proofItems.push({
        type: 'diff_confirmation',
        detail: `Diff severity=${diff.severity_score}, verdict=${diff.verdict}`,
      });
    }

    const cookieDowngrades = (diff.cookie_diff || []).filter(cd =>
      cd.type === 'cookie_httpOnly_downgrade' || cd.type === 'cookie_secure_downgrade'
    );
    if (cookieDowngrades.length > 0) {
      proofItems.push({
        type: 'cookie_regression',
        detail: `${cookieDowngrades.length} cookie downgrade(s): ${cookieDowngrades.map(cd => cd.name).join(', ')}`,
      });
    }

    const addedRisks = diff.risk_delta?.added || [];
    if (addedRisks.length > 0) {
      proofItems.push({
        type: 'risk_regression',
        detail: `New risks: ${addedRisks.join(', ')}`,
      });
    }

    const validated = proofItems.length >= 1;
    return {
      hypothesis_id: hypothesis.id,
      validated,
      confidence_adjusted: validated ? Math.min(hypothesis.confidence + 5, 95) : Math.max(hypothesis.confidence - 15, 10),
      validation_method: 'diff_analysis',
      validation_proof: proofItems,
      validation_notes: validated
        ? `Security regression confirmed: ${proofItems.length} regression signal(s)`
        : 'No security regression verified',
      validated_at: Date.now(),
    };
  }

  /**
   * Generic validator for unknown categories
   */
  _validateGeneric(hypothesis, events, report) {
    return {
      hypothesis_id: hypothesis.id,
      validated: false,
      confidence_adjusted: Math.max(hypothesis.confidence - 30, 5),
      validation_method: 'generic',
      validation_proof: [],
      validation_notes: 'No category-specific validator available — manual review required',
      validated_at: Date.now(),
    };
  }

  // ─── Helpers ──────────────────────────────────────────────────

  _fail(hypothesis, reason) {
    return {
      hypothesis_id: hypothesis.id,
      validated: false,
      confidence_adjusted: Math.max(hypothesis.confidence - 30, 5),
      validation_method: 'insufficient_data',
      validation_proof: [],
      validation_notes: `Validation failed: ${reason}`,
      validated_at: Date.now(),
    };
  }

  getResults() {
    return [...this.validationResults.values()];
  }

  getValidated() {
    return [...this.validationResults.values()].filter(r => r.validated);
  }

  getUnvalidated() {
    return [...this.validationResults.values()].filter(r => !r.validated);
  }
}

module.exports = { ValidatorEngine };

