/**
 * BOQA evidence.js — Evidence Engine
 *
 * Builds proof packages from captured observability evidence.
 * Each finding gets a structured evidence chain that supports
 * responsible disclosure and reproduction.
 *
 * Evidence types:
 *   - event_reference: Links to specific events in the NDJSON stream
 *   - header_snapshot: Captured HTTP headers
 *   - cookie_snapshot: Cookie state at a point in time
 *   - response_body_excerpt: Sanitized response body excerpt
 *   - timeline_segment: Sequence of events showing the behavior
 *   - baseline_comparison: Before/after from baseline
 *   - validation_proof: Output from ValidatorEngine
 *
 * Safe mode: No full cookie values, no full tokens, no PII.
 *            Values are truncated/hashed for evidence packages.
 */

const crypto = require('crypto');

class EvidenceEngine {
  constructor() {
    this.evidencePackages = new Map(); // findingId → evidencePackage
  }

  /**
   * Build an evidence package for a validated finding
   * @param {object} finding - normalized finding (from risk.js)
   * @param {object} validationResult - from ValidatorEngine
   * @param {object} observations - { events, report, anomalies, baseline, diff }
   * @returns {object} evidence package
   */
  buildPackage(finding, validationResult, observations) {
    const { events = [], report = {}, anomalies = [], baseline = null, diff = null } = observations;

    const evidence = {
      finding_id: finding.id,
      category: finding.category,
      built_at: Date.now(),

      // Evidence chain
      evidence_chain: [],

      // Timeline of relevant events
      timeline: [],

      // Affected resources
      affected_cookies: finding.affected_cookies || [],
      affected_endpoints: finding.affected_endpoints || [],

      // Reproduction hints (safe mode — no exploitation steps)
      reproduction: [],

      // Recommended fix
      recommended_fix: this._getRecommendedFix(finding.category),

      // Sanitization metadata
      sanitization: {
        cookie_values_truncated: true,
        token_values_redacted: true,
        pii_removed: true,
        safe_mode: true,
      },
    };

    // 1. Build evidence chain from validation proof
    if (validationResult.validation_proof) {
      for (const proof of validationResult.validation_proof) {
        evidence.evidence_chain.push({
          type: 'validation_proof',
          source: proof.type,
          detail: proof.detail,
          ts: proof.ts || null,
          corroborates: true,
        });
      }
    }

    // 2. Build timeline from relevant events
    evidence.timeline = this._buildTimeline(finding, events);

    // 3. Add category-specific evidence
    this._addCategoryEvidence(evidence, finding, events, report, baseline, diff);

    // 4. Build reproduction steps (observability only, safe mode)
    evidence.reproduction = this._buildReproduction(finding, events, report);

    this.evidencePackages.set(finding.id, evidence);
    return evidence;
  }

  /**
   * Build evidence packages for all findings
   */
  buildAll(findings, validationResults, observations) {
    const packages = [];
    const validationMap = new Map();

    for (const vr of validationResults) {
      validationMap.set(vr.hypothesis_id, vr);
    }

    for (const finding of findings) {
      // Use hypothesis_id to find the validation result (finding.id is FND-xxx, hypothesis_id is hyp-xxx)
      const vr = validationMap.get(finding.hypothesis_id) || { validated: false, validation_proof: [], validation_method: 'none' };
      if (vr.validated) {
        const pkg = this.buildPackage(finding, vr, observations);
        packages.push(pkg);
      }
    }

    return packages;
  }

  // ─── Timeline Builder ─────────────────────────────────────────

  _buildTimeline(finding, events) {
    const timeline = [];
    const category = finding.category;
    const affectedCookies = new Set(finding.affected_cookies || []);
    const affectedEndpoints = new Set(finding.affected_endpoints || []);

    for (const e of events) {
      let relevant = false;
      let note = '';

      switch (category) {
        case 'missing_httpOnly':
        case 'missing_secure':
        case 'weak_samesite':
          if (e.type === 'cookie_snapshot' && e.meta?.authCookies) {
            const matching = e.meta.authCookies.filter(c => affectedCookies.has(c.name));
            if (matching.length > 0) {
              relevant = true;
              note = matching.map(c => `${c.name}[H=${c.httpOnly},S=${c.secure},SS=${c.sameSite}]`).join(', ');
            }
          }
          break;

        case 'bearer_token_exposure':
          if (e.type === 'network_request' && e.headers) {
            const lower = {};
            for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;
            if (lower['authorization']) {
              relevant = true;
              note = `Authorization: ${this._sanitizeHeader(lower['authorization'])}`;
            }
          }
          break;

        case 'jwt_in_browser_memory':
          if (e.type === 'console_log' && e.payload &&
            (e.payload.includes('CryptoJS') || e.payload.includes('aes_decrypt'))) {
            relevant = true;
            note = 'Client-side decryption detected';
          }
          break;

        case 'session_fixation_indicators':
        case 'session_rotation_failure':
          if (e.type === 'auth_signal' && e.meta?.cookies) {
            const sid = e.meta.cookies.find(c => c.name === 'sessionid');
            if (sid) {
              relevant = true;
              note = `sessionid=${this._sanitizeValue(sid.valuePreview || sid.value)} signal=${e.meta.signalType}`;
            }
          }
          break;

        case 'cache_control_misconfiguration':
          if (e.type === 'network_response' && e.url) {
            try {
              const pathname = new URL(e.url).pathname;
              if (affectedEndpoints.has(pathname)) {
                relevant = true;
                const lower = {};
                if (e.headers) for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;
                note = `Cache-Control: ${lower['cache-control'] || '(missing)'}`;
              }
            } catch (_) {}
          }
          break;

        case 'cors_misconfiguration':
          if (e.type === 'network_response' && e.headers) {
            const lower = {};
            for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;
            if (lower['access-control-allow-origin']) {
              relevant = true;
              note = `ACAO: ${lower['access-control-allow-origin']} ACAC: ${lower['access-control-allow-credentials'] || '(none)'}`;
            }
          }
          break;

        case 'csrf_signal_anomaly':
          if (e.type === 'network_request' && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(e.method)) {
            const lower = {};
            if (e.headers) for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;
            const hasCsrf = lower['x-csrftoken'] || lower['x-csrf-token'];
            if (!hasCsrf) {
              relevant = true;
              try { note = `${e.method} ${new URL(e.url).pathname} (no CSRF header)`; } catch (_) {}
            }
          }
          break;

        case 'auth_state_desynchronization':
          if (e.type === 'auth_signal') {
            if (e.meta?.signalType === 'unauthorized' || e.meta?.signalType === 'forbidden') {
              relevant = true;
              note = `${e.meta.signalType} on ${e.url || 'unknown'}`;
            }
            if (e.meta?.signalType === 'auth_cookie_set') {
              relevant = true;
              note = 'Auth cookies set';
            }
          }
          break;

        default:
          // Generic: include auth signals and cookie snapshots
          if (e.type === 'auth_signal') {
            relevant = true;
            note = e.meta?.signalType || 'auth event';
          }
      }

      if (relevant) {
        timeline.push({
          event_id: e.id,
          ts: e.ts,
          elapsed: e.elapsed,
          type: e.type,
          url: e.url ? this._sanitizeUrl(e.url) : null,
          method: e.method || null,
          status: e.status || null,
          note,
        });
      }

      // Cap timeline at 50 entries
      if (timeline.length >= 50) break;
    }

    return timeline;
  }

  // ─── Category-Specific Evidence ───────────────────────────────

  _addCategoryEvidence(evidence, finding, events, report, baseline, diff) {
    switch (finding.category) {
      case 'missing_httpOnly':
      case 'missing_secure':
      case 'weak_samesite':
        this._addCookieEvidence(evidence, finding, report, events);
        break;

      case 'jwt_in_browser_memory':
        this._addJwtEvidence(evidence, finding, events);
        break;

      case 'session_fixation_indicators':
        this._addSessionFixationEvidence(evidence, finding, events);
        break;

      case 'cors_misconfiguration':
        this._addCorsEvidence(evidence, finding, events);
        break;

      case 'regression_security_change':
        this._addRegressionEvidence(evidence, finding, diff, baseline);
        break;

      default:
        // Generic header evidence
        this._addGenericEvidence(evidence, finding, events);
    }
  }

  _addCookieEvidence(evidence, finding, report, events) {
    const cookieName = finding.affected_cookies[0];
    if (!cookieName) return;

    // Cookie attributes at session end
    const cookie = (report.cookies || []).find(c => c.name === cookieName);
    if (cookie) {
      evidence.evidence_chain.push({
        type: 'cookie_snapshot',
        source: 'auth_report',
        detail: `Final state: ${cookieName} [httpOnly=${cookie.httpOnly}, secure=${cookie.secure}, sameSite=${cookie.sameSite}, domain=${cookie.domain}, path=${cookie.path}]`,
      });
    }

    // Set-Cookie headers that established the cookie
    for (const e of events) {
      if (e.type === 'network_response' && e.headers) {
        const lower = {};
        for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;
        const sc = lower['set-cookie'] || '';
        if (sc.includes(cookieName)) {
          evidence.evidence_chain.push({
            type: 'header_snapshot',
            source: 'network_response',
            ts: e.ts,
            detail: `Set-Cookie: ${this._sanitizeSetCookie(sc)}`,
          });
        }
      }
    }
  }

  _addJwtEvidence(evidence, finding, events) {
    // CryptoJS decrypt events
    const decryptEvents = events.filter(e =>
      e.type === 'console_log' && e.payload &&
      (e.payload.includes('CryptoJS.AES.decrypt') || e.payload.includes('__BOQA__aes_decrypt'))
    );

    for (const de of decryptEvents) {
      evidence.evidence_chain.push({
        type: 'event_reference',
        source: 'console_log',
        ts: de.ts,
        detail: `Client-side AES decryption detected: ${this._sanitizeValue(de.payload)}`,
      });
    }

    // Encrypted cookie prefix evidence
    for (const e of events) {
      if (e.type === 'cookie_snapshot' && e.meta?.authCookies) {
        const encrypted = e.meta.authCookies.filter(c => c.value && c.value.startsWith('U2FsdGVkX1'));
        if (encrypted.length > 0) {
          evidence.evidence_chain.push({
            type: 'cookie_snapshot',
            source: 'cookie_poll',
            ts: e.ts,
            detail: `Encrypted cookie(s): ${encrypted.map(c => `${c.name}=U2FsdGVkX1...`).join(', ')}`,
          });
        }
      }
    }
  }

  _addSessionFixationEvidence(evidence, finding, events) {
    const sessionValues = [];
    for (const e of events) {
      if (e.type === 'cookie_snapshot' && e.meta?.authCookies) {
        const sid = e.meta.authCookies.find(c => c.name === 'sessionid');
        if (sid) {
          sessionValues.push({ ts: e.ts, hash: this._hashValue(sid.valuePreview || sid.value) });
        }
      }
    }

    if (sessionValues.length >= 2) {
      const allSame = sessionValues.every(s => s.hash === sessionValues[0].hash);
      evidence.evidence_chain.push({
        type: 'timeline_segment',
        source: 'cookie_tracking',
        detail: `${sessionValues.length} sessionid snapshots, all_same_hash=${allSame}`,
        data: sessionValues.map(s => ({ ts: s.ts, hash: s.hash.substring(0, 8) + '...' })),
      });
    }
  }

  _addCorsEvidence(evidence, finding, events) {
    for (const e of events) {
      if (e.type === 'network_response' && e.headers) {
        const lower = {};
        for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;

        if (lower['access-control-allow-origin'] === '*' && lower['access-control-allow-credentials'] === 'true') {
          evidence.evidence_chain.push({
            type: 'header_snapshot',
            source: 'network_response',
            ts: e.ts,
            detail: `${this._sanitizeUrl(e.url || '')} → ACAO:*, ACAC:true (CRITICAL)`,
          });
        }
      }
    }
  }

  _addRegressionEvidence(evidence, finding, diff, baseline) {
    if (diff) {
      evidence.evidence_chain.push({
        type: 'baseline_comparison',
        source: 'diff_engine',
        detail: `Severity: ${diff.severity_score}/100, verdict: ${diff.verdict}`,
      });

      if (diff.cookie_diff?.length > 0) {
        evidence.evidence_chain.push({
          type: 'baseline_comparison',
          source: 'cookie_diff',
          detail: diff.cookie_diff.map(cd => `${cd.type}: ${cd.name}`).join('; '),
        });
      }
    }
  }

  _addGenericEvidence(evidence, finding, events) {
    // Include auth signals as generic evidence
    const authEvents = events.filter(e => e.type === 'auth_signal').slice(0, 10);
    for (const ae of authEvents) {
      evidence.evidence_chain.push({
        type: 'event_reference',
        source: 'auth_signal',
        ts: ae.ts,
        detail: ae.meta?.signalType || 'auth event',
      });
    }
  }

  // ─── Reproduction Steps ───────────────────────────────────────

  _buildReproduction(finding, events, report) {
    const steps = [];
    const category = finding.category;

    steps.push({
      step: 1,
      action: 'observe',
      description: `Open BOQA dashboard and navigate to the target application`,
      safe: true,
    });

    switch (category) {
      case 'missing_httpOnly':
        steps.push({
          step: 2,
          action: 'observe',
          description: `Check cookie attributes in browser DevTools → Application → Cookies. Confirm "${finding.affected_cookies[0]}" is accessible via document.cookie (no HttpOnly flag).`,
          safe: true,
        });
        steps.push({
          step: 3,
          action: 'observe',
          description: `In console, execute: document.cookie.includes('${finding.affected_cookies[0]}') — should return true if HttpOnly is missing.`,
          safe: true,
        });
        break;

      case 'missing_secure':
        steps.push({
          step: 2,
          action: 'observe',
          description: `Access the application over HTTP (not HTTPS) and check if "${finding.affected_cookies[0]}" is sent in the request headers. Use browser DevTools → Network tab to verify.`,
          safe: true,
        });
        break;

      case 'jwt_in_browser_memory':
        steps.push({
          step: 2,
          action: 'observe',
          description: `Open browser DevTools → Console and look for CryptoJS.AES.decrypt calls. Set a breakpoint on CryptoJS.AES.decrypt to observe the decrypted token value in memory.`,
          safe: true,
        });
        steps.push({
          step: 3,
          action: 'observe',
          description: `After decryption, search browser memory (DevTools → Memory → Heap Snapshot) for the decrypted JWT payload. The token is accessible to any JavaScript running in the page context.`,
          safe: true,
        });
        break;

      case 'cors_misconfiguration':
        steps.push({
          step: 2,
          action: 'observe',
          description: `From a different origin (e.g., local HTML file), make a fetch request to the affected endpoint with credentials: 'include'. Observe the response headers in DevTools.`,
          safe: true,
        });
        break;

      case 'csrf_signal_anomaly':
        steps.push({
          step: 2,
          action: 'observe',
          description: `Submit a state-changing request (POST/PUT/PATCH/DELETE) and verify in DevTools Network tab that no X-CSRFToken or CSRF header is included.`,
          safe: true,
        });
        steps.push({
          step: 3,
          action: 'observe',
          description: `Check if the csrftoken cookie is set but not being sent as a header (double-submit pattern failure).`,
          safe: true,
        });
        break;

      case 'session_fixation_indicators':
        steps.push({
          step: 2,
          action: 'observe',
          description: `Note the sessionid cookie value before login. Complete the login flow. Check if sessionid changed after authentication. If unchanged, session fixation may be possible.`,
          safe: true,
        });
        break;

      default:
        steps.push({
          step: 2,
          action: 'observe',
          description: `Review the evidence chain and timeline in the finding report. Use browser DevTools to corroborate the observed behavior.`,
          safe: true,
        });
    }

    steps.push({
      step: steps.length + 1,
      action: 'disclosure',
      description: `Report finding to the security team via responsible disclosure. Include the BOQA finding ID and evidence package.`,
      safe: true,
    });

    return steps;
  }

  // ─── Recommended Fixes ────────────────────────────────────────

  _getRecommendedFix(category) {
    const fixes = {
      missing_httpOnly: 'Set the HttpOnly flag on all authentication cookies. This prevents JavaScript from accessing session tokens, mitigating XSS-based session theft.',
      missing_secure: 'Set the Secure flag on all authentication cookies. This ensures cookies are only sent over HTTPS, preventing passive network interception.',
      weak_samesite: 'Set SameSite=Strict or SameSite=Lax on authentication cookies. This prevents the browser from sending cookies with cross-site requests, mitigating CSRF attacks.',
      bearer_token_exposure: 'Avoid sending Authorization headers to non-API endpoints. Move authentication to HttpOnly cookies. If bearer tokens are required, restrict them to specific API paths and never expose them to JavaScript.',
      jwt_in_browser_memory: 'Avoid client-side token decryption. Perform token decryption server-side and use HttpOnly cookies for session management. If client-side decryption is required, consider using Web Workers to isolate the decryption context.',
      session_fixation_indicators: 'Always rotate the session ID after successful authentication. Use the Django session cycle_key() method or equivalent framework feature to generate a new session ID upon login.',
      session_rotation_failure: 'Investigate the session rotation logic. Excessive rotation may indicate a bug in the session management code or a race condition. Ensure rotation happens only at appropriate times (login, privilege change).',
      cache_control_misconfiguration: 'Add Cache-Control: no-store, no-cache, must-revalidate and Pragma: no-cache headers to all responses containing sensitive data (auth, user info, wallet data).',
      csrf_signal_anomaly: 'Implement CSRF protection on all state-changing endpoints. Use the double-submit cookie pattern (csrftoken cookie + X-CSRFToken header) or Django CSRF middleware.',
      cors_misconfiguration: 'Remove Access-Control-Allow-Origin: * from API endpoints. Specify explicit allowed origins. Never combine wildcard origin with Access-Control-Allow-Credentials: true.',
      cookie_scope_oversharing: 'Restrict cookie path and domain. Use path=/api or more specific paths for auth cookies. Avoid .domain.com scoping unless all subdomains require the cookie.',
      cross_subdomain_trust_expansion: 'Review which subdomains require authentication cookies. Add explicit subdomain restrictions. Audit the cookie domain configuration in the application server.',
      unexpected_auth_model_change: 'Investigate the authentication architecture change. Ensure the new model provides equivalent or better security. Update the security baseline.',
      sensitive_data_exposure: 'Never include sensitive data (tokens, passwords, API keys) in URL query strings. Use request headers or POST bodies instead. URLs are logged in browser history, server logs, and referer headers.',
      excessive_client_side_secrets: 'Minimize the number of secrets accessible to JavaScript. Move authentication tokens to HttpOnly cookies. Use server-side session management. Reduce the attack surface for XSS.',
      auth_state_desynchronization: 'Investigate the root cause of auth desync. Ensure session cookies are properly set after authentication. Check for race conditions between login API and cookie-setting responses.',
      ws_auth_inconsistency: 'Enforce consistent authentication across all WebSocket connections. Verify the auth token on every WS message, not just at connection time. Close connections with invalid auth immediately.',
      permission_boundary_anomaly: 'Add server-side authorization checks for admin/privileged endpoints. Verify the user role before returning sensitive data. Implement proper RBAC.',
      regression_security_change: 'Revert the security regression. Review the diff between the baseline and current session. Ensure cookie attributes, auth model, and risk flags match or exceed the baseline.',
    };

    return fixes[category] || 'Review the finding details and implement appropriate security controls. Follow responsible disclosure practices.';
  }

  // ─── Sanitization ─────────────────────────────────────────────

  _sanitizeValue(value) {
    if (!value) return '(empty)';
    const s = String(value);
    if (s.length <= 8) return '***';
    return s.substring(0, 4) + '***' + s.substring(s.length - 4);
  }

  _sanitizeHeader(value) {
    if (!value) return '(none)';
    if (value.startsWith('Bearer ')) return `Bearer ${this._sanitizeValue(value.substring(7))}`;
    return this._sanitizeValue(value);
  }

  _sanitizeSetCookie(header) {
    // Remove full cookie values, keep attributes
    return header.replace(/=([^;,]+)/g, '=***REDACTED***');
  }

  _sanitizeUrl(url) {
    try {
      const u = new URL(url);
      // Remove query parameter values that might be sensitive
      const params = u.searchParams;
      for (const key of params.keys()) {
        params.set(key, '***');
      }
      return u.toString();
    } catch (_) {
      return url;
    }
  }

  _hashValue(value) {
    if (!value) return 'null';
    return crypto.createHash('sha256').update(String(value)).digest('hex');
  }

  // ─── Accessors ────────────────────────────────────────────────

  getPackage(findingId) {
    return this.evidencePackages.get(findingId);
  }

  getAllPackages() {
    return [...this.evidencePackages.values()];
  }
}

module.exports = { EvidenceEngine };

