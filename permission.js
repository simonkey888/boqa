/**
 * BOQA permission.js — Permission Engine
 *
 * Detects authorization inconsistencies from observed roles and flows.
 * Analyzes the event stream to identify:
 *   - Role escalation paths (user accessing admin endpoints)
 *   - Permission boundary violations (cross-role data access)
 *   - Missing authorization checks (endpoints that should verify roles)
 *   - Session-based auth inconsistencies (different auth states seeing same data)
 *   - API response discrepancies (data returned beyond user's permission level)
 *
 * Safe mode: no privilege escalation attempts, no role manipulation.
 *            Only observes what the authenticated session can access
 *            and flags potential authorization gaps.
 *
 * Verification category: authorization_inconsistency
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = path.join(__dirname, 'output', 'permissions');
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

// ─── Role Definitions (Ripio-specific) ────────────────────────────

const KNOWN_ROLES = {
  anonymous: { level: 0, description: 'Unauthenticated visitor' },
  user: { level: 1, description: 'Standard authenticated user' },
  verified: { level: 2, description: 'KYC-verified user' },
  premium: { level: 3, description: 'Premium/VIP user' },
  admin: { level: 10, description: 'Administrator' },
  superadmin: { level: 20, description: 'Super administrator' },
};

// ─── Endpoint Classification ──────────────────────────────────────

const ENDPOINT_ROLE_REQUIREMENTS = {
  // Public endpoints (no auth required)
  '/api/public/': { min_role: 'anonymous', description: 'Public API' },
  '/login': { min_role: 'anonymous', description: 'Login page' },
  '/signup': { min_role: 'anonymous', description: 'Registration' },
  '/api/auth/': { min_role: 'anonymous', description: 'Auth endpoints' },

  // User-level endpoints
  '/api/users/me': { min_role: 'user', description: 'User profile' },
  '/api/wallet': { min_role: 'user', description: 'Wallet access' },
  '/api/balance': { min_role: 'user', description: 'Balance check' },
  '/api/transactions': { min_role: 'user', description: 'Transaction history' },
  '/dashboard': { min_role: 'user', description: 'User dashboard' },

  // Verified-level endpoints
  '/api/trade': { min_role: 'verified', description: 'Trading' },
  '/api/swap': { min_role: 'verified', description: 'Token swap' },
  '/api/withdraw': { min_role: 'verified', description: 'Withdrawal' },
  '/api/send': { min_role: 'verified', description: 'Send funds' },

  // Admin-level endpoints
  '/api/admin': { min_role: 'admin', description: 'Admin API' },
  '/admin': { min_role: 'admin', description: 'Admin panel' },
  '/api/manage': { min_role: 'admin', description: 'Management API' },
  '/api/internal': { min_role: 'admin', description: 'Internal API' },
};

// ─── Permission Issue Schema ──────────────────────────────────────

// {
//   id: string,
//   type: string,
//   severity: string,
//   description: string,
//   endpoint: string,
//   method: string,
//   required_role: string,
//   observed_role: string,
//   evidence: object,
//   confidence: 0-100,
// }

class PermissionEngine {
  constructor(options = {}) {
    this.issues = [];              // Permission issues found
    this.roleMap = new Map();      // sessionId → inferred role
    this.endpointAccess = new Map(); // endpoint → [{ sessionId, role, method, status }]
    this.options = {
      safeMode: true,
      ...options,
    };
  }

  /**
   * Analyze observations for permission inconsistencies
   * @param {object} observations - { events, report, anomalies, baseline, diff }
   * @param {array} confirmedBugs - from VerificationEngine
   * @returns {object} analysis result
   */
  analyze(observations = {}, confirmedBugs = []) {
    const { events = [], report = {}, anomalies = [] } = observations;

    // Step 1: Infer the user's role from observed behavior
    const inferredRole = this._inferRole(events, report);

    // Step 2: Map endpoint access patterns
    this._mapEndpointAccess(events, report);

    // Step 3: Detect permission boundary issues
    const boundaryIssues = this._detectBoundaryIssues(inferredRole);

    // Step 4: Detect missing auth checks
    const missingAuthIssues = this._detectMissingAuthChecks(events, report);

    // Step 5: Detect response-based permission leaks
    const responseLeaks = this._detectResponseLeaks(events, report);

    // Step 6: Cross-reference with confirmed bugs
    const bugCorrelations = this._correlateWithBugs(confirmedBugs);

    // Combine all issues
    this.issues = [
      ...boundaryIssues,
      ...missingAuthIssues,
      ...responseLeaks,
    ];

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    this.issues.sort((a, b) => (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4));

    return {
      inferred_role: inferredRole,
      total_issues: this.issues.length,
      issues: this.issues,
      endpoint_access_count: this.endpointAccess.size,
      bug_correlations: bugCorrelations,
      summary: this._buildSummary(),
    };
  }

  // ─── Role Inference ───────────────────────────────────────────

  _inferRole(events, report) {
    const roleSignals = {
      has_sessionid: false,
      has_auth_cookies: false,
      accessed_verified_endpoints: false,
      accessed_admin_endpoints: false,
      accessed_trade: false,
      accessed_withdraw: false,
    };

    // Check cookies
    for (const c of (report.cookies || [])) {
      if (c.name === 'sessionid' || c.name === 'ripio_access') {
        roleSignals.has_sessionid = true;
        roleSignals.has_auth_cookies = true;
      }
    }

    // Check endpoint access
    for (const e of events) {
      if (e.type === 'network_request' && e.url) {
        try {
          const pathname = new URL(e.url).pathname;

          if (/\/api\/trade|\/api\/swap/.test(pathname)) {
            roleSignals.accessed_trade = true;
            roleSignals.accessed_verified_endpoints = true;
          }
          if (/\/api\/withdraw|\/api\/send/.test(pathname)) {
            roleSignals.accessed_withdraw = true;
            roleSignals.accessed_verified_endpoints = true;
          }
          if (/\/api\/admin|\/admin|\/api\/manage|\/api\/internal/.test(pathname)) {
            roleSignals.accessed_admin_endpoints = true;
          }
          if (/\/api\/users\/me|\/api\/wallet|\/api\/balance|\/dashboard/.test(pathname)) {
            roleSignals.has_auth_cookies = true; // These require auth
          }
        } catch (_) {}
      }
    }

    // Infer role from signals
    if (roleSignals.accessed_admin_endpoints) return 'admin';
    if (roleSignals.accessed_verified_endpoints) return 'verified';
    if (roleSignals.has_sessionid || roleSignals.has_auth_cookies) return 'user';
    return 'anonymous';
  }

  // ─── Endpoint Access Mapping ──────────────────────────────────

  _mapEndpointAccess(events, report) {
    this.endpointAccess.clear();

    for (const e of events) {
      if ((e.type === 'network_request' || e.type === 'network_response') && e.url) {
        try {
          const u = new URL(e.url);
          const pathname = u.pathname;
          const method = e.method || 'GET';
          const status = e.status || null;

          if (!this.endpointAccess.has(pathname)) {
            this.endpointAccess.set(pathname, []);
          }

          this.endpointAccess.get(pathname).push({
            method,
            status,
            ts: e.ts,
            has_auth_header: this._hasAuthHeader(e),
            has_csrf: this._hasCsrfHeader(e),
          });
        } catch (_) {}
      }
    }
  }

  // ─── Boundary Issue Detection ─────────────────────────────────

  _detectBoundaryIssues(inferredRole) {
    const issues = [];
    const roleLevel = KNOWN_ROLES[inferredRole]?.level || 0;

    for (const [endpoint, accesses] of this.endpointAccess) {
      const requiredRole = this._getRequiredRole(endpoint);
      const requiredLevel = KNOWN_ROLES[requiredRole]?.level || 0;

      // If user's role level is below the required level and they got 2xx
      if (roleLevel < requiredLevel) {
        const successfulAccess = accesses.filter(a => a.status && a.status >= 200 && a.status < 300);
        if (successfulAccess.length > 0) {
          issues.push({
            id: `perm-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36) + Math.random().toString(36).substring(2, 6)}`,
            type: 'role_boundary_violation',
            severity: requiredLevel >= 10 ? 'critical' : 'high',
            description: `User with role "${inferredRole}" (level ${roleLevel}) successfully accessed "${endpoint}" which requires role "${requiredRole}" (level ${requiredLevel})`,
            endpoint,
            method: successfulAccess[0].method,
            required_role: requiredRole,
            observed_role: inferredRole,
            evidence: {
              access_count: successfulAccess.length,
              status_codes: [...new Set(successfulAccess.map(a => a.status))],
              has_auth_header: successfulAccess[0].has_auth_header,
            },
            confidence: Math.min(95, 60 + successfulAccess.length * 10),
          });
        }
      }
    }

    return issues;
  }

  // ─── Missing Auth Check Detection ─────────────────────────────

  _detectMissingAuthChecks(events, report) {
    const issues = [];

    // Find auth-required endpoints that were accessed without auth headers
    for (const [endpoint, accesses] of this.endpointAccess) {
      if (!this._requiresAuth(endpoint)) continue;

      const noAuthAccess = accesses.filter(a =>
        a.status && a.status >= 200 && a.status < 300 && !a.has_auth_header
      );

      if (noAuthAccess.length > 0) {
        issues.push({
          id: `perm-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36) + Math.random().toString(36).substring(2, 6)}`,
          type: 'missing_auth_check',
          severity: 'high',
          description: `Auth-required endpoint "${endpoint}" returned 2xx without authentication headers. Possible missing authorization middleware.`,
          endpoint,
          method: noAuthAccess[0].method,
          required_role: 'user',
          observed_role: 'anonymous',
          evidence: {
            access_without_auth: noAuthAccess.length,
            status_codes: [...new Set(noAuthAccess.map(a => a.status))],
          },
          confidence: Math.min(90, 50 + noAuthAccess.length * 15),
        });
      }
    }

    // Find state-changing requests without CSRF protection
    const stateChangingNoCsrf = [];
    for (const e of events) {
      if (e.type === 'network_request' && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(e.method)) {
        if (!this._hasCsrfHeader(e) && e.url) {
          try {
            const pathname = new URL(e.url).pathname;
            stateChangingNoCsrf.push({ pathname, method: e.method, ts: e.ts });
          } catch (_) {}
        }
      }
    }

    if (stateChangingNoCsrf.length > 0) {
      issues.push({
        id: `perm-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36) + Math.random().toString(36).substring(2, 6)}`,
        type: 'missing_csrf_protection',
        severity: 'high',
        description: `${stateChangingNoCsrf.length} state-changing request(s) without CSRF token. Endpoints: ${[...new Set(stateChangingNoCsrf.map(s => s.pathname))].slice(0, 5).join(', ')}`,
        endpoint: [...new Set(stateChangingNoCsrf.map(s => s.pathname))].slice(0, 3),
        method: 'POST/PUT/PATCH/DELETE',
        required_role: 'user',
        observed_role: 'user',
        evidence: {
          unprotected_requests: stateChangingNoCsrf.length,
          endpoints: [...new Set(stateChangingNoCsrf.map(s => s.pathname))].slice(0, 10),
        },
        confidence: Math.min(90, 40 + stateChangingNoCsrf.length * 10),
      });
    }

    return issues;
  }

  // ─── Response Leak Detection ──────────────────────────────────

  _detectResponseLeaks(events, report) {
    const issues = [];

    // Check for sensitive data in responses that shouldn't be there
    const responses = events.filter(e => e.type === 'network_response');

    for (const r of responses) {
      if (!r.url || !r.headers) continue;

      try {
        const u = new URL(r.url);
        const lower = {};
        for (const [k, v] of Object.entries(r.headers)) lower[k.toLowerCase()] = v;

        // Check for information disclosure via headers
        if (lower['server'] && /express|django|nginx|apache/i.test(lower['server'])) {
          // Only flag once
          if (!issues.find(i => i.type === 'server_header_disclosure')) {
            issues.push({
              id: `perm-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36) + Math.random().toString(36).substring(2, 6)}`,
              type: 'server_header_disclosure',
              severity: 'low',
              description: `Server header reveals technology: ${lower['server']}`,
              endpoint: u.pathname,
              method: 'GET',
              required_role: 'anonymous',
              observed_role: 'anonymous',
              evidence: { server_header: lower['server'] },
              confidence: 90,
            });
          }
        }

        // Check for overly permissive CORS on sensitive endpoints
        if (lower['access-control-allow-origin'] === '*' &&
            /\/api\/users\/me|\/api\/wallet|\/api\/balance/.test(u.pathname)) {
          issues.push({
            id: `perm-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36) + Math.random().toString(36).substring(2, 6)}`,
            type: 'cors_wildcard_on_sensitive_endpoint',
            severity: 'critical',
            description: `Wildcard CORS (ACAO:*) on sensitive endpoint: ${u.pathname}`,
            endpoint: u.pathname,
            method: 'GET',
            required_role: 'user',
            observed_role: 'any',
            evidence: { acao: '*', endpoint: u.pathname },
            confidence: 95,
          });
        }
      } catch (_) {}
    }

    return issues;
  }

  // ─── Bug Correlation ──────────────────────────────────────────

  _correlateWithBugs(confirmedBugs) {
    const correlations = [];

    for (const bug of confirmedBugs) {
      if (bug.category === 'authorization_inconsistency') {
        const matchingIssues = this.issues.filter(i =>
          i.type === 'role_boundary_violation' || i.type === 'missing_auth_check'
        );

        correlations.push({
          bug_id: bug.id,
          bug_title: bug.title,
          related_permission_issues: matchingIssues.length,
          highest_issue_severity: matchingIssues.length > 0
            ? matchingIssues.sort((a, b) => {
                const o = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                return (o[a.severity] || 4) - (o[b.severity] || 4);
              })[0].severity
            : null,
        });
      }
    }

    return correlations;
  }

  // ─── Utility Methods ─────────────────────────────────────────

  _getRequiredRole(pathname) {
    // Check against known patterns
    for (const [pattern, req] of Object.entries(ENDPOINT_ROLE_REQUIREMENTS)) {
      if (pathname.startsWith(pattern) || pathname.includes(pattern)) {
        return req.min_role;
      }
    }

    // Heuristic: /api/ paths likely require auth
    if (pathname.startsWith('/api/') && !pathname.includes('/public/')) {
      return 'user';
    }

    return 'anonymous';
  }

  _requiresAuth(pathname) {
    const requiredRole = this._getRequiredRole(pathname);
    return KNOWN_ROLES[requiredRole]?.level > 0;
  }

  _hasAuthHeader(event) {
    const headers = event.headers || {};
    const lower = {};
    for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
    return !!(lower['authorization'] || lower['x-auth-token'] || lower['x-access-token']);
  }

  _hasCsrfHeader(event) {
    const headers = event.headers || {};
    const lower = {};
    for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
    return !!(lower['x-csrftoken'] || lower['x-csrf-token']);
  }

  _buildSummary() {
    const byType = {};
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

    for (const issue of this.issues) {
      byType[issue.type] = (byType[issue.type] || 0) + 1;
      bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
    }

    return {
      total_issues: this.issues.length,
      by_type: byType,
      by_severity: bySeverity,
      endpoints_analyzed: this.endpointAccess.size,
    };
  }

  // ─── Persistence ──────────────────────────────────────────────

  save() {
    const report = {
      generated_at: Date.now(),
      version: '0.4.0',
      safe_mode: this.options.safeMode,
      issues: this.issues,
      summary: this._buildSummary(),
    };

    const filePath = path.join(OUTPUT_DIR, `permission-report-${Date.now()}.json`);
    fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
    return filePath;
  }

  // ─── Accessors ────────────────────────────────────────────────

  getIssues() {
    return this.issues;
  }

  getIssuesByType(type) {
    return this.issues.filter(i => i.type === type);
  }

  getIssuesBySeverity(severity) {
    return this.issues.filter(i => i.severity === severity);
  }

  getInferredRole() {
    return this.roleMap;
  }

  getEndpointAccess() {
    return this.endpointAccess;
  }
}

module.exports = { PermissionEngine, KNOWN_ROLES, ENDPOINT_ROLE_REQUIREMENTS, OUTPUT_DIR };

