/**
 * BOQA verification.js — Verification Engine
 *
 * Executes deterministic validation plans for findings produced by the
 * v0.3 pipeline (finder → validator → evidence → risk).
 *
 * Finding lifecycle: observation → hypothesis → validation_plan →
 *                    verification → evidence → confirmed_bug
 *
 * This engine bridges the gap between "validated hypothesis" and
 * "confirmed reproducible bug" by creating and executing structured
 * verification plans that use only allowed safe-mode actions:
 *   navigation, authenticated_replay, request_replay, state_comparison,
 *   header_variation, cookie_variation, cache_validation,
 *   permission_validation, workflow_validation
 *
 * Forbidden: bruteforce, fuzzing_at_scale, credential_attacks, dos,
 *            privilege_escalation_attempts, destructive_mutations,
 *            mass_scanning
 *
 * Verification categories:
 *   authentication_regression, session_management_issue,
 *   authorization_inconsistency, cookie_security_failure,
 *   csrf_protection_failure, cors_policy_issue,
 *   cache_control_issue, sensitive_data_exposure,
 *   workflow_state_corruption, websocket_auth_desync
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = path.join(__dirname, 'output', 'verifications');
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

// ─── Allowed / Forbidden Action Enforcement ───────────────────────

const ALLOWED_ACTIONS = new Set([
  'navigation', 'authenticated_replay', 'request_replay',
  'state_comparison', 'header_variation', 'cookie_variation',
  'cache_validation', 'permission_validation', 'workflow_validation',
]);

const FORBIDDEN_ACTIONS = new Set([
  'bruteforce', 'fuzzing_at_scale', 'credential_attacks', 'dos',
  'privilege_escalation_attempts', 'destructive_mutations', 'mass_scanning',
]);

// ─── Verification Categories ──────────────────────────────────────

const VERIFICATION_CATEGORIES = [
  'authentication_regression',
  'session_management_issue',
  'authorization_inconsistency',
  'cookie_security_failure',
  'csrf_protection_failure',
  'cors_policy_issue',
  'cache_control_issue',
  'sensitive_data_exposure',
  'workflow_state_corruption',
  'websocket_auth_desync',
];

// ─── Bug Schema Template ──────────────────────────────────────────

// {
//   id: 'BUG-XXXX',
//   title: string,
//   severity: 'critical|high|medium|low',
//   confidence: 0-100,
//   status: 'confirmed',
//   category: string,
//   evidence_count: number,
//   affected_assets: [],
//   reproduction_steps: [],
//   verification_trace: [],
//   recommended_fix: string,
// }

// ─── Verification Plan Step Schema ────────────────────────────────

// {
//   step: number,
//   action: string,          // from ALLOWED_ACTIONS
//   description: string,
//   expected_outcome: string,
//   actual_outcome: string | null,
//   passed: boolean | null,
//   evidence: object | null,
//   ts: number | null,
// }

// ─── Category → Verification Plan Mapping ─────────────────────────

const CATEGORY_PLAN_MAP = {
  // v0.3 finding categories → v0.4 verification categories → plan templates
  missing_httpOnly: {
    verification_category: 'cookie_security_failure',
    steps: [
      { action: 'navigation', description: 'Navigate to authenticated page', expected_outcome: 'Page loads with auth cookies set' },
      { action: 'state_comparison', description: 'Check cookie accessibility via document.cookie', expected_outcome: 'Auth cookie should NOT appear in document.cookie if HttpOnly' },
      { action: 'cookie_variation', description: 'Verify Set-Cookie header lacks HttpOnly flag', expected_outcome: 'Set-Cookie header for auth cookie missing HttpOnly attribute' },
      { action: 'request_replay', description: 'Replay an authenticated request and confirm cookie is accessible to JS', expected_outcome: 'Cookie is readable by JavaScript (confirms missing HttpOnly)' },
    ],
  },
  missing_secure: {
    verification_category: 'cookie_security_failure',
    steps: [
      { action: 'navigation', description: 'Navigate to the application over HTTP', expected_outcome: 'Application may be accessible over HTTP' },
      { action: 'cookie_variation', description: 'Verify Secure flag absence on auth cookies', expected_outcome: 'Auth cookie lacks Secure flag, may be sent over HTTP' },
      { action: 'request_replay', description: 'Observe cookie transmission in request headers', expected_outcome: 'Cookie sent in cleartext if Secure flag absent' },
    ],
  },
  weak_samesite: {
    verification_category: 'cookie_security_failure',
    steps: [
      { action: 'cookie_variation', description: 'Check SameSite attribute on auth cookies', expected_outcome: 'Auth cookie has SameSite=None or no SameSite attribute' },
      { action: 'request_replay', description: 'Verify cross-site request includes the cookie', expected_outcome: 'Cookie sent with cross-site request (CSRF risk)' },
    ],
  },
  bearer_token_exposure: {
    verification_category: 'sensitive_data_exposure',
    steps: [
      { action: 'state_comparison', description: 'Check browser memory for Authorization header values', expected_outcome: 'Bearer token visible in browser JS context' },
      { action: 'request_replay', description: 'Replay request with Authorization header and verify exposure', expected_outcome: 'Token accessible to any JS running in the page' },
      { action: 'header_variation', description: 'Check if Authorization is sent to non-API endpoints', expected_outcome: 'Bearer token sent to non-API paths (overexposure)' },
    ],
  },
  jwt_in_browser_memory: {
    verification_category: 'sensitive_data_exposure',
    steps: [
      { action: 'state_comparison', description: 'Check for CryptoJS.AES.decrypt calls in page scripts', expected_outcome: 'Client-side decryption detected — JWT decrypted in browser memory' },
      { action: 'authenticated_replay', description: 'Replay auth flow and observe decryption timing', expected_outcome: 'JWT decrypted and stored in JS variable accessible to XSS' },
      { action: 'request_replay', description: 'Verify decrypted token is used in subsequent API calls', expected_outcome: 'Decrypted JWT payload readable from JS memory' },
    ],
  },
  session_fixation_indicators: {
    verification_category: 'session_management_issue',
    steps: [
      { action: 'state_comparison', description: 'Compare sessionid before and after authentication', expected_outcome: 'sessionid value should change after login (rotation)' },
      { action: 'authenticated_replay', description: 'Replay login flow and track session cookie rotation', expected_outcome: 'Session ID fails to rotate after authentication (fixation risk)' },
      { action: 'cookie_variation', description: 'Check Set-Cookie headers for session rotation signals', expected_outcome: 'No Set-Cookie with new sessionid after login endpoint' },
    ],
  },
  session_rotation_failure: {
    verification_category: 'session_management_issue',
    steps: [
      { action: 'state_comparison', description: 'Track sessionid changes across the session timeline', expected_outcome: 'Session ID should only rotate at appropriate times' },
      { action: 'authenticated_replay', description: 'Replay authenticated actions and verify session stability', expected_outcome: 'Session rotates unexpectedly or not at all during auth transitions' },
    ],
  },
  cache_control_misconfiguration: {
    verification_category: 'cache_control_issue',
    steps: [
      { action: 'cache_validation', description: 'Check Cache-Control headers on sensitive endpoints', expected_outcome: 'Sensitive endpoints should have no-store, no-cache headers' },
      { action: 'request_replay', description: 'Replay authenticated request and verify caching headers', expected_outcome: 'Missing or misconfigured Cache-Control on auth/user endpoints' },
      { action: 'header_variation', description: 'Check if Vary header is set correctly for authenticated content', expected_outcome: 'Vary header absent or incomplete (may cause cache poisoning)' },
    ],
  },
  csrf_signal_anomaly: {
    verification_category: 'csrf_protection_failure',
    steps: [
      { action: 'request_replay', description: 'Replay state-changing request without CSRF token', expected_outcome: 'Request should be rejected without valid CSRF token' },
      { action: 'cookie_variation', description: 'Verify csrftoken cookie is set and X-CSRFToken header is sent', expected_outcome: 'CSRF cookie set but header not sent on some state-changing requests' },
      { action: 'header_variation', description: 'Check CSRF header presence across all POST/PUT/PATCH/DELETE', expected_outcome: 'At least one state-changing endpoint missing CSRF header' },
    ],
  },
  cors_misconfiguration: {
    verification_category: 'cors_policy_issue',
    steps: [
      { action: 'header_variation', description: 'Check Access-Control-Allow-Origin on API endpoints', expected_outcome: 'ACAO should not be * with ACAC:true' },
      { action: 'request_replay', description: 'Replay request with different Origin header', expected_outcome: 'Reflected or wildcard origin accepted with credentials' },
      { action: 'cache_validation', description: 'Verify CORS headers are not cacheable with sensitive data', expected_outcome: 'CORS headers cached improperly may allow origin confusion' },
    ],
  },
  cookie_scope_oversharing: {
    verification_category: 'cookie_security_failure',
    steps: [
      { action: 'cookie_variation', description: 'Check cookie domain and path scope', expected_outcome: 'Auth cookies should not use overly broad domain/path' },
      { action: 'navigation', description: 'Navigate to subdomains and verify cookie transmission', expected_outcome: 'Auth cookie sent to subdomains that dont need it' },
    ],
  },
  cross_subdomain_trust_expansion: {
    verification_category: 'cookie_security_failure',
    steps: [
      { action: 'cookie_variation', description: 'Audit cookie domain attributes across subdomains', expected_outcome: 'Domain-scoped cookies sent to unintended subdomains' },
      { action: 'navigation', description: 'Navigate to different subdomains and track cookie presence', expected_outcome: 'Auth cookies present on subdomains outside trust boundary' },
    ],
  },
  unexpected_auth_model_change: {
    verification_category: 'authentication_regression',
    steps: [
      { action: 'state_comparison', description: 'Compare current auth model against baseline', expected_outcome: 'Auth model should match or exceed baseline security' },
      { action: 'authenticated_replay', description: 'Replay authentication flow and verify model consistency', expected_outcome: 'Auth model changed without corresponding security improvement' },
    ],
  },
  sensitive_data_exposure: {
    verification_category: 'sensitive_data_exposure',
    steps: [
      { action: 'request_replay', description: 'Replay request and check response for sensitive data in URLs', expected_outcome: 'No tokens, passwords, or API keys in URL query strings' },
      { action: 'header_variation', description: 'Check Referer header leakage on external links', expected_outcome: 'Sensitive URL parameters leaked via Referer header' },
    ],
  },
  excessive_client_side_secrets: {
    verification_category: 'sensitive_data_exposure',
    steps: [
      { action: 'state_comparison', description: 'Enumerate secrets accessible to JavaScript', expected_outcome: 'Minimize client-side secret exposure' },
      { action: 'cookie_variation', description: 'Check which auth cookies lack HttpOnly', expected_outcome: 'Multiple auth tokens accessible to JavaScript' },
    ],
  },
  auth_state_desynchronization: {
    verification_category: 'authentication_regression',
    steps: [
      { action: 'authenticated_replay', description: 'Replay auth flow and check for desync signals', expected_outcome: 'Auth state should be consistent across cookies, tokens, and API responses' },
      { action: 'state_comparison', description: 'Compare cookie state vs API auth state', expected_outcome: 'Cookie auth state differs from API-returned auth state' },
    ],
  },
  ws_auth_inconsistency: {
    verification_category: 'websocket_auth_desync',
    steps: [
      { action: 'authenticated_replay', description: 'Replay WS connection and verify auth on each message', expected_outcome: 'WS should validate auth on every message, not just connect' },
      { action: 'state_comparison', description: 'Compare WS auth state vs HTTP auth state', expected_outcome: 'WS auth differs from HTTP auth — messages accepted after HTTP logout' },
    ],
  },
  permission_boundary_anomaly: {
    verification_category: 'authorization_inconsistency',
    steps: [
      { action: 'permission_validation', description: 'Check if admin/privileged endpoints verify user role', expected_outoutcome: 'Privileged endpoints should return 403 for non-admin users' },
      { action: 'request_replay', description: 'Replay request to privileged endpoint from observed session', expected_outcome: 'Endpoint returns data without proper role verification' },
    ],
  },
  regression_security_change: {
    verification_category: 'authentication_regression',
    steps: [
      { action: 'state_comparison', description: 'Compare current session security posture against baseline', expected_outcome: 'Security posture should match or exceed baseline' },
      { action: 'cookie_variation', description: 'Verify no cookie attribute downgrades from baseline', expected_outcome: 'One or more cookies have downgraded security attributes' },
      { action: 'cache_validation', description: 'Check cache headers match baseline expectations', expected_outcome: 'Cache control regression detected vs baseline' },
    ],
  },
};

class VerificationEngine {
  constructor(options = {}) {
    this.safeMode = options.safeMode !== false; // true by default
    this.plans = new Map();      // planId → verificationPlan
    this.results = new Map();    // planId → verificationResult

    // FASE 2 — Canonical bug store: dedup by stable fingerprint, NOT push to array.
    // this.confirmedBugs is kept as a getter for backward-compat with existing
    // API consumers, but the source of truth is this.canonicalStore.
    const { CanonicalBugStore } = require('./canonical-bug-store');
    this.canonicalStore = new CanonicalBugStore();
    this._currentTarget = null;  // set per-analysis-run via setTarget()

    this.bugCounter = 0;  // display-only, never used as identity

    // Track verification metrics
    this.metrics = {
      plans_created: 0,
      plans_executed: 0,
      plans_passed: 0,
      plans_failed: 0,
      bugs_confirmed: 0,
      bugs_by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
      bugs_by_category: {},
      false_positive_rejected: 0,
      average_confidence: 0,
    };
  }

  // ─── Plan Creation ────────────────────────────────────────────

  /**
   * Create a verification plan for a finding
   * @param {object} finding - from RiskEngine (v0.3)
   * @param {object} observations - { events, report, anomalies, baseline, diff }
   * @returns {object} verification plan
   */
  createPlan(finding, observations = {}) {
    const category = finding.category;
    const planTemplate = CATEGORY_PLAN_MAP[category];

    if (!planTemplate) {
      // Generic plan for unmapped categories
      return this._createGenericPlan(finding, observations);
    }

    const planId = `plan-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36) + Math.random().toString(36).substring(2, 6)}`;

    // Build steps from template, enriching with observation data
    const steps = planTemplate.steps.map((stepTemplate, idx) => {
      // Validate action is allowed
      if (!ALLOWED_ACTIONS.has(stepTemplate.action)) {
        console.warn(`[Verification] Forbidden action in template: ${stepTemplate.action} — skipping step`);
        return null;
      }
      return {
        step: idx + 1,
        action: stepTemplate.action,
        description: stepTemplate.description,
        expected_outcome: stepTemplate.expected_outcome,
        actual_outcome: null,
        passed: null,
        evidence: null,
        ts: null,
      };
    }).filter(Boolean);

    const plan = {
      id: planId,
      finding_id: finding.id,
      finding_title: finding.title,
      category,
      verification_category: planTemplate.verification_category,
      severity_hint: finding.severity,
      confidence_hint: finding.confidence,
      created_at: Date.now(),
      status: 'pending', // pending → executing → completed | failed
      steps,
      observations_snapshot: {
        event_count: observations.events?.length || 0,
        has_baseline: !!observations.baseline,
        has_diff: !!observations.diff,
        anomaly_count: observations.anomalies?.length || 0,
        auth_model: observations.report?.auth_model || 'unknown',
      },
    };

    this.plans.set(planId, plan);
    this.metrics.plans_created++;
    return plan;
  }

  /**
   * Create verification plans for all findings
   */
  createPlans(findings, observations = {}) {
    const plans = [];
    for (const finding of findings) {
      const plan = this.createPlan(finding, observations);
      if (plan) plans.push(plan);
    }
    return plans;
  }

  /**
   * Create a generic plan for unmapped finding categories
   */
  _createGenericPlan(finding, observations) {
    const planId = `plan-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36) + Math.random().toString(36).substring(2, 6)}`;

    const steps = [
      { step: 1, action: 'navigation', description: `Navigate to target and observe finding "${finding.title}"`, expected_outcome: 'Observable behavior matches finding description', actual_outcome: null, passed: null, evidence: null, ts: null },
      { step: 2, action: 'state_comparison', description: 'Compare application state before and after the finding trigger', expected_outcome: 'State change confirms the finding', actual_outcome: null, passed: null, evidence: null, ts: null },
      { step: 3, action: 'request_replay', description: 'Replay relevant requests to confirm the behavior', expected_outcome: 'Replayed request produces same observable behavior', actual_outcome: null, passed: null, evidence: null, ts: null },
    ];

    const plan = {
      id: planId,
      finding_id: finding.id,
      finding_title: finding.title,
      category: finding.category,
      verification_category: this._inferVerificationCategory(finding.category),
      severity_hint: finding.severity,
      confidence_hint: finding.confidence,
      created_at: Date.now(),
      status: 'pending',
      steps,
      observations_snapshot: {
        event_count: observations.events?.length || 0,
        has_baseline: !!observations.baseline,
        has_diff: !!observations.diff,
        anomaly_count: observations.anomalies?.length || 0,
        auth_model: observations.report?.auth_model || 'unknown',
      },
    };

    this.plans.set(planId, plan);
    this.metrics.plans_created++;
    return plan;
  }

  // ─── Plan Execution ───────────────────────────────────────────

  /**
   * Execute a verification plan against observability data
   *
   * This is the core verification logic. Since BOQA operates in
   * safe mode (no exploitation, no modification), we verify by:
   *   1. Re-examining the observed event stream
   *   2. Cross-referencing multiple independent signals
   *   3. Applying deterministic checks to the captured data
   *   4. Checking temporal consistency of the finding
   *   5. Validating against baseline when available
   *
   * @param {string} planId - verification plan ID
   * @param {object} observations - { events, report, anomalies, baseline, diff }
   * @returns {object} verification result
   */
  executePlan(planId, observations = {}) {
    const plan = this.plans.get(planId);
    if (!plan) throw new Error(`Plan not found: ${planId}`);

    if (plan.status === 'executing') {
      return { error: 'Plan already executing', planId };
    }

    plan.status = 'executing';
    const { events = [], report = {}, anomalies = [], baseline = null, diff = null } = observations;

    // Execute each step deterministically against the observation data
    let passedSteps = 0;
    let failedSteps = 0;
    const verificationTrace = [];

    for (const step of plan.steps) {
      const stepResult = this._executeStep(step, { events, report, anomalies, baseline, diff, finding: { category: plan.category, id: plan.finding_id } });
      step.actual_outcome = stepResult.actual_outcome;
      step.passed = stepResult.passed;
      step.evidence = stepResult.evidence;
      step.ts = Date.now();

      verificationTrace.push({
        step: step.step,
        action: step.action,
        passed: step.passed,
        confidence_delta: stepResult.confidence_delta,
        note: stepResult.note,
      });

      if (step.passed) passedSteps++;
      else failedSteps++;
    }

    // Determine overall verification result
    const totalSteps = plan.steps.length;
    const passRate = totalSteps > 0 ? passedSteps / totalSteps : 0;
    const isConfirmed = passRate >= 0.6; // 60% of steps must pass

    // Compute final confidence
    const confidenceAdjustments = verificationTrace.map(vt => vt.confidence_delta);
    const netConfidence = confidenceAdjustments.reduce((sum, d) => sum + d, 0);
    const finalConfidence = Math.max(0, Math.min(100, (plan.confidence_hint || 50) + netConfidence));

    // Compute severity
    const severity = this._computeBugSeverity(plan.severity_hint, passRate, finalConfidence, plan.verification_category);

    const result = {
      plan_id: planId,
      finding_id: plan.finding_id,
      status: isConfirmed ? 'confirmed' : 'rejected',
      verification_category: plan.verification_category,
      pass_rate: passRate,
      passed_steps: passedSteps,
      total_steps: totalSteps,
      confidence: finalConfidence,
      severity,
      verification_trace: verificationTrace,
      executed_at: Date.now(),
      false_positive: !isConfirmed && plan.confidence_hint >= 60,
    };

    plan.status = isConfirmed ? 'completed' : 'failed';
    this.results.set(planId, result);
    this.metrics.plans_executed++;

    if (isConfirmed) {
      this.metrics.plans_passed++;
      const bug = this._createBug(plan, result, observations);

      // FASE 2 — Replace push to array with canonical store observe().
      // Same bug in 4 cycles → ONE canonical bug with observation_count=4.
      if (!this._currentTarget) {
        // Fallback: synthesize a target from the plan so observe() can run.
        // This should not normally happen — setTarget() should be called
        // before analysis begins.
        this._currentTarget = {
          id: plan.target_id || 'unknown-target',
          url: plan.target_url || '',
          authorization_status: 'authorized',  // assume; ReportabilityEngine will verify
        };
      }
      const { bug: canonicalBug, is_new: isNew } = this.canonicalStore.observe(bug, this._currentTarget);

      // Only increment metrics on FIRST observation of this fingerprint.
      // Repeat observations do NOT inflate bugs_confirmed / by_severity / by_category.
      if (isNew) {
        this.metrics.bugs_confirmed++;
        const sev = String(canonicalBug.severity || 'medium').toLowerCase();
        if (this.metrics.bugs_by_severity[sev] !== undefined) {
          this.metrics.bugs_by_severity[sev]++;
        }
        const cat = canonicalBug.category || 'unknown';
        this.metrics.bugs_by_category[cat] = (this.metrics.bugs_by_category[cat] || 0) + 1;
      }
      // Replace the bug reference with the canonical one so downstream
      // code (ReportabilityEngine, bounty estimator) sees the merged record.
      Object.assign(bug, canonicalBug);
    } else {
      this.metrics.plans_failed++;
      if (result.false_positive) this.metrics.false_positive_rejected++;
    }

    // Update average confidence — over CANONICAL bugs only, not raw observations
    const canonicalBugs = this.canonicalStore.all();
    if (canonicalBugs.length > 0) {
      this.metrics.average_confidence = Math.round(
        canonicalBugs.reduce((sum, b) => sum + (b.confidence || 0), 0) / canonicalBugs.length
      );
    }

    return result;
  }

  /**
   * Set the current target for canonical bug fingerprinting.
   * Must be called at the start of each analysis run.
   */
  setTarget(target) {
    if (!target) return;
    this._currentTarget = target;
  }

  /**
   * Backward-compatible accessor: returns canonical bugs as an array.
   * Existing code that reads `engine.confirmedBugs` keeps working,
   * but now receives DEDUPLICATED bugs.
   */
  get confirmedBugs() {
    return this.canonicalStore.all();
  }

  /**
   * Execute all pending plans
   */
  executeAll(observations = {}) {
    const results = [];
    for (const [planId, plan] of this.plans) {
      if (plan.status === 'pending') {
        results.push(this.executePlan(planId, observations));
      }
    }
    return results;
  }

  // ─── Step Execution (Deterministic Checks) ────────────────────

  _executeStep(step, context) {
    const { events, report, anomalies, baseline, diff, finding } = context;

    switch (step.action) {
      case 'navigation':
        return this._checkNavigation(step, context);
      case 'authenticated_replay':
        return this._checkAuthenticatedReplay(step, context);
      case 'request_replay':
        return this._checkRequestReplay(step, context);
      case 'state_comparison':
        return this._checkStateComparison(step, context);
      case 'header_variation':
        return this._checkHeaderVariation(step, context);
      case 'cookie_variation':
        return this._checkCookieVariation(step, context);
      case 'cache_validation':
        return this._checkCacheValidation(step, context);
      case 'permission_validation':
        return this._checkPermissionValidation(step, context);
      case 'workflow_validation':
        return this._checkWorkflowValidation(step, context);
      default:
        return { passed: false, actual_outcome: 'Unknown action type', evidence: null, confidence_delta: -10, note: 'Invalid step action' };
    }
  }

  /**
   * Navigation check — verify page was reached and auth state is consistent
   */
  _checkNavigation(step, context) {
    const { events, report } = context;
    const navEvents = events.filter(e => e.type === 'page_navigation');
    const authSignals = events.filter(e => e.type === 'auth_signal');

    const hasNavigation = navEvents.length > 0;
    const authStateConsistent = authSignals.every(s => {
      // No conflicting auth signals
      return s.meta?.signalType !== 'unauthorized' || s.meta?.signalType !== 'forbidden';
    });

    const passed = hasNavigation;
    return {
      passed,
      actual_outcome: passed
        ? `${navEvents.length} navigation events observed, auth state consistent: ${authStateConsistent}`
        : 'No navigation events found in session',
      evidence: { nav_count: navEvents.length, auth_consistent: authStateConsistent },
      confidence_delta: passed ? 5 : -15,
      note: `Navigation events: ${navEvents.length}`,
    };
  }

  /**
   * Authenticated replay — verify auth flow produces consistent signals
   */
  _checkAuthenticatedReplay(step, context) {
    const { events, report, finding } = context;
    const authSignals = events.filter(e => e.type === 'auth_signal');
    const cookieSnapshots = events.filter(e => e.type === 'cookie_snapshot');

    // Check for auth cookie set events
    const loginSignals = authSignals.filter(s => s.meta?.signalType === 'auth_cookie_set');
    const logoutSignals = authSignals.filter(s => s.meta?.signalType === 'auth_cookie_cleared');

    // Verify auth model consistency
    const hasAuthModel = report.auth_model && report.auth_model !== 'unknown';

    // For WS auth desync, check if WS has auth
    if (finding.category === 'ws_auth_inconsistency') {
      const wsOpenEvents = events.filter(e => e.type === 'websocket_open');
      const wsWithAuth = wsOpenEvents.filter(e => e.meta?.auth === true);
      const wsWithoutAuth = wsOpenEvents.filter(e => !e.meta?.auth);

      const inconsistent = wsWithAuth.length > 0 && wsWithoutAuth.length > 0;
      return {
        passed: inconsistent,
        actual_outcome: `${wsWithAuth.length} WS connections with auth, ${wsWithoutAuth.length} without auth`,
        evidence: { ws_with_auth: wsWithAuth.length, ws_without_auth: wsWithoutAuth.length },
        confidence_delta: inconsistent ? 10 : -10,
        note: inconsistent ? 'WS auth inconsistency confirmed' : 'WS auth appears consistent',
      };
    }

    // For session management issues
    if (finding.category === 'session_fixation_indicators' || finding.category === 'session_rotation_failure') {
      const sessionValues = [];
      for (const cs of cookieSnapshots) {
        const sid = (cs.meta?.authCookies || []).find(c => c.name === 'sessionid');
        if (sid) sessionValues.push({ ts: cs.ts, value: sid.valuePreview || sid.value });
      }

      const preLogin = loginSignals.length > 0 ? sessionValues.slice(0, loginSignals.length) : [];
      const postLogin = loginSignals.length > 0 ? sessionValues.slice(loginSignals.length) : sessionValues;

      let sessionRotated = false;
      if (preLogin.length > 0 && postLogin.length > 0) {
        // Check if session ID changed after login
        const preHash = this._hashValue(preLogin[0]?.value);
        const postHash = this._hashValue(postLogin[0]?.value);
        sessionRotated = preHash !== postHash;
      }

      if (finding.category === 'session_fixation_indicators') {
        const passed = !sessionRotated && preLogin.length > 0;
        return {
          passed,
          actual_outcome: `Session rotated after login: ${sessionRotated}`,
          evidence: { session_rotated: sessionRotated, pre_login_snapshots: preLogin.length, post_login_snapshots: postLogin.length },
          confidence_delta: passed ? 15 : -10,
          note: passed ? 'Session NOT rotated — fixation risk confirmed' : 'Session rotated properly',
        };
      }

      if (finding.category === 'session_rotation_failure') {
        // Excessive rotation
        const uniqueSessions = new Set(sessionValues.map(s => this._hashValue(s.value)));
        const excessive = uniqueSessions.size > 5 && sessionValues.length > 0;
        return {
          passed: excessive,
          actual_outcome: `${uniqueSessions.size} unique session IDs observed across ${sessionValues.length} snapshots`,
          evidence: { unique_session_count: uniqueSessions.size, total_snapshots: sessionValues.length },
          confidence_delta: excessive ? 10 : -5,
          note: excessive ? 'Excessive session rotation detected' : 'Session rotation appears normal',
        };
      }
    }

    // Generic authenticated replay
    const passed = loginSignals.length > 0 && hasAuthModel;
    return {
      passed,
      actual_outcome: `${loginSignals.length} login signals, auth_model=${report.auth_model || 'unknown'}`,
      evidence: { login_signals: loginSignals.length, auth_model: report.auth_model },
      confidence_delta: passed ? 5 : -10,
      note: passed ? 'Auth flow consistent' : 'Incomplete auth flow evidence',
    };
  }

  /**
   * Request replay — verify observed requests show the finding
   */
  _checkRequestReplay(step, context) {
    const { events, report, finding } = context;
    const requests = events.filter(e => e.type === 'network_request');
    const responses = events.filter(e => e.type === 'network_response');

    const category = finding.category;

    if (category === 'csrf_signal_anomaly') {
      const stateChangingRequests = requests.filter(r =>
        ['POST', 'PUT', 'PATCH', 'DELETE'].includes(r.method)
      );

      let missingCsrf = 0;
      for (const req of stateChangingRequests) {
        const headers = req.headers || {};
        const lower = {};
        for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
        if (!lower['x-csrftoken'] && !lower['x-csrf-token']) {
          missingCsrf++;
        }
      }

      const passed = missingCsrf > 0;
      return {
        passed,
        actual_outcome: `${missingCsrf}/${stateChangingRequests.length} state-changing requests missing CSRF header`,
        evidence: { missing_csrf_count: missingCsrf, total_state_changing: stateChangingRequests.length },
        confidence_delta: passed ? 15 : -10,
        note: passed ? 'CSRF protection gap confirmed' : 'CSRF headers present on all state-changing requests',
      };
    }

    if (category === 'bearer_token_exposure') {
      const requestsWithBearer = requests.filter(r => {
        const headers = r.headers || {};
        const lower = {};
        for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
        return lower['authorization']?.startsWith('Bearer ');
      });

      // Check if bearer is sent to non-API paths
      const nonApiBearer = requestsWithBearer.filter(r => {
        try {
          const pathname = new URL(r.url).pathname;
          return !pathname.startsWith('/api/');
        } catch (_) { return false; }
      });

      const passed = requestsWithBearer.length > 0;
      return {
        passed,
        actual_outcome: `${requestsWithBearer.length} requests with Bearer, ${nonApiBearer.length} to non-API paths`,
        evidence: { bearer_count: requestsWithBearer.length, non_api_bearer: nonApiBearer.length },
        confidence_delta: passed ? 10 : -10,
        note: passed ? 'Bearer token exposure confirmed' : 'No Bearer token exposure observed',
      };
    }

    if (category === 'cors_misconfiguration') {
      const corsResponses = responses.filter(r => {
        const headers = r.headers || {};
        const lower = {};
        for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
        return lower['access-control-allow-origin'];
      });

      const dangerousCors = corsResponses.filter(r => {
        const headers = r.headers || {};
        const lower = {};
        for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
        return lower['access-control-allow-origin'] === '*' && lower['access-control-allow-credentials'] === 'true';
      });

      const passed = dangerousCors.length > 0;
      return {
        passed,
        actual_outcome: `${corsResponses.length} CORS responses, ${dangerousCors.length} with dangerous wildcard+credentials`,
        evidence: { cors_count: corsResponses.length, dangerous_count: dangerousCors.length },
        confidence_delta: passed ? 20 : -15,
        note: passed ? 'CORS misconfiguration confirmed (ACAO:* + ACAC:true)' : 'No dangerous CORS configuration found',
      };
    }

    // Generic request replay check
    const passed = requests.length > 0;
    return {
      passed,
      actual_outcome: `${requests.length} requests available for replay analysis`,
      evidence: { request_count: requests.length },
      confidence_delta: passed ? 3 : -5,
      note: passed ? 'Requests available for verification' : 'No requests found',
    };
  }

  /**
   * State comparison — compare before/after application state
   */
  _checkStateComparison(step, context) {
    const { events, report, baseline, finding } = context;

    if (finding.category === 'jwt_in_browser_memory') {
      const decryptEvents = events.filter(e =>
        e.type === 'console_log' && e.payload &&
        (e.payload.includes('CryptoJS.AES.decrypt') || e.payload.includes('__BOQA__aes_decrypt'))
      );

      const encryptedCookies = events.filter(e =>
        e.type === 'cookie_snapshot' && e.meta?.authCookies
      ).flatMap(e => e.meta.authCookies.filter(c => c.value?.startsWith('U2FsdGVkX1')));

      const passed = decryptEvents.length > 0 || encryptedCookies.length > 0;
      return {
        passed,
        actual_outcome: `${decryptEvents.length} client-side decrypt events, ${encryptedCookies.length} encrypted cookie observations`,
        evidence: { decrypt_events: decryptEvents.length, encrypted_cookies: encryptedCookies.length },
        confidence_delta: passed ? 15 : -10,
        note: passed ? 'Client-side JWT decryption confirmed' : 'No client-side decryption evidence',
      };
    }

    if (finding.category === 'missing_httpOnly') {
      const jsAccessibleCookies = (report.cookies || []).filter(c => !c.httpOnly);
      const authJsAccessible = jsAccessibleCookies.filter(c =>
        ['ripio_access', 'sessionid', 'access_token', 'auth_token', '_jwt'].includes(c.name)
      );

      const passed = authJsAccessible.length > 0;
      return {
        passed,
        actual_outcome: `${authJsAccessible.length} auth cookies accessible via JavaScript (missing HttpOnly)`,
        evidence: { js_accessible_auth_cookies: authJsAccessible.map(c => c.name) },
        confidence_delta: passed ? 15 : -10,
        note: passed ? `Missing HttpOnly confirmed on: ${authJsAccessible.map(c => c.name).join(', ')}` : 'All auth cookies have HttpOnly',
      };
    }

    if (finding.category === 'auth_state_desynchronization') {
      const unauthorizedSignals = events.filter(e =>
        e.type === 'auth_signal' && (e.meta?.signalType === 'unauthorized' || e.meta?.signalType === 'forbidden')
      );
      const cookieSetAfterAuth = events.filter(e =>
        e.type === 'auth_signal' && e.meta?.signalType === 'auth_cookie_set'
      );

      const desync = unauthorizedSignals.length > 0 && cookieSetAfterAuth.length > 0;
      return {
        passed: desync,
        actual_outcome: `${unauthorizedSignals.length} unauthorized signals despite ${cookieSetAfterAuth.length} auth cookie set events`,
        evidence: { unauthorized_count: unauthorizedSignals.length, auth_cookie_set_count: cookieSetAfterAuth.length },
        confidence_delta: desync ? 10 : -5,
        note: desync ? 'Auth state desync confirmed' : 'Auth state appears consistent',
      };
    }

    if (finding.category === 'unexpected_auth_model_change' && baseline) {
      const baselineModel = baseline.fingerprint?.auth_model;
      const currentModel = report.auth_model;
      const changed = baselineModel && currentModel && baselineModel !== currentModel;
      return {
        passed: changed,
        actual_outcome: `Baseline: ${baselineModel}, Current: ${currentModel}`,
        evidence: { baseline_model: baselineModel, current_model: currentModel },
        confidence_delta: changed ? 15 : -15,
        note: changed ? 'Auth model change confirmed' : 'Auth model unchanged from baseline',
      };
    }

    // Generic state comparison
    const cookieCount = (report.cookies || []).length;
    const passed = cookieCount > 0;
    return {
      passed,
      actual_outcome: `${cookieCount} cookies in final state, ${events.length} events observed`,
      evidence: { cookie_count: cookieCount, event_count: events.length },
      confidence_delta: passed ? 3 : -5,
      note: 'State comparison baseline check',
    };
  }

  /**
   * Header variation — check header patterns
   */
  _checkHeaderVariation(step, context) {
    const { events, finding } = context;
    const responses = events.filter(e => e.type === 'network_response' && e.headers);

    if (finding.category === 'cors_misconfiguration') {
      let wildcardOrigin = 0;
      let wildcardWithCreds = 0;
      for (const r of responses) {
        const lower = {};
        for (const [k, v] of Object.entries(r.headers)) lower[k.toLowerCase()] = v;
        if (lower['access-control-allow-origin'] === '*') {
          wildcardOrigin++;
          if (lower['access-control-allow-credentials'] === 'true') wildcardWithCreds++;
        }
      }

      const passed = wildcardWithCreds > 0;
      return {
        passed,
        actual_outcome: `${wildcardOrigin} wildcard ACAO, ${wildcardWithCreds} with credentials=true`,
        evidence: { wildcard_origin: wildcardOrigin, wildcard_with_creds: wildcardWithCreds },
        confidence_delta: passed ? 20 : -15,
        note: passed ? 'ACAO:* + ACAC:true is a critical CORS misconfiguration' : 'No dangerous CORS headers found',
      };
    }

    if (finding.category === 'csrf_signal_anomaly') {
      const requests = events.filter(e => e.type === 'network_request' && e.headers);
      const stateChanging = requests.filter(r => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(r.method));

      let noCsrfHeader = 0;
      for (const r of stateChanging) {
        const lower = {};
        for (const [k, v] of Object.entries(r.headers)) lower[k.toLowerCase()] = v;
        if (!lower['x-csrftoken'] && !lower['x-csrf-token']) noCsrfHeader++;
      }

      const passed = noCsrfHeader > 0;
      return {
        passed,
        actual_outcome: `${noCsrfHeader}/${stateChanging.length} state-changing requests without CSRF header`,
        evidence: { no_csrf_count: noCsrfHeader, total_state_changing: stateChanging.length },
        confidence_delta: passed ? 15 : -10,
        note: passed ? 'CSRF header missing on some requests' : 'CSRF headers present on all state-changing requests',
      };
    }

    // Generic header variation check
    const passed = responses.length > 0;
    return {
      passed,
      actual_outcome: `${responses.length} responses with headers available for analysis`,
      evidence: { response_count: responses.length },
      confidence_delta: passed ? 3 : -5,
      note: 'Header variation check completed',
    };
  }

  /**
   * Cookie variation — verify cookie attribute patterns
   */
  _checkCookieVariation(step, context) {
    const { events, report, baseline, finding } = context;
    const cookieSnapshots = events.filter(e => e.type === 'cookie_snapshot');
    const responses = events.filter(e => e.type === 'network_response' && e.headers);

    if (finding.category === 'missing_secure') {
      const insecureAuthCookies = (report.cookies || []).filter(c =>
        !c.secure && ['ripio_access', 'sessionid', 'access_token', 'auth_token', '_jwt', 'csrftoken'].includes(c.name)
      );

      const passed = insecureAuthCookies.length > 0;
      return {
        passed,
        actual_outcome: `${insecureAuthCookies.length} auth cookies missing Secure flag`,
        evidence: { insecure_cookies: insecureAuthCookies.map(c => ({ name: c.name, secure: c.secure })) },
        confidence_delta: passed ? 15 : -10,
        note: passed ? `Missing Secure confirmed: ${insecureAuthCookies.map(c => c.name).join(', ')}` : 'All auth cookies have Secure flag',
      };
    }

    if (finding.category === 'weak_samesite') {
      const weakSamesite = (report.cookies || []).filter(c =>
        ['ripio_access', 'sessionid', 'access_token', 'auth_token', '_jwt', 'csrftoken'].includes(c.name) &&
        (!c.sameSite || c.sameSite === 'None' || c.sameSite === 'none')
      );

      const passed = weakSamesite.length > 0;
      return {
        passed,
        actual_outcome: `${weakSamesite.length} auth cookies with weak SameSite (${weakSamesite.map(c => `${c.name}=${c.sameSite || 'unset'}`).join(', ')})`,
        evidence: { weak_samesite_cookies: weakSamesite.map(c => ({ name: c.name, sameSite: c.sameSite })) },
        confidence_delta: passed ? 10 : -10,
        note: passed ? 'Weak SameSite confirmed' : 'All auth cookies have strong SameSite',
      };
    }

    if (finding.category === 'cookie_scope_oversharing' || finding.category === 'cross_subdomain_trust_expansion') {
      const domainScoped = (report.cookies || []).filter(c =>
        c.domain && c.domain.startsWith('.') && ['ripio_access', 'sessionid', 'access_token'].includes(c.name)
      );

      const passed = domainScoped.length > 0;
      return {
        passed,
        actual_outcome: `${domainScoped.length} auth cookies with broad domain scope (${domainScoped.map(c => `${c.name}@${c.domain}`).join(', ')})`,
        evidence: { domain_scoped: domainScoped.map(c => ({ name: c.name, domain: c.domain })) },
        confidence_delta: passed ? 8 : -5,
        note: passed ? 'Broad cookie domain scope confirmed' : 'Cookie domain scoping appears appropriate',
      };
    }

    // Set-Cookie header analysis
    let setCookieEvents = 0;
    for (const r of responses) {
      const lower = {};
      for (const [k, v] of Object.entries(r.headers)) lower[k.toLowerCase()] = v;
      if (lower['set-cookie']) setCookieEvents++;
    }

    const passed = cookieSnapshots.length > 0 || setCookieEvents > 0;
    return {
      passed,
      actual_outcome: `${cookieSnapshots.length} cookie snapshots, ${setCookieEvents} Set-Cookie headers`,
      evidence: { snapshot_count: cookieSnapshots.length, set_cookie_count: setCookieEvents },
      confidence_delta: passed ? 3 : -5,
      note: 'Cookie variation analysis completed',
    };
  }

  /**
   * Cache validation — check cache control headers
   */
  _checkCacheValidation(step, context) {
    const { events, report, finding } = context;
    const responses = events.filter(e => e.type === 'network_response' && e.headers);

    if (finding.category === 'cache_control_misconfiguration') {
      let missingCacheControl = 0;
      let hasStore = 0;
      const authEndpoints = [];

      for (const r of responses) {
        const lower = {};
        for (const [k, v] of Object.entries(r.headers)) lower[k.toLowerCase()] = v;
        const cc = lower['cache-control'] || '';

        try {
          const u = new URL(r.url || '');
          const isAuthRelated = /\/api\/users\/me|\/auth\/|\/session|\/wallet|\/balance/.test(u.pathname);
          if (isAuthRelated) {
            authEndpoints.push({
              path: u.pathname,
              cache_control: cc || '(missing)',
              has_no_store: cc.includes('no-store'),
            });
            if (!cc) missingCacheControl++;
            if (cc.includes('no-store')) hasStore++;
          }
        } catch (_) {}
      }

      const passed = missingCacheControl > 0 || (authEndpoints.length > 0 && hasStore < authEndpoints.length);
      return {
        passed,
        actual_outcome: `${missingCacheControl} auth endpoints missing Cache-Control, ${hasStore}/${authEndpoints.length} have no-store`,
        evidence: { missing_cache_control: missingCacheControl, auth_endpoints: authEndpoints.length, no_store_count: hasStore },
        confidence_delta: passed ? 10 : -10,
        note: passed ? 'Cache control misconfiguration confirmed' : 'Cache control appears correct',
      };
    }

    // Generic cache check
    let noStore = 0;
    for (const r of responses) {
      const lower = {};
      for (const [k, v] of Object.entries(r.headers)) lower[k.toLowerCase()] = v;
      if ((lower['cache-control'] || '').includes('no-store')) noStore++;
    }

    const passed = responses.length > 0;
    return {
      passed,
      actual_outcome: `${noStore}/${responses.length} responses with no-store`,
      evidence: { no_store_count: noStore, total_responses: responses.length },
      confidence_delta: passed ? 3 : -5,
      note: 'Cache validation check completed',
    };
  }

  /**
   * Permission validation — check authorization boundaries
   */
  _checkPermissionValidation(step, context) {
    const { events, report, finding } = context;
    const requests = events.filter(e => e.type === 'network_request');
    const responses = events.filter(e => e.type === 'network_response');

    if (finding.category === 'permission_boundary_anomaly') {
      // Check for admin endpoints that might lack proper auth
      const adminPaths = requests.filter(r => {
        try {
          const u = new URL(r.url);
          return /\/admin|\/manage|\/dashboard\/settings|\/api\/admin/.test(u.pathname);
        } catch (_) { return false; }
      });

      const adminResponses = responses.filter(r => {
        const req = requests.find(req => {
          try { return new URL(req.url).pathname === new URL(r.url).pathname; } catch (_) { return false; }
        });
        return req && r.status && r.status < 300; // Successful access to admin paths
      });

      // If we see successful access to admin paths, check if proper auth was involved
      const hasCsrfOnAdmin = adminPaths.filter(r => {
        const headers = r.headers || {};
        const lower = {};
        for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
        return lower['x-csrftoken'] || lower['authorization'];
      });

      const passed = adminPaths.length > 0;
      return {
        passed,
        actual_outcome: `${adminPaths.length} admin path requests, ${hasCsrfOnAdmin.length} with auth headers`,
        evidence: { admin_requests: adminPaths.length, admin_with_auth: hasCsrfOnAdmin.length },
        confidence_delta: passed ? 10 : -5,
        note: passed ? 'Admin path access observed — permission boundary analysis' : 'No admin path access observed',
      };
    }

    const passed = requests.length > 0;
    return {
      passed,
      actual_outcome: `${requests.length} requests available for permission analysis`,
      evidence: { request_count: requests.length },
      confidence_delta: passed ? 3 : -5,
      note: 'Permission validation check completed',
    };
  }

  /**
   * Workflow validation — check business workflow consistency
   */
  _checkWorkflowValidation(step, context) {
    const { events, report } = context;
    const navEvents = events.filter(e => e.type === 'page_navigation');
    const authSignals = events.filter(e => e.type === 'auth_signal');

    // Identify workflow sequences
    const workflowPhases = [];
    let currentPhase = null;

    for (const e of events) {
      if (e.type === 'page_navigation') {
        try {
          const u = new URL(e.url || '');
          const phase = this._classifyWorkflowPhase(u.pathname);
          if (phase !== currentPhase) {
            workflowPhases.push({ phase, ts: e.ts, path: u.pathname });
            currentPhase = phase;
          }
        } catch (_) {}
      }
      if (e.type === 'auth_signal' && e.meta?.signalType === 'auth_cookie_set') {
        workflowPhases.push({ phase: 'authenticated', ts: e.ts, path: null });
      }
    }

    // Check for unexpected workflow transitions
    const unexpectedTransitions = [];
    for (let i = 1; i < workflowPhases.length; i++) {
      const prev = workflowPhases[i - 1];
      const curr = workflowPhases[i];
      if (prev.phase === 'unauthenticated' && curr.phase === 'admin') {
        unexpectedTransitions.push({ from: prev.phase, to: curr.phase, ts: curr.ts });
      }
    }

    const passed = unexpectedTransitions.length > 0 || workflowPhases.length >= 3;
    return {
      passed,
      actual_outcome: `${workflowPhases.length} workflow phases, ${unexpectedTransitions.length} unexpected transitions`,
      evidence: { phases: workflowPhases.length, unexpected: unexpectedTransitions.length, transitions: unexpectedTransitions.slice(0, 5) },
      confidence_delta: unexpectedTransitions.length > 0 ? 15 : (workflowPhases.length >= 3 ? 5 : -5),
      note: unexpectedTransitions.length > 0 ? 'Unexpected workflow transitions detected' : 'Workflow appears consistent',
    };
  }

  // ─── Bug Creation ─────────────────────────────────────────────

  _createBug(plan, result, observations) {
    this.bugCounter++;
    const bugId = `BUG-${String(this.bugCounter).padStart(4, '0')}`;

    const bug = {
      id: bugId,
      title: plan.finding_title,
      severity: result.severity,
      confidence: result.confidence,
      status: 'confirmed',
      category: plan.verification_category,
      evidence_count: result.verification_trace.filter(vt => vt.passed).length,
      affected_assets: this._extractAffectedAssets(plan, observations),
      reproduction_steps: this._buildReproductionSteps(plan, result),
      verification_trace: result.verification_trace,
      recommended_fix: this._getRecommendedFix(plan.verification_category, plan.category),
      created_at: Date.now(),
      finding_id: plan.finding_id,
      plan_id: plan.id,
    };

    return bug;
  }

  _extractAffectedAssets(plan, observations) {
    const assets = [];
    const { report = {}, events = [] } = observations;

    // Affected cookies
    for (const c of (report.cookies || [])) {
      if (['ripio_access', 'sessionid', 'access_token', 'auth_token', '_jwt', 'csrftoken'].includes(c.name)) {
        assets.push({ type: 'cookie', name: c.name, domain: c.domain });
      }
    }

    // Affected endpoints
    const endpoints = new Set();
    for (const e of events) {
      if ((e.type === 'network_request' || e.type === 'network_response') && e.url) {
        try {
          const u = new URL(e.url);
          const isAuth = /\/auth\/|\/login|\/api\/users\/me|\/session|\/token/.test(u.pathname);
          if (isAuth) endpoints.add(`${u.origin}${u.pathname}`);
        } catch (_) {}
      }
    }
    for (const ep of endpoints) {
      assets.push({ type: 'endpoint', url: ep });
    }

    return assets;
  }

  _buildReproductionSteps(plan, result) {
    const steps = [];
    const passedSteps = result.verification_trace.filter(vt => vt.passed);

    for (const vt of passedSteps) {
      const planStep = plan.steps.find(s => s.step === vt.step);
      if (planStep) {
        steps.push({
          step: steps.length + 1,
          action: planStep.action,
          description: planStep.description,
          expected: planStep.expected_outcome,
          observed: planStep.actual_outcome || 'Confirmed by verification',
          safe: true,
        });
      }
    }

    steps.push({
      step: steps.length + 1,
      action: 'disclosure',
      description: 'Report this confirmed bug through responsible disclosure channels',
      expected: 'Bug reported to security team',
      observed: null,
      safe: true,
    });

    return steps;
  }

  _getRecommendedFix(verificationCategory, findingCategory) {
    const fixes = {
      authentication_regression: 'Review recent authentication changes. Ensure auth model provides equivalent or better security than the baseline. Revert any regression in cookie attributes or auth flow.',
      session_management_issue: 'Ensure session IDs are rotated after authentication. Implement Django session cycle_key() or equivalent. Set proper session timeout and invalidation on logout.',
      authorization_inconsistency: 'Add server-side authorization checks on all privileged endpoints. Implement proper RBAC with role-based access control middleware. Verify user role before returning sensitive data.',
      cookie_security_failure: 'Set HttpOnly, Secure, and SameSite=Lax/Strict flags on all authentication cookies. Restrict cookie domain to the minimum necessary scope. Avoid .domain.com scoping unless required.',
      csrf_protection_failure: 'Implement CSRF protection on all state-changing endpoints. Use the double-submit cookie pattern (csrftoken cookie + X-CSRFToken header). Verify CSRF token on every POST/PUT/PATCH/DELETE request.',
      cors_policy_issue: 'Remove wildcard Access-Control-Allow-Origin from API endpoints. Never combine ACAO:* with ACAC:true. Specify explicit allowed origins in CORS configuration.',
      cache_control_issue: 'Add Cache-Control: no-store, no-cache, must-revalidate to all responses containing sensitive data. Add Pragma: no-cache for HTTP/1.0 compatibility. Set proper Vary headers.',
      sensitive_data_exposure: 'Avoid sending tokens or sensitive data in URL query strings. Use request headers or POST bodies. Move authentication tokens to HttpOnly cookies. Minimize client-side secret exposure.',
      workflow_state_corruption: 'Validate workflow state transitions server-side. Ensure state changes are atomic and consistent. Check for race conditions in multi-step workflows.',
      websocket_auth_desync: 'Enforce consistent authentication across all WebSocket connections. Verify auth token on every WS message, not just at connection time. Close connections with invalid auth immediately. Sync WS auth state with HTTP auth state.',
    };

    return fixes[verificationCategory] || 'Review the finding details and implement appropriate security controls. Follow responsible disclosure practices.';
  }

  // ─── Severity Computation ─────────────────────────────────────

  _computeBugSeverity(hint, passRate, confidence, verificationCategory) {
    // Category base severity
    const categorySeverities = {
      authentication_regression: 'high',
      session_management_issue: 'high',
      authorization_inconsistency: 'high',
      cookie_security_failure: 'high',
      csrf_protection_failure: 'high',
      cors_policy_issue: 'critical',
      cache_control_issue: 'medium',
      sensitive_data_exposure: 'high',
      workflow_state_corruption: 'medium',
      websocket_auth_desync: 'medium',
    };

    let base = categorySeverities[verificationCategory] || hint || 'medium';

    // Upgrade if high confidence and full verification
    if (passRate >= 0.8 && confidence >= 85) {
      const upgrades = { medium: 'high', low: 'medium', info: 'low' };
      base = upgrades[base] || base;
    }

    // Downgrade if partial verification
    if (passRate < 0.7 || confidence < 50) {
      const downgrades = { critical: 'high', high: 'medium', medium: 'low' };
      base = downgrades[base] || base;
    }

    return base;
  }

  // ─── Utility Methods ─────────────────────────────────────────

  _inferVerificationCategory(findingCategory) {
    const mapping = {
      missing_httpOnly: 'cookie_security_failure',
      missing_secure: 'cookie_security_failure',
      weak_samesite: 'cookie_security_failure',
      bearer_token_exposure: 'sensitive_data_exposure',
      jwt_in_browser_memory: 'sensitive_data_exposure',
      session_fixation_indicators: 'session_management_issue',
      session_rotation_failure: 'session_management_issue',
      cache_control_misconfiguration: 'cache_control_issue',
      csrf_signal_anomaly: 'csrf_protection_failure',
      cors_misconfiguration: 'cors_policy_issue',
      cookie_scope_oversharing: 'cookie_security_failure',
      cross_subdomain_trust_expansion: 'cookie_security_failure',
      unexpected_auth_model_change: 'authentication_regression',
      sensitive_data_exposure: 'sensitive_data_exposure',
      excessive_client_side_secrets: 'sensitive_data_exposure',
      auth_state_desynchronization: 'authentication_regression',
      ws_auth_inconsistency: 'websocket_auth_desync',
      permission_boundary_anomaly: 'authorization_inconsistency',
      regression_security_change: 'authentication_regression',
    };
    return mapping[findingCategory] || 'authentication_regression';
  }

  _classifyWorkflowPhase(pathname) {
    if (/\/login|\/auth|\/signup|\/register/.test(pathname)) return 'unauthenticated';
    if (/\/admin|\/manage|\/dashboard\/settings/.test(pathname)) return 'admin';
    if (/\/api\/users\/me|\/api\/wallet|\/api\/balance/.test(pathname)) return 'authenticated';
    if (/\/trade|\/swap|\/send|\/receive/.test(pathname)) return 'transaction';
    return 'general';
  }

  _hashValue(value) {
    if (!value) return 'null';
    return crypto.createHash('sha256').update(String(value)).digest('hex').substring(0, 16);
  }

  // ─── Persistence ──────────────────────────────────────────────

  saveResults() {
    const report = {
      generated_at: Date.now(),
      version: '0.4.0',
      safe_mode: this.safeMode,
      metrics: this.metrics,
      confirmed_bugs: this.confirmedBugs,
      total_plans: this.plans.size,
      total_results: this.results.size,
    };

    const filePath = path.join(OUTPUT_DIR, `verification-report-${Date.now()}.json`);
    fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
    return filePath;
  }

  saveConfirmedBugs() {
    const filePath = path.join(OUTPUT_DIR, `confirmed-bugs-${Date.now()}.json`);
    fs.writeFileSync(filePath, JSON.stringify({
      generated_at: Date.now(),
      version: '0.4.0',
      total_bugs: this.confirmedBugs.length,
      bugs: this.confirmedBugs,
    }, null, 2));
    return filePath;
  }

  // ─── Accessors ────────────────────────────────────────────────

  getPlan(planId) {
    return this.plans.get(planId);
  }

  getPlans() {
    return [...this.plans.values()];
  }

  getResult(planId) {
    return this.results.get(planId);
  }

  getResults() {
    return [...this.results.values()];
  }

  getConfirmedBugs() {
    return this.confirmedBugs;
  }

  getMetrics() {
    return this.metrics;
  }

  getSummary() {
    return {
      plans_created: this.metrics.plans_created,
      plans_executed: this.metrics.plans_executed,
      bugs_confirmed: this.metrics.bugs_confirmed,
      false_positive_rejected: this.metrics.false_positive_rejected,
      findings_to_bug_ratio: this.metrics.plans_executed > 0
        ? (this.metrics.bugs_confirmed / this.metrics.plans_executed).toFixed(2)
        : '0.00',
      bugs_by_severity: { ...this.metrics.bugs_by_severity },
      bugs_by_category: { ...this.metrics.bugs_by_category },
      average_confidence: this.metrics.average_confidence,
    };
  }
}

module.exports = { VerificationEngine, VERIFICATION_CATEGORIES, ALLOWED_ACTIONS, FORBIDDEN_ACTIONS, OUTPUT_DIR };

