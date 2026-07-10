/**
 * BOQA reproduction.js — Reproduction Engine
 *
 * Generates reproducible step chains from observed sessions.
 * Takes confirmed findings and builds minimal, deterministic
 * reproduction sequences that can re-trigger the observed behavior.
 *
 * Safe mode: reproduction steps only use allowed actions
 *   (navigation, observation, authenticated_replay)
 *   No exploitation, no privilege escalation, no destructive actions.
 *
 * Key features:
 *   - Event timeline analysis to find minimal trigger sequences
 *   - Pre-condition extraction (auth state, cookies, page context)
 *   - Step deduplication (shortest path to reproduce)
 *   - Confidence scoring for each reproduction step
 *   - Machine-readable JSON + human-readable Markdown output
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = path.join(__dirname, 'output', 'reproductions');
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

// ─── Reproduction Step Schema ─────────────────────────────────────

// {
//   step: number,
//   action: 'navigate' | 'wait' | 'observe' | 'interact' | 'verify',
//   target: string,          // URL, selector, or cookie name
//   description: string,
//   preconditions: object,   // required state before this step
//   expected_result: string,
//   confidence: 0-100,
//   event_refs: [],          // event IDs that inform this step
//   safe: true,              // always true in safe mode
// }

// ─── Category → Reproduction Strategy ─────────────────────────────

const REPRODUCTION_STRATEGIES = {
  missing_httpOnly: {
    steps: [
      { action: 'navigate', target: '/login', description: 'Navigate to login page' },
      { action: 'interact', target: 'login-form', description: 'Complete login flow to set authentication cookies' },
      { action: 'observe', target: 'document.cookie', description: 'Check if auth cookie is accessible via document.cookie' },
      { action: 'verify', target: 'HttpOnly-check', description: 'Verify cookie appears in JS context (missing HttpOnly confirmed)' },
    ],
    preconditions: { requires_auth: false, requires_baseline: false },
  },
  missing_secure: {
    steps: [
      { action: 'navigate', target: 'http://{target}', description: 'Navigate to application over HTTP (non-TLS)' },
      { action: 'observe', target: 'request-headers', description: 'Check if auth cookies are sent in the request over HTTP' },
      { action: 'verify', target: 'Secure-flag', description: 'Confirm cookie lacks Secure flag and is transmitted over HTTP' },
    ],
    preconditions: { requires_auth: true, requires_baseline: false },
  },
  weak_samesite: {
    steps: [
      { action: 'navigate', target: '/dashboard', description: 'Navigate to authenticated page' },
      { action: 'observe', target: 'cookie-attributes', description: 'Check SameSite attribute on auth cookies' },
      { action: 'verify', target: 'SameSite-check', description: 'Confirm auth cookie has SameSite=None or unset' },
    ],
    preconditions: { requires_auth: true, requires_baseline: false },
  },
  bearer_token_exposure: {
    steps: [
      { action: 'navigate', target: '/api/users/me', description: 'Navigate to an authenticated API endpoint' },
      { action: 'observe', target: 'Authorization-header', description: 'Check for Bearer token in request headers visible to JS' },
      { action: 'verify', target: 'bearer-exposure', description: 'Confirm Bearer token is accessible to JavaScript in browser memory' },
    ],
    preconditions: { requires_auth: true, requires_baseline: false },
  },
  jwt_in_browser_memory: {
    steps: [
      { action: 'navigate', target: '/login', description: 'Navigate to login page' },
      { action: 'interact', target: 'login-form', description: 'Complete login to trigger CryptoJS.AES.decrypt' },
      { action: 'observe', target: 'CryptoJS.AES.decrypt', description: 'Observe client-side AES decryption in console' },
      { action: 'observe', target: 'memory-search', description: 'Search browser heap for decrypted JWT payload' },
      { action: 'verify', target: 'jwt-memory', description: 'Confirm decrypted JWT is readable from JS memory' },
    ],
    preconditions: { requires_auth: false, requires_baseline: false },
  },
  session_fixation_indicators: {
    steps: [
      { action: 'observe', target: 'pre-login-sessionid', description: 'Note sessionid cookie value before login' },
      { action: 'navigate', target: '/login', description: 'Navigate to login page' },
      { action: 'interact', target: 'login-form', description: 'Complete login flow' },
      { action: 'observe', target: 'post-login-sessionid', description: 'Check sessionid cookie value after login' },
      { action: 'verify', target: 'session-rotation', description: 'Confirm sessionid did NOT change after login (fixation risk)' },
    ],
    preconditions: { requires_auth: false, requires_baseline: false },
  },
  session_rotation_failure: {
    steps: [
      { action: 'navigate', target: '/dashboard', description: 'Navigate to authenticated page' },
      { action: 'observe', target: 'sessionid-timeline', description: 'Track sessionid values across multiple page loads' },
      { action: 'verify', target: 'rotation-frequency', description: 'Confirm excessive or absent session rotation' },
    ],
    preconditions: { requires_auth: true, requires_baseline: false },
  },
  cache_control_misconfiguration: {
    steps: [
      { action: 'navigate', target: '/api/users/me', description: 'Navigate to authenticated API endpoint' },
      { action: 'observe', target: 'response-headers', description: 'Check Cache-Control header on sensitive response' },
      { action: 'verify', target: 'cache-headers', description: 'Confirm missing or misconfigured Cache-Control on sensitive endpoint' },
    ],
    preconditions: { requires_auth: true, requires_baseline: false },
  },
  csrf_signal_anomaly: {
    steps: [
      { action: 'navigate', target: '/dashboard', description: 'Navigate to authenticated page with forms' },
      { action: 'interact', target: 'state-changing-form', description: 'Submit a state-changing request (POST/PUT/PATCH/DELETE)' },
      { action: 'observe', target: 'request-headers', description: 'Check for X-CSRFToken header in the outgoing request' },
      { action: 'verify', target: 'csrf-presence', description: 'Confirm CSRF header is missing on the state-changing request' },
    ],
    preconditions: { requires_auth: true, requires_baseline: false },
  },
  cors_misconfiguration: {
    steps: [
      { action: 'navigate', target: '/api/endpoint', description: 'Navigate to API endpoint' },
      { action: 'observe', target: 'response-headers', description: 'Check Access-Control-Allow-Origin and Allow-Credentials headers' },
      { action: 'verify', target: 'cors-config', description: 'Confirm ACAO:* with ACAC:true (critical misconfiguration)' },
    ],
    preconditions: { requires_auth: false, requires_baseline: false },
  },
  cookie_scope_oversharing: {
    steps: [
      { action: 'navigate', target: '/dashboard', description: 'Navigate to main application domain' },
      { action: 'observe', target: 'cookie-domain', description: 'Check domain attribute on auth cookies' },
      { action: 'navigate', target: 'subdomain.ripio.com', description: 'Navigate to a subdomain' },
      { action: 'observe', target: 'cookie-transmission', description: 'Verify auth cookies are sent to subdomain' },
      { action: 'verify', target: 'scope-oversharing', description: 'Confirm auth cookies sent to subdomains that dont need them' },
    ],
    preconditions: { requires_auth: true, requires_baseline: false },
  },
  auth_state_desynchronization: {
    steps: [
      { action: 'navigate', target: '/login', description: 'Navigate to login page' },
      { action: 'interact', target: 'login-form', description: 'Complete login flow' },
      { action: 'observe', target: 'cookie-vs-api', description: 'Compare cookie auth state vs API response auth state' },
      { action: 'verify', target: 'desync', description: 'Confirm inconsistency between cookie auth and API auth state' },
    ],
    preconditions: { requires_auth: false, requires_baseline: false },
  },
  ws_auth_inconsistency: {
    steps: [
      { action: 'navigate', target: '/dashboard', description: 'Navigate to page with WebSocket connection' },
      { action: 'observe', target: 'ws-connection', description: 'Observe WebSocket connection establishment and auth' },
      { action: 'interact', target: 'logout', description: 'Trigger HTTP logout while WS connection remains open' },
      { action: 'observe', target: 'ws-after-logout', description: 'Check if WS continues to accept messages after HTTP logout' },
      { action: 'verify', target: 'ws-auth-desync', description: 'Confirm WS messages accepted after HTTP session invalidated' },
    ],
    preconditions: { requires_auth: true, requires_baseline: false },
  },
  permission_boundary_anomaly: {
    steps: [
      { action: 'navigate', target: '/api/admin/endpoint', description: 'Navigate to admin/privileged endpoint' },
      { action: 'observe', target: 'response', description: 'Check response status and content' },
      { action: 'verify', target: 'permission-check', description: 'Confirm endpoint returns data without proper role verification' },
    ],
    preconditions: { requires_auth: true, requires_baseline: false },
  },
  regression_security_change: {
    steps: [
      { action: 'observe', target: 'baseline-comparison', description: 'Compare current session cookie attributes against baseline' },
      { action: 'observe', target: 'auth-model', description: 'Compare auth model against baseline' },
      { action: 'verify', target: 'regression', description: 'Confirm security posture has regressed from baseline' },
    ],
    preconditions: { requires_auth: true, requires_baseline: true },
  },
};

class ReproductionEngine {
  constructor(options = {}) {
    this.reproductions = new Map(); // bugId → reproduction
    this.options = {
      maxSteps: 15,
      minConfidence: 40,
      safeMode: true,
      ...options,
    };
  }

  /**
   * Generate a reproduction chain for a confirmed bug
   * @param {object} bug - confirmed bug from VerificationEngine
   * @param {object} observations - { events, report, anomalies, baseline, diff }
   * @returns {object} reproduction chain
   */
  generateReproduction(bug, observations = {}) {
    const { events = [], report = {} } = observations;
    const findingCategory = this._mapVerificationToFindingCategory(bug.category);

    const strategy = REPRODUCTION_STRATEGIES[findingCategory];
    const reproductionId = `repro-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36)}`;

    // Build steps from strategy, enriched with observed data
    let steps;
    if (strategy) {
      steps = this._enrichStrategySteps(strategy.steps, bug, observations);
    } else {
      steps = this._buildGenericSteps(bug, observations);
    }

    // Extract preconditions
    const preconditions = this._extractPreconditions(bug, observations, strategy);

    // Build event references (link each step to actual observed events)
    const eventRefs = this._buildEventReferences(steps, events, findingCategory);

    // Compute per-step confidence
    for (const step of steps) {
      step.confidence = this._computeStepConfidence(step, events, report);
    }

    // Compute overall reproduction confidence
    const overallConfidence = this._computeOverallConfidence(steps);

    const reproduction = {
      id: reproductionId,
      bug_id: bug.id,
      bug_title: bug.title,
      category: bug.category,
      finding_category: findingCategory,
      severity: bug.severity,
      status: overallConfidence >= this.options.minConfidence ? 'reproducible' : 'partial',
      confidence: overallConfidence,
      preconditions,
      steps,
      event_references: eventRefs,
      safe_mode: this.options.safeMode,
      generated_at: Date.now(),
      metadata: {
        event_count: events.length,
        auth_model: report.auth_model || 'unknown',
        has_baseline: !!observations.baseline,
      },
    };

    this.reproductions.set(bug.id, reproduction);
    return reproduction;
  }

  /**
   * Generate reproductions for all confirmed bugs
   */
  generateAll(bugs, observations = {}) {
    const reproductions = [];
    for (const bug of bugs) {
      reproductions.push(this.generateReproduction(bug, observations));
    }
    return reproductions;
  }

  // ─── Strategy Step Enrichment ─────────────────────────────────

  _enrichStrategySteps(templateSteps, bug, observations) {
    const { events = [], report = {} } = observations;
    const target = report.target || 'https://ripio.com';

    return templateSteps.map((template, idx) => {
      // Replace placeholders
      const description = template.description
        .replace('{target}', target);

      const targetValue = template.target
        .replace('{target}', target);

      return {
        step: idx + 1,
        action: template.action,
        target: targetValue,
        description,
        preconditions: this._getStepPreconditions(template, idx, observations),
        expected_result: this._getExpectedResult(template, bug),
        confidence: 0, // computed later
        event_refs: [],
        safe: true,
      };
    });
  }

  _buildGenericSteps(bug, observations) {
    const { events = [], report = {} } = observations;

    const steps = [
      {
        step: 1,
        action: 'navigate',
        target: report.target || 'https://ripio.com',
        description: 'Navigate to the target application',
        preconditions: { browser_open: true },
        expected_result: 'Application loads successfully',
        confidence: 0,
        event_refs: [],
        safe: true,
      },
      {
        step: 2,
        action: 'interact',
        target: 'login-flow',
        description: 'Complete the authentication flow to reach the state where the bug was observed',
        preconditions: { on_login_page: true },
        expected_result: 'Authenticated session established',
        confidence: 0,
        event_refs: [],
        safe: true,
      },
      {
        step: 3,
        action: 'observe',
        target: 'bug-trigger',
        description: `Observe the behavior that confirms bug "${bug.title}"`,
        preconditions: { authenticated: true },
        expected_result: `Bug behavior confirmed: ${bug.title}`,
        confidence: 0,
        event_refs: [],
        safe: true,
      },
      {
        step: 4,
        action: 'verify',
        target: 'verification',
        description: 'Verify the finding matches the expected bug pattern',
        preconditions: { observation_made: true },
        expected_result: 'Bug confirmed through independent verification',
        confidence: 0,
        event_refs: [],
        safe: true,
      },
    ];

    return steps;
  }

  // ─── Precondition Extraction ──────────────────────────────────

  _extractPreconditions(bug, observations, strategy) {
    const { events = [], report = {}, baseline = null } = observations;
    const preconditions = {
      requires_auth: strategy?.preconditions?.requires_auth ?? true,
      requires_baseline: strategy?.preconditions?.requires_baseline ?? false,
      required_cookies: [],
      required_page_state: [],
      required_endpoints: [],
    };

    // Extract required cookies
    for (const c of (report.cookies || [])) {
      if (['ripio_access', 'sessionid', 'csrftoken', 'access_token'].includes(c.name)) {
        preconditions.required_cookies.push({
          name: c.name,
          domain: c.domain,
          must_be_set: true,
        });
      }
    }

    // Extract required page states
    const navEvents = events.filter(e => e.type === 'page_navigation');
    if (navEvents.length > 0) {
      try {
        const firstNav = new URL(navEvents[0].url || '');
        preconditions.required_page_state.push({
          type: 'on_domain',
          value: firstNav.origin,
        });
      } catch (_) {}
    }

    // Extract required endpoints
    for (const e of events) {
      if ((e.type === 'network_request' || e.type === 'network_response') && e.url) {
        try {
          const u = new URL(e.url);
          const isAuth = /\/auth\/|\/login|\/api\/users\/me/.test(u.pathname);
          if (isAuth) {
            preconditions.required_endpoints.push({
              method: e.method || 'GET',
              path: u.pathname,
              must_respond: e.type === 'network_response' ? e.status : 200,
            });
          }
        } catch (_) {}
      }
    }

    return preconditions;
  }

  _getStepPreconditions(template, stepIndex, observations) {
    const preconditions = {};

    if (stepIndex > 0) {
      preconditions.previous_step_completed = true;
    }

    if (template.action === 'interact' || template.action === 'observe') {
      preconditions.page_loaded = true;
    }

    if (template.action === 'verify') {
      preconditions.observation_made = true;
    }

    return preconditions;
  }

  _getExpectedResult(template, bug) {
    const results = {
      navigate: 'Page loads successfully with expected content',
      wait: 'Expected state change or event occurs',
      observe: 'Observed behavior matches bug description',
      interact: 'Action produces expected side effect',
      verify: 'Bug behavior confirmed through independent check',
    };
    return results[template.action] || `Bug "${bug.title}" confirmed`;
  }

  // ─── Event Reference Builder ─────────────────────────────────

  _buildEventReferences(steps, events, findingCategory) {
    const refs = [];

    for (const e of events) {
      let relevant = false;

      switch (findingCategory) {
        case 'missing_httpOnly':
        case 'missing_secure':
        case 'weak_samesite':
          relevant = e.type === 'cookie_snapshot' || (e.type === 'network_response' && e.headers);
          break;
        case 'jwt_in_browser_memory':
          relevant = e.type === 'console_log' || e.type === 'cookie_snapshot';
          break;
        case 'session_fixation_indicators':
        case 'session_rotation_failure':
          relevant = e.type === 'auth_signal' || e.type === 'cookie_snapshot';
          break;
        case 'csrf_signal_anomaly':
          relevant = e.type === 'network_request' && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(e.method);
          break;
        case 'cors_misconfiguration':
          relevant = e.type === 'network_response' && e.headers;
          break;
        default:
          relevant = e.type === 'auth_signal' || e.type === 'network_request';
      }

      if (relevant) {
        refs.push({ event_id: e.id, type: e.type, ts: e.ts });
      }
    }

    return refs.slice(0, 50); // Cap at 50 references
  }

  // ─── Confidence Computation ───────────────────────────────────

  _computeStepConfidence(step, events, report) {
    let confidence = 50; // Base confidence

    switch (step.action) {
      case 'navigate':
        // High confidence if we have navigation events
        const navEvents = events.filter(e => e.type === 'page_navigation').length;
        confidence = Math.min(90, 60 + navEvents * 3);
        break;

      case 'interact':
        // Medium confidence — depends on auth flow complexity
        const authEvents = events.filter(e => e.type === 'auth_signal').length;
        confidence = Math.min(85, 45 + authEvents * 5);
        break;

      case 'observe':
        // Confidence based on whether we have matching event types
        const observeTargets = step.target;
        if (observeTargets.includes('cookie') || observeTargets.includes('Cookie')) {
          const cookieEvents = events.filter(e => e.type === 'cookie_snapshot').length;
          confidence = Math.min(90, 40 + cookieEvents * 8);
        } else if (observeTargets.includes('header') || observeTargets.includes('Header')) {
          const headerEvents = events.filter(e => e.type === 'network_response' && e.headers).length;
          confidence = Math.min(90, 40 + headerEvents * 4);
        } else if (observeTargets.includes('sessionid') || observeTargets.includes('session')) {
          const sessionEvents = events.filter(e => e.type === 'auth_signal').length;
          confidence = Math.min(90, 45 + sessionEvents * 6);
        } else {
          confidence = 60;
        }
        break;

      case 'verify':
        // Verification step confidence is based on upstream observation quality
        confidence = 70; // Default — adjusted by overall confidence
        break;

      case 'wait':
        confidence = 40; // Waiting steps have low standalone confidence
        break;

      default:
        confidence = 50;
    }

    return Math.max(0, Math.min(100, confidence));
  }

  _computeOverallConfidence(steps) {
    if (steps.length === 0) return 0;

    // Weighted average — verify steps are weighted higher
    let totalWeight = 0;
    let weightedSum = 0;

    for (const step of steps) {
      const weight = step.action === 'verify' ? 2.0 : step.action === 'observe' ? 1.5 : 1.0;
      weightedSum += step.confidence * weight;
      totalWeight += weight;
    }

    return Math.round(weightedSum / totalWeight);
  }

  // ─── Category Mapping ────────────────────────────────────────

  _mapVerificationToFindingCategory(verificationCategory) {
    const mapping = {
      authentication_regression: 'unexpected_auth_model_change',
      session_management_issue: 'session_fixation_indicators',
      authorization_inconsistency: 'permission_boundary_anomaly',
      cookie_security_failure: 'missing_httpOnly',
      csrf_protection_failure: 'csrf_signal_anomaly',
      cors_policy_issue: 'cors_misconfiguration',
      cache_control_issue: 'cache_control_misconfiguration',
      sensitive_data_exposure: 'bearer_token_exposure',
      workflow_state_corruption: 'auth_state_desynchronization',
      websocket_auth_desync: 'ws_auth_inconsistency',
    };
    return mapping[verificationCategory] || 'missing_httpOnly';
  }

  // ─── Persistence ──────────────────────────────────────────────

  saveReproduction(bugId) {
    const repro = this.reproductions.get(bugId);
    if (!repro) return null;

    const filePath = path.join(OUTPUT_DIR, `repro-${repro.id}.json`);
    fs.writeFileSync(filePath, JSON.stringify(repro, null, 2));

    // Also generate Markdown
    const md = this.generateMarkdown(repro);
    const mdPath = path.join(OUTPUT_DIR, `repro-${repro.id}.md`);
    fs.writeFileSync(mdPath, md, 'utf8');

    return { json: filePath, markdown: mdPath };
  }

  generateMarkdown(reproduction) {
    const lines = [];

    lines.push(`# Reproduction: ${reproduction.bug_title}`);
    lines.push('');
    lines.push(`**Bug ID:** ${reproduction.bug_id}`);
    lines.push(`**Category:** ${reproduction.category}`);
    lines.push(`**Severity:** ${reproduction.severity}`);
    lines.push(`**Status:** ${reproduction.status}`);
    lines.push(`**Confidence:** ${reproduction.confidence}%`);
    lines.push(`**Safe Mode:** ${reproduction.safe_mode}`);
    lines.push('');

    // Preconditions
    lines.push('## Preconditions');
    lines.push('');
    if (reproduction.preconditions.requires_auth) {
      lines.push('- Authenticated session required');
    }
    if (reproduction.preconditions.requires_baseline) {
      lines.push('- Baseline comparison required');
    }
    for (const cookie of (reproduction.preconditions.required_cookies || [])) {
      lines.push(`- Cookie: ${cookie.name} (${cookie.domain})`);
    }
    lines.push('');

    // Steps
    lines.push('## Reproduction Steps');
    lines.push('');
    for (const step of reproduction.steps) {
      lines.push(`### Step ${step.step}: ${step.action.toUpperCase()}`);
      lines.push('');
      lines.push(`**Target:** \`${step.target}\``);
      lines.push('');
      lines.push(`**Description:** ${step.description}`);
      lines.push('');
      lines.push(`**Expected Result:** ${step.expected_result}`);
      lines.push('');
      lines.push(`**Confidence:** ${step.confidence}%`);
      lines.push('');
    }

    lines.push('---');
    lines.push('');
    lines.push('*Generated by BOQA v0.4 — Verification Engine (Safe Mode)*');

    return lines.join('\n');
  }

  // ─── Accessors ────────────────────────────────────────────────

  getReproduction(bugId) {
    return this.reproductions.get(bugId);
  }

  getAllReproductions() {
    return [...this.reproductions.values()];
  }

  // ─── P5: Replay-Based Verification & Time-Machine Metadata ───

  /**
   * Enhance a reproduction chain with time-machine metadata
   * from a replay manifest. Adds context hash, manifest reference,
   * and deterministic replay hints.
   *
   * @param {string} bugId - Bug ID
   * @param {object} manifest - Replay manifest from ReplayManifestBuilder
   * @returns {object|null} Enhanced reproduction
   */
  attachTimeMachineMetadata(bugId, manifest) {
    const repro = this.reproductions.get(bugId);
    if (!repro) return null;

    repro.time_machine = {
      replay_id: manifest.replay_id,
      boqa_version: manifest.boqa_version,
      context_hash: manifest.artifact_hash || manifest.state_hash,
      target_domain: manifest.target_domain,
      scenario_name: manifest.scenario_name,
      attached_at: Date.now(),
    };

    // Add manifest reference to each step
    for (const step of repro.steps) {
      step.replay_context = manifest.replay_id;
    }

    return repro;
  }

  /**
   * Accept a replay manifest as input for generating reproductions.
   * This allows reproductions to be derived from deterministic replays
   * rather than only from verification results.
   *
   * @param {object} manifest - Replay manifest
   * @param {object} recording - Recording export
   * @returns {object} Replay-derived reproduction
   */
  generateFromReplay(manifest, recording) {
    const events = recording.events || [];
    const boundaries = recording.step_boundaries || [];
    const reproductionId = `repro-rpl-${Date.now().toString(36)}`;

    // Build steps from replay step boundaries
    const steps = boundaries.length > 0
      ? boundaries.map((b, idx) => ({
          step: idx + 1,
          action: 'observe',
          target: `(replay step: ${b.name})`,
          description: `Replay step ${idx + 1}: ${b.name}`,
          preconditions: { replay_step: true },
          expected_result: 'Replay reproduces recorded behavior',
          confidence: 70,
          event_refs: [],
          safe: true,
          replay_context: manifest.replay_id,
        }))
      : [{
          step: 1,
          action: 'observe',
          target: '(full replay)',
          description: `Full deterministic replay with ${events.length} events`,
          preconditions: { replay_loaded: true },
          expected_result: 'Replay reproduces recorded session',
          confidence: 60,
          event_refs: [],
          safe: true,
          replay_context: manifest.replay_id,
        }];

    const reproduction = {
      id: reproductionId,
      bug_id: `RPL-${manifest.replay_id}`,
      bug_title: `Replay-derived reproduction: ${manifest.scenario_name}`,
      category: 'replay_verification',
      finding_category: 'replay_derived',
      severity: 'info',
      status: 'replay_based',
      confidence: steps.length > 0
        ? Math.round(steps.reduce((sum, s) => sum + s.confidence, 0) / steps.length)
        : 0,
      preconditions: {
        requires_auth: events.some(e => e.type === 'auth_signal'),
        requires_baseline: false,
        requires_replay_manifest: true,
      },
      steps,
      event_references: [],
      safe_mode: this.options.safeMode,
      generated_at: Date.now(),
      time_machine: {
        replay_id: manifest.replay_id,
        boqa_version: manifest.boqa_version,
        context_hash: manifest.artifact_hash || manifest.state_hash,
        target_domain: manifest.target_domain,
        scenario_name: manifest.scenario_name,
        attached_at: Date.now(),
      },
      metadata: {
        event_count: events.length,
        step_count: steps.length,
        auth_model: 'unknown',
        has_baseline: false,
        from_replay: true,
      },
    };

    this.reproductions.set(reproduction.bug_id, reproduction);
    return reproduction;
  }
}

module.exports = { ReproductionEngine, REPRODUCTION_STRATEGIES, OUTPUT_DIR };

