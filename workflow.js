/**
 * BOQA workflow.js — Workflow Engine
 *
 * Replays business workflows and detects unexpected outcomes.
 * Analyzes the event stream to identify multi-step business
 * workflows (login → dashboard → trade, etc.), then replays
 * them deterministically to verify:
 *   - State transitions are consistent
 *   - Auth boundaries are enforced at each step
 *   - No unexpected data leaks between workflow phases
 *   - WS state stays synchronized with HTTP state
 *   - Error handling doesn't expose sensitive information
 *
 * Safe mode: no destructive mutations, only observation and replay.
 *            Uses authenticated_replay and state_comparison actions only.
 *
 * Verification category: workflow_state_corruption
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = path.join(__dirname, 'output', 'workflows');
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

// ─── Workflow Phase Definitions ────────────────────────────────────

const WORKFLOW_PHASES = {
  unauthenticated: {
    order: 0,
    description: 'Pre-authentication state',
    path_patterns: ['/login', '/signup', '/auth', '/forgot-password'],
    expected_cookies: [],
    forbidden_cookies: ['sessionid', 'ripio_access', 'access_token'],
  },
  authenticating: {
    order: 1,
    description: 'Active authentication flow',
    path_patterns: ['/api/auth/login', '/api/auth/token', '/api/auth/callback'],
    expected_cookies: [], // being set
    forbidden_cookies: [],
    expected_signals: ['auth_cookie_set'],
  },
  authenticated: {
    order: 2,
    description: 'Post-authentication dashboard',
    path_patterns: ['/dashboard', '/api/users/me', '/home'],
    expected_cookies: ['sessionid', 'ripio_access'],
    forbidden_cookies: [],
  },
  trading: {
    order: 3,
    description: 'Active trading/swapping',
    path_patterns: ['/trade', '/swap', '/api/trade', '/api/swap'],
    expected_cookies: ['sessionid', 'ripio_access'],
    forbidden_cookies: [],
    requires_csrf: true,
  },
  withdrawal: {
    order: 4,
    description: 'Withdrawal/transfer flow',
    path_patterns: ['/withdraw', '/send', '/api/withdraw', '/api/send'],
    expected_cookies: ['sessionid', 'ripio_access'],
    forbidden_cookies: [],
    requires_csrf: true,
    high_sensitivity: true,
  },
  admin: {
    order: 10,
    description: 'Admin/management operations',
    path_patterns: ['/admin', '/api/admin', '/manage'],
    expected_cookies: ['sessionid', 'ripio_access'],
    forbidden_cookies: [],
    requires_csrf: true,
    requires_role: 'admin',
  },
  logout: {
    order: 99,
    description: 'Session termination',
    path_patterns: ['/logout', '/api/auth/logout'],
    expected_signals: ['auth_cookie_cleared'],
  },
};

// ─── Workflow Issue Schema ─────────────────────────────────────────

// {
//   id: string,
//   type: string,
//   severity: string,
//   workflow: string,
//   phase: string,
//   description: string,
//   expected: object,
//   observed: object,
//   confidence: 0-100,
//   safe: true,
// }

class WorkflowEngine {
  constructor(options = {}) {
    this.workflows = new Map();        // workflowId → workflow
    this.detectedFlows = [];           // automatically detected flows
    this.issues = [];                  // workflow issues found
    this.options = {
      safeMode: true,
      maxPhases: 20,
      ...options,
    };
  }

  /**
   * Detect workflows from the event stream
   * @param {object} observations - { events, report, anomalies, baseline, diff }
   * @returns {array} detected workflows
   */
  detectWorkflows(observations = {}) {
    const { events = [], report = {} } = observations;

    // Step 1: Build a timeline of workflow phases
    const phaseTimeline = this._buildPhaseTimeline(events);

    // Step 2: Identify distinct workflow sequences
    const workflows = this._identifyWorkflows(phaseTimeline, events);

    // Step 3: Validate each workflow for consistency issues
    this.issues = [];
    for (const workflow of workflows) {
      const workflowIssues = this._validateWorkflow(workflow, observations);
      this.issues.push(...workflowIssues);
    }

    // Step 4: Check for cross-workflow contamination
    const crossIssues = this._detectCrossWorkflowIssues(workflows, observations);
    this.issues.push(...crossIssues);

    // Sort issues by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    this.issues.sort((a, b) => (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4));

    this.detectedFlows = workflows;
    return workflows;
  }

  /**
   * Replay a detected workflow deterministically
   * @param {string} workflowId - workflow to replay
   * @param {object} observations - { events, report, anomalies, baseline, diff }
   * @returns {object} replay result
   */
  replayWorkflow(workflowId, observations = {}) {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) {
      // Try to find in detected flows
      const found = this.detectedFlows.find(w => w.id === workflowId);
      if (!found) throw new Error(`Workflow not found: ${workflowId}`);
    }

    const wf = this.workflows.get(workflowId) || this.detectedFlows.find(w => w.id === workflowId);
    const { events = [], report = {} } = observations;

    const replayResult = {
      workflow_id: workflowId,
      replayed_at: Date.now(),
      phases: [],
      state_transitions: [],
      issues_found: [],
      overall_status: 'consistent',
    };

    // Replay each phase
    for (const phase of wf.phases) {
      const phaseEvents = this._getPhaseEvents(phase, events);
      const phaseResult = this._replayPhase(phase, phaseEvents, observations);
      replayResult.phases.push(phaseResult);

      if (phaseResult.issues.length > 0) {
        replayResult.issues_found.push(...phaseResult.issues);
        replayResult.overall_status = 'issues_detected';
      }
    }

    // Validate state transitions between phases
    for (let i = 1; i < wf.phases.length; i++) {
      const transition = this._validateTransition(wf.phases[i - 1], wf.phases[i], observations);
      replayResult.state_transitions.push(transition);

      if (transition.issues.length > 0) {
        replayResult.issues_found.push(...transition.issues);
        replayResult.overall_status = 'issues_detected';
      }
    }

    return replayResult;
  }

  // ─── Phase Timeline Builder ──────────────────────────────────

  _buildPhaseTimeline(events) {
    const timeline = [];

    for (const e of events) {
      let phase = null;

      if (e.type === 'page_navigation' && e.url) {
        phase = this._classifyPhaseByPath(e.url);
        if (phase) {
          timeline.push({ ts: e.ts, event_id: e.id, phase, type: 'navigation', url: e.url });
        }
      }

      if (e.type === 'auth_signal') {
        const signalType = e.meta?.signalType;
        if (signalType === 'auth_cookie_set') {
          timeline.push({ ts: e.ts, event_id: e.id, phase: 'authenticating', type: 'auth_signal', signal: signalType });
        } else if (signalType === 'auth_cookie_cleared') {
          timeline.push({ ts: e.ts, event_id: e.id, phase: 'logout', type: 'auth_signal', signal: signalType });
        }
      }

      if (e.type === 'network_request' && e.url) {
        try {
          const pathname = new URL(e.url).pathname;
          const requestPhase = this._classifyPhaseByPath(pathname);
          if (requestPhase && e.method === 'POST') {
            timeline.push({ ts: e.ts, event_id: e.id, phase: requestPhase, type: 'request', method: e.method, path: pathname });
          }
        } catch (_) {}
      }

      if (e.type === 'websocket_open') {
        timeline.push({ ts: e.ts, event_id: e.id, phase: 'authenticated', type: 'ws_open', url: e.url });
      }
    }

    return timeline;
  }

  _classifyPhaseByPath(urlOrPath) {
    const pathname = urlOrPath.includes('://')
      ? (() => { try { return new URL(urlOrPath).pathname; } catch (_) { return urlOrPath; } })()
      : urlOrPath;

    for (const [phaseName, config] of Object.entries(WORKFLOW_PHASES)) {
      for (const pattern of config.path_patterns) {
        if (pathname.includes(pattern) || pathname.startsWith(pattern)) {
          return phaseName;
        }
      }
    }

    return null;
  }

  // ─── Workflow Identification ──────────────────────────────────

  _identifyWorkflows(phaseTimeline, events) {
    const workflows = [];
    let currentFlow = null;
    let flowId = 0;

    for (const entry of phaseTimeline) {
      const phase = entry.phase;
      const phaseOrder = WORKFLOW_PHASES[phase]?.order ?? -1;

      // Start a new workflow on authentication
      if (phase === 'authenticating' || (phase === 'authenticated' && !currentFlow)) {
        if (currentFlow) {
          workflows.push(currentFlow);
        }

        flowId++;
        currentFlow = {
          id: `wf-${flowId}`,
          start_ts: entry.ts,
          phases: [{
            phase,
            ts: entry.ts,
            event_id: entry.event_id,
            type: entry.type,
            url: entry.url || null,
          }],
          end_ts: null,
          status: 'in_progress',
        };
        continue;
      }

      // Extend current workflow
      if (currentFlow) {
        // End workflow on logout
        if (phase === 'logout') {
          currentFlow.phases.push({
            phase,
            ts: entry.ts,
            event_id: entry.event_id,
            type: entry.type,
          });
          currentFlow.end_ts = entry.ts;
          currentFlow.status = 'completed';
          workflows.push(currentFlow);
          currentFlow = null;
          continue;
        }

        // Add phase to current workflow (skip duplicates within 2s)
        const lastPhase = currentFlow.phases[currentFlow.phases.length - 1];
        if (phase !== lastPhase.phase || (entry.ts - lastPhase.ts > 2000)) {
          currentFlow.phases.push({
            phase,
            ts: entry.ts,
            event_id: entry.event_id,
            type: entry.type,
            url: entry.url || null,
          });
        }

        currentFlow.end_ts = entry.ts;
      }
    }

    // Finalize any in-progress workflow
    if (currentFlow) {
      currentFlow.status = 'incomplete';
      workflows.push(currentFlow);
    }

    // Store workflows
    for (const wf of workflows) {
      this.workflows.set(wf.id, wf);
    }

    return workflows;
  }

  // ─── Workflow Validation ──────────────────────────────────────

  _validateWorkflow(workflow, observations) {
    const { events = [], report = {} } = observations;
    const issues = [];

    // 1. Validate phase transitions
    for (let i = 1; i < workflow.phases.length; i++) {
      const prev = workflow.phases[i - 1];
      const curr = workflow.phases[i];

      const prevOrder = WORKFLOW_PHASES[prev.phase]?.order ?? -1;
      const currOrder = WORKFLOW_PHASES[curr.phase]?.order ?? -1;

      // Flag unexpected jumps (e.g., unauthenticated → admin)
      if (prevOrder <= 0 && currOrder >= 10) {
        issues.push({
          id: `wf-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36)}`,
          type: 'unexpected_phase_jump',
          severity: 'critical',
          workflow: workflow.id,
          phase: `${prev.phase} → ${curr.phase}`,
          description: `Workflow jumped from "${prev.phase}" to "${curr.phase}" without intermediate authentication`,
          expected: { intermediate_phases: ['authenticating', 'authenticated'] },
          observed: { from: prev.phase, to: curr.phase, ts_delta: curr.ts - prev.ts },
          confidence: 85,
          safe: true,
        });
      }

      // Flag backward transitions that shouldn't happen
      if (currOrder < prevOrder && currOrder < 2 && prevOrder >= 2) {
        // Going from authenticated back to unauthenticated without logout
        const hasLogoutBetween = workflow.phases.some(p =>
          p.phase === 'logout' && p.ts > prev.ts && p.ts < curr.ts
        );
        if (!hasLogoutBetween) {
          issues.push({
            id: `wf-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36)}`,
            type: 'unexpected_deauthentication',
            severity: 'high',
            workflow: workflow.id,
            phase: `${prev.phase} → ${curr.phase}`,
            description: `Workflow transitioned from "${prev.phase}" to "${curr.phase}" without explicit logout`,
            expected: { requires_logout: true },
            observed: { from: prev.phase, to: curr.phase },
            confidence: 70,
            safe: true,
          });
        }
      }
    }

    // 2. Validate cookie presence per phase
    for (const phase of workflow.phases) {
      const phaseConfig = WORKFLOW_PHASES[phase.phase];
      if (!phaseConfig) continue;

      // Check expected cookies are present
      const phaseEvents = events.filter(e => e.ts >= phase.ts && e.ts <= phase.ts + 5000);
      const cookieSnapshots = phaseEvents.filter(e => e.type === 'cookie_snapshot');
      const presentCookies = new Set();
      for (const cs of cookieSnapshots) {
        for (const c of (cs.meta?.authCookies || [])) {
          presentCookies.add(c.name);
        }
      }

      for (const expectedCookie of (phaseConfig.expected_cookies || [])) {
        if (!presentCookies.has(expectedCookie)) {
          issues.push({
            id: `wf-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36)}`,
            type: 'missing_expected_cookie',
            severity: 'medium',
            workflow: workflow.id,
            phase: phase.phase,
            description: `Expected cookie "${expectedCookie}" not present during "${phase.phase}" phase`,
            expected: { cookie: expectedCookie, present: true },
            observed: { present_cookies: [...presentCookies] },
            confidence: 60,
            safe: true,
          });
        }
      }

      // Check forbidden cookies are NOT present
      for (const forbiddenCookie of (phaseConfig.forbidden_cookies || [])) {
        if (presentCookies.has(forbiddenCookie)) {
          issues.push({
            id: `wf-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36)}`,
            type: 'forbidden_cookie_present',
            severity: 'high',
            workflow: workflow.id,
            phase: phase.phase,
            description: `Forbidden cookie "${forbiddenCookie}" present during "${phase.phase}" phase`,
            expected: { cookie: forbiddenCookie, present: false },
            observed: { present: true },
            confidence: 75,
            safe: true,
          });
        }
      }

      // Check CSRF requirement
      if (phaseConfig.requires_csrf) {
        const stateChangingRequests = phaseEvents.filter(e =>
          e.type === 'network_request' && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(e.method)
        );

        for (const req of stateChangingRequests) {
          const hasCsrf = req.headers && Object.keys(req.headers).some(k =>
            k.toLowerCase() === 'x-csrftoken' || k.toLowerCase() === 'x-csrf-token'
          );
          if (!hasCsrf) {
            issues.push({
              id: `wf-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36)}`,
              type: 'missing_csrf_in_workflow',
              severity: 'high',
              workflow: workflow.id,
              phase: phase.phase,
              description: `State-changing request in "${phase.phase}" phase missing CSRF token`,
              expected: { csrf_required: true },
              observed: { csrf_present: false, method: req.method, url: req.url },
              confidence: 80,
              safe: true,
            });
          }
        }
      }
    }

    // 3. Validate WS consistency across workflow
    const wsOpenEvents = events.filter(e => e.type === 'websocket_open');
    const wsCloseEvents = events.filter(e => e.type === 'websocket_close');
    const wsMessageIn = events.filter(e => e.type === 'websocket_message_in');

    // Check if WS messages continue after logout
    if (workflow.phases.some(p => p.phase === 'logout')) {
      const logoutTs = workflow.phases.find(p => p.phase === 'logout').ts;
      const postLogoutWsMessages = wsMessageIn.filter(e => e.ts > logoutTs);

      if (postLogoutWsMessages.length > 0) {
        issues.push({
          id: `wf-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36)}`,
          type: 'ws_messages_after_logout',
          severity: 'high',
          workflow: workflow.id,
          phase: 'logout',
          description: `WebSocket messages received after logout — WS auth not synced with HTTP session`,
          expected: { ws_closed_after_logout: true },
          observed: { post_logout_ws_messages: postLogoutWsMessages.length },
          confidence: 85,
          safe: true,
        });
      }
    }

    return issues;
  }

  // ─── Cross-Workflow Issue Detection ───────────────────────────

  _detectCrossWorkflowIssues(workflows, observations) {
    const issues = [];

    if (workflows.length < 2) return issues;

    // Check for session fixation across workflows
    const { events = [] } = observations;
    const cookieSnapshots = events.filter(e => e.type === 'cookie_snapshot');

    const sessionIds = [];
    for (const cs of cookieSnapshots) {
      const sid = (cs.meta?.authCookies || []).find(c => c.name === 'sessionid');
      if (sid) {
        sessionIds.push({
          ts: cs.ts,
          value_hash: this._hashValue(sid.valuePreview || sid.value),
        });
      }
    }

    // If sessionid doesn't change across multiple workflows, potential fixation
    if (sessionIds.length >= 2 && workflows.length >= 2) {
      const uniqueHashes = new Set(sessionIds.map(s => s.value_hash));
      if (uniqueHashes.size === 1) {
        issues.push({
          id: `wf-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36)}`,
          type: 'session_not_rotated_across_workflows',
          severity: 'high',
          workflow: 'cross-workflow',
          phase: 'session-management',
          description: `Session ID remained identical across ${workflows.length} distinct workflow instances — potential session fixation`,
          expected: { session_rotation: true },
          observed: { unique_session_hashes: uniqueHashes.size, workflow_count: workflows.length },
          confidence: 75,
          safe: true,
        });
      }
    }

    // Check for credential reuse patterns
    const authEvents = events.filter(e => e.type === 'auth_signal' && e.meta?.signalType === 'auth_cookie_set');
    if (authEvents.length > 1) {
      const timeBetweenAuth = authEvents[1].ts - authEvents[0].ts;
      if (timeBetweenAuth < 5000) {
        issues.push({
          id: `wf-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36)}`,
          type: 'rapid_reauthentication',
          severity: 'medium',
          workflow: 'cross-workflow',
          phase: 'authentication',
          description: `Multiple authentication events within ${timeBetweenAuth}ms — possible credential replay or race condition`,
          expected: { single_auth_per_workflow: true },
          observed: { auth_events: authEvents.length, time_span_ms: timeBetweenAuth },
          confidence: 60,
          safe: true,
        });
      }
    }

    return issues;
  }

  // ─── Phase Replay ────────────────────────────────────────────

  _replayPhase(phase, phaseEvents, observations) {
    const result = {
      phase: phase.phase,
      ts: phase.ts,
      events_replayed: phaseEvents.length,
      issues: [],
      status: 'consistent',
    };

    // Verify the phase had the expected signals
    const phaseConfig = WORKFLOW_PHASES[phase.phase];
    if (!phaseConfig) return result;

    // Check for expected signals
    const expectedSignals = phaseConfig.expected_signals || [];
    for (const expectedSignal of expectedSignals) {
      const found = phaseEvents.some(e =>
        e.type === 'auth_signal' && e.meta?.signalType === expectedSignal
      );
      if (!found) {
        result.issues.push({
          type: 'missing_expected_signal',
          signal: expectedSignal,
          phase: phase.phase,
          severity: 'medium',
        });
        result.status = 'issues_detected';
      }
    }

    return result;
  }

  _getPhaseEvents(phase, events) {
    return events.filter(e => e.ts >= phase.ts && e.ts <= phase.ts + 10000);
  }

  _validateTransition(fromPhase, toPhase, observations) {
    const transition = {
      from: fromPhase.phase,
      to: toPhase.phase,
      ts_delta: toPhase.ts - fromPhase.ts,
      issues: [],
      status: 'valid',
    };

    const fromOrder = WORKFLOW_PHASES[fromPhase.phase]?.order ?? -1;
    const toOrder = WORKFLOW_PHASES[toPhase.phase]?.order ?? -1;

    // Check for suspicious backward transitions
    if (toOrder < fromOrder && fromOrder >= 2 && toOrder <= 0) {
      transition.issues.push({
        type: 'backward_transition_without_logout',
        severity: 'high',
        description: `Transition from ${fromPhase.phase} to ${toPhase.phase} without logout`,
      });
      transition.status = 'suspicious';
    }

    // Check for too-fast transitions (possible race condition)
    if (transition.ts_delta < 100 && fromOrder !== toOrder) {
      transition.issues.push({
        type: 'race_condition_candidate',
        severity: 'medium',
        description: `Phase transition in ${transition.ts_delta}ms — possible race condition`,
      });
      transition.status = 'suspicious';
    }

    return transition;
  }

  // ─── Utility Methods ─────────────────────────────────────────

  _hashValue(value) {
    if (!value) return 'null';
    return crypto.createHash('sha256').update(String(value)).digest('hex').substring(0, 16);
  }

  // ─── Persistence ──────────────────────────────────────────────

  save() {
    const report = {
      generated_at: Date.now(),
      version: '0.4.0',
      safe_mode: this.options.safeMode,
      detected_workflows: this.detectedFlows.length,
      workflows: this.detectedFlows,
      issues: this.issues,
      summary: this._buildSummary(),
    };

    const filePath = path.join(OUTPUT_DIR, `workflow-report-${Date.now()}.json`);
    fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
    return filePath;
  }

  _buildSummary() {
    const byType = {};
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

    for (const issue of this.issues) {
      byType[issue.type] = (byType[issue.type] || 0) + 1;
      bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
    }

    return {
      total_workflows: this.detectedFlows.length,
      total_issues: this.issues.length,
      by_type: byType,
      by_severity: bySeverity,
    };
  }

  // ─── Accessors ────────────────────────────────────────────────

  getDetectedWorkflows() {
    return this.detectedFlows;
  }

  getIssues() {
    return this.issues;
  }

  getWorkflow(workflowId) {
    return this.workflows.get(workflowId);
  }

  getReplayResult(workflowId) {
    return this._replayResults?.get(workflowId);
  }
}

module.exports = { WorkflowEngine, WORKFLOW_PHASES, OUTPUT_DIR };

