/**
 * BOQA bus.js — Event bus with session isolation, UUID, metrics, NDJSON
 *
 * v0.7: Discovery Operating System events.
 *       campaign_started, campaign_completed, campaign_iteration,
 *       learning_outcome, learning_reweight, optimizer_rebalance,
 *       pattern_detected, regression_detected, evidence_scored,
 *       disclosure_certified, report_generated.
 *       Extended metrics for campaigns, learning, and evidence quality.
 * v0.6: Added discovery_event types for Autonomous Discovery Engine.
 *       coverage_delta, hypothesis_new, hypothesis_verdict, verification_result,
 *       correlation_found, planner_phase, discovery_loop metrics.
 * v0.3: Added finding_event, evidence_event types for real-time
 *       finding stream. Extended metrics for findings.
 */

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const EVENT_TYPES = new Set([
  'network_request', 'network_response', 'network_failure',
  'websocket_open', 'websocket_message_in', 'websocket_message_out', 'websocket_close',
  'console_log', 'console_error', 'page_navigation',
  'cookie_snapshot', 'auth_signal', 'performance_resource',
  'finding_new', 'finding_updated', 'evidence_new',
  'bug_confirmed', 'bug_updated', 'verification_step',
  // v0.6: Autonomous Discovery events
  'coverage_delta', 'hypothesis_new', 'hypothesis_verdict',
  'verification_result', 'correlation_found', 'planner_phase',
  // v0.7: Discovery Operating System events
  'campaign_started', 'campaign_completed', 'campaign_iteration',
  'learning_outcome', 'learning_reweight', 'optimizer_rebalance',
  'pattern_detected', 'regression_detected', 'evidence_scored',
  'disclosure_certified', 'report_generated',
  // v1.2: Decision Evolution Layer events
  'economic_scored', 'opportunity_compared', 'policy_decided',
  'portfolio_simulated', 'decision_run_started', 'decision_run_completed',
  'allocation_optimized',
  // v1.3: Decision Intelligence Hardening events
  'uncertainty_gated', 'counterfactual_validated', 'stability_filtered',
  'reality_aligned', 'decision_locked',
  // v1.4: Autonomous Decision Kernel events
  'autonomy_checked', 'autonomy_pipeline_completed', 'autonomy_level_changed',
  'firewall_violation', 'budget_exceeded', 'behavioral_mode_changed',
]);

class EventBus extends EventEmitter {
  constructor(wsServer = null, options = {}) {
    super();
    this.wsServer = wsServer;
    this.sessionId = options.sessionId || this._generateUUID();
    this.target = options.target || null;
    this.sessionStart = Date.now();
    this.sessionEnd = null;
    this.eventIndex = 0;
    this.eventLog = [];
    this.maxLogSize = options.maxLogSize || 50000;
    this.clients = new Set();
    this.paused = false;

    // Session metrics
    this.metrics = {
      request_count: 0,
      error_count: 0,
      ws_message_count: 0,
      auth_events: 0,
      status_codes: {},
      // v0.3: Finding metrics
      finding_count: 0,
      findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      evidence_count: 0,
      // v0.6: Autonomous Discovery metrics
      coverage_deltas: 0,
      hypothesis_count: 0,
      hypotheses_by_status: { pending: 0, confirmed: 0, rejected: 0, validating: 0, deferred: 0 },
      verification_results: 0,
      correlation_count: 0,
      planner_iterations: 0,
      // v0.7: Discovery Operating System metrics
      campaign_events: 0,
      learning_outcomes: 0,
      learning_reweights: 0,
      optimizer_rebalances: 0,
      patterns_detected: 0,
      regressions_detected: 0,
      evidence_scores: 0,
      disclosure_certificates: 0,
      reports_generated: 0,
      // v1.2: Decision Evolution Layer metrics
      economic_scores: 0,
      opportunity_comparisons: 0,
      policy_decisions: 0,
      portfolio_simulations: 0,
      decision_runs: 0,
      allocation_optimizations: 0,
      // v1.3: Decision Intelligence Hardening metrics
      uncertainty_gates: 0,
      counterfactual_validations: 0,
      stability_filters: 0,
      reality_alignments: 0,
      decision_locks: 0,
    };

    // v0.3: Live finding stream buffer
    this.findingStream = [];
    this.evidenceStream = [];

    // NDJSON append stream
    this.ndjsonPath = options.ndjsonPath || null;
    if (this.ndjsonPath) {
      fs.mkdirSync(path.dirname(this.ndjsonPath), { recursive: true });
      this.ndjsonStream = fs.createWriteStream(this.ndjsonPath, { flags: 'a' });
    }

    if (wsServer) {
      this._attachWsServer(wsServer);
    }
  }

  _generateUUID() {
    return crypto.randomUUID ? crypto.randomUUID() :
      'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
      });
  }

  _attachWsServer(wsServer) {
    wsServer.on('connection', (ws) => {
      this.clients.add(ws);

      this._sendToClient(ws, {
        type: 'session_meta',
        sessionId: this.sessionId,
        target: this.target,
        sessionStart: this.sessionStart,
        eventCount: this.eventIndex,
      });

      const replay = this.eventLog.slice(-300);
      if (replay.length > 0) {
        this._sendToClient(ws, { type: 'replay', events: replay });
      }

      // v0.3: Send finding stream to new clients
      if (this.findingStream.length > 0) {
        this._sendToClient(ws, {
          type: 'finding_replay',
          findings: this.findingStream.slice(-100),
        });
      }

      ws.on('close', () => this.clients.delete(ws));
      ws.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw);
          if (msg.action === 'pause') this.paused = true;
          if (msg.action === 'resume') this.paused = false;
          if (msg.action === 'export') this._handleExportRequest(ws);
        } catch (_) {}
      });
    });
  }

  emit(event) {
    if (!EVENT_TYPES.has(event.type)) return;

    const normalized = this._normalize(event);
    this.eventIndex++;

    this.eventLog.push(normalized);
    if (this.eventLog.length > this.maxLogSize) this.eventLog.shift();

    if (this.ndjsonStream) {
      this.ndjsonStream.write(JSON.stringify(normalized) + '\n');
    }

    // Update metrics
    this._updateMetrics(normalized);

    super.emit('event', normalized);
    super.emit(normalized.type, normalized);

    if (!this.paused) this._broadcast(normalized);
  }

  /**
   * v0.3: Emit a finding to the live stream
   */
  emitFinding(finding) {
    const findingEvent = {
      type: 'finding_new',
      ts: Date.now(),
      elapsed: Date.now() - this.sessionStart,
      payload: {
        id: finding.id,
        title: finding.title,
        category: finding.category,
        severity: finding.severity,
        confidence: finding.confidence,
        risk_score: finding.risk_score,
        affected_cookies: finding.affected_cookies,
        affected_endpoints: finding.affected_endpoints,
        description: finding.description,
      },
      source: 'risk_engine',
    };

    this.findingStream.push(findingEvent.payload);
    this.metrics.finding_count++;
    this.metrics.findings_by_severity[finding.severity] =
      (this.metrics.findings_by_severity[finding.severity] || 0) + 1;

    if (!this.paused) this._broadcast(findingEvent);
    super.emit('finding', finding);
  }

  /**
   * v0.3: Emit evidence to the live stream
   */
  emitEvidence(evidencePackage) {
    const evidenceEvent = {
      type: 'evidence_new',
      ts: Date.now(),
      elapsed: Date.now() - this.sessionStart,
      payload: {
        finding_id: evidencePackage.finding_id,
        category: evidencePackage.category,
        evidence_chain_count: evidencePackage.evidence_chain?.length || 0,
        timeline_count: evidencePackage.timeline?.length || 0,
        reproduction_steps: evidencePackage.reproduction?.length || 0,
      },
      source: 'evidence_engine',
    };

    this.evidenceStream.push(evidencePackage);
    this.metrics.evidence_count++;

    if (!this.paused) this._broadcast(evidenceEvent);
    super.emit('evidence', evidencePackage);
  }

  _normalize(raw) {
    return Object.freeze({
      id: this.eventIndex,
      ts: raw.ts || Date.now(),
      elapsed: Date.now() - this.sessionStart,
      type: raw.type,
      url: raw.url || null,
      method: raw.method || null,
      status: raw.status || null,
      headers: raw.headers || null,
      payload: raw.payload || null,
      source: raw.source || 'playwright',
      meta: raw.meta || {},
    });
  }

  _updateMetrics(event) {
    switch (event.type) {
      case 'network_request':
        this.metrics.request_count++;
        break;
      case 'network_response':
        if (event.status) {
          this.metrics.status_codes[event.status] = (this.metrics.status_codes[event.status] || 0) + 1;
        }
        break;
      case 'console_error':
      case 'network_failure':
        this.metrics.error_count++;
        break;
      case 'websocket_message_in':
      case 'websocket_message_out':
        this.metrics.ws_message_count++;
        break;
      case 'auth_signal':
        this.metrics.auth_events++;
        break;
      // v0.6: Discovery metrics
      case 'coverage_delta':
        this.metrics.coverage_deltas++;
        break;
      case 'hypothesis_new':
        this.metrics.hypothesis_count++;
        this.metrics.hypotheses_by_status.pending =
          (this.metrics.hypotheses_by_status.pending || 0) + 1;
        break;
      case 'hypothesis_verdict':
        if (event.payload?.verdict && this.metrics.hypotheses_by_status[event.payload.verdict] !== undefined) {
          this.metrics.hypotheses_by_status[event.payload.verdict]++;
          this.metrics.hypotheses_by_status.pending = Math.max(0, (this.metrics.hypotheses_by_status.pending || 0) - 1);
        }
        break;
      case 'verification_result':
        this.metrics.verification_results++;
        break;
      case 'correlation_found':
        this.metrics.correlation_count++;
        break;
      case 'planner_phase':
        this.metrics.planner_iterations++;
        break;
      // v0.7: Discovery Operating System metrics
      case 'campaign_started':
      case 'campaign_completed':
      case 'campaign_iteration':
        this.metrics.campaign_events++;
        break;
      case 'learning_outcome':
        this.metrics.learning_outcomes++;
        break;
      case 'learning_reweight':
        this.metrics.learning_reweights++;
        break;
      case 'optimizer_rebalance':
        this.metrics.optimizer_rebalances++;
        break;
      case 'pattern_detected':
        this.metrics.patterns_detected++;
        break;
      case 'regression_detected':
        this.metrics.regressions_detected++;
        break;
      case 'evidence_scored':
        this.metrics.evidence_scores++;
        break;
      case 'disclosure_certified':
        this.metrics.disclosure_certificates++;
        break;
      case 'report_generated':
        this.metrics.reports_generated++;
        break;
      // v1.2: Decision Evolution Layer metrics
      case 'economic_scored':
        this.metrics.economic_scores++;
        break;
      case 'opportunity_compared':
        this.metrics.opportunity_comparisons++;
        break;
      case 'policy_decided':
        this.metrics.policy_decisions++;
        break;
      case 'portfolio_simulated':
        this.metrics.portfolio_simulations++;
        break;
      case 'decision_run_started':
      case 'decision_run_completed':
        this.metrics.decision_runs++;
        break;
      case 'allocation_optimized':
        this.metrics.allocation_optimizations++;
        break;
      // v1.3: Decision Intelligence Hardening metrics
      case 'uncertainty_gated':
        this.metrics.uncertainty_gates++;
        break;
      case 'counterfactual_validated':
        this.metrics.counterfactual_validations++;
        break;
      case 'stability_filtered':
        this.metrics.stability_filters++;
        break;
      case 'reality_aligned':
        this.metrics.reality_alignments++;
        break;
      case 'decision_locked':
        this.metrics.decision_locks++;
        break;
      // v1.4: Autonomous Decision Kernel metrics
      case 'autonomy_checked':
        this.metrics.autonomy_checks = (this.metrics.autonomy_checks || 0) + 1;
        break;
      case 'autonomy_pipeline_completed':
        this.metrics.autonomy_pipelines = (this.metrics.autonomy_pipelines || 0) + 1;
        break;
      case 'firewall_violation':
        this.metrics.firewall_violations = (this.metrics.firewall_violations || 0) + 1;
        break;
      case 'budget_exceeded':
        this.metrics.budget_exceeded = (this.metrics.budget_exceeded || 0) + 1;
        break;
    }
  }

  _broadcast(event) {
    const msg = JSON.stringify(event);
    for (const ws of this.clients) {
      if (ws.readyState === 1) ws.send(msg);
    }
  }

  _sendToClient(ws, data) {
    if (ws.readyState === 1) ws.send(JSON.stringify(data));
  }

  _handleExportRequest(ws) {
    this._sendToClient(ws, { type: 'export', data: this.exportSession() });
  }

  getStats() {
    const byType = {};
    for (const evt of this.eventLog) {
      byType[evt.type] = (byType[evt.type] || 0) + 1;
    }
    return {
      sessionId: this.sessionId,
      target: this.target,
      sessionStart: this.sessionStart,
      duration: Date.now() - this.sessionStart,
      totalEvents: this.eventIndex,
      inMemory: this.eventLog.length,
      byType,
      clients: this.clients.size,
      paused: this.paused,
      metrics: this.metrics,
    };
  }

  exportSession() {
    this.sessionEnd = this.sessionEnd || Date.now();
    return {
      id: this.sessionId,
      target: this.target,
      sessionStart: this.sessionStart,
      sessionEnd: this.sessionEnd,
      totalEvents: this.eventIndex,
      events: this.eventLog,
      metrics: this.metrics,
    };
  }

  async flush() {
    if (this.ndjsonStream) {
      return new Promise((resolve) => this.ndjsonStream.end(resolve));
    }
  }

  clear() {
    this.eventLog = [];
    this.eventIndex = 0;
    this.sessionStart = Date.now();
    this.sessionEnd = null;
    this.findingStream = [];
    this.evidenceStream = [];
    this.metrics = {
      request_count: 0, error_count: 0, ws_message_count: 0, auth_events: 0,
      status_codes: {}, finding_count: 0,
      findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      evidence_count: 0,
      coverage_deltas: 0, hypothesis_count: 0,
      hypotheses_by_status: { pending: 0, confirmed: 0, rejected: 0, validating: 0, deferred: 0 },
      verification_results: 0, correlation_count: 0, planner_iterations: 0,
      campaign_events: 0, learning_outcomes: 0, learning_reweights: 0,
      optimizer_rebalances: 0, patterns_detected: 0, regressions_detected: 0,
      evidence_scores: 0, disclosure_certificates: 0, reports_generated: 0,
      economic_scores: 0, opportunity_comparisons: 0, policy_decisions: 0,
      portfolio_simulations: 0, decision_runs: 0, allocation_optimizations: 0,
      uncertainty_gates: 0, counterfactual_validations: 0, stability_filters: 0,
      reality_alignments: 0, decision_locks: 0,
    };
  }
}

/**
 * SessionManager — manages multiple isolated sessions
 */
class SessionManager {
  constructor() {
    this.sessions = new Map(); // sessionId → EventBus
  }

  create(wsServer, options = {}) {
    const bus = new EventBus(wsServer, options);
    this.sessions.set(bus.sessionId, bus);
    return bus;
  }

  get(sessionId) {
    return this.sessions.get(sessionId);
  }

  list() {
    return [...this.sessions.values()].map(bus => ({
      id: bus.sessionId,
      target: bus.target,
      start: bus.sessionStart,
      events: bus.eventIndex,
      metrics: bus.metrics,
    }));
  }

  async close(sessionId) {
    const bus = this.sessions.get(sessionId);
    if (bus) {
      bus.sessionEnd = Date.now();
      await bus.flush();
      this.sessions.delete(sessionId);
    }
  }

  async closeAll() {
    for (const id of this.sessions.keys()) {
      await this.close(id);
    }
  }
}

module.exports = { EventBus, SessionManager, EVENT_TYPES };

