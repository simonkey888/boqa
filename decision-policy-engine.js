/**
 * BOQA decision-policy-engine.js — DecisionPolicyEngine v1.2
 *
 * Converts ranked hypotheses and economic scores into action policies.
 * Each opportunity is assigned a policy mode based on its economic
 * profile, risk assessment, and decision constraints.
 *
 * Policy modes:
 *   WATCH   — Monitor for changes; don't allocate resources yet.
 *             Trigger: low confidence, high uncertainty, or waiting
 *             for more data before committing.
 *   BUILD   — Invest resources in building capability for this
 *             opportunity. Trigger: high expected value, moderate
 *             risk, clear execution path.
 *   IGNORE  — Deprioritize; low EV, high competition, or poor fit.
 *             Trigger: below threshold on all key dimensions.
 *   SIMULATE — Run simulation only (default for all v1.2 operations).
 *             Trigger: promising but unvalidated, or safety mode
 *             requires simulation before any action.
 *   DEPLOY  — Execute in real environment. REQUIRES HUMAN APPROVAL.
 *             Trigger: validated simulation, high confidence,
 *             approved by human gate.
 *
 * Policy decision flow:
 *   1. Evaluate economic_score thresholds
 *   2. Apply risk tolerance filters
 *   3. Check confidence requirements
 *   4. Apply human approval gates for DEPLOY
 *   5. Generate policy with rationale and constraints
 *
 * Guardrails:
 *   - DEPLOY mode ALWAYS requires human_approval
 *   - simulation_only mode forces all policies to SIMULATE or WATCH
 *   - No policy can bypass safe mode constraints
 *   - All policy decisions are audit-logged
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const DPE_DIR = path.join(__dirname, 'output', 'knowledge', 'policy');

// ─── Constants ──────────────────────────────────────────────────────

const POLICY_MODES = {
  WATCH:    'WATCH',
  BUILD:    'BUILD',
  IGNORE:   'IGNORE',
  SIMULATE: 'SIMULATE',
  DEPLOY:   'DEPLOY',
  HOLD:     'HOLD',      // v1.3: null decision — insufficient certainty
};

const POLICY_PRIORITIES = {
  HOLD:     0.5,
  WATCH:    1,
  SIMULATE: 2,
  BUILD:    3,
  IGNORE:   0,
  DEPLOY:   4,
};

const DEFAULT_POLICY_RULES = {
  // Score thresholds
  watch_min_score: 20,
  build_min_score: 50,
  simulate_min_score: 35,
  deploy_min_score: 75,

  // Confidence thresholds
  watch_max_confidence: 0.4,
  build_min_confidence: 0.5,
  simulate_max_confidence: 0.7,
  deploy_min_confidence: 0.8,
  hold_max_confidence: 0.6,      // v1.3: below this → HOLD (no action)

  // v1.3: Hardening constraints
  min_confidence_for_any_action: 0.6,  // No action if confidence < 0.6
  require_multi_objective_consensus: true,
  forbid_autonomous_deploy: true,
  forbid_live_execution: true,

  // Risk constraints
  max_risk_for_build: 15,
  max_risk_for_deploy: 8,
  max_var_for_deploy: 1000,

  // Competition constraints
  max_competition_for_build: 'MODERATE',
  max_competition_for_deploy: 'LOW',

  // Human approval
  human_approval_required_for_deploy: true,
  simulation_only_mode: true,  // Default: simulation only
};

const DEFAULT_OPTIONS = {
  maxPolicies: 500,
  policyRules: { ...DEFAULT_POLICY_RULES },
  auditLogMaxSize: 2000,
  persistenceIntervalMs: 300000,
};

// =====================================================================
//  PolicyDecision
// =====================================================================

class PolicyDecision {
  constructor(data = {}) {
    this.id                    = data.id || `POL-${crypto.randomUUID().substring(0, 10)}`;
    this.opportunity_id        = data.opportunity_id || null;
    this.hypothesis_id         = data.hypothesis_id || null;
    this.opportunity_class     = data.opportunity_class || null;
    this.target_id             = data.target_id || null;

    // Decision
    this.policy                = data.policy || POLICY_MODES.SIMULATE;
    this.prev_policy           = data.prev_policy || null;
    this.policy_priority       = POLICY_PRIORITIES[data.policy] ?? 0;

    // Rationale
    this.reasons               = data.reasons || [];
    this.constraints           = data.constraints || [];
    this.conditions_met        = data.conditions_met || [];
    this.conditions_failed     = data.conditions_failed || [];

    // Score context at decision time
    this.economic_score        = data.economic_score ?? 0;
    this.risk_score            = data.risk_score ?? 0;
    this.confidence            = data.confidence ?? 0;
    this.competition_level     = data.competition_level || 'MODERATE';

    // Human approval
    this.human_approval        = data.human_approval ?? false;
    this.approved_by           = data.approved_by || null;
    this.approved_at           = data.approved_at || null;

    // Audit
    this.audit_id              = data.audit_id || crypto.randomUUID().substring(0, 12);
    this.decided_at            = data.decided_at || Date.now();
    this.version               = '1.2';
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  AuditLogEntry
// =====================================================================

class AuditLogEntry {
  constructor(data = {}) {
    this.id          = data.id || crypto.randomUUID().substring(0, 10);
    this.audit_id    = data.audit_id || null;
    this.action      = data.action || '';
    this.opportunity_id = data.opportunity_id || null;
    this.policy      = data.policy || '';
    this.details     = data.details || {};
    this.timestamp   = data.timestamp || Date.now();
  }
}

// =====================================================================
//  DecisionPolicyEngine
// =====================================================================

class DecisionPolicyEngine {
  /**
   * @param {object} options
   * @param {object} [options.economicValueEngine] - EconomicValueEngine instance
   * @param {object} [options.opportunityComparator] - OpportunityComparator instance
   */
  constructor(options = {}) {
    this.economicValueEngine = options.economicValueEngine || null;
    this.opportunityComparator = options.opportunityComparator || null;
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.policyRules = { ...DEFAULT_POLICY_RULES, ...(this.options.policyRules || {}) };

    /** @type {Map<string, PolicyDecision>} opportunity_id → PolicyDecision */
    this.policies = new Map();

    /** @type {AuditLogEntry[]} */
    this.auditLog = [];

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_decisions: 0,
      decisions_by_policy: {
        WATCH: 0, BUILD: 0, IGNORE: 0, SIMULATE: 0, DEPLOY: 0,
      },
      total_human_approvals: 0,
      total_policy_changes: 0,
      avg_economic_score_acted: 0,
      policy_distribution: {},
    };

    // ── Persistence timer ────────────────────────────────────
    this._persistTimer = null;

    fs.mkdirSync(DPE_DIR, { recursive: true });
    this.load();

    if (this.options.persistenceIntervalMs > 0) {
      this._persistTimer = setInterval(() => this.save(), this.options.persistenceIntervalMs);
    }
  }

  // ─── Policy Decision ──────────────────────────────────────────────

  /**
   * Decide the policy for a single opportunity.
   *
   * @param {object} data - Economic score + context
   * @param {string} data.opportunity_id
   * @param {number} data.economic_score
   * @param {number} data.risk_score
   * @param {number} data.confidence
   * @param {string} [data.competition_level]
   * @param {string} [data.opportunity_class]
   * @param {string} [data.target_id]
   * @param {string} [data.hypothesis_id]
   * @param {number} [data.var_95]
   * @returns {PolicyDecision}
   */
  decide(data) {
    const rules = this.policyRules;
    const reasons = [];
    const constraints = [];
    const conditionsMet = [];
    const conditionsFailed = [];

    const score = data.economic_score ?? 0;
    const riskScore = data.risk_score ?? 0;
    const confidence = data.confidence ?? 0.5;
    const competition = data.competition_level || 'MODERATE';
    const var95 = data.var_95 ?? 0;

    // Previous policy (if exists)
    const prevPolicy = this.policies.get(data.opportunity_id)?.policy || null;

    // ── Decision Logic ──────────────────────────────────────

    let policy = POLICY_MODES.IGNORE; // Default

    // v1.3: Hard constraint — no_action_if_confidence < threshold
    if (confidence < (rules.min_confidence_for_any_action ?? 0.6)) {
      policy = POLICY_MODES.HOLD;
      reasons.push(`Confidence ${confidence.toFixed(2)} below minimum action threshold ${(rules.min_confidence_for_any_action ?? 0.6)} — forcing HOLD`);
      conditionsFailed.push('min_confidence_for_any_action');
      constraints.push('v13_hardening_confidence_floor');
    }

    // Check IGNORE conditions
    if (score < rules.watch_min_score) {
      reasons.push(`Score ${score} below watch threshold ${rules.watch_min_score}`);
      conditionsFailed.push('min_watch_score');
    } else {
      conditionsMet.push('min_watch_score');
    }

    // Check SIMULATE conditions
    if (score >= rules.simulate_min_score && confidence <= rules.simulate_max_confidence) {
      policy = POLICY_MODES.SIMULATE;
      reasons.push(`Score ${score} meets simulate threshold, confidence ${confidence} within simulate range`);
      conditionsMet.push('simulate_score_range');
    } else if (score >= rules.simulate_min_score) {
      conditionsMet.push('simulate_score_range');
    } else {
      conditionsFailed.push('simulate_score_range');
    }

    // Check WATCH conditions
    if (score >= rules.watch_min_score && confidence < rules.watch_max_confidence) {
      if (POLICY_PRIORITIES[policy] < POLICY_PRIORITIES[POLICY_MODES.WATCH]) {
        policy = POLICY_MODES.WATCH;
      }
      reasons.push(`Low confidence ${confidence}, better to watch`);
      conditionsMet.push('watch_confidence_range');
    }

    // Check BUILD conditions
    const competitionLevels = ['NONE', 'LOW', 'MODERATE', 'HIGH', 'SATURATED'];
    const maxCompIdx = competitionLevels.indexOf(rules.max_competition_for_build);
    const currentCompIdx = competitionLevels.indexOf(competition);

    if (score >= rules.build_min_score &&
        confidence >= rules.build_min_confidence &&
        riskScore <= rules.max_risk_for_build &&
        currentCompIdx <= maxCompIdx) {
      policy = POLICY_MODES.BUILD;
      reasons.push(`Score ${score}, confidence ${confidence}, risk ${riskScore} meet build criteria`);
      conditionsMet.push('build_criteria');
    } else {
      if (score < rules.build_min_score) conditionsFailed.push('build_min_score');
      if (confidence < rules.build_min_confidence) conditionsFailed.push('build_min_confidence');
      if (riskScore > rules.max_risk_for_build) conditionsFailed.push('build_max_risk');
      if (currentCompIdx > maxCompIdx) conditionsFailed.push('build_max_competition');
    }

    // Check DEPLOY conditions (most restrictive)
    const maxCompDeployIdx = competitionLevels.indexOf(rules.max_competition_for_deploy);

    if (score >= rules.deploy_min_score &&
        confidence >= rules.deploy_min_confidence &&
        riskScore <= rules.max_risk_for_deploy &&
        var95 <= rules.max_var_for_deploy &&
        currentCompIdx <= maxCompDeployIdx) {
      // DEPLOY requires human approval
      if (rules.human_approval_required_for_deploy && !data.human_approval) {
        policy = POLICY_MODES.SIMULATE; // Downgrade to SIMULATE
        reasons.push('Meets DEPLOY criteria but human approval not granted — downgrading to SIMULATE');
        constraints.push('human_approval_required');
        conditionsMet.push('deploy_criteria');
        conditionsFailed.push('human_approval');
      } else {
        policy = POLICY_MODES.DEPLOY;
        reasons.push(`All DEPLOY criteria met, human approval ${data.human_approval ? 'granted' : 'not required'}`);
        conditionsMet.push('deploy_criteria');
        conditionsMet.push('human_approval');
      }
    } else {
      if (score >= rules.deploy_min_score) conditionsMet.push('deploy_min_score');
      else conditionsFailed.push('deploy_min_score');
      if (confidence < rules.deploy_min_confidence) conditionsFailed.push('deploy_min_confidence');
      if (riskScore > rules.max_risk_for_deploy) conditionsFailed.push('deploy_max_risk');
      if (var95 > rules.max_var_for_deploy) conditionsFailed.push('deploy_max_var');
      if (currentCompIdx > maxCompDeployIdx) conditionsFailed.push('deploy_max_competition');
    }

    // Simulation-only mode override
    if (rules.simulation_only_mode && policy === POLICY_MODES.DEPLOY) {
      policy = POLICY_MODES.SIMULATE;
      reasons.push('Simulation-only mode active — DEPLOY downgraded to SIMULATE');
      constraints.push('simulation_only_mode');
    }

    if (rules.simulation_only_mode && policy === POLICY_MODES.BUILD) {
      policy = POLICY_MODES.SIMULATE;
      reasons.push('Simulation-only mode active — BUILD downgraded to SIMULATE');
      constraints.push('simulation_only_mode');
    }

    // v1.3: Forbid AUTONOMOUS_DEPLOY and LIVE_EXECUTION
    if (rules.forbid_autonomous_deploy && policy === POLICY_MODES.DEPLOY && !data.human_approval) {
      policy = POLICY_MODES.SIMULATE;
      reasons.push('v1.3 hardening: AUTONOMOUS_DEPLOY forbidden — downgraded');
      constraints.push('v13_forbid_autonomous_deploy');
    }

    if (rules.forbid_live_execution && policy === POLICY_MODES.DEPLOY) {
      policy = POLICY_MODES.SIMULATE;
      reasons.push('v1.3 hardening: LIVE_EXECUTION forbidden — downgraded');
      constraints.push('v13_forbid_live_execution');
    }

    const decision = new PolicyDecision({
      opportunity_id: data.opportunity_id,
      hypothesis_id: data.hypothesis_id || null,
      opportunity_class: data.opportunity_class || null,
      target_id: data.target_id || null,
      policy,
      prev_policy: prevPolicy,
      reasons,
      constraints,
      conditions_met: conditionsMet,
      conditions_failed: conditionsFailed,
      economic_score: score,
      risk_score: riskScore,
      confidence,
      competition_level: competition,
      human_approval: data.human_approval ?? false,
    });

    // Record
    this.policies.set(data.opportunity_id, decision);
    this.metrics.total_decisions++;
    this.metrics.decisions_by_policy[policy] = (this.metrics.decisions_by_policy[policy] || 0) + 1;

    if (prevPolicy && prevPolicy !== policy) {
      this.metrics.total_policy_changes++;
    }

    // Audit log
    this._auditLog({
      action: 'decide',
      opportunity_id: data.opportunity_id,
      policy,
      details: { score, risk: riskScore, confidence, prev_policy: prevPolicy },
    });

    this._updateMetrics();
    return decision;
  }

  /**
   * Decide policies for a batch of opportunities.
   * @param {object[]} items
   * @returns {PolicyDecision[]}
   */
  decideBatch(items) {
    return items.map(item => this.decide(item));
  }

  /**
   * Decide policies for all scored opportunities.
   * @returns {PolicyDecision[]}
   */
  decideAll() {
    if (!this.economicValueEngine) {
      throw new Error('EconomicValueEngine not connected');
    }

    const decisions = [];
    for (const [id, score] of this.economicValueEngine.scores) {
      decisions.push(this.decide({
        opportunity_id: id,
        economic_score: score.normalized_score,
        risk_score: score.risk_adjusted_penalty,
        confidence: score.confidence,
        competition_level: this._mapCompetitionFromScore(score),
        opportunity_class: score.opportunity_class,
        target_id: score.target_id,
        hypothesis_id: score.hypothesis_id,
        var_95: score.var_95,
      }));
    }

    return decisions.sort((a, b) => b.policy_priority - a.policy_priority);
  }

  _mapCompetitionFromScore(score) {
    const pressure = score.competition_pressure || 0;
    if (pressure <= 0.05) return 'NONE';
    if (pressure <= 0.12) return 'LOW';
    if (pressure <= 0.22) return 'MODERATE';
    if (pressure <= 0.35) return 'HIGH';
    return 'SATURATED';
  }

  // ─── Human Approval Gate ──────────────────────────────────────────

  /**
   * Grant human approval for a DEPLOY policy.
   * @param {string} opportunityId
   * @param {string} [approver] - Identifier of the human approver
   * @returns {PolicyDecision|null}
   */
  grantApproval(opportunityId, approver = 'human_operator') {
    const decision = this.policies.get(opportunityId);
    if (!decision) return null;

    decision.human_approval = true;
    decision.approved_by = approver;
    decision.approved_at = Date.now();
    this.metrics.total_human_approvals++;

    this._auditLog({
      action: 'approval_granted',
      opportunity_id: opportunityId,
      policy: decision.policy,
      details: { approver, previous_policy: decision.policy },
    });

    // Re-evaluate with approval — preserve approval info on new decision
    if (this.economicValueEngine) {
      const score = this.economicValueEngine.getScore(opportunityId);
      if (score) {
        const newDecision = this.decide({
          opportunity_id: opportunityId,
          economic_score: score.normalized_score,
          risk_score: score.risk_adjusted_penalty,
          confidence: score.confidence,
          competition_level: this._mapCompetitionFromScore(score),
          opportunity_class: score.opportunity_class,
          target_id: score.target_id,
          hypothesis_id: score.hypothesis_id,
          var_95: score.var_95,
          human_approval: true,
        });
        // Ensure approval info is preserved on the new decision
        newDecision.approved_by = approver;
        newDecision.approved_at = decision.approved_at;
        return newDecision;
      }
    }

    return decision;
  }

  /**
   * Revoke human approval.
   * @param {string} opportunityId
   * @returns {PolicyDecision|null}
   */
  revokeApproval(opportunityId) {
    const decision = this.policies.get(opportunityId);
    if (!decision) return null;

    decision.human_approval = false;
    decision.approved_by = null;
    decision.approved_at = null;

    if (decision.policy === POLICY_MODES.DEPLOY) {
      decision.policy = POLICY_MODES.SIMULATE;
    }

    this._auditLog({
      action: 'approval_revoked',
      opportunity_id: opportunityId,
      policy: decision.policy,
      details: {},
    });

    return decision;
  }

  // ─── Query ──────────────────────────────────────────────────────────

  /**
   * Get the policy for an opportunity.
   * @param {string} opportunityId
   * @returns {PolicyDecision|null}
   */
  getPolicy(opportunityId) {
    return this.policies.get(opportunityId) || null;
  }

  /**
   * Get all policies, optionally filtered.
   * @param {object} [filter] - { policy, opportunity_class, min_score }
   * @returns {PolicyDecision[]}
   */
  getPolicies(filter = {}) {
    let items = [...this.policies.values()];

    if (filter.policy) {
      items = items.filter(p => p.policy === filter.policy);
    }
    if (filter.opportunity_class) {
      items = items.filter(p => p.opportunity_class === filter.opportunity_class);
    }
    if (filter.min_score !== undefined) {
      items = items.filter(p => p.economic_score >= filter.min_score);
    }

    return items.sort((a, b) => b.policy_priority - a.policy_priority || b.economic_score - a.economic_score);
  }

  /**
   * Get the ranked action portfolio.
   * @returns {object[]}
   */
  getRankedActionPortfolio() {
    const policies = this.getPolicies();
    return policies.map(p => ({
      opportunity_id: p.opportunity_id,
      opportunity_class: p.opportunity_class,
      decision: p.policy,
      economic_score: p.economic_score,
      risk_score: p.risk_score,
      capital_required: this._getCapitalRequired(p.opportunity_id),
      competition_level: p.competition_level,
      time_to_revenue: this._getTimeToRevenue(p.opportunity_id),
      confidence: p.confidence,
      human_approved: p.human_approval,
    }));
  }

  _getCapitalRequired(opportunityId) {
    if (!this.economicValueEngine) return 0;
    const score = this.economicValueEngine.getScore(opportunityId);
    return score ? score.capital_required : 0;
  }

  _getTimeToRevenue(opportunityId) {
    if (!this.economicValueEngine) return 0;
    const opp = this.economicValueEngine.getOpportunity(opportunityId);
    return opp ? opp.time_to_revenue_days : 0;
  }

  getAuditLog(limit = 100) {
    return this.auditLog.slice(-limit);
  }

  getMetrics() {
    return { ...this.metrics };
  }

  // ─── Internal ──────────────────────────────────────────────────────

  _auditLog(entry) {
    this.auditLog.push(new AuditLogEntry({
      ...entry,
      audit_id: this.policies.get(entry.opportunity_id)?.audit_id || crypto.randomUUID().substring(0, 12),
    }));

    if (this.auditLog.length > this.options.auditLogMaxSize) {
      this.auditLog = this.auditLog.slice(-this.options.auditLogMaxSize);
    }
  }

  _updateMetrics() {
    const distribution = {};
    for (const [, decision] of this.policies) {
      distribution[decision.policy] = (distribution[decision.policy] || 0) + 1;
    }
    this.metrics.policy_distribution = distribution;

    // Avg economic score of acted (non-IGNORE) policies
    const acted = [...this.policies.values()].filter(p => p.policy !== POLICY_MODES.IGNORE);
    if (acted.length > 0) {
      this.metrics.avg_economic_score_acted = Math.round(
        acted.reduce((s, p) => s + p.economic_score, 0) / acted.length * 100
      ) / 100;
    }
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(DPE_DIR, 'policy-state.json');
    const data = {
      version: '1.2',
      saved_at: Date.now(),
      policy_rules: this.policyRules,
      policies: [...this.policies.entries()].slice(-this.options.maxPolicies),
      audit_log: this.auditLog.slice(-500),
      metrics: this.metrics,
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(DPE_DIR, 'policy-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (data.policy_rules) this.policyRules = { ...this.policyRules, ...data.policy_rules };
      if (data.policies) {
        this.policies = new Map(
          data.policies.map(([k, v]) => [k, new PolicyDecision(v)])
        );
      }
      if (data.audit_log) {
        this.auditLog = data.audit_log.map(e => new AuditLogEntry(e));
      }
      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      this._updateMetrics();
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.policies.clear();
    this.auditLog = [];
    this.policyRules = { ...DEFAULT_POLICY_RULES };
    this.metrics = {
      total_decisions: 0,
      decisions_by_policy: { WATCH: 0, BUILD: 0, IGNORE: 0, SIMULATE: 0, DEPLOY: 0 },
      total_human_approvals: 0, total_policy_changes: 0,
      avg_economic_score_acted: 0, policy_distribution: {},
    };
    // Clear persisted file to prevent stale state on next load
    const filePath = path.join(DPE_DIR, 'policy-state.json');
    try { fs.unlinkSync(filePath); } catch (_) {}
  }

  shutdown() {
    if (this._persistTimer) clearInterval(this._persistTimer);
    this.save();
  }
}

module.exports = {
  DecisionPolicyEngine,
  PolicyDecision,
  AuditLogEntry,
  POLICY_MODES,
  POLICY_PRIORITIES,
  DEFAULT_POLICY_RULES,
};

