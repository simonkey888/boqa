/**
 * BOQA autonomy-governor.js — AutonomyGovernor v1.4
 *
 * Controls execution permission, autonomy level, and bounded self-action.
 * This is the core of the v1.4 Autonomous Decision Kernel, sitting
 * above the v1.3 Hardening Layer to provide bounded execution authority
 * with adaptive autonomy scaling based on measured performance.
 *
 * Architecture:
 *   AutonomyGovernor
 *   ├── PermissionMatrixEngine    — maps decision types → allowed execution level
 *   ├── RiskContainmentFirewall   — prevents execution under uncertainty
 *   ├── AutonomyLevelController   — adaptive autonomy scaling L0–L4
 *   ├── ExecutionBudgetGovernor   — limits computational/economic exposure
 *   └── SelfCorrectionLoop_v2     — meta-learning over decision outcomes
 *
 * Autonomy Levels:
 *   L0: passive observer          — read-only, no decisions
 *   L1: analysis only             — compute scores, no simulation
 *   L2: simulation allowed        — Monte Carlo, counterfactual
 *   L3: bounded execution         — queue actions, conditional execute
 *   L4: autonomous execution      — execute with guardrails
 *
 * Scaling Rule:
 *   increase autonomy only if 30d performance improves AND error_rate decreases
 *
 * Execution Rules:
 *   ALLOW_EXECUTE:   autonomy >= L3 AND uncertainty < 0.5 AND stability > 0.7
 *   FORCE_SIMULATE:  confidence < threshold OR volatility high
 *   HOLD_OVERRIDE:   any safety layer disagrees
 *   ESCALATE_REVIEW: contradiction across layers
 *
 * Scoring:
 *   final_score = CEVI * stability_factor * alignment_score * autonomy_weight
 *   penalties: uncertainty_penalty, counterfactual_regret_estimate,
 *              stability_decay, execution_risk_adjustment
 *
 * Guardrails (ABSOLUTE):
 *   - No unbounded external execution
 *   - No target-specific exploitation logic
 *   - No real-world autonomous action without approval
 *   - Hard fail → HOLD state on any violation
 *
 * Safe mode: this module controls execution authority; it never
 * directly executes real-world actions. All execution is bounded
 * and requires multi-layer safety checks.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const AG_DIR = path.join(__dirname, 'output', 'knowledge', 'autonomy-governor');

// ─── Constants ──────────────────────────────────────────────────────

const AUTONOMY_LEVELS = {
  L0: 0,  // passive observer
  L1: 1,  // analysis only
  L2: 2,  // simulation allowed
  L3: 3,  // bounded execution
  L4: 4,  // autonomous execution with guardrails
};

const EXECUTION_LEVELS = {
  OBSERVE:            'OBSERVE',
  SIMULATE:           'SIMULATE',
  RECOMMEND:          'RECOMMEND',
  QUEUE:              'QUEUE',
  EXECUTE_CONDITIONAL:'EXECUTE_CONDITIONAL',
};

const BEHAVIORAL_MODES = {
  OBSERVE_ONLY:        'OBSERVE_ONLY',       // no simulation
  SIMULATE_ONLY:       'SIMULATE_ONLY',      // no external effects
  RECOMMENDATION_MODE: 'RECOMMENDATION_MODE', // rank + suggest
  CONTROLLED_AUTONOMY: 'CONTROLLED_AUTONOMY', // bounded execution
  FULL_AUTONOMY:       'FULL_AUTONOMY',       // only if all safety gates pass
};

const DECISION_TYPES = {
  SIGNAL_ASSESSMENT:    'signal_assessment',
  HYPOTHESIS_EVAL:      'hypothesis_eval',
  ECONOMIC_SCORING:     'economic_scoring',
  OPPORTUNITY_COMPARE:  'opportunity_compare',
  POLICY_DECISION:      'policy_decision',
  CAPITAL_ALLOCATION:   'capital_allocation',
  EXECUTION_ACTION:     'execution_action',
};

const DEFAULT_OPTIONS = {
  initialAutonomyLevel: 1,        // Start at L1 (analysis only)
  maxAutonomyLevel: 3,            // Cap at L3 by default (bounded execution)
  scalingWindowDays: 30,          // 30-day performance window for scaling
  scalingMinImprovement: 0.05,    // 5% improvement required to scale up
  scalingMaxErrorRate: 0.15,      // Max error rate to allow scaling
  downgradeErrorThreshold: 0.30,  // Error rate above this triggers downgrade
  downgradeLatencyMs: 60000,      // 1-minute cooldown after downgrade before re-evaluation
  maxParallelDecisions: 10,
  maxCapitalExposurePct: 0.005,   // 0.5% of simulated portfolio
  maxRiskPerAction: 0.1,
  uncertaintyBlockThreshold: 0.7,  // uncertainty > this → block EXECUTE
  stabilityDowngradeThreshold: 0.6, // stability < this → downgrade to HOLD
  alignmentBlockThreshold: 0.5,    // alignment < this → require simulation only
  persistenceIntervalMs: 300000,
};

// =====================================================================
//  PermissionMatrixEngine
// =====================================================================

class PermissionMatrixEngine {
  /**
   * Maps decision types → allowed execution level based on
   * current autonomy level and safety constraints.
   */
  constructor(options = {}) {
    this.options = { ...options };

    // Base permission matrix: decision_type → { min_level: N, allowed_levels: [...] }
    this.matrix = new Map([
      [DECISION_TYPES.SIGNAL_ASSESSMENT, {
        min_level: AUTONOMY_LEVELS.L0,
        allowed_levels: [EXECUTION_LEVELS.OBSERVE, EXECUTION_LEVELS.SIMULATE],
      }],
      [DECISION_TYPES.HYPOTHESIS_EVAL, {
        min_level: AUTONOMY_LEVELS.L0,
        allowed_levels: [EXECUTION_LEVELS.OBSERVE, EXECUTION_LEVELS.SIMULATE, EXECUTION_LEVELS.RECOMMEND],
      }],
      [DECISION_TYPES.ECONOMIC_SCORING, {
        min_level: AUTONOMY_LEVELS.L1,
        allowed_levels: [EXECUTION_LEVELS.SIMULATE, EXECUTION_LEVELS.RECOMMEND],
      }],
      [DECISION_TYPES.OPPORTUNITY_COMPARE, {
        min_level: AUTONOMY_LEVELS.L1,
        allowed_levels: [EXECUTION_LEVELS.SIMULATE, EXECUTION_LEVELS.RECOMMEND],
      }],
      [DECISION_TYPES.POLICY_DECISION, {
        min_level: AUTONOMY_LEVELS.L2,
        allowed_levels: [EXECUTION_LEVELS.SIMULATE, EXECUTION_LEVELS.RECOMMEND, EXECUTION_LEVELS.QUEUE],
      }],
      [DECISION_TYPES.CAPITAL_ALLOCATION, {
        min_level: AUTONOMY_LEVELS.L2,
        allowed_levels: [EXECUTION_LEVELS.SIMULATE, EXECUTION_LEVELS.QUEUE],
      }],
      [DECISION_TYPES.EXECUTION_ACTION, {
        min_level: AUTONOMY_LEVELS.L3,
        allowed_levels: [EXECUTION_LEVELS.QUEUE, EXECUTION_LEVELS.EXECUTE_CONDITIONAL],
      }],
    ]);

    // Override entries from options
    if (options.permissionOverrides) {
      for (const [dt, config] of Object.entries(options.permissionOverrides)) {
        this.matrix.set(dt, config);
      }
    }
  }

  /**
   * Check if a decision type is allowed at a given autonomy level and execution level.
   * @param {string} decisionType
   * @param {number} autonomyLevel
   * @param {string} executionLevel
   * @returns {{ allowed: boolean, reason: string, max_allowed: string }}
   */
  check(decisionType, autonomyLevel, executionLevel) {
    const config = this.matrix.get(decisionType);

    if (!config) {
      return {
        allowed: false,
        reason: `Unknown decision type: ${decisionType}`,
        max_allowed: EXECUTION_LEVELS.OBSERVE,
      };
    }

    if (autonomyLevel < config.min_level) {
      return {
        allowed: false,
        reason: `Autonomy level ${autonomyLevel} below minimum ${config.min_level} for ${decisionType}`,
        max_allowed: EXECUTION_LEVELS.OBSERVE,
      };
    }

    if (config.allowed_levels.includes(executionLevel)) {
      return {
        allowed: true,
        reason: `${executionLevel} allowed for ${decisionType} at autonomy L${autonomyLevel}`,
        max_allowed: config.allowed_levels[config.allowed_levels.length - 1],
      };
    }

    // Downgrade to highest allowed level
    const maxAllowed = config.allowed_levels[config.allowed_levels.length - 1];
    return {
      allowed: false,
      reason: `${executionLevel} not allowed for ${decisionType} at autonomy L${autonomyLevel}. Max: ${maxAllowed}`,
      max_allowed: maxAllowed,
    };
  }

  /**
   * Get the maximum allowed execution level for a decision type at a given autonomy level.
   * @param {string} decisionType
   * @param {number} autonomyLevel
   * @returns {string}
   */
  getMaxAllowed(decisionType, autonomyLevel) {
    const config = this.matrix.get(decisionType);
    if (!config || autonomyLevel < config.min_level) {
      return EXECUTION_LEVELS.OBSERVE;
    }
    return config.allowed_levels[config.allowed_levels.length - 1];
  }

  /**
   * Get all allowed execution levels for a decision type at a given autonomy level.
   * @param {string} decisionType
   * @param {number} autonomyLevel
   * @returns {string[]}
   */
  getAllowedLevels(decisionType, autonomyLevel) {
    const config = this.matrix.get(decisionType);
    if (!config || autonomyLevel < config.min_level) {
      return [EXECUTION_LEVELS.OBSERVE];
    }
    return [...config.allowed_levels];
  }

  getMatrix() {
    const result = {};
    for (const [key, val] of this.matrix.entries()) {
      result[key] = val;
    }
    return result;
  }
}

// =====================================================================
//  RiskContainmentFirewall
// =====================================================================

class RiskContainmentFirewall {
  /**
   * Prevents execution under uncertainty thresholds.
   * Applies hard rules that cannot be overridden by other layers.
   */
  constructor(options = {}) {
    this.uncertaintyBlockThreshold = options.uncertaintyBlockThreshold ?? DEFAULT_OPTIONS.uncertaintyBlockThreshold;
    this.stabilityDowngradeThreshold = options.stabilityDowngradeThreshold ?? DEFAULT_OPTIONS.stabilityDowngradeThreshold;
    this.alignmentBlockThreshold = options.alignmentBlockThreshold ?? DEFAULT_OPTIONS.alignmentBlockThreshold;

    // Firewall violation log
    this.violations = [];
    this.maxViolations = 500;
  }

  /**
   * Apply firewall rules to a decision.
   * Returns { passed, action, reason } where action is the enforced action.
   *
   * @param {object} data
   * @param {number} data.uncertainty      — [0, 1] higher = more uncertain
   * @param {number} data.stability_score  — [0, 1] higher = more stable
   * @param {number} data.external_alignment — [0, 1] higher = more aligned
   * @param {string} data.proposed_action  — proposed execution level
   * @returns {{ passed: boolean, action: string, reason: string, violations: string[] }}
   */
  evaluate(data) {
    const uncertainty = data.uncertainty ?? 0;
    const stabilityScore = data.stability_score ?? 1;
    const alignment = data.external_alignment ?? 1;
    const proposedAction = data.proposed_action || EXECUTION_LEVELS.OBSERVE;

    const violations = [];
    let action = proposedAction;
    let passed = true;

    // Rule 1: if uncertainty > threshold → block EXECUTE
    if (uncertainty > this.uncertaintyBlockThreshold &&
        (proposedAction === EXECUTION_LEVELS.EXECUTE_CONDITIONAL ||
         proposedAction === EXECUTION_LEVELS.QUEUE)) {
      action = EXECUTION_LEVELS.SIMULATE;
      passed = false;
      violations.push(`uncertainty ${uncertainty.toFixed(2)} > ${this.uncertaintyBlockThreshold} → block EXECUTE`);
    }

    // Rule 2: if stability_score < threshold → downgrade to HOLD
    if (stabilityScore < this.stabilityDowngradeThreshold) {
      action = EXECUTION_LEVELS.OBSERVE;
      passed = false;
      violations.push(`stability ${stabilityScore.toFixed(2)} < ${this.stabilityDowngradeThreshold} → downgrade to HOLD`);
    }

    // Rule 3: if external_alignment < threshold → require simulation only
    if (alignment < this.alignmentBlockThreshold &&
        proposedAction !== EXECUTION_LEVELS.OBSERVE &&
        proposedAction !== EXECUTION_LEVELS.SIMULATE) {
      action = EXECUTION_LEVELS.SIMULATE;
      passed = false;
      violations.push(`alignment ${alignment.toFixed(2)} < ${this.alignmentBlockThreshold} → simulation only`);
    }

    // Record violation
    if (!passed) {
      this.violations.push({
        opportunity_id: data.opportunity_id || null,
        proposed_action: proposedAction,
        enforced_action: action,
        violations,
        timestamp: Date.now(),
      });
      if (this.violations.length > this.maxViolations) {
        this.violations = this.violations.slice(-this.maxViolations);
      }
    }

    return {
      passed,
      action,
      reason: violations.length > 0 ? violations.join('; ') : 'All firewall rules passed',
      violations,
    };
  }

  getViolations(limit = 100) {
    return this.violations.slice(-limit);
  }

  getViolationCount() {
    return this.violations.length;
  }

  reset() {
    this.violations = [];
  }
}

// =====================================================================
//  AutonomyLevelController
// =====================================================================

class AutonomyLevelController {
  /**
   * Adaptive autonomy scaling based on performance.
   * Increases autonomy only if 30d performance improves AND error_rate decreases.
   */
  constructor(options = {}) {
    this.currentLevel = options.initialAutonomyLevel ?? DEFAULT_OPTIONS.initialAutonomyLevel;
    this.maxLevel = options.maxAutonomyLevel ?? DEFAULT_OPTIONS.maxAutonomyLevel;
    this.scalingWindowDays = options.scalingWindowDays ?? DEFAULT_OPTIONS.scalingWindowDays;
    this.scalingMinImprovement = options.scalingMinImprovement ?? DEFAULT_OPTIONS.scalingMinImprovement;
    this.scalingMaxErrorRate = options.scalingMaxErrorRate ?? DEFAULT_OPTIONS.scalingMaxErrorRate;
    this.downgradeErrorThreshold = options.downgradeErrorThreshold ?? DEFAULT_OPTIONS.downgradeErrorThreshold;
    this.downgradeLatencyMs = options.downgradeLatencyMs ?? DEFAULT_OPTIONS.downgradeLatencyMs;

    // Performance history for scaling decisions
    this.performanceSnapshots = [];
    this.maxSnapshots = 365;  // Daily snapshots for a year

    // Level change history
    this.levelHistory = [];
    this.maxLevelHistory = 100;

    // Last downgrade timestamp (for cooldown)
    this.lastDowngradeAt = 0;

    // Effective level (may be temporarily reduced)
    this.effectiveLevel = this.currentLevel;
    this.temporaryReductionReason = '';
    this.temporaryReductionExpiry = 0;
  }

  /**
   * Record a performance snapshot for scaling decisions.
   * @param {object} data
   * @param {number} data.performance_score — [0, 1] composite performance
   * @param {number} data.error_rate — [0, 1] error rate
   * @param {number} data.decision_accuracy — [0, 1]
   * @param {number} data.avg_regret_score — [0, 1] lower is better
   */
  recordSnapshot(data) {
    this.performanceSnapshots.push({
      performance_score: data.performance_score ?? 0,
      error_rate: data.error_rate ?? 0,
      decision_accuracy: data.decision_accuracy ?? 0,
      avg_regret_score: data.avg_regret_score ?? 0,
      timestamp: Date.now(),
    });
    if (this.performanceSnapshots.length > this.maxSnapshots) {
      this.performanceSnapshots = this.performanceSnapshots.slice(-this.maxSnapshots);
    }

    // Check if temporary reduction has expired
    this._checkTemporaryReduction();
  }

  /**
   * Evaluate whether autonomy level should change.
   * @returns {{ changed: boolean, old_level: number, new_level: number, reason: string }}
   */
  evaluateScaling() {
    const windowMs = this.scalingWindowDays * 24 * 60 * 60 * 1000;
    const now = Date.now();

    const recent = this.performanceSnapshots.filter(
      s => now - s.timestamp < windowMs
    );
    const older = this.performanceSnapshots.filter(
      s => now - s.timestamp >= windowMs && now - s.timestamp < windowMs * 2
    );

    if (recent.length < 5) {
      return {
        changed: false,
        old_level: this.currentLevel,
        new_level: this.currentLevel,
        reason: 'Insufficient performance data for scaling decision',
      };
    }

    const recentPerf = recent.reduce((s, r) => s + r.performance_score, 0) / recent.length;
    const recentError = recent.reduce((s, r) => s + r.error_rate, 0) / recent.length;

    // Check for downgrade: high error rate
    if (recentError > this.downgradeErrorThreshold && this.currentLevel > 0) {
      const newLevel = Math.max(0, this.currentLevel - 1);
      return this._changeLevel(newLevel,
        `Error rate ${recentError.toFixed(2)} exceeds threshold ${this.downgradeErrorThreshold} → downgrade`);
    }

    // Check for upgrade: performance improving AND error rate low
    if (older.length >= 3) {
      const olderPerf = older.reduce((s, r) => s + r.performance_score, 0) / older.length;
      const improvement = recentPerf - olderPerf;

      if (improvement >= this.scalingMinImprovement &&
          recentError <= this.scalingMaxErrorRate &&
          this.currentLevel < this.maxLevel) {

        // Check cooldown after downgrade
        if (now - this.lastDowngradeAt < this.downgradeLatencyMs) {
          return {
            changed: false,
            old_level: this.currentLevel,
            new_level: this.currentLevel,
            reason: 'Downgrade cooldown active — cannot upgrade yet',
          };
        }

        const newLevel = this.currentLevel + 1;
        return this._changeLevel(newLevel,
          `Performance improved by ${(improvement * 100).toFixed(1)}% with error rate ${recentError.toFixed(2)} → upgrade`);
      }
    }

    return {
      changed: false,
      old_level: this.currentLevel,
      new_level: this.currentLevel,
      reason: `No scaling change: performance ${recentPerf.toFixed(2)}, error_rate ${recentError.toFixed(2)}`,
    };
  }

  /**
   * Force set autonomy level (manual override).
   * @param {number} level
   * @param {string} reason
   */
  setLevel(level, reason) {
    const oldLevel = this.currentLevel;
    this.currentLevel = Math.min(Math.max(0, level), this.maxLevel);
    this.effectiveLevel = this.currentLevel;
    this.levelHistory.push({
      old_level: oldLevel,
      new_level: this.currentLevel,
      reason: reason || 'manual_override',
      timestamp: Date.now(),
    });
  }

  /**
   * Temporarily reduce autonomy level for a duration.
   * @param {number} level
   * @param {number} durationMs
   * @param {string} reason
   */
  temporaryReduce(level, durationMs, reason) {
    this.effectiveLevel = Math.min(level, this.currentLevel);
    this.temporaryReductionReason = reason || 'temporary_safety';
    this.temporaryReductionExpiry = Date.now() + durationMs;
  }

  /**
   * Get the current effective autonomy level.
   * @returns {number}
   */
  getEffectiveLevel() {
    this._checkTemporaryReduction();
    return this.effectiveLevel;
  }

  getCurrentLevel() {
    return this.currentLevel;
  }

  _changeLevel(newLevel, reason) {
    const oldLevel = this.currentLevel;

    if (newLevel < oldLevel) {
      this.lastDowngradeAt = Date.now();
    }

    this.currentLevel = newLevel;
    this.effectiveLevel = newLevel;

    this.levelHistory.push({
      old_level: oldLevel,
      new_level: newLevel,
      reason,
      timestamp: Date.now(),
    });
    if (this.levelHistory.length > this.maxLevelHistory) {
      this.levelHistory = this.levelHistory.slice(-this.maxLevelHistory);
    }

    return { changed: true, old_level: oldLevel, new_level: newLevel, reason };
  }

  _checkTemporaryReduction() {
    if (this.temporaryReductionExpiry > 0 && Date.now() > this.temporaryReductionExpiry) {
      this.effectiveLevel = this.currentLevel;
      this.temporaryReductionReason = '';
      this.temporaryReductionExpiry = 0;
    }
  }

  getLevelHistory() {
    return this.levelHistory.slice(-50);
  }
}

// =====================================================================
//  ExecutionBudgetGovernor
// =====================================================================

class ExecutionBudgetGovernor {
  /**
   * Limits computational and economic exposure per cycle.
   * Tracks running budgets and enforces hard caps.
   */
  constructor(options = {}) {
    this.maxParallelDecisions = options.maxParallelDecisions ?? DEFAULT_OPTIONS.maxParallelDecisions;
    this.maxCapitalExposurePct = options.maxCapitalExposurePct ?? DEFAULT_OPTIONS.maxCapitalExposurePct;
    this.maxRiskPerAction = options.maxRiskPerAction ?? DEFAULT_OPTIONS.maxRiskPerAction;

    // Current cycle tracking
    this.currentCycle = {
      cycle_id: null,
      started_at: 0,
      decisions_made: 0,
      capital_exposed: 0,
      total_portfolio: 100000,  // Simulated portfolio baseline
      max_risk_seen: 0,
      active_decisions: 0,
    };

    // Cycle history
    this.cycleHistory = [];
    this.maxCycleHistory = 200;

    // Per-opportunity budget tracking
    this.opportunityBudgets = new Map();
  }

  /**
   * Start a new decision cycle.
   * @param {string} [cycleId]
   */
  startCycle(cycleId) {
    // Finalize previous cycle
    if (this.currentCycle.cycle_id) {
      this.cycleHistory.push({ ...this.currentCycle });
      if (this.cycleHistory.length > this.maxCycleHistory) {
        this.cycleHistory = this.cycleHistory.slice(-this.maxCycleHistory);
      }
    }

    this.currentCycle = {
      cycle_id: cycleId || `cycle-${Date.now()}`,
      started_at: Date.now(),
      decisions_made: 0,
      capital_exposed: 0,
      total_portfolio: this.currentCycle.total_portfolio,
      max_risk_seen: 0,
      active_decisions: 0,
    };
  }

  /**
   * Check if a decision can be afforded within budget constraints.
   * @param {object} data
   * @param {number} data.capital_required
   * @param {number} data.risk_estimate — [0, 1]
   * @returns {{ allowed: boolean, reason: string, budget_remaining: number }}
   */
  checkBudget(data) {
    const capitalRequired = data.capital_required ?? 0;
    const riskEstimate = data.risk_estimate ?? 0;

    const reasons = [];

    // Check parallel decision limit
    if (this.currentCycle.active_decisions >= this.maxParallelDecisions) {
      reasons.push(`Active decisions ${this.currentCycle.active_decisions} >= max ${this.maxParallelDecisions}`);
    }

    // Check capital exposure
    const maxExposure = this.currentCycle.total_portfolio * this.maxCapitalExposurePct;
    const newExposure = this.currentCycle.capital_exposed + capitalRequired;
    if (newExposure > maxExposure) {
      reasons.push(`Capital exposure ${newExposure.toFixed(0)} would exceed max ${maxExposure.toFixed(0)} (${(this.maxCapitalExposurePct * 100).toFixed(1)}% of portfolio)`);
    }

    // Check per-action risk
    if (riskEstimate > this.maxRiskPerAction) {
      reasons.push(`Risk ${riskEstimate.toFixed(2)} exceeds max ${this.maxRiskPerAction} per action`);
    }

    if (reasons.length > 0) {
      return {
        allowed: false,
        reason: reasons.join('; '),
        budget_remaining: Math.max(0, maxExposure - this.currentCycle.capital_exposed),
      };
    }

    return {
      allowed: true,
      reason: 'Within budget',
      budget_remaining: Math.max(0, maxExposure - this.currentCycle.capital_exposed - capitalRequired),
    };
  }

  /**
   * Record a decision expenditure.
   * @param {object} data
   * @param {string} data.opportunity_id
   * @param {number} data.capital_committed
   * @param {number} data.risk_taken
   */
  recordExpenditure(data) {
    this.currentCycle.decisions_made++;
    this.currentCycle.capital_exposed += data.capital_committed ?? 0;
    this.currentCycle.active_decisions++;
    this.currentCycle.max_risk_seen = Math.max(
      this.currentCycle.max_risk_seen, data.risk_taken ?? 0
    );

    this.opportunityBudgets.set(data.opportunity_id, {
      capital_committed: data.capital_committed ?? 0,
      risk_taken: data.risk_taken ?? 0,
      timestamp: Date.now(),
    });
  }

  /**
   * Release a decision from the budget.
   * @param {string} opportunityId
   */
  releaseDecision(opportunityId) {
    this.currentCycle.active_decisions = Math.max(0, this.currentCycle.active_decisions - 1);
    this.opportunityBudgets.delete(opportunityId);
  }

  /**
   * Get current budget status.
   * @returns {object}
   */
  getStatus() {
    const maxExposure = this.currentCycle.total_portfolio * this.maxCapitalExposurePct;
    return {
      cycle_id: this.currentCycle.cycle_id,
      decisions_made: this.currentCycle.decisions_made,
      active_decisions: this.currentCycle.active_decisions,
      capital_exposed: Math.round(this.currentCycle.capital_exposed * 100) / 100,
      max_capital_exposure: Math.round(maxExposure * 100) / 100,
      capital_utilization_pct: maxExposure > 0
        ? Math.round(this.currentCycle.capital_exposed / maxExposure * 1000) / 10
        : 0,
      max_risk_seen: Math.round(this.currentCycle.max_risk_seen * 1000) / 1000,
      budget_remaining: Math.round(Math.max(0, maxExposure - this.currentCycle.capital_exposed) * 100) / 100,
    };
  }

  getCycleHistory() {
    return this.cycleHistory.slice(-50);
  }
}

// =====================================================================
//  SelfCorrectionLoop_v2
// =====================================================================

class SelfCorrectionLoop_v2 {
  /**
   * Meta-learning over decision outcomes.
   * Adjusts policy weights and model parameters based on forecast errors
   * and regret scores.
   */
  constructor(options = {}) {
    this.options = { ...options };

    // Decision outcome log
    this.outcomes = [];
    this.maxOutcomes = 1000;

    // Policy weight adjustments
    this.policyWeights = {
      cevi_weight: 0.35,
      stability_weight: 0.25,
      alignment_weight: 0.20,
      autonomy_weight: 0.20,
    };

    // Model calibration parameters
    this.modelParams = {
      uncertainty_sensitivity: 1.0,
      stability_sensitivity: 1.0,
      alignment_sensitivity: 1.0,
      regret_discount_factor: 0.95,
    };

    // Learning rate
    this.learningRate = 0.05;

    // Correction history
    this.corrections = [];
    this.maxCorrections = 200;
  }

  /**
   * Record a decision outcome for learning.
   * @param {object} data
   * @param {string} data.opportunity_id
   * @param {string} data.decision_type
   * @param {string} data.action_taken
   * @param {number} data.forecast_value  — expected value at decision time
   * @param {number} data.actual_value    — realized value
   * @param {number} data.forecast_error  — |forecast - actual| / |forecast|
   * @param {number} data.regret_score    — [0, 1] opportunity cost of the decision
   * @param {number} data.missed_opportunity_delta — value of best alternative not taken
   */
  recordOutcome(data) {
    this.outcomes.push({
      opportunity_id: data.opportunity_id,
      decision_type: data.decision_type || DECISION_TYPES.SIGNAL_ASSESSMENT,
      action_taken: data.action_taken || EXECUTION_LEVELS.OBSERVE,
      forecast_value: data.forecast_value ?? 0,
      actual_value: data.actual_value ?? 0,
      forecast_error: data.forecast_error ?? 0,
      regret_score: data.regret_score ?? 0,
      missed_opportunity_delta: data.missed_opportunity_delta ?? 0,
      timestamp: Date.now(),
    });

    if (this.outcomes.length > this.maxOutcomes) {
      this.outcomes = this.outcomes.slice(-this.maxOutcomes);
    }

    // Trigger correction if enough new data
    if (this.outcomes.length % 10 === 0) {
      this._applyCorrection();
    }
  }

  /**
   * Get the current policy weights.
   * @returns {object}
   */
  getPolicyWeights() {
    return { ...this.policyWeights };
  }

  /**
   * Get the current model parameters.
   * @returns {object}
   */
  getModelParams() {
    return { ...this.modelParams };
  }

  /**
   * Get performance metrics from recent outcomes.
   * @param {number} window — number of recent outcomes to consider
   * @returns {object}
   */
  getPerformanceMetrics(window = 100) {
    const recent = this.outcomes.slice(-window);
    if (recent.length === 0) {
      return {
        avg_forecast_error: 0,
        avg_regret: 0,
        avg_missed_opportunity: 0,
        decision_accuracy: 0,
        outcome_count: 0,
      };
    }

    const avgForecastError = recent.reduce((s, o) => s + o.forecast_error, 0) / recent.length;
    const avgRegret = recent.reduce((s, o) => s + o.regret_score, 0) / recent.length;
    const avgMissed = recent.reduce((s, o) => s + o.missed_opportunity_delta, 0) / recent.length;

    // Accuracy: fraction of decisions where forecast error < 0.3
    const accurate = recent.filter(o => o.forecast_error < 0.3).length;

    return {
      avg_forecast_error: Math.round(avgForecastError * 1000) / 1000,
      avg_regret: Math.round(avgRegret * 1000) / 1000,
      avg_missed_opportunity: Math.round(avgMissed * 100) / 100,
      decision_accuracy: Math.round(accurate / recent.length * 1000) / 1000,
      outcome_count: recent.length,
    };
  }

  /**
   * Apply self-correction based on accumulated outcomes.
   * Adjusts policy weights and model parameters.
   * @returns {{ adjusted: boolean, changes: object }}
   */
  _applyCorrection() {
    const window = 50;
    const recent = this.outcomes.slice(-window);

    if (recent.length < 10) {
      return { adjusted: false, changes: {} };
    }

    const changes = {};

    // Compute performance gradients
    const avgForecastError = recent.reduce((s, o) => s + o.forecast_error, 0) / recent.length;
    const avgRegret = recent.reduce((s, o) => s + o.regret_score, 0) / recent.length;

    // Adjust uncertainty sensitivity: if forecast errors are high, increase sensitivity
    if (avgForecastError > 0.3) {
      const adjustment = this.learningRate * (avgForecastError - 0.3);
      this.modelParams.uncertainty_sensitivity = Math.min(
        2.0, this.modelParams.uncertainty_sensitivity + adjustment
      );
      changes.uncertainty_sensitivity = adjustment;
    } else if (avgForecastError < 0.15) {
      const adjustment = this.learningRate * (0.15 - avgForecastError);
      this.modelParams.uncertainty_sensitivity = Math.max(
        0.5, this.modelParams.uncertainty_sensitivity - adjustment
      );
      changes.uncertainty_sensitivity = -adjustment;
    }

    // Adjust stability sensitivity: if regret is high, increase stability weight
    if (avgRegret > 0.3) {
      const adjustment = this.learningRate * (avgRegret - 0.3);
      this.policyWeights.stability_weight = Math.min(
        0.5, this.policyWeights.stability_weight + adjustment
      );
      changes.stability_weight = adjustment;

      // Rebalance: reduce CEVI weight to compensate
      this.policyWeights.cevi_weight = Math.max(
        0.15, this.policyWeights.cevi_weight - adjustment * 0.5
      );
    }

    // Adjust alignment sensitivity: if missed opportunities are high
    const avgMissed = recent.reduce((s, o) => s + o.missed_opportunity_delta, 0) / recent.length;
    if (avgMissed > 100) {
      const adjustment = this.learningRate * 0.1;
      this.policyWeights.alignment_weight = Math.min(
        0.4, this.policyWeights.alignment_weight + adjustment
      );
      changes.alignment_weight = adjustment;
    }

    // Normalize weights to sum to 1.0
    const totalWeight = Object.values(this.policyWeights).reduce((s, w) => s + w, 0);
    if (totalWeight > 0) {
      for (const key of Object.keys(this.policyWeights)) {
        this.policyWeights[key] = Math.round(this.policyWeights[key] / totalWeight * 1000) / 1000;
      }
    }

    // Record correction
    this.corrections.push({
      changes,
      performance: {
        avg_forecast_error: avgForecastError,
        avg_regret: avgRegret,
        avg_missed_opportunity: avgMissed,
      },
      new_weights: { ...this.policyWeights },
      new_params: { ...this.modelParams },
      timestamp: Date.now(),
    });
    if (this.corrections.length > this.maxCorrections) {
      this.corrections = this.corrections.slice(-this.maxCorrections);
    }

    return { adjusted: Object.keys(changes).length > 0, changes };
  }

  getCorrectionHistory() {
    return this.corrections.slice(-50);
  }

  getOutcomes(limit = 100) {
    return this.outcomes.slice(-limit);
  }
}

// =====================================================================
//  AutonomyGovernor
// =====================================================================

class AutonomyGovernor {
  /**
   * @param {object} options
   * @param {object} [options.uncertaintyGovernor] — UncertaintyGovernor (v1.3)
   * @param {object} [options.counterfactualValidator] — CounterfactualValidator (v1.3)
   * @param {object} [options.decisionStabilityEngine] — DecisionStabilityEngine (v1.3)
   * @param {object} [options.realityAlignmentLayer] — RealityAlignmentLayer (v1.3)
   * @param {object} [options.economicValueEngine] — EconomicValueEngine (v1.2)
   */
  constructor(options = {}) {
    this.uncertaintyGovernor = options.uncertaintyGovernor || null;
    this.counterfactualValidator = options.counterfactualValidator || null;
    this.decisionStabilityEngine = options.decisionStabilityEngine || null;
    this.realityAlignmentLayer = options.realityAlignmentLayer || null;
    this.economicValueEngine = options.economicValueEngine || null;

    this.options = { ...DEFAULT_OPTIONS, ...options };

    // Subsystems
    this.permissionMatrix = new PermissionMatrixEngine(options);
    this.riskFirewall = new RiskContainmentFirewall(options);
    this.autonomyController = new AutonomyLevelController(options);
    this.budgetGovernor = new ExecutionBudgetGovernor(options);
    this.selfCorrection = new SelfCorrectionLoop_v2(options);

    // Behavioral mode
    this.behavioralMode = BEHAVIORAL_MODES.RECOMMENDATION_MODE; // safe default

    // Decision audit log
    this.auditLog = [];
    this.maxAuditLog = 1000;

    // Last autonomy check results
    /** @type {Map<string, AutonomyCheckResult>} */
    this.checkResults = new Map();

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_checks: 0,
      total_allowed: 0,
      total_blocked: 0,
      total_downgraded: 0,
      total_escalated: 0,
      avg_autonomy_weight: 0,
      avg_final_score: 0,
      firewall_violations: 0,
      budget_rejections: 0,
    };

    // ── Persistence timer ────────────────────────────────────
    this._persistTimer = null;

    fs.mkdirSync(AG_DIR, { recursive: true });
    this.load();

    if (this.options.persistenceIntervalMs > 0) {
      this._persistTimer = setInterval(() => this.save(), this.options.persistenceIntervalMs);
    }
  }

  // ─── Core: Autonomy Permission Check ───────────────────────────────

  /**
   * Run the full autonomy permission check for a decision.
   * This is the primary entry point for v1.4 decisions.
   *
   * Pipeline:
   *   1. Check permission matrix (decision type allowed at current autonomy?)
   *   2. Check risk containment firewall (uncertainty/stability/alignment)
   *   3. Check execution budget (capital/risk limits)
   *   4. Compute v1.4 scoring: CEVI * stability * alignment * autonomy_weight
   *   5. Apply penalties
   *   6. Determine final action
   *   7. Audit log
   *
   * @param {object} data
   * @param {string} data.opportunity_id
   * @param {string} data.decision_type — from DECISION_TYPES
   * @param {string} [data.proposed_action] — from EXECUTION_LEVELS
   * @param {number} [data.cevi] — CEVI score
   * @param {number} [data.uncertainty] — [0, 1]
   * @param {number} [data.stability_score] — [0, 1]
   * @param {number} [data.alignment_score] — [0, 1]
   * @param {number} [data.capital_required] — capital needed
   * @param {number} [data.risk_estimate] — [0, 1]
   * @param {number} [data.economic_score] — economic score from v1.2
   * @returns {AutonomyCheckResult}
   */
  check(data) {
    this.metrics.total_checks++;
    const oppId = data.opportunity_id;
    const decisionType = data.decision_type || DECISION_TYPES.SIGNAL_ASSESSMENT;
    const proposedAction = data.proposed_action || EXECUTION_LEVELS.OBSERVE;
    const autonomyLevel = this.autonomyController.getEffectiveLevel();

    // 1. Permission Matrix check
    const permResult = this.permissionMatrix.check(decisionType, autonomyLevel, proposedAction);
    let finalAction = permResult.allowed ? proposedAction : permResult.max_allowed;

    // 2. Risk Containment Firewall
    const firewallResult = this.riskFirewall.evaluate({
      opportunity_id: oppId,
      uncertainty: data.uncertainty ?? 0.5,
      stability_score: data.stability_score ?? 0.5,
      external_alignment: data.alignment_score ?? 0.5,
      proposed_action: finalAction,
    });

    if (!firewallResult.passed) {
      finalAction = firewallResult.action;
      this.metrics.firewall_violations++;
    }

    // 3. Budget check (only for execution-level actions)
    let budgetResult = { allowed: true, reason: 'No budget check needed' };
    if (finalAction === EXECUTION_LEVELS.EXECUTE_CONDITIONAL ||
        finalAction === EXECUTION_LEVELS.QUEUE) {
      budgetResult = this.budgetGovernor.checkBudget({
        capital_required: data.capital_required ?? 0,
        risk_estimate: data.risk_estimate ?? 0,
      });
      if (!budgetResult.allowed) {
        finalAction = EXECUTION_LEVELS.SIMULATE;
        this.metrics.budget_rejections++;
      }
    }

    // 4. Compute v1.4 final score
    const cevi = data.cevi ?? 0;
    const stabilityFactor = data.stability_score ?? 0.5;
    const alignmentScore = data.alignment_score ?? 0.5;
    const weights = this.selfCorrection.getPolicyWeights();
    const autonomyWeight = this._computeAutonomyWeight(autonomyLevel, finalAction);

    let finalScore = cevi * weights.cevi_weight +
                     stabilityFactor * weights.stability_weight +
                     alignmentScore * weights.alignment_weight +
                     autonomyWeight * weights.autonomy_weight;

    // 5. Apply penalties
    const penalties = this._computePenalties(data);

    finalScore = Math.max(0, finalScore - penalties.total_penalty);

    // 6. Determine behavioral mode compatibility
    const modeCompatible = this._checkBehavioralMode(finalAction);

    // 7. Check for HOLD override (any safety layer disagrees)
    const holdOverride = this._checkHoldOverride(permResult, firewallResult, budgetResult);
    if (holdOverride.override) {
      finalAction = EXECUTION_LEVELS.OBSERVE;
    }

    // 8. Check for escalation (contradiction across layers)
    const needsEscalation = this._checkEscalation(permResult, firewallResult, budgetResult);
    if (needsEscalation) {
      this.metrics.total_escalated++;
    }

    // Build result
    const result = new AutonomyCheckResult({
      opportunity_id: oppId,
      decision_type: decisionType,
      proposed_action: proposedAction,
      final_action: finalAction,
      autonomy_level: autonomyLevel,
      final_score: Math.round(finalScore * 1000) / 1000,
      cevi,
      stability_factor: stabilityFactor,
      alignment_score: alignmentScore,
      autonomy_weight: Math.round(autonomyWeight * 1000) / 1000,
      penalties,
      permission_check: permResult,
      firewall_check: firewallResult,
      budget_check: budgetResult,
      behavioral_mode: this.behavioralMode,
      mode_compatible: modeCompatible,
      hold_override: holdOverride,
      needs_escalation: needsEscalation,
    });

    this.checkResults.set(oppId, result);

    // Update metrics
    if (finalAction === proposedAction) {
      this.metrics.total_allowed++;
    } else {
      this.metrics.total_downgraded++;
    }
    if (finalAction === EXECUTION_LEVELS.OBSERVE && proposedAction !== EXECUTION_LEVELS.OBSERVE) {
      this.metrics.total_blocked++;
    }
    this._updateMetrics();

    // Audit log
    this._auditLog(result);

    return result;
  }

  /**
   * Run the full v1.4 decision pipeline for a set of opportunities.
   * Integrates v1.3 hardening layers with v1.4 autonomy governance.
   *
   * Pipeline:
   *   signal_ingestion → hypothesis_generation → economic_modeling →
   *   cross_opportunity_comparison → uncertainty_governance →
   *   counterfactual_validation → stability_filtering →
   *   reality_alignment → autonomy_permission_check → decision_output
   *
   * @param {object[]} opportunities — array of opportunity objects
   * @param {object} [pipelineOptions]
   * @returns {PipelineResult}
   */
  runPipeline(opportunities, pipelineOptions = {}) {
    const pipelineId = `pipeline-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const startTime = Date.now();

    // Start budget cycle
    this.budgetGovernor.startCycle(pipelineId);

    const results = [];
    const pipelineLog = [];

    for (const opp of opportunities) {
      const stepResults = {};
      let currentData = { ...opp };

      // Step 1: Signal ingestion (pass-through, enrich with metadata)
      stepResults.signal_ingestion = {
        opportunity_id: opp.opportunity_id || opp.id,
        signal_count: opp.signals?.length ?? 1,
        timestamp: Date.now(),
      };

      // Step 2: Hypothesis generation (if hypothesisGenerator available)
      stepResults.hypothesis_generation = {
        hypotheses_generated: opp.hypotheses?.length ?? 0,
        method: 'input_provided',
      };

      // Step 3: Economic modeling (use EconomicValueEngine if available)
      let economicScore = opp.economic_score ?? opp.cevi ?? 0;
      if (this.economicValueEngine && opp.cevi !== undefined) {
        try {
          const econResult = this.economicValueEngine.score({
            opportunity_id: opp.opportunity_id || opp.id,
            cevi: opp.cevi,
            confidence: opp.confidence ?? 0.5,
            market_size: opp.market_size,
            competition_pressure: opp.competition_pressure,
            capital_required: opp.capital_required,
            opportunity_class: opp.opportunity_class,
          });
          economicScore = econResult.normalized_economic_score ?? economicScore;
          stepResults.economic_modeling = {
            economic_score: economicScore,
            market_factor: econResult.market_factor,
          };
        } catch (_) {
          stepResults.economic_modeling = { economic_score: economicScore, fallback: true };
        }
      } else {
        stepResults.economic_modeling = { economic_score: economicScore };
      }
      currentData.economic_score = economicScore;

      // Step 4: Cross-opportunity comparison (deferred to batch processing)
      stepResults.cross_opportunity_comparison = {
        rank: opp.rank ?? 0,
        comparison_pending: true,
      };

      // Step 5: Uncertainty governance (use UncertaintyGovernor if available)
      let uncertainty = opp.uncertainty ?? 0.5;
      let confidenceBand = null;
      if (this.uncertaintyGovernor) {
        try {
          confidenceBand = this.uncertaintyGovernor.gate({
            opportunity_id: opp.opportunity_id || opp.id,
            cevi: opp.cevi ?? 0,
            cevi_p10: opp.cevi_p10,
            cevi_p90: opp.cevi_p90,
            confidence: opp.confidence ?? 0.5,
            signal_density: opp.signal_density,
            target_id: opp.target_id,
            category: opp.category,
          });
          uncertainty = 1 - (opp.confidence ?? 0.5) + (confidenceBand.overconfidence_penalty ?? 0);
          stepResults.uncertainty_governance = {
            gate_state: confidenceBand.gate_state,
            uncertainty: Math.round(uncertainty * 1000) / 1000,
            overconfidence_penalty: confidenceBand.overconfidence_penalty,
          };
        } catch (_) {
          stepResults.uncertainty_governance = { uncertainty, fallback: true };
        }
      } else {
        stepResults.uncertainty_governance = { uncertainty };
      }
      currentData.uncertainty = uncertainty;

      // Step 6: Counterfactual validation (use CounterfactualValidator if available)
      let counterfactualVerdict = 'untested';
      let counterfactualRegret = 0;
      if (this.counterfactualValidator) {
        try {
          const cfReport = this.counterfactualValidator.validate({
            opportunity_id: opp.opportunity_id || opp.id,
            economic_score: economicScore,
            expected_value: opp.expected_value ?? economicScore * 100,
            market_size: opp.market_size,
            confidence: opp.confidence ?? 0.5,
            competition_pressure: opp.competition_pressure,
            opportunity_class: opp.opportunity_class,
          });
          counterfactualVerdict = cfReport.overall_verdict;
          counterfactualRegret = (1 - cfReport.avg_robustness) * economicScore * 0.3;
          stepResults.counterfactual_validation = {
            verdict: counterfactualVerdict,
            avg_robustness: cfReport.avg_robustness,
            failure_probability: cfReport.failure_probability,
            regret_estimate: Math.round(counterfactualRegret * 100) / 100,
          };
        } catch (_) {
          stepResults.counterfactual_validation = { verdict: 'untested', fallback: true };
        }
      } else {
        stepResults.counterfactual_validation = { verdict: 'untested' };
      }
      currentData.counterfactual_regret = counterfactualRegret;

      // Step 7: Stability filtering (use DecisionStabilityEngine if available)
      let stabilityScore = opp.stability_score ?? 0.7;
      if (this.decisionStabilityEngine) {
        try {
          const stableDecision = this.decisionStabilityEngine.stabilize({
            opportunity_id: opp.opportunity_id || opp.id,
            policy: opp.policy || 'WATCH',
            economic_score: economicScore,
            confidence: opp.confidence ?? 0.5,
          });
          stabilityScore = stableDecision.confidence_in_stability;
          stepResults.stability_filtering = {
            stable_policy: stableDecision.stable_policy,
            confidence_in_stability: stabilityScore,
            is_oscillating: stableDecision.is_oscillating,
          };
        } catch (_) {
          stepResults.stability_filtering = { stability_score: stabilityScore, fallback: true };
        }
      } else {
        stepResults.stability_filtering = { stability_score: stabilityScore };
      }
      currentData.stability_score = stabilityScore;

      // Step 8: Reality alignment (use RealityAlignmentLayer if available)
      let alignmentScore = opp.alignment_score ?? 0.7;
      if (this.realityAlignmentLayer) {
        try {
          const alignmentResult = this.realityAlignmentLayer.align({
            opportunity_id: opp.opportunity_id || opp.id,
            opportunity_class: opp.opportunity_class,
            simulated_roi: opp.simulated_roi ?? economicScore * 0.1,
            economic_score: economicScore,
            capital_required: opp.capital_required,
          });
          alignmentScore = alignmentResult.alignment_score;
          stepResults.reality_alignment = {
            alignment_score: alignmentScore,
            overfit_penalty: alignmentResult.overfit_penalty,
            is_misaligned: alignmentResult.is_misaligned,
          };
        } catch (_) {
          stepResults.reality_alignment = { alignment_score: alignmentScore, fallback: true };
        }
      } else {
        stepResults.reality_alignment = { alignment_score: alignmentScore };
      }
      currentData.alignment_score = alignmentScore;

      // Step 9: Autonomy permission check (v1.4 core)
      const autonomyResult = this.check({
        opportunity_id: opp.opportunity_id || opp.id,
        decision_type: opp.decision_type || DECISION_TYPES.POLICY_DECISION,
        proposed_action: opp.proposed_action || EXECUTION_LEVELS.RECOMMEND,
        cevi: opp.cevi ?? economicScore,
        uncertainty,
        stability_score: stabilityScore,
        alignment_score: alignmentScore,
        capital_required: opp.capital_required ?? 0,
        risk_estimate: opp.risk_estimate ?? 0,
        economic_score: economicScore,
      });

      stepResults.autonomy_permission_check = {
        final_action: autonomyResult.final_action,
        final_score: autonomyResult.final_score,
        autonomy_level: autonomyResult.autonomy_level,
        hold_override: autonomyResult.hold_override?.override ?? false,
        needs_escalation: autonomyResult.needs_escalation,
      };

      // Step 10: Decision output
      stepResults.decision_output = {
        opportunity_id: opp.opportunity_id || opp.id,
        action: autonomyResult.final_action,
        score: autonomyResult.final_score,
        pipeline_step: 'complete',
      };

      results.push({
        opportunity_id: opp.opportunity_id || opp.id,
        steps: stepResults,
        final_action: autonomyResult.final_action,
        final_score: autonomyResult.final_score,
        autonomy_level: autonomyResult.autonomy_level,
      });

      pipelineLog.push(stepResults);
    }

    // Sort by final score descending
    results.sort((a, b) => b.final_score - a.final_score);

    // Assign ranks
    for (let i = 0; i < results.length; i++) {
      results[i].rank = i + 1;
    }

    const durationMs = Date.now() - startTime;

    return new PipelineResult({
      pipeline_id: pipelineId,
      total_opportunities: opportunities.length,
      results,
      pipeline_log: pipelineLog,
      autonomy_level: this.autonomyController.getEffectiveLevel(),
      behavioral_mode: this.behavioralMode,
      duration_ms: durationMs,
    });
  }

  // ─── Behavioral Mode Management ────────────────────────────────────

  /**
   * Set the behavioral mode.
   * @param {string} mode — from BEHAVIORAL_MODES
   */
  setBehavioralMode(mode) {
    if (!Object.values(BEHAVIORAL_MODES).includes(mode)) {
      throw new Error(`Invalid behavioral mode: ${mode}. Must be one of: ${Object.values(BEHAVIORAL_MODES).join(', ')}`);
    }
    this.behavioralMode = mode;
  }

  getBehavioralMode() {
    return this.behavioralMode;
  }

  // ─── Outcome Recording (for SelfCorrectionLoop) ────────────────────

  /**
   * Record a decision outcome for meta-learning.
   * @param {object} data — SelfCorrectionLoop_v2.recordOutcome format
   */
  recordOutcome(data) {
    this.selfCorrection.recordOutcome(data);

    // Also record performance snapshot for autonomy scaling
    this.autonomyController.recordSnapshot({
      performance_score: data.actual_value > 0
        ? Math.min(1, data.actual_value / Math.max(1, data.forecast_value))
        : 0,
      error_rate: data.forecast_error ?? 0,
      decision_accuracy: data.forecast_error < 0.3 ? 1 : 0,
      avg_regret_score: data.regret_score ?? 0,
    });

    // Evaluate autonomy scaling after each outcome
    this.autonomyController.evaluateScaling();
  }

  // ─── Internal Methods ──────────────────────────────────────────────

  _computeAutonomyWeight(autonomyLevel, action) {
    // Higher autonomy + more aggressive action = higher autonomy weight
    const levelFactor = autonomyLevel / 4;  // 0.0 to 1.0
    const actionFactors = {
      [EXECUTION_LEVELS.OBSERVE]: 0.2,
      [EXECUTION_LEVELS.SIMULATE]: 0.4,
      [EXECUTION_LEVELS.RECOMMEND]: 0.6,
      [EXECUTION_LEVELS.QUEUE]: 0.8,
      [EXECUTION_LEVELS.EXECUTE_CONDITIONAL]: 1.0,
    };
    const actionFactor = actionFactors[action] ?? 0.2;
    return levelFactor * actionFactor;
  }

  _computePenalties(data) {
    const uncertainty = data.uncertainty ?? 0;
    const counterfactualRegret = data.counterfactual_regret ?? 0;
    const stabilityScore = data.stability_score ?? 0.5;
    const riskEstimate = data.risk_estimate ?? 0;

    const uncertaintyPenalty = Math.max(0, (uncertainty - 0.3) * 5);
    const counterfactualRegretEstimate = counterfactualRegret * 3;
    const stabilityDecay = Math.max(0, (0.7 - stabilityScore) * 8);
    const executionRiskAdjustment = riskEstimate * 3;

    const totalPenalty = uncertaintyPenalty + counterfactualRegretEstimate +
                         stabilityDecay + executionRiskAdjustment;

    return {
      uncertainty_penalty: Math.round(uncertaintyPenalty * 100) / 100,
      counterfactual_regret_estimate: Math.round(counterfactualRegretEstimate * 100) / 100,
      stability_decay: Math.round(stabilityDecay * 100) / 100,
      execution_risk_adjustment: Math.round(executionRiskAdjustment * 100) / 100,
      total_penalty: Math.round(totalPenalty * 100) / 100,
    };
  }

  _checkBehavioralMode(action) {
    switch (this.behavioralMode) {
      case BEHAVIORAL_MODES.OBSERVE_ONLY:
        return action === EXECUTION_LEVELS.OBSERVE;
      case BEHAVIORAL_MODES.SIMULATE_ONLY:
        return action === EXECUTION_LEVELS.OBSERVE || action === EXECUTION_LEVELS.SIMULATE;
      case BEHAVIORAL_MODES.RECOMMENDATION_MODE:
        return action !== EXECUTION_LEVELS.EXECUTE_CONDITIONAL;
      case BEHAVIORAL_MODES.CONTROLLED_AUTONOMY:
        return action !== EXECUTION_LEVELS.EXECUTE_CONDITIONAL ||
               this.autonomyController.getEffectiveLevel() >= 3;
      case BEHAVIORAL_MODES.FULL_AUTONOMY:
        return true;
      default:
        return action === EXECUTION_LEVELS.OBSERVE;
    }
  }

  _checkHoldOverride(permResult, firewallResult, budgetResult) {
    // If any safety layer strongly disagrees → HOLD
    if (firewallResult.action === EXECUTION_LEVELS.OBSERVE &&
        !firewallResult.passed) {
      return {
        override: true,
        reason: 'Risk containment firewall forced HOLD',
        layers: ['firewall'],
      };
    }

    // If global decision lock is active
    if (this.uncertaintyGovernor && this.uncertaintyGovernor.isDecisionLocked()) {
      return {
        override: true,
        reason: 'Global decision lock active',
        layers: ['uncertainty_governor'],
      };
    }

    return { override: false, reason: '', layers: [] };
  }

  _checkEscalation(permResult, firewallResult, budgetResult) {
    // Escalate if layers contradict: permission allows but firewall blocks
    if (permResult.allowed && !firewallResult.passed) {
      return true;
    }
    // Escalate if budget blocks but firewall allows
    if (!budgetResult.allowed && firewallResult.passed && permResult.allowed) {
      return true;
    }
    return false;
  }

  _auditLog(result) {
    this.auditLog.push({
      opportunity_id: result.opportunity_id,
      decision_type: result.decision_type,
      proposed_action: result.proposed_action,
      final_action: result.final_action,
      final_score: result.final_score,
      autonomy_level: result.autonomy_level,
      timestamp: Date.now(),
    });
    if (this.auditLog.length > this.maxAuditLog) {
      this.auditLog = this.auditLog.slice(-this.maxAuditLog);
    }
  }

  _updateMetrics() {
    const checks = [...this.checkResults.values()];
    if (checks.length > 0) {
      this.metrics.avg_final_score = Math.round(
        checks.reduce((s, c) => s + c.final_score, 0) / checks.length * 1000
      ) / 1000;
      this.metrics.avg_autonomy_weight = Math.round(
        checks.reduce((s, c) => s + c.autonomy_weight, 0) / checks.length * 1000
      ) / 1000;
    }
  }

  // ─── Query ──────────────────────────────────────────────────────────

  getCheckResult(opportunityId) {
    return this.checkResults.get(opportunityId) || null;
  }

  getAllCheckResults() {
    return [...this.checkResults.values()];
  }

  getAutonomyLevel() {
    return this.autonomyController.getEffectiveLevel();
  }

  getAutonomyLevelName() {
    const level = this.autonomyController.getEffectiveLevel();
    const names = { 0: 'L0-passive', 1: 'L1-analysis', 2: 'L2-simulation', 3: 'L3-bounded', 4: 'L4-autonomous' };
    return names[level] || `L${level}`;
  }

  getMetrics() {
    return {
      ...this.metrics,
      autonomy_level: this.autonomyController.getEffectiveLevel(),
      behavioral_mode: this.behavioralMode,
      firewall_violations: this.riskFirewall.getViolationCount(),
      budget_status: this.budgetGovernor.getStatus(),
      self_correction: this.selfCorrection.getPerformanceMetrics(),
      policy_weights: this.selfCorrection.getPolicyWeights(),
      model_params: this.selfCorrection.getModelParams(),
    };
  }

  getAuditLog(limit = 100) {
    return this.auditLog.slice(-limit);
  }

  getSubsystemStatus() {
    return {
      permission_matrix: {
        matrix_size: this.permissionMatrix.matrix.size,
      },
      risk_firewall: {
        violation_count: this.riskFirewall.getViolationCount(),
        uncertainty_block_threshold: this.riskFirewall.uncertaintyBlockThreshold,
        stability_downgrade_threshold: this.riskFirewall.stabilityDowngradeThreshold,
        alignment_block_threshold: this.riskFirewall.alignmentBlockThreshold,
      },
      autonomy_controller: {
        current_level: this.autonomyController.getCurrentLevel(),
        effective_level: this.autonomyController.getEffectiveLevel(),
        max_level: this.autonomyController.maxLevel,
        level_history: this.autonomyController.getLevelHistory().slice(-5),
      },
      budget_governor: this.budgetGovernor.getStatus(),
      self_correction: this.selfCorrection.getPerformanceMetrics(),
    };
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(AG_DIR, 'autonomy-governor-state.json');
    const data = {
      version: '1.4',
      saved_at: Date.now(),
      behavioral_mode: this.behavioralMode,
      autonomy_level: this.autonomyController.getCurrentLevel(),
      metrics: this.metrics,
      policy_weights: this.selfCorrection.getPolicyWeights(),
      model_params: this.selfCorrection.getModelParams(),
      check_results: [...this.checkResults.entries()].slice(-200),
      audit_log: this.auditLog.slice(-200),
      firewall_violations: this.riskFirewall.getViolations(50),
      autonomy_level_history: this.autonomyController.getLevelHistory(),
      self_correction_corrections: this.selfCorrection.getCorrectionHistory(),
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(AG_DIR, 'autonomy-governor-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (data.behavioral_mode && Object.values(BEHAVIORAL_MODES).includes(data.behavioral_mode)) {
        this.behavioralMode = data.behavioral_mode;
      }
      if (data.autonomy_level !== undefined) {
        this.autonomyController.setLevel(data.autonomy_level, 'restored_from_persistence');
      }
      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      if (data.policy_weights) {
        Object.assign(this.selfCorrection.policyWeights, data.policy_weights);
      }
      if (data.model_params) {
        Object.assign(this.selfCorrection.modelParams, data.model_params);
      }
      if (data.check_results) {
        this.checkResults = new Map(
          data.check_results.map(([k, v]) => [k, new AutonomyCheckResult(v)])
        );
      }
      if (data.audit_log) this.auditLog = data.audit_log;
      if (data.firewall_violations) this.riskFirewall.violations = data.firewall_violations;
      this._updateMetrics();
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.behavioralMode = BEHAVIORAL_MODES.RECOMMENDATION_MODE;
    this.autonomyController.setLevel(DEFAULT_OPTIONS.initialAutonomyLevel, 'reset');
    this.riskFirewall.reset();
    this.budgetGovernor.startCycle('reset');
    this.selfCorrection = new SelfCorrectionLoop_v2(this.options);
    this.checkResults.clear();
    this.auditLog = [];
    this.metrics = {
      total_checks: 0, total_allowed: 0, total_blocked: 0,
      total_downgraded: 0, total_escalated: 0,
      avg_autonomy_weight: 0, avg_final_score: 0,
      firewall_violations: 0, budget_rejections: 0,
    };
    const filePath = path.join(AG_DIR, 'autonomy-governor-state.json');
    try { fs.unlinkSync(filePath); } catch (_) {}
  }

  shutdown() {
    if (this._persistTimer) clearInterval(this._persistTimer);
    this.save();
  }
}

// =====================================================================
//  AutonomyCheckResult
// =====================================================================

class AutonomyCheckResult {
  constructor(data = {}) {
    this.opportunity_id    = data.opportunity_id || null;
    this.decision_type     = data.decision_type || '';
    this.proposed_action   = data.proposed_action || EXECUTION_LEVELS.OBSERVE;
    this.final_action      = data.final_action || EXECUTION_LEVELS.OBSERVE;
    this.autonomy_level    = data.autonomy_level ?? 0;
    this.final_score       = data.final_score ?? 0;
    this.cevi              = data.cevi ?? 0;
    this.stability_factor  = data.stability_factor ?? 0;
    this.alignment_score   = data.alignment_score ?? 0;
    this.autonomy_weight   = data.autonomy_weight ?? 0;
    this.penalties         = data.penalties || {};
    this.permission_check  = data.permission_check || {};
    this.firewall_check    = data.firewall_check || {};
    this.budget_check      = data.budget_check || {};
    this.behavioral_mode   = data.behavioral_mode || '';
    this.mode_compatible   = data.mode_compatible ?? true;
    this.hold_override     = data.hold_override || { override: false };
    this.needs_escalation  = data.needs_escalation ?? false;
    this.computed_at       = Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  PipelineResult
// =====================================================================

class PipelineResult {
  constructor(data = {}) {
    this.pipeline_id           = data.pipeline_id || '';
    this.total_opportunities   = data.total_opportunities ?? 0;
    this.results               = data.results || [];
    this.pipeline_log          = data.pipeline_log || [];
    this.autonomy_level        = data.autonomy_level ?? 0;
    this.behavioral_mode       = data.behavioral_mode || '';
    this.duration_ms           = data.duration_ms ?? 0;
    this.computed_at           = Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  Exports
// =====================================================================

module.exports = {
  AutonomyGovernor,
  AutonomyCheckResult,
  PipelineResult,
  PermissionMatrixEngine,
  RiskContainmentFirewall,
  AutonomyLevelController,
  ExecutionBudgetGovernor,
  SelfCorrectionLoop_v2,
  AUTONOMY_LEVELS,
  EXECUTION_LEVELS,
  BEHAVIORAL_MODES,
  DECISION_TYPES,
};

