/**
 * BOQA optimizer-engine.js — OptimizerEngine v0.9
 *
 * Core optimization engine that integrates predictions and feedback
 * to tune strategies and parameters. The OptimizerEngine is the
 * central brain of the v0.9 Optimization Layer, orchestrating:
 *
 *   - Strategy selection: choose exploration vs exploitation balance
 *   - Parameter tuning: adjust weights, thresholds, intervals
 *   - Multi-objective optimization: maximize bugs, minimize cost,
 *     reduce false positives, improve throughput
 *   - Adaptive rebalancing: shift resources as conditions change
 *   - Feedback integration: consume verification outcomes to refine
 *
 * Optimization model:
 *   objective = alpha × bugs_found + beta × severity_score -
 *               gamma × false_positive_cost - delta × time_cost
 *
 * Where:
 *   alpha = 0.40  (bug discovery weight)
 *   beta  = 0.25  (severity quality weight)
 *   gamma = 0.20  (false positive penalty)
 *   delta = 0.15  (time/resource cost weight)
 *
 * The engine continuously:
 *   1. Collects current state from all subsystems
 *   2. Evaluates current strategy performance
 *   3. Generates candidate parameter adjustments
 *   4. Simulates expected impact of each adjustment
 *   5. Applies the best adjustment (or keeps current)
 *   6. Records the outcome for future learning
 *
 * Safe mode: optimization only adjusts internal parameters and
 * priorities; it never bypasses safe mode constraints or
 * authorization boundaries.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const OPTIMIZER_DIR = path.join(__dirname, 'output', 'knowledge', 'optimizer');

// ─── Default Objective Weights ──────────────────────────────────────

const DEFAULT_OBJECTIVE = {
  alpha: 0.40,   // bug discovery weight
  beta: 0.25,    // severity quality weight
  gamma: 0.20,   // false positive penalty
  delta: 0.15,   // time/resource cost weight
};

// ─── Strategy Types ─────────────────────────────────────────────────

const STRATEGIES = {
  EXPLORE_HEAVY:       'explore_heavy',       // 70% explore, 30% exploit
  BALANCED:            'balanced',             // 50% explore, 50% exploit
  EXPLOIT_HEAVY:       'exploit_heavy',        // 30% explore, 70% exploit
  COVERAGE_FOCUSED:    'coverage_focused',     // Maximize coverage growth
  VERIFICATION_FOCUSED:'verification_focused', // Maximize verification throughput
  REGRESSION_WATCH:    'regression_watch',     // Focus on regression detection
};

// ─── Default Strategy Parameters ────────────────────────────────────

const DEFAULT_PARAMS = {
  exploration_ratio: 0.50,
  verification_batch_size: 10,
  hypothesis_threshold: 0.30,
  coverage_target_pct: 85,
  rebalance_interval_ms: 120000,
  prediction_weight: 0.30,
  risk_weight: 0.20,
  learning_rate: 0.10,
  decay_rate: 0.95,
};

// ─── Optimization Thresholds ────────────────────────────────────────

const THRESHOLDS = {
  min_bugs_per_worker: 3.0,
  max_false_positive_rate: 0.10,
  min_scan_time_reduction: 0.20,
  min_resource_utilization: 0.90,
};

// =====================================================================
//  OptimizationSnapshot
// =====================================================================

class OptimizationSnapshot {
  constructor(data = {}) {
    this.id = data.id || `SNAP-${crypto.randomUUID().substring(0, 8)}`;
    this.ts = data.ts || Date.now();

    // Current strategy
    this.strategy = data.strategy || STRATEGIES.BALANCED;
    this.params = data.params || { ...DEFAULT_PARAMS };
    this.objective = data.objective || { ...DEFAULT_OBJECTIVE };

    // Performance metrics at this point
    this.bugs_per_worker = data.bugs_per_worker || 0;
    this.false_positive_rate = data.false_positive_rate || 0;
    this.scan_time_reduction = data.scan_time_reduction || 0;
    this.resource_utilization = data.resource_utilization || 0;

    // Objective score
    this.objective_score = data.objective_score || 0;

    // What changed to reach this state
    this.change_from_previous = data.change_from_previous || null;
    this.change_impact = data.change_impact || null;
  }
}

// =====================================================================
//  ParameterAdjustment
// =====================================================================

class ParameterAdjustment {
  constructor(data = {}) {
    this.id = data.id || `ADJ-${crypto.randomUUID().substring(0, 8)}`;
    this.ts = data.ts || Date.now();
    this.param_name = data.param_name || '';
    this.old_value = data.old_value;
    this.new_value = data.new_value;
    this.reason = data.reason || '';
    this.expected_impact = data.expected_impact || 0;
    this.actual_impact = data.actual_impact || null;
    this.strategy = data.strategy || null;
  }
}

// =====================================================================
//  OptimizerEngine
// =====================================================================

class OptimizerEngine {
  /**
   * @param {object} options
   * @param {object} [options.predictionEngine]     - PredictionEngine instance
   * @param {object} [options.yieldForecaster]      - YieldForecaster instance
   * @param {object} [options.riskForecaster]       - RiskForecaster instance
   * @param {object} [options.campaignForecaster]   - CampaignForecaster instance
   * @param {object} [options.priorityShaper]       - PriorityShaper instance
   * @param {object} [options.learningEngine]       - LearningEngine instance
   * @param {object} [options.resourceOptimizer]    - ResourceOptimizer instance
   * @param {object} [options.efficiencyTracker]    - EfficiencyTracker instance
   * @param {object} [options.budgetOptimizer]      - BudgetOptimizer instance
   * @param {object} [options.knowledgeBase]        - KnowledgeBase instance
   * @param {object} [options.brainRegistry]        - BrainRegistry instance
   * @param {object} [options.config]               - Override default config
   */
  constructor(options = {}) {
    this.predictionEngine = options.predictionEngine || null;
    this.yieldForecaster = options.yieldForecaster || null;
    this.riskForecaster = options.riskForecaster || null;
    this.campaignForecaster = options.campaignForecaster || null;
    this.priorityShaper = options.priorityShaper || null;
    this.learningEngine = options.learningEngine || null;
    this.resourceOptimizer = options.resourceOptimizer || null;
    this.efficiencyTracker = options.efficiencyTracker || null;
    this.budgetOptimizer = options.budgetOptimizer || null;
    this.kb = options.knowledgeBase || null;
    this.brainRegistry = options.brainRegistry || null;

    // ── Current state ────────────────────────────────────────
    this.currentStrategy = STRATEGIES.BALANCED;
    this.currentParams = { ...DEFAULT_PARAMS };
    this.currentObjective = { ...DEFAULT_OBJECTIVE };

    // ── History ──────────────────────────────────────────────
    /** @type {OptimizationSnapshot[]} */
    this.snapshots = [];

    /** @type {ParameterAdjustment[]} */
    this.adjustments = [];

    /** @type {Map<string, number>} strategy → cumulative score */
    this.strategyScores = new Map();
    for (const s of Object.values(STRATEGIES)) {
      this.strategyScores.set(s, 0);
    }

    /** @type {Map<string, number>} strategy → selection count */
    this.strategyCounts = new Map();
    for (const s of Object.values(STRATEGIES)) {
      this.strategyCounts.set(s, 0);
    }

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_optimizations: 0,
      total_adjustments: 0,
      strategy_changes: 0,
      params_changed: 0,
      avg_objective_score: 0,
      best_objective_score: 0,
      current_objective_score: 0,
      objective_improvement: 0,
      optimization_latency_ms: 0,
      last_optimization_at: null,
    };

    // ── Optimization loop ────────────────────────────────────
    this._optimizeTimer = setInterval(() => {
      this.optimize();
    }, this.currentParams.rebalance_interval_ms);

    // Ensure directory exists
    fs.mkdirSync(OPTIMIZER_DIR, { recursive: true });

    // Auto-load
    this.load();
  }

  // ─── Core Optimization Loop ─────────────────────────────────────

  /**
   * Run one optimization cycle:
   *   1. Collect current state snapshot
   *   2. Evaluate objective score
   *   3. Generate candidate adjustments
   *   4. Select and apply best adjustment
   *   5. Record outcome
   *
   * @returns {object} optimization result
   */
  optimize() {
    const startTime = Date.now();

    // Step 1: Collect snapshot
    const snapshot = this._collectSnapshot();

    // Step 2: Compute objective score
    snapshot.objective_score = this._computeObjectiveScore(snapshot);
    this.metrics.current_objective_score = snapshot.objective_score;

    if (snapshot.objective_score > this.metrics.best_objective_score) {
      this.metrics.best_objective_score = snapshot.objective_score;
    }

    // Step 3: Generate candidate adjustments
    const candidates = this._generateCandidates(snapshot);

    // Step 4: Score each candidate by simulated impact
    for (const candidate of candidates) {
      candidate.expected_impact = this._simulateImpact(candidate, snapshot);
    }

    // Step 5: Select best candidate
    candidates.sort((a, b) => b.expected_impact - a.expected_impact);
    const best = candidates[0];

    let applied = null;
    if (best && best.expected_impact > 0.01) {
      // Apply the adjustment
      applied = this._applyAdjustment(best, snapshot);
      this.metrics.params_changed++;
    }

    // Step 6: Consider strategy change
    const strategyResult = this._evaluateStrategyChange(snapshot);
    if (strategyResult.changed) {
      this.currentStrategy = strategyResult.new_strategy;
      this._applyStrategyParams(strategyResult.new_strategy);
      this.metrics.strategy_changes++;
    }

    // Record snapshot
    snapshot.change_from_previous = applied ? applied.param_name : null;
    snapshot.change_impact = applied ? applied.expected_impact : 0;
    this.snapshots.push(snapshot);
    if (this.snapshots.length > 500) {
      this.snapshots = this.snapshots.slice(-500);
    }

    // Update strategy scores
    this.strategyScores.set(
      this.currentStrategy,
      (this.strategyScores.get(this.currentStrategy) || 0) + snapshot.objective_score
    );
    this.strategyCounts.set(
      this.currentStrategy,
      (this.strategyCounts.get(this.currentStrategy) || 0) + 1
    );

    // Update metrics
    this.metrics.total_optimizations++;
    this.metrics.optimization_latency_ms = Date.now() - startTime;
    this.metrics.last_optimization_at = Date.now();

    // Compute average objective
    const recentSnaps = this.snapshots.slice(-20);
    if (recentSnaps.length > 0) {
      this.metrics.avg_objective_score =
        Math.round(recentSnaps.reduce((s, sn) => s + sn.objective_score, 0) / recentSnaps.length * 1000) / 1000;
    }

    // Compute improvement trend
    if (this.snapshots.length >= 10) {
      const older = this.snapshots.slice(-20, -10);
      const newer = this.snapshots.slice(-10);
      const olderAvg = older.reduce((s, sn) => s + sn.objective_score, 0) / older.length;
      const newerAvg = newer.reduce((s, sn) => s + sn.objective_score, 0) / newer.length;
      this.metrics.objective_improvement = Math.round((newerAvg - olderAvg) * 1000) / 1000;
    }

    return {
      snapshot,
      applied_adjustment: applied,
      strategy: strategyResult,
      candidates_evaluated: candidates.length,
      latency_ms: this.metrics.optimization_latency_ms,
    };
  }

  // ─── Snapshot Collection ──────────────────────────────────────────

  _collectSnapshot() {
    const snapshot = new OptimizationSnapshot({
      strategy: this.currentStrategy,
      params: { ...this.currentParams },
      objective: { ...this.currentObjective },
    });

    // Collect efficiency metrics
    if (this.efficiencyTracker) {
      const eff = this.efficiencyTracker.getMetrics();
      snapshot.bugs_per_worker = eff.bugs_per_worker || 0;
      snapshot.false_positive_rate = eff.false_positive_rate || 0;
      snapshot.scan_time_reduction = eff.scan_time_reduction || 0;
      snapshot.resource_utilization = eff.resource_utilization || 0;
    } else {
      // Estimate from available data
      snapshot.bugs_per_worker = this._estimateBugsPerWorker();
      snapshot.false_positive_rate = this._estimateFalsePositiveRate();
      snapshot.scan_time_reduction = this._estimateScanTimeReduction();
      snapshot.resource_utilization = this._estimateResourceUtilization();
    }

    return snapshot;
  }

  _estimateBugsPerWorker() {
    if (!this.kb) return 0;
    const metrics = this.kb.getMetrics();
    const totalWorkers = this.resourceOptimizer
      ? this.resourceOptimizer.config.max_workers
      : 8;
    const confirmedBugs = metrics.confirmed_bugs || 0;
    return totalWorkers > 0 ? Math.round(confirmedBugs / totalWorkers * 100) / 100 : 0;
  }

  _estimateFalsePositiveRate() {
    if (!this.learningEngine) return 0.05; // default assumption
    const metrics = this.learningEngine.getMetrics();
    if (metrics.total_observations === 0) return 0.05;
    return Math.round(metrics.total_rejected / metrics.total_observations * 1000) / 1000;
  }

  _estimateScanTimeReduction() {
    // Estimate based on prediction accuracy and coverage efficiency
    if (!this.predictionEngine) return 0;
    const accuracy = this.predictionEngine.getAccuracy();
    if (accuracy.total_predictions < 5) return 0;
    // Higher prediction accuracy → more time saved by focusing
    return Math.round(accuracy.correct_direction / accuracy.total_predictions * 30) / 100;
  }

  _estimateResourceUtilization() {
    if (!this.resourceOptimizer) return 0.5;
    const dist = this.resourceOptimizer.currentDistribution;
    const total = dist.total_workers || 1;
    const idle = dist.idle || 0;
    return Math.round((1 - idle / total) * 1000) / 1000;
  }

  // ─── Objective Function ───────────────────────────────────────────

  _computeObjectiveScore(snapshot) {
    const { alpha, beta, gamma, delta } = this.currentObjective;

    // Normalize each dimension to 0-1
    const bugScore = Math.min(snapshot.bugs_per_worker / THRESHOLDS.min_bugs_per_worker, 2.0) / 2.0;
    const severityScore = this._computeSeverityQuality();
    const fpPenalty = Math.min(snapshot.false_positive_rate / THRESHOLDS.max_false_positive_rate, 2.0) / 2.0;
    const timeCost = 1 - Math.min(snapshot.scan_time_reduction / THRESHOLDS.min_scan_time_reduction, 2.0) / 2.0;

    const score = alpha * bugScore + beta * severityScore - gamma * fpPenalty - delta * timeCost;

    return Math.round(Math.max(0, Math.min(1, score)) * 1000) / 1000;
  }

  _computeSeverityQuality() {
    if (!this.kb) return 0.5;

    let findings = this.kb.findings || [];
    // KnowledgeBase stores findings as a Map — convert to array
    if (findings instanceof Map) findings = [...findings.values()];
    if (!Array.isArray(findings) || findings.length === 0) return 0.5;

    const severityMap = { critical: 1.0, high: 0.8, medium: 0.5, low: 0.3, info: 0.1 };
    const total = findings.length;
    const avgSeverity = findings.reduce((s, f) => s + (severityMap[f.severity] || 0.5), 0) / total;

    return avgSeverity;
  }

  // ─── Candidate Generation ─────────────────────────────────────────

  _generateCandidates(snapshot) {
    const candidates = [];

    // Candidate: adjust exploration ratio
    if (snapshot.bugs_per_worker < THRESHOLDS.min_bugs_per_worker) {
      // Too few bugs — shift towards exploitation (focus on high-yield targets)
      candidates.push(new ParameterAdjustment({
        param_name: 'exploration_ratio',
        old_value: this.currentParams.exploration_ratio,
        new_value: Math.max(0.20, this.currentParams.exploration_ratio - 0.05),
        reason: 'bugs_per_worker below threshold — reduce exploration, increase exploitation',
      }));
    } else if (snapshot.resource_utilization < THRESHOLDS.min_resource_utilization) {
      // Under-utilized — increase exploration to use idle resources
      candidates.push(new ParameterAdjustment({
        param_name: 'exploration_ratio',
        old_value: this.currentParams.exploration_ratio,
        new_value: Math.min(0.80, this.currentParams.exploration_ratio + 0.05),
        reason: 'resource_utilization below threshold — increase exploration to use idle workers',
      }));
    }

    // Candidate: adjust prediction weight
    if (this.predictionEngine) {
      const accuracy = this.predictionEngine.getAccuracy();
      if (accuracy.total_predictions >= 10) {
        const dirAccuracy = accuracy.correct_direction / accuracy.total_predictions;
        if (dirAccuracy >= 0.70 && this.currentParams.prediction_weight < 0.50) {
          candidates.push(new ParameterAdjustment({
            param_name: 'prediction_weight',
            old_value: this.currentParams.prediction_weight,
            new_value: Math.min(0.50, this.currentParams.prediction_weight + 0.03),
            reason: `prediction accuracy ${Math.round(dirAccuracy * 100)}% — increase prediction weight`,
          }));
        } else if (dirAccuracy < 0.50 && this.currentParams.prediction_weight > 0.15) {
          candidates.push(new ParameterAdjustment({
            param_name: 'prediction_weight',
            old_value: this.currentParams.prediction_weight,
            new_value: Math.max(0.15, this.currentParams.prediction_weight - 0.03),
            reason: `prediction accuracy ${Math.round(dirAccuracy * 100)}% — decrease prediction weight`,
          }));
        }
      }
    }

    // Candidate: adjust hypothesis threshold
    if (snapshot.false_positive_rate > THRESHOLDS.max_false_positive_rate) {
      candidates.push(new ParameterAdjustment({
        param_name: 'hypothesis_threshold',
        old_value: this.currentParams.hypothesis_threshold,
        new_value: Math.min(0.60, this.currentParams.hypothesis_threshold + 0.05),
        reason: 'false_positive_rate above threshold — raise hypothesis threshold',
      }));
    } else if (snapshot.false_positive_rate < 0.03 && snapshot.bugs_per_worker < THRESHOLDS.min_bugs_per_worker) {
      candidates.push(new ParameterAdjustment({
        param_name: 'hypothesis_threshold',
        old_value: this.currentParams.hypothesis_threshold,
        new_value: Math.max(0.10, this.currentParams.hypothesis_threshold - 0.03),
        reason: 'very low FP rate but low yield — lower hypothesis threshold to discover more',
      }));
    }

    // Candidate: adjust verification batch size
    if (snapshot.bugs_per_worker < THRESHOLDS.min_bugs_per_worker) {
      candidates.push(new ParameterAdjustment({
        param_name: 'verification_batch_size',
        old_value: this.currentParams.verification_batch_size,
        new_value: Math.min(25, this.currentParams.verification_batch_size + 3),
        reason: 'low bugs_per_worker — increase verification batch to find more',
      }));
    }

    // Candidate: adjust learning rate
    if (this.metrics.objective_improvement > 0.05) {
      // Improving — can be more conservative
      candidates.push(new ParameterAdjustment({
        param_name: 'learning_rate',
        old_value: this.currentParams.learning_rate,
        new_value: Math.max(0.03, this.currentParams.learning_rate - 0.02),
        reason: 'objective improving — reduce learning rate for stability',
      }));
    } else if (this.metrics.objective_improvement < -0.05) {
      // Declining — be more aggressive
      candidates.push(new ParameterAdjustment({
        param_name: 'learning_rate',
        old_value: this.currentParams.learning_rate,
        new_value: Math.min(0.30, this.currentParams.learning_rate + 0.02),
        reason: 'objective declining — increase learning rate for adaptation',
      }));
    }

    // Candidate: adjust risk weight based on regression risk
    if (this.riskForecaster) {
      const portfolio = this.riskForecaster.portfolioForecast;
      if (portfolio && portfolio.risk_score > 50) {
        candidates.push(new ParameterAdjustment({
          param_name: 'risk_weight',
          old_value: this.currentParams.risk_weight,
          new_value: Math.min(0.40, this.currentParams.risk_weight + 0.03),
          reason: `portfolio risk score ${portfolio.risk_score} — increase risk weight`,
        }));
      }
    }

    // Candidate: adjust rebalance interval
    if (this.metrics.optimization_latency_ms > 200) {
      candidates.push(new ParameterAdjustment({
        param_name: 'rebalance_interval_ms',
        old_value: this.currentParams.rebalance_interval_ms,
        new_value: Math.min(600000, this.currentParams.rebalance_interval_ms + 30000),
        reason: 'optimization latency high — increase rebalance interval',
      }));
    } else if (this.metrics.optimization_latency_ms < 50 && this.currentParams.rebalance_interval_ms > 60000) {
      candidates.push(new ParameterAdjustment({
        param_name: 'rebalance_interval_ms',
        old_value: this.currentParams.rebalance_interval_ms,
        new_value: Math.max(60000, this.currentParams.rebalance_interval_ms - 30000),
        reason: 'optimization latency low — decrease rebalance interval for faster adaptation',
      }));
    }

    return candidates;
  }

  // ─── Impact Simulation ────────────────────────────────────────────

  _simulateImpact(candidate, snapshot) {
    // Simple simulation: estimate how much the objective would improve
    const paramName = candidate.param_name;
    const delta = Math.abs(candidate.new_value - candidate.old_value);

    let impactScore = 0;

    switch (paramName) {
      case 'exploration_ratio':
        // Adjusting exploration can have large impact
        impactScore = delta * 2.0;
        if (snapshot.bugs_per_worker < THRESHOLDS.min_bugs_per_worker && candidate.new_value < candidate.old_value) {
          impactScore *= 1.5; // bonus for moving towards exploitation when low yield
        }
        break;

      case 'prediction_weight':
        impactScore = delta * 1.5;
        break;

      case 'hypothesis_threshold':
        impactScore = delta * 1.2;
        if (snapshot.false_positive_rate > THRESHOLDS.max_false_positive_rate && candidate.new_value > candidate.old_value) {
          impactScore *= 1.8; // bonus for reducing FP
        }
        break;

      case 'verification_batch_size':
        impactScore = delta * 0.5; // moderate impact
        break;

      case 'learning_rate':
        impactScore = delta * 0.8;
        break;

      case 'risk_weight':
        impactScore = delta * 1.0;
        break;

      case 'rebalance_interval_ms':
        impactScore = delta * 0.3; // lower impact
        break;

      default:
        impactScore = delta * 0.5;
    }

    // Diminishing returns: if we've adjusted this param recently, reduce impact
    const recentAdjustments = this.adjustments.slice(-10).filter(
      a => a.param_name === paramName
    );
    if (recentAdjustments.length > 2) {
      impactScore *= 0.5; // reduce for frequent adjustment
    }

    return Math.round(impactScore * 1000) / 1000;
  }

  // ─── Adjustment Application ───────────────────────────────────────

  _applyAdjustment(candidate, snapshot) {
    const adjustment = new ParameterAdjustment({
      ...candidate,
      ts: Date.now(),
      strategy: this.currentStrategy,
    });

    // Apply the parameter change
    this.currentParams[candidate.param_name] = candidate.new_value;

    // Propagate to connected systems
    this._propagateParam(candidate.param_name, candidate.new_value);

    // Record
    this.adjustments.push(adjustment);
    if (this.adjustments.length > 500) {
      this.adjustments = this.adjustments.slice(-500);
    }
    this.metrics.total_adjustments++;

    return adjustment;
  }

  _propagateParam(paramName, value) {
    // Propagate parameter changes to connected subsystems
    switch (paramName) {
      case 'prediction_weight':
        if (this.priorityShaper) {
          this.priorityShaper.currentPredictionWeight = value;
        }
        break;

      case 'exploration_ratio':
        if (this.resourceOptimizer) {
          this.resourceOptimizer.config.exploration_reserve_ratio = value;
        }
        break;

      case 'hypothesis_threshold':
        if (this.priorityShaper && this.priorityShaper.config) {
          this.priorityShaper.config.coverage_gap_weight = value * 0.5;
        }
        break;

      case 'risk_weight':
        if (this.priorityShaper && this.priorityShaper.config) {
          this.priorityShaper.config.risk_weight = value;
        }
        break;
    }
  }

  // ─── Strategy Evaluation ──────────────────────────────────────────

  _evaluateStrategyChange(snapshot) {
    // Evaluate if current strategy is optimal or should change
    const result = {
      changed: false,
      old_strategy: this.currentStrategy,
      new_strategy: this.currentStrategy,
      reason: 'current strategy performing adequately',
    };

    // Compute average score per strategy
    const strategyAvgs = {};
    for (const [strategy, score] of this.strategyScores) {
      const count = this.strategyCounts.get(strategy) || 1;
      strategyAvgs[strategy] = score / count;
    }

    // Find best performing strategy
    let bestStrategy = this.currentStrategy;
    let bestAvg = strategyAvgs[this.currentStrategy] || 0;
    for (const [strategy, avg] of Object.entries(strategyAvgs)) {
      if (avg > bestAvg) {
        bestAvg = avg;
        bestStrategy = strategy;
      }
    }

    // Only change if the best strategy is significantly better
    const currentAvg = strategyAvgs[this.currentStrategy] || 0;
    if (bestStrategy !== this.currentStrategy && bestAvg > currentAvg + 0.05) {
      result.changed = true;
      result.new_strategy = bestStrategy;
      result.reason = `${bestStrategy} avg score ${bestAvg.toFixed(3)} > current ${currentAvg.toFixed(3)}`;
      return result;
    }

    // Rule-based strategy selection for edge cases
    if (snapshot.false_positive_rate > 0.20 && this.currentStrategy !== STRATEGIES.VERIFICATION_FOCUSED) {
      result.changed = true;
      result.new_strategy = STRATEGIES.VERIFICATION_FOCUSED;
      result.reason = 'high false positive rate — switch to verification focus';
      return result;
    }

    if (snapshot.resource_utilization < 0.50 && this.currentStrategy !== STRATEGIES.EXPLORE_HEAVY) {
      result.changed = true;
      result.new_strategy = STRATEGIES.EXPLORE_HEAVY;
      result.reason = 'low resource utilization — switch to exploration heavy';
      return result;
    }

    if (snapshot.bugs_per_worker >= THRESHOLDS.min_bugs_per_worker * 1.5 &&
        this.currentStrategy !== STRATEGIES.EXPLOIT_HEAVY) {
      result.changed = true;
      result.new_strategy = STRATEGIES.EXPLOIT_HEAVY;
      result.reason = 'high yield — switch to exploitation to maximize returns';
      return result;
    }

    if (this.riskForecaster) {
      const portfolio = this.riskForecaster.portfolioForecast;
      if (portfolio && portfolio.risk_score > 70 && this.currentStrategy !== STRATEGIES.REGRESSION_WATCH) {
        result.changed = true;
        result.new_strategy = STRATEGIES.REGRESSION_WATCH;
        result.reason = `portfolio risk ${portfolio.risk_score} — switch to regression watch`;
        return result;
      }
    }

    return result;
  }

  _applyStrategyParams(strategy) {
    // Apply default parameters associated with each strategy
    switch (strategy) {
      case STRATEGIES.EXPLORE_HEAVY:
        this.currentParams.exploration_ratio = 0.70;
        this.currentParams.hypothesis_threshold = 0.20;
        break;
      case STRATEGIES.BALANCED:
        this.currentParams.exploration_ratio = 0.50;
        this.currentParams.hypothesis_threshold = 0.30;
        break;
      case STRATEGIES.EXPLOIT_HEAVY:
        this.currentParams.exploration_ratio = 0.30;
        this.currentParams.hypothesis_threshold = 0.40;
        break;
      case STRATEGIES.COVERAGE_FOCUSED:
        this.currentParams.exploration_ratio = 0.60;
        this.currentParams.coverage_target_pct = 90;
        break;
      case STRATEGIES.VERIFICATION_FOCUSED:
        this.currentParams.exploration_ratio = 0.25;
        this.currentParams.verification_batch_size = 20;
        this.currentParams.hypothesis_threshold = 0.45;
        break;
      case STRATEGIES.REGRESSION_WATCH:
        this.currentParams.exploration_ratio = 0.35;
        this.currentParams.risk_weight = 0.35;
        this.currentParams.rebalance_interval_ms = 60000;
        break;
    }
  }

  // ─── Query Methods ──────────────────────────────────────────────

  getCurrentState() {
    return {
      strategy: this.currentStrategy,
      params: { ...this.currentParams },
      objective: { ...this.currentObjective },
      objective_score: this.metrics.current_objective_score,
      best_objective_score: this.metrics.best_objective_score,
    };
  }

  getStrategyRanking() {
    const ranking = [];
    for (const [strategy, score] of this.strategyScores) {
      const count = this.strategyCounts.get(strategy) || 1;
      ranking.push({
        strategy,
        avg_score: Math.round(score / count * 1000) / 1000,
        selections: count,
        total_score: Math.round(score * 1000) / 1000,
      });
    }
    ranking.sort((a, b) => b.avg_score - a.avg_score);
    return ranking;
  }

  getRecentAdjustments(count = 20) {
    return this.adjustments.slice(-count);
  }

  getMetrics() {
    return {
      ...this.metrics,
      strategy: this.currentStrategy,
      params: { ...this.currentParams },
      objective: { ...this.currentObjective },
      snapshots_count: this.snapshots.length,
      adjustments_count: this.adjustments.length,
      success_criteria: {
        bugs_per_worker: {
          current: this._estimateBugsPerWorker(),
          target: THRESHOLDS.min_bugs_per_worker,
          met: this._estimateBugsPerWorker() >= THRESHOLDS.min_bugs_per_worker,
        },
        false_positive_rate: {
          current: this._estimateFalsePositiveRate(),
          target: THRESHOLDS.max_false_positive_rate,
          met: this._estimateFalsePositiveRate() <= THRESHOLDS.max_false_positive_rate,
        },
        scan_time_reduction: {
          current: this._estimateScanTimeReduction(),
          target: THRESHOLDS.min_scan_time_reduction,
          met: this._estimateScanTimeReduction() >= THRESHOLDS.min_scan_time_reduction,
        },
        resource_utilization: {
          current: this._estimateResourceUtilization(),
          target: THRESHOLDS.min_resource_utilization,
          met: this._estimateResourceUtilization() >= THRESHOLDS.min_resource_utilization,
        },
      },
    };
  }

  // ─── Persistence ────────────────────────────────────────────────

  save() {
    const filePath = path.join(OPTIMIZER_DIR, 'optimizer-state.json');
    const data = {
      version: '0.9',
      saved_at: Date.now(),
      current_strategy: this.currentStrategy,
      current_params: this.currentParams,
      current_objective: this.currentObjective,
      strategy_scores: [...this.strategyScores.entries()],
      strategy_counts: [...this.strategyCounts.entries()],
      metrics: this.metrics,
      snapshots: this.snapshots.slice(-100),
      adjustments: this.adjustments.slice(-100),
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(OPTIMIZER_DIR, 'optimizer-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      this.currentStrategy = data.current_strategy || STRATEGIES.BALANCED;
      this.currentParams = data.current_params || { ...DEFAULT_PARAMS };
      this.currentObjective = data.current_objective || { ...DEFAULT_OBJECTIVE };
      this.strategyScores = new Map(data.strategy_scores || []);
      this.strategyCounts = new Map(data.strategy_counts || []);
      this.metrics = { ...this.metrics, ...(data.metrics || {}) };
      this.snapshots = data.snapshots || [];
      this.adjustments = data.adjustments || [];
      return true;
    } catch (_) {
      return false;
    }
  }

  shutdown() {
    if (this._optimizeTimer) clearInterval(this._optimizeTimer);
    this.save();
  }
}

module.exports = {
  OptimizerEngine,
  OptimizationSnapshot,
  ParameterAdjustment,
  STRATEGIES,
  DEFAULT_PARAMS,
  DEFAULT_OBJECTIVE,
  THRESHOLDS,
  OPTIMIZER_DIR,
};

