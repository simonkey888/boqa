/**
 * BOQA counterfactual-validator.js — CounterfactualValidator v1.3
 *
 * Simulates "what if wrong" scenarios for each decision. Every time the
 * decision engine proposes an action, this module branches into the
 * counterfactual: what happens if the underlying hypothesis is false,
 * if the market estimate is inflated, or if the signal is noise?
 *
 * Core principle: penalize_overconfidence
 *   - For every positive decision, simulate the negative outcome
 *   - Compute failure_probability_surface across scenarios
 *   - Estimate false_positive_rate from counterfactual branches
 *   - Decisions that look good in all branches pass; those that
 *     fail under counterfactual stress get flagged or rejected
 *
 * Counterfactual scenarios:
 *   1. Signal Noise: What if the signal is pure noise? (zero true positive)
 *   2. Market Overestimate: What if market size is 50% of estimate?
 *   3. Competition Underestimate: What if competition is 2x worse?
 *   4. Execution Failure: What if the hypothesis is fundamentally wrong?
 *   5. Timing Error: What if the opportunity window closes earlier?
 *
 * Monte Carlo branching:
 *   For each scenario, run N simulations with the counterfactual
 *   parameters. Compare the expected outcome under truth vs.
 *   counterfactual. If the counterfactual doesn't significantly
 *   worsen the outcome, the decision is robust. If it does, the
 *   decision is fragile and should be downgraded.
 *
 * Safe mode: all counterfactual analysis is simulation-only.
 * No real-world execution is implied by any branch.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const CV_DIR = path.join(__dirname, 'output', 'knowledge', 'counterfactual');

// ─── Constants ──────────────────────────────────────────────────────

const COUNTERFACTUAL_SCENARIOS = {
  SIGNAL_NOISE: {
    id: 'signal_noise',
    label: 'Signal is pure noise',
    market_multiplier: 0.1,        // Market effectively doesn't exist
    confidence_multiplier: 0.2,     // Confidence drops to noise level
    competition_multiplier: 5.0,    // Looks like everyone is competing
  },
  MARKET_OVERESTIMATE: {
    id: 'market_overestimate',
    label: 'Market size is 50% of estimate',
    market_multiplier: 0.5,
    confidence_multiplier: 0.8,
    competition_multiplier: 1.5,
  },
  COMPETITION_UNDERESTIMATE: {
    id: 'competition_underestimate',
    label: 'Competition is 2x worse',
    market_multiplier: 0.9,
    confidence_multiplier: 0.7,
    competition_multiplier: 2.0,
  },
  EXECUTION_FAILURE: {
    id: 'execution_failure',
    label: 'Hypothesis is fundamentally wrong',
    market_multiplier: 0.0,        // No return
    confidence_multiplier: 0.1,
    competition_multiplier: 1.0,
  },
  TIMING_ERROR: {
    id: 'timing_error',
    label: 'Opportunity window closes early',
    market_multiplier: 0.6,
    confidence_multiplier: 0.5,
    competition_multiplier: 1.8,
  },
};

const DEFAULT_OPTIONS = {
  monteCarloBranches: 200,      // Simulations per counterfactual scenario
  fragilityThreshold: 0.4,      // If counterfactual drops outcome by > 60%, decision is fragile
  robustnessThreshold: 0.7,     // If counterfactual preserves > 70% of value, decision is robust
  fpEstimationWindow: 100,      // How many past decisions to use for FP estimation
  persistenceIntervalMs: 300000,
};

// =====================================================================
//  CounterfactualResult
// =====================================================================

class CounterfactualResult {
  constructor(data = {}) {
    this.opportunity_id       = data.opportunity_id || null;
    this.scenario_id          = data.scenario_id || null;
    this.scenario_label       = data.scenario_label || '';

    // Base case outcome
    this.base_expected_value  = data.base_expected_value ?? 0;
    this.base_economic_score  = data.base_economic_score ?? 0;

    // Counterfactual outcome
    this.cf_expected_value    = data.cf_expected_value ?? 0;
    this.cf_economic_score    = data.cf_economic_score ?? 0;

    // Loss metrics
    this.value_loss_pct       = data.value_loss_pct ?? 0;
    this.score_loss_pct       = data.score_loss_pct ?? 0;

    // Robustness
    this.robustness_score     = data.robustness_score ?? 0;   // 1 = fully robust, 0 = total collapse
    this.is_fragile           = data.is_fragile ?? false;

    // Simulation metadata
    this.simulation_rounds    = data.simulation_rounds ?? 0;
    this.computed_at          = Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  ValidationReport
// =====================================================================

class ValidationReport {
  constructor(data = {}) {
    this.opportunity_id           = data.opportunity_id || null;
    this.base_economic_score      = data.base_economic_score ?? 0;
    this.scenarios                = data.scenarios || [];     // CounterfactualResult[]
    this.avg_robustness           = data.avg_robustness ?? 0;
    this.failure_probability      = data.failure_probability ?? 0;
    this.false_positive_estimate  = data.false_positive_estimate ?? 0;
    this.overall_verdict          = data.overall_verdict || 'untested'; // robust/fragile/critical
    this.computed_at              = Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  CounterfactualValidator
// =====================================================================

class CounterfactualValidator {
  /**
   * @param {object} options
   * @param {object} [options.economicValueEngine] - EconomicValueEngine instance
   */
  constructor(options = {}) {
    this.economicValueEngine = options.economicValueEngine || null;
    this.options = { ...DEFAULT_OPTIONS, ...options };

    /** @type {Map<string, ValidationReport>} opportunity_id → latest report */
    this.reports = new Map();

    // Track false positive estimates over time
    this.fpHistory = [];
    this.maxFpHistory = 500;

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_validations: 0,
      total_robust: 0,
      total_fragile: 0,
      total_critical: 0,
      avg_robustness: 0,
      avg_failure_probability: 0,
      estimated_false_positive_rate: 0,
    };

    // ── Persistence timer ────────────────────────────────────
    this._persistTimer = null;

    fs.mkdirSync(CV_DIR, { recursive: true });
    this.load();

    if (this.options.persistenceIntervalMs > 0) {
      this._persistTimer = setInterval(() => this.save(), this.options.persistenceIntervalMs);
    }
  }

  // ─── Validation ────────────────────────────────────────────────────

  /**
   * Validate an opportunity by running all counterfactual scenarios.
   *
   * @param {object} data
   * @param {string} data.opportunity_id
   * @param {number} data.economic_score
   * @param {number} data.expected_value
   * @param {number} data.market_size
   * @param {number} data.confidence
   * @param {number} data.competition_pressure
   * @param {string} [data.opportunity_class]
   * @returns {ValidationReport}
   */
  validate(data) {
    const oppId = data.opportunity_id;
    const baseScore = data.economic_score ?? 0;
    const baseEV = data.expected_value ?? 0;

    const scenarioResults = [];

    for (const [scenarioId, scenario] of Object.entries(COUNTERFACTUAL_SCENARIOS)) {
      const result = this._runCounterfactualScenario(data, scenario);
      scenarioResults.push(result);
    }

    // Compute aggregate metrics
    const avgRobustness = scenarioResults.reduce((s, r) => s + r.robustness_score, 0) / scenarioResults.length;
    const failureProbability = scenarioResults.filter(r => r.is_fragile).length / scenarioResults.length;
    const fpEstimate = this._estimateFalsePositive(scenarioResults);

    // Determine overall verdict
    let overallVerdict = 'robust';
    if (avgRobustness < this.options.fragilityThreshold) {
      overallVerdict = 'critical';
    } else if (avgRobustness < this.options.robustnessThreshold) {
      overallVerdict = 'fragile';
    }

    const report = new ValidationReport({
      opportunity_id: oppId,
      base_economic_score: baseScore,
      scenarios: scenarioResults,
      avg_robustness: Math.round(avgRobustness * 1000) / 1000,
      failure_probability: Math.round(failureProbability * 1000) / 1000,
      false_positive_estimate: Math.round(fpEstimate * 1000) / 1000,
      overall_verdict: overallVerdict,
    });

    this.reports.set(oppId, report);

    // Update metrics
    this.metrics.total_validations++;
    if (overallVerdict === 'robust') this.metrics.total_robust++;
    else if (overallVerdict === 'fragile') this.metrics.total_fragile++;
    else this.metrics.total_critical++;

    this._updateMetrics();
    return report;
  }

  /**
   * Validate a batch of opportunities.
   * @param {object[]} items
   * @returns {ValidationReport[]}
   */
  validateBatch(items) {
    return items.map(item => this.validate(item));
  }

  // ─── Counterfactual Scenario Runner ────────────────────────────────

  _runCounterfactualScenario(baseData, scenario) {
    const baseScore = baseData.economic_score ?? 0;
    const baseEV = baseData.expected_value ?? 0;
    const rounds = this.options.monteCarloBranches;

    // Apply counterfactual multipliers
    const cfMarket = (baseData.market_size ?? 50000) * scenario.market_multiplier;
    const cfConfidence = (baseData.confidence ?? 0.5) * scenario.confidence_multiplier;
    const cfCompetition = (baseData.competition_pressure ?? 0.15) * scenario.competition_multiplier;

    // Monte Carlo: simulate outcomes under counterfactual
    let cfEVSum = 0;
    let cfScoreSum = 0;

    for (let i = 0; i < rounds; i++) {
      // Sample with counterfactual parameters + noise
      const noise = this._randomNormal() * 0.1;
      const cfEV = Math.max(0, cfMarket * cfConfidence * (1 + noise) / 100);
      const cfScore = Math.max(0, baseScore * scenario.confidence_multiplier * (1 + noise * 0.5));

      cfEVSum += cfEV;
      cfScoreSum += cfScore;
    }

    const cfEV = cfEVSum / rounds;
    const cfScore = cfScoreSum / rounds;

    // Compute loss
    const valueLossPct = baseEV > 0 ? Math.max(0, 1 - cfEV / baseEV) : 1;
    const scoreLossPct = baseScore > 0 ? Math.max(0, 1 - cfScore / baseScore) : 1;

    // Robustness: how much value is preserved under counterfactual
    const robustnessScore = 1 - valueLossPct;
    const isFragile = robustnessScore < this.options.robustnessThreshold;

    return new CounterfactualResult({
      opportunity_id: baseData.opportunity_id,
      scenario_id: scenario.id,
      scenario_label: scenario.label,
      base_expected_value: baseEV,
      base_economic_score: baseScore,
      cf_expected_value: Math.round(cfEV * 100) / 100,
      cf_economic_score: Math.round(cfScore * 100) / 100,
      value_loss_pct: Math.round(valueLossPct * 1000) / 1000,
      score_loss_pct: Math.round(scoreLossPct * 1000) / 1000,
      robustness_score: Math.round(robustnessScore * 1000) / 1000,
      is_fragile: isFragile,
      simulation_rounds: rounds,
    });
  }

  // ─── False Positive Estimation ─────────────────────────────────────

  _estimateFalsePositive(scenarioResults) {
    // FP estimate: fraction of scenarios where the decision would be
    // positive under base case but negative under counterfactual
    const fragileScenarios = scenarioResults.filter(r => r.is_fragile);
    const fpEstimate = fragileScenarios.length / Math.max(1, scenarioResults.length);

    // Track over time
    this.fpHistory.push({
      fp_estimate: fpEstimate,
      timestamp: Date.now(),
    });
    if (this.fpHistory.length > this.maxFpHistory) {
      this.fpHistory = this.fpHistory.slice(-this.maxFpHistory);
    }

    return fpEstimate;
  }

  /**
   * Get the estimated false positive rate over recent validations.
   * @returns {number}
   */
  getEstimatedFPRate() {
    if (this.fpHistory.length === 0) return 0;
    const recent = this.fpHistory.slice(-this.options.fpEstimationWindow);
    return recent.reduce((s, h) => s + h.fp_estimate, 0) / recent.length;
  }

  /**
   * Get the failure probability surface across all validated opportunities.
   * @returns {object[]} Array of { opportunity_id, failure_probability, verdict }
   */
  getFailureProbabilitySurface() {
    return [...this.reports.values()].map(r => ({
      opportunity_id: r.opportunity_id,
      failure_probability: r.failure_probability,
      avg_robustness: r.avg_robustness,
      verdict: r.overall_verdict,
    }));
  }

  // ─── Query ──────────────────────────────────────────────────────────

  getReport(opportunityId) {
    return this.reports.get(opportunityId) || null;
  }

  getAllReports() {
    return [...this.reports.values()];
  }

  getMetrics() {
    return { ...this.metrics, estimated_fp_rate: this.getEstimatedFPRate() };
  }

  _updateMetrics() {
    const reports = [...this.reports.values()];
    if (reports.length > 0) {
      this.metrics.avg_robustness = Math.round(
        reports.reduce((s, r) => s + r.avg_robustness, 0) / reports.length * 1000
      ) / 1000;
      this.metrics.avg_failure_probability = Math.round(
        reports.reduce((s, r) => s + r.failure_probability, 0) / reports.length * 1000
      ) / 1000;
    }
    this.metrics.estimated_false_positive_rate = Math.round(this.getEstimatedFPRate() * 1000) / 1000;
  }

  // ─── Utility ────────────────────────────────────────────────────────

  _randomNormal() {
    const u1 = Math.random();
    const u2 = Math.random();
    return Math.sqrt(-2 * Math.log(Math.max(1e-10, u1))) * Math.cos(2 * Math.PI * u2);
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(CV_DIR, 'counterfactual-state.json');
    const data = {
      version: '1.3',
      saved_at: Date.now(),
      reports: [...this.reports.entries()].slice(-200),
      fp_history: this.fpHistory.slice(-200),
      metrics: this.metrics,
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(CV_DIR, 'counterfactual-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (data.reports) {
        this.reports = new Map(data.reports.map(([k, v]) => [k, new ValidationReport(v)]));
      }
      if (data.fp_history) this.fpHistory = data.fp_history;
      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      this._updateMetrics();
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.reports.clear();
    this.fpHistory = [];
    this.metrics = {
      total_validations: 0, total_robust: 0, total_fragile: 0, total_critical: 0,
      avg_robustness: 0, avg_failure_probability: 0, estimated_false_positive_rate: 0,
    };
    const filePath = path.join(CV_DIR, 'counterfactual-state.json');
    try { fs.unlinkSync(filePath); } catch (_) {}
  }

  shutdown() {
    if (this._persistTimer) clearInterval(this._persistTimer);
    this.save();
  }
}

module.exports = {
  CounterfactualValidator,
  CounterfactualResult,
  ValidationReport,
  COUNTERFACTUAL_SCENARIOS,
};

