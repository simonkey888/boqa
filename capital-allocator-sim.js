/**
 * BOQA capital-allocator-sim.js — CapitalAllocatorSim v1.2
 *
 * Simulates capital allocation across opportunities under constraints
 * using Monte Carlo simulation, risk decay modeling, and liquidity
 * constraints. Produces an expected portfolio return surface that
 * maps allocation strategies to projected outcomes.
 *
 * Simulation model:
 *   1. Generate N Monte Carlo scenarios (default 1000)
 *   2. For each scenario, sample returns from opportunity distributions
 *   3. Apply risk decay (returns diminish with time and uncertainty)
 *   4. Apply liquidity constraints (can't exit before lock-up period)
 *   5. Compute portfolio-level metrics (EV, VaR, Sharpe, drawdown)
 *   6. Optimize allocation weights using scenario results
 *   7. Output: expected_portfolio_return_surface
 *
 * Constraints:
 *   - Max capital per opportunity (concentration limit)
 *   - Min capital per opportunity (viability threshold)
 *   - Total capital budget
 *   - Liquidity windows (can't reallocate during lock-up)
 *   - Risk budget (max portfolio VaR)
 *
 * Safe mode: all simulations are computational projections. No real
 * capital is committed or transferred. All outputs are decision
 * support estimates for portfolio construction.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const CAS_DIR = path.join(__dirname, 'output', 'knowledge', 'capital-allocator');

// ─── Constants ──────────────────────────────────────────────────────

const SIM_STATUS = {
  IDLE:        'idle',
  RUNNING:     'running',
  COMPLETED:   'completed',
  FAILED:      'failed',
};

const DEFAULT_OPTIONS = {
  monteCarloRounds: 1000,
  maxConcentrationPct: 0.30,    // Max 30% in single opportunity
  minAllocationPct: 0.02,       // Min 2% to be worth including
  totalCapitalBudget: 100000,   // Default total capital
  riskBudgetVaR: 0.15,          // Max 15% portfolio VaR (95%)
  riskDecayRate: 0.03,          // 3% daily risk decay
  liquidityWindowDays: 30,      // Min holding period
  maxSimultaneousOpportunities: 20,
  convergenceThreshold: 0.01,   // Stop if improvement < 1%
  maxOptimizationSteps: 50,
  persistenceIntervalMs: 300000,
};

// =====================================================================
//  AllocationCandidate
// =====================================================================

class AllocationCandidate {
  constructor(data = {}) {
    this.opportunity_id        = data.opportunity_id || null;
    this.opportunity_class     = data.opportunity_class || null;
    this.expected_return       = data.expected_return ?? 0;
    this.volatility            = data.volatility ?? 0.3;
    this.var_95                = data.var_95 ?? 0;
    this.max_drawdown          = data.max_drawdown ?? 0;
    this.capital_required      = data.capital_required ?? 0;
    this.liquidity_days        = data.liquidity_days ?? 30;
    this.correlation_group     = data.correlation_group || 'default';
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  AllocationResult
// =====================================================================

class AllocationResult {
  constructor(data = {}) {
    this.allocations           = data.allocations || {}; // opp_id → weight
    this.expected_portfolio_return = data.expected_portfolio_return ?? 0;
    this.portfolio_var_95      = data.portfolio_var_95 ?? 0;
    this.portfolio_max_drawdown = data.portfolio_max_drawdown ?? 0;
    this.portfolio_sharpe      = data.portfolio_sharpe ?? 0;
    this.capital_utilized      = data.capital_utilized ?? 0;
    this.opportunity_count     = data.opportunity_count ?? 0;
    this.concentration_score   = data.concentration_score ?? 0;  // 0=diverse, 1=concentrated
    this.liquidity_risk        = data.liquidity_risk ?? 0;
    this.simulation_rounds     = data.simulation_rounds ?? 0;
    this.optimization_steps    = data.optimization_steps ?? 0;
    this.computed_at           = Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  ScenarioResult
// =====================================================================

class ScenarioResult {
  constructor(data = {}) {
    this.scenario_id    = data.scenario_id || 0;
    this.returns        = data.returns || {};      // opp_id → return
    this.total_return   = data.total_return ?? 0;
    this.drawdown       = data.drawdown ?? 0;
    this.realized_at    = data.realized_at ?? Date.now();
  }
}

// =====================================================================
//  CapitalAllocatorSim
// =====================================================================

class CapitalAllocatorSim {
  /**
   * @param {object} options
   * @param {object} [options.economicValueEngine] - EconomicValueEngine instance
   */
  constructor(options = {}) {
    this.economicValueEngine = options.economicValueEngine || null;
    this.options = { ...DEFAULT_OPTIONS, ...options };

    /** @type {Map<string, AllocationCandidate>} */
    this.candidates = new Map();

    /** @type {AllocationResult|null} */
    this.lastResult = null;

    /** @type {ScenarioResult[]} */
    this.lastScenarios = [];

    this.simStatus = SIM_STATUS.IDLE;

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_simulations: 0,
      total_scenarios_run: 0,
      avg_portfolio_return: 0,
      avg_portfolio_var: 0,
      avg_sharpe_ratio: 0,
      avg_capital_utilization: 0,
      best_portfolio_return: 0,
      optimization_convergence_rate: 0,
    };

    // ── Persistence timer ────────────────────────────────────
    this._persistTimer = null;

    fs.mkdirSync(CAS_DIR, { recursive: true });
    this.load();

    if (this.options.persistenceIntervalMs > 0) {
      this._persistTimer = setInterval(() => this.save(), this.options.persistenceIntervalMs);
    }
  }

  // ─── Candidate Management ──────────────────────────────────────────

  /**
   * Add an allocation candidate.
   * @param {object} data
   * @returns {AllocationCandidate}
   */
  addCandidate(data) {
    const candidate = data instanceof AllocationCandidate ? data : new AllocationCandidate(data);
    this.candidates.set(candidate.opportunity_id, candidate);
    return candidate;
  }

  /**
   * Load candidates from EconomicValueEngine scores.
   */
  loadFromEngine() {
    if (!this.economicValueEngine) return 0;

    this.candidates.clear();
    for (const [id, score] of this.economicValueEngine.scores) {
      this.addCandidate({
        opportunity_id: id,
        opportunity_class: score.opportunity_class,
        expected_return: score.expected_value / Math.max(1, score.capital_required),
        volatility: score.var_95 / Math.max(1, score.expected_value || 1),
        var_95: score.var_95,
        max_drawdown: score.max_drawdown,
        capital_required: score.capital_required,
        liquidity_days: this._estimateLiquidity(score.opportunity_class),
      });
    }

    return this.candidates.size;
  }

  _estimateLiquidity(opportunityClass) {
    const liquidityMap = {
      ssl_tls_feed: 7,
      government_tender_api: 90,
      competitor_changelog_webhook: 14,
      expiring_domain_feed: 7,
      sec_anomaly_webhook: 14,
      polyedge_prediction_system: 30,
      morpho_liquidation_scanner: 3,
      data_api_marketplace_products: 14,
      security_bug_bounty: 60,
      defi_yield_opportunity: 7,
    };
    return liquidityMap[opportunityClass] || 30;
  }

  // ─── Monte Carlo Simulation ───────────────────────────────────────

  /**
   * Run a Monte Carlo simulation for portfolio returns.
   *
   * @param {object} [allocations] - Optional fixed allocation weights { opp_id: weight }
   * @param {number} [rounds] - Override number of simulation rounds
   * @returns {object} { scenarios, summary }
   */
  simulate(allocations, rounds) {
    const n = rounds || this.options.monteCarloRounds;
    const candidates = [...this.candidates.values()];

    if (candidates.length === 0) {
      return { scenarios: [], summary: new AllocationResult() };
    }

    // If no allocations provided, use equal-weight
    const weights = allocations || this._equalWeightAllocation(candidates);

    const scenarios = [];
    let totalReturn = 0;
    let totalDrawdown = 0;
    let returns = [];

    for (let i = 0; i < n; i++) {
      const scenario = this._simulateOneScenario(candidates, weights, i);
      scenarios.push(scenario);
      totalReturn += scenario.total_return;
      totalDrawdown += scenario.drawdown;
      returns.push(scenario.total_return);
    }

    // Sort returns for percentile calculations
    returns.sort((a, b) => a - b);

    const avgReturn = totalReturn / n;
    const avgDrawdown = totalDrawdown / n;
    const var95Idx = Math.floor(n * 0.05);
    const var95 = returns[var95Idx] || 0;

    // Sharpe ratio (simplified)
    const returnStdDev = this._stdDev(returns);
    const sharpe = returnStdDev > 0
      ? (avgReturn - this.options.riskDecayRate) / returnStdDev
      : 0;

    const summary = new AllocationResult({
      allocations: weights,
      expected_portfolio_return: Math.round(avgReturn * 100) / 100,
      portfolio_var_95: Math.round(var95 * 100) / 100,
      portfolio_max_drawdown: Math.round(avgDrawdown * 1000) / 1000,
      portfolio_sharpe: Math.round(sharpe * 1000) / 1000,
      capital_utilized: Object.values(weights).reduce((s, w) => s + w, 0),
      opportunity_count: Object.keys(weights).length,
      concentration_score: this._computeConcentration(weights),
      liquidity_risk: this._computeLiquidityRisk(candidates, weights),
      simulation_rounds: n,
    });

    this.lastScenarios = scenarios.slice(-200); // Keep last 200 scenarios
    this.metrics.total_simulations++;
    this.metrics.total_scenarios_run += n;
    this._updateMetrics(summary);

    return { scenarios, summary };
  }

  /**
   * Simulate a single scenario.
   */
  _simulateOneScenario(candidates, weights, scenarioId) {
    const returns = {};
    let portfolioReturn = 0;

    for (const candidate of candidates) {
      const weight = weights[candidate.opportunity_id] || 0;
      if (weight === 0) continue;

      // Sample return from normal distribution (simplified Box-Muller)
      const z = this._randomNormal();
      const sampledReturn = candidate.expected_return +
                            z * candidate.volatility;

      // Apply risk decay over liquidity window
      const decayFactor = Math.exp(-this.options.riskDecayRate * candidate.liquidity_days / 30);
      const adjustedReturn = sampledReturn * decayFactor;

      returns[candidate.opportunity_id] = adjustedReturn;
      portfolioReturn += weight * adjustedReturn;
    }

    // Compute drawdown for this scenario
    const worstReturn = Math.min(...Object.values(returns), 0);
    const drawdown = Math.abs(worstReturn);

    return new ScenarioResult({
      scenario_id: scenarioId,
      returns,
      total_return: portfolioReturn,
      drawdown,
    });
  }

  // ─── Portfolio Optimization ───────────────────────────────────────

  /**
   * Optimize portfolio allocation using iterative scenario-based search.
   *
   * @param {number} [maxSteps] - Override max optimization steps
   * @returns {AllocationResult}
   */
  optimize(maxSteps) {
    const steps = maxSteps || this.options.maxOptimizationSteps;
    const candidates = [...this.candidates.values()];

    if (candidates.length === 0) {
      this.lastResult = new AllocationResult();
      return this.lastResult;
    }

    this.simStatus = SIM_STATUS.RUNNING;

    // Start with equal-weight
    let currentWeights = this._equalWeightAllocation(candidates);
    let bestResult = this.simulate(currentWeights, Math.min(500, this.options.monteCarloRounds));
    let bestScore = this._objectiveScore(bestResult.summary);
    let noImprovement = 0;

    for (let step = 0; step < steps; step++) {
      // Perturb weights
      const perturbedWeights = this._perturbWeights(currentWeights, 0.05 * (1 - step / steps));

      // Apply constraints
      const constrainedWeights = this._applyConstraints(perturbedWeights, candidates);

      // Simulate
      const result = this.simulate(constrainedWeights, Math.min(200, this.options.monteCarloRounds));
      const score = this._objectiveScore(result.summary);

      if (score > bestScore) {
        bestScore = score;
        bestResult = result;
        currentWeights = constrainedWeights;
        noImprovement = 0;
      } else {
        noImprovement++;
      }

      // Convergence check
      if (noImprovement >= 5) break;
    }

    // Final simulation with full rounds on best weights
    const finalResult = this.simulate(currentWeights, this.options.monteCarloRounds);
    finalResult.summary.optimization_steps = steps;

    this.lastResult = finalResult.summary;
    this.simStatus = SIM_STATUS.COMPLETED;

    return this.lastResult;
  }

  _objectiveScore(result) {
    // Maximize Sharpe-like score with risk penalty
    return (result.expected_portfolio_return || 0) *
           (1 - (result.portfolio_var_95 || 0) * 0.5) *
           (1 + (result.portfolio_sharpe || 0) * 0.1) -
           (result.concentration_score || 0) * 2 -
           (result.liquidity_risk || 0) * 1;
  }

  _equalWeightAllocation(candidates) {
    const n = candidates.length;
    if (n === 0) return {};

    const weight = 1 / n;
    const weights = {};
    for (const c of candidates) {
      weights[c.opportunity_id] = weight;
    }
    return weights;
  }

  _perturbWeights(weights, magnitude) {
    const perturbed = {};
    const keys = Object.keys(weights);

    for (const key of keys) {
      perturbed[key] = weights[key] + (Math.random() - 0.5) * magnitude;
    }

    // Normalize to sum to 1
    const total = Object.values(perturbed).reduce((s, w) => s + Math.max(0, w), 0);
    if (total > 0) {
      for (const key of keys) {
        perturbed[key] = Math.max(0, perturbed[key]) / total;
      }
    }

    return perturbed;
  }

  _applyConstraints(weights, candidates) {
    const constrained = {};
    const maxWeight = this.options.maxConcentrationPct;
    const minWeight = this.options.minAllocationPct;
    const maxOpps = this.options.maxSimultaneousOpportunities;

    // Enforce max concentration
    for (const [id, w] of Object.entries(weights)) {
      constrained[id] = Math.min(w, maxWeight);
    }

    // Filter out below-minimum allocations
    const significant = Object.entries(constrained)
      .filter(([, w]) => w >= minWeight)
      .sort(([, a], [, b]) => b - a)
      .slice(0, maxOpps);

    // Re-normalize
    const total = significant.reduce((s, [, w]) => s + w, 0);
    const result = {};
    for (const [id, w] of significant) {
      result[id] = Math.round(w / total * 10000) / 10000;
    }

    return result;
  }

  // ─── Return Surface ───────────────────────────────────────────────

  /**
   * Compute the expected portfolio return surface for a range of
   * risk/return trade-offs.
   *
   * @param {number} [points] - Number of points on the surface
   * @returns {object[]} Array of { risk_level, expected_return, allocation_snapshot }
   */
  computeReturnSurface(points = 10) {
    const candidates = [...this.candidates.values()];
    if (candidates.length === 0) return [];

    const surface = [];
    const sortedCandidates = [...candidates].sort((a, b) =>
      b.expected_return - a.expected_return
    );

    for (let i = 0; i < points; i++) {
      const riskLevel = i / (points - 1); // 0 to 1

      // At low risk: favor low-volatility candidates
      // At high risk: favor high-return candidates
      const weights = this._riskAdjustedWeights(sortedCandidates, riskLevel);
      const result = this.simulate(weights, Math.min(200, this.options.monteCarloRounds));

      surface.push({
        risk_level: Math.round(riskLevel * 100) / 100,
        expected_return: result.summary.expected_portfolio_return,
        var_95: result.summary.portfolio_var_95,
        sharpe: result.summary.portfolio_sharpe,
        allocation_snapshot: Object.entries(weights).map(([id, w]) => ({
          opportunity_id: id,
          weight: Math.round(w * 1000) / 1000,
        })),
      });
    }

    return surface;
  }

  _riskAdjustedWeights(candidates, riskLevel) {
    // Low risk: weight by inverse volatility
    // High risk: weight by expected return
    const raw = {};

    for (const c of candidates) {
      const safetyScore = c.volatility > 0 ? 1 / c.volatility : 10;
      const returnScore = Math.max(0, c.expected_return);
      raw[c.opportunity_id] = safetyScore * (1 - riskLevel) + returnScore * riskLevel;
    }

    // Normalize
    const total = Object.values(raw).reduce((s, v) => s + v, 0);
    const weights = {};
    for (const [id, v] of Object.entries(raw)) {
      weights[id] = v / total;
    }

    return this._applyConstraints(weights, candidates);
  }

  // ─── Utility Methods ──────────────────────────────────────────────

  _randomNormal() {
    // Box-Muller transform for approximate normal distribution
    const u1 = Math.random();
    const u2 = Math.random();
    return Math.sqrt(-2 * Math.log(Math.max(1e-10, u1))) * Math.cos(2 * Math.PI * u2);
  }

  _stdDev(arr) {
    if (arr.length < 2) return 0;
    const mean = arr.reduce((s, v) => s + v, 0) / arr.length;
    const squaredDiffs = arr.reduce((s, v) => s + (v - mean) ** 2, 0);
    return Math.sqrt(squaredDiffs / (arr.length - 1));
  }

  _computeConcentration(weights) {
    // Herfindahl-Hirschman Index (HHI) for concentration
    const ws = Object.values(weights);
    if (ws.length === 0) return 0;
    return ws.reduce((s, w) => s + w * w, 0);
  }

  _computeLiquidityRisk(candidates, weights) {
    // Weighted average liquidity days (higher = more risk)
    let totalLiquidity = 0;
    let totalWeight = 0;

    for (const c of candidates) {
      const w = weights[c.opportunity_id] || 0;
      totalLiquidity += w * c.liquidity_days;
      totalWeight += w;
    }

    return totalWeight > 0 ? Math.round(totalLiquidity / totalWeight) : 0;
  }

  // ─── Query ──────────────────────────────────────────────────────────

  getLastResult() {
    return this.lastResult;
  }

  getLastScenarios(limit = 100) {
    return this.lastScenarios.slice(-limit);
  }

  getReturnSurface() {
    return this._returnSurface || [];
  }

  getMetrics() {
    return { ...this.metrics, sim_status: this.simStatus };
  }

  _updateMetrics(result) {
    if (!result) return;

    // EMA update
    const alpha = 0.1;
    this.metrics.avg_portfolio_return = this.metrics.avg_portfolio_return * (1 - alpha) +
      (result.expected_portfolio_return || 0) * alpha;
    this.metrics.avg_portfolio_var = this.metrics.avg_portfolio_var * (1 - alpha) +
      (result.portfolio_var_95 || 0) * alpha;
    this.metrics.avg_sharpe_ratio = this.metrics.avg_sharpe_ratio * (1 - alpha) +
      (result.portfolio_sharpe || 0) * alpha;
    this.metrics.avg_capital_utilization = this.metrics.avg_capital_utilization * (1 - alpha) +
      (result.capital_utilized || 0) * alpha;

    if ((result.expected_portfolio_return || 0) > this.metrics.best_portfolio_return) {
      this.metrics.best_portfolio_return = result.expected_portfolio_return;
    }
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(CAS_DIR, 'capital-allocator-state.json');
    const data = {
      version: '1.2',
      saved_at: Date.now(),
      candidates: [...this.candidates.entries()].slice(-this.options.maxSimultaneousOpportunities * 5),
      last_result: this.lastResult ? this.lastResult.toJSON() : null,
      metrics: this.metrics,
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(CAS_DIR, 'capital-allocator-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (data.candidates) {
        this.candidates = new Map(
          data.candidates.map(([k, v]) => [k, new AllocationCandidate(v)])
        );
      }
      if (data.last_result) {
        this.lastResult = new AllocationResult(data.last_result);
      }
      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.candidates.clear();
    this.lastResult = null;
    this.lastScenarios = [];
    this.simStatus = SIM_STATUS.IDLE;
    this.metrics = {
      total_simulations: 0, total_scenarios_run: 0,
      avg_portfolio_return: 0, avg_portfolio_var: 0,
      avg_sharpe_ratio: 0, avg_capital_utilization: 0,
      best_portfolio_return: 0, optimization_convergence_rate: 0,
    };
  }

  shutdown() {
    if (this._persistTimer) clearInterval(this._persistTimer);
    this.save();
  }
}

module.exports = {
  CapitalAllocatorSim,
  AllocationCandidate,
  AllocationResult,
  ScenarioResult,
  SIM_STATUS,
};

