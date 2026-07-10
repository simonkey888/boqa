/**
 * BOQA economic-value-engine.js — EconomicValueEngine v1.2
 *
 * Converts CEVI-scored hypotheses into comparable economic units
 * (EV, ROI, risk-adjusted yield). This is the core of the v1.2
 * Decision Evolution Layer, enabling cross-class comparison of
 * opportunities from different systems and domains.
 *
 * Economic scoring model:
 *   normalized_economic_score =
 *     EVI * market_factor
 *     - risk_adjusted_penalty
 *     + liquidity_bonus
 *     + capital_efficiency_bonus
 *     - execution_latency_penalty
 *     + data_availability_score
 *
 * Where:
 *   EVI = base CEVI score from ConfidenceCalibrator
 *   market_factor = f(market_size, growth_rate, addressable_segment)
 *   risk_adjusted_penalty = f(var_95, max_drawdown, tail_risk)
 *   liquidity_bonus = f(exit_velocity, market_depth, time_to_liquidity)
 *   capital_efficiency_bonus = f(capital_required, expected_yield_per_unit)
 *   execution_latency_penalty = f(time_to_revenue, opportunity_decay_rate)
 *   data_availability_score = f(signal_quality, coverage, confidence)
 *
 * Safe mode: all economic values are simulated projections. No real
 * financial transactions or commitments are made. All outputs are
 * observational estimates for decision support only.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const EVE_DIR = path.join(__dirname, 'output', 'knowledge', 'economic-value');

// ─── Constants ──────────────────────────────────────────────────────

const MARKET_SIZE_BANDS = {
  MICRO:      { min: 0,       max: 10000,     factor: 0.6  },
  SMALL:      { min: 10000,   max: 100000,    factor: 0.8  },
  MEDIUM:     { min: 100000,  max: 1000000,   factor: 1.0  },
  LARGE:      { min: 1000000, max: 10000000,  factor: 1.2  },
  MEGA:       { min: 10000000, max: Infinity,  factor: 1.5  },
};

const COMPETITION_LEVELS = {
  NONE:        { level: 0, penalty: 0.00 },
  LOW:         { level: 1, penalty: 0.05 },
  MODERATE:    { level: 2, penalty: 0.12 },
  HIGH:        { level: 3, penalty: 0.22 },
  SATURATED:   { level: 4, penalty: 0.35 },
};

const OPPORTUNITY_CLASSES = {
  SSL_TLS_FEED:              'ssl_tls_feed',
  GOVERNMENT_TENDER_API:     'government_tender_api',
  COMPETITOR_CHANGELOG:      'competitor_changelog_webhook',
  EXPIRING_DOMAIN_FEED:      'expiring_domain_feed',
  SEC_ANOMALY_WEBHOOK:       'sec_anomaly_webhook',
  POLYEDGE_PREDICTION:       'polyedge_prediction_system',
  MORPHO_LIQUIDATION:        'morpho_liquidation_scanner',
  DATA_API_MARKETPLACE:      'data_api_marketplace_products',
  SECURITY_BUG_BOUNTY:       'security_bug_bounty',
  DEFI_YIELD_OPPORTUNITY:    'defi_yield_opportunity',
};

const DEFAULT_OPTIONS = {
  maxOpportunities: 500,
  riskFreeRate: 0.04,             // 4% baseline risk-free rate
  riskAversionCoeff: 2.0,         // CRRA coefficient
  defaultMarketSize: 50000,       // Default market size if unknown
  defaultCompetitionLevel: 'MODERATE',
  defaultCapitalRequired: 1000,
  defaultTimeToRevenueDays: 30,
  latencyDecayRate: 0.02,         // Per-day decay of opportunity value
  maxVar95Penalty: 25,            // Max penalty from VaR
  maxDrawdownCap: 0.50,           // Max expected drawdown
  liquidityWindowDays: 90,        // Default liquidity window
  persistenceIntervalMs: 300000,
};

// =====================================================================
//  EconomicScore
// =====================================================================

class EconomicScore {
  constructor(data = {}) {
    this.opportunity_id        = data.opportunity_id || null;
    this.hypothesis_id         = data.hypothesis_id || null;
    this.opportunity_class     = data.opportunity_class || null;
    this.target_id             = data.target_id || null;

    // Base inputs
    this.cevi                  = data.cevi ?? 0;
    this.confidence            = data.confidence ?? 0.5;
    this.market_size           = data.market_size ?? 0;
    this.competition_pressure  = data.competition_pressure ?? 0;
    this.capital_required      = data.capital_required ?? 0;
    this.time_to_revenue_days  = data.time_to_revenue_days ?? 30;

    // Computed components
    this.market_factor         = data.market_factor ?? 1.0;
    this.risk_adjusted_penalty = data.risk_adjusted_penalty ?? 0;
    this.liquidity_bonus       = data.liquidity_bonus ?? 0;
    this.capital_efficiency_bonus = data.capital_efficiency_bonus ?? 0;
    this.execution_latency_penalty = data.execution_latency_penalty ?? 0;
    this.data_availability_score  = data.data_availability_score ?? 0;

    // Final outputs
    this.expected_value        = data.expected_value ?? 0;
    this.roi                   = data.roi ?? 0;
    this.risk_adjusted_yield   = data.risk_adjusted_yield ?? 0;
    this.normalized_score      = data.normalized_score ?? 0;

    // Risk metrics
    this.var_95                = data.var_95 ?? 0;
    this.max_drawdown          = data.max_drawdown ?? 0;
    this.sharpe_ratio          = data.sharpe_ratio ?? 0;

    // Metadata
    this.computed_at           = Date.now();
    this.version               = '1.2';
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  Opportunity
// =====================================================================

class Opportunity {
  constructor(data = {}) {
    this.id                    = data.id || `OPP-${crypto.randomUUID().substring(0, 10)}`;
    this.opportunity_class     = data.opportunity_class || OPPORTUNITY_CLASSES.SECURITY_BUG_BOUNTY;
    this.target_id             = data.target_id || null;
    this.hypothesis_id         = data.hypothesis_id || null;

    // CEVI input
    this.cevi                  = data.cevi ?? 0;
    this.cevi_p10              = data.cevi_p10 ?? 0;
    this.cevi_p50              = data.cevi_p50 ?? 0;
    this.cevi_p90              = data.cevi_p90 ?? 0;
    this.calibration_factor    = data.calibration_factor ?? 1.0;

    // Economic inputs
    this.market_size           = data.market_size ?? DEFAULT_OPTIONS.defaultMarketSize;
    this.competition_level     = data.competition_level || DEFAULT_OPTIONS.defaultCompetitionLevel;
    this.competition_pressure  = data.competition_pressure ?? 0;
    this.capital_required      = data.capital_required ?? DEFAULT_OPTIONS.defaultCapitalRequired;
    this.time_to_revenue_days  = data.time_to_revenue_days ?? DEFAULT_OPTIONS.defaultTimeToRevenueDays;
    this.confidence            = data.confidence ?? 0.5;

    // Signal quality
    this.signal_quality        = data.signal_quality ?? 0.5;
    this.coverage              = data.coverage ?? 0.3;
    this.data_availability     = data.data_availability ?? 0.5;

    // Risk inputs
    this.historical_volatility = data.historical_volatility ?? 0.3;
    this.tail_risk             = data.tail_risk ?? 0.1;

    // Metadata
    this.label                 = data.label || '';
    this.tags                  = data.tags || [];
    this.source                = data.source || 'manual';
    this.created_at            = data.created_at || Date.now();
    this.updated_at            = Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  EconomicValueEngine
// =====================================================================

class EconomicValueEngine {
  /**
   * @param {object} options
   * @param {object} [options.confidenceCalibrator] - ConfidenceCalibrator instance
   * @param {object} [options.memoryGraph] - MemoryGraph instance
   */
  constructor(options = {}) {
    this.confidenceCalibrator = options.confidenceCalibrator || null;
    this.memoryGraph = options.memoryGraph || null;
    this.options = { ...DEFAULT_OPTIONS, ...options };

    /** @type {Map<string, Opportunity>} opportunity_id → Opportunity */
    this.opportunities = new Map();

    /** @type {Map<string, EconomicScore>} opportunity_id → EconomicScore */
    this.scores = new Map();

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_opportunities: 0,
      total_scored: 0,
      avg_expected_value: 0,
      avg_roi: 0,
      avg_risk_adjusted_yield: 0,
      avg_normalized_score: 0,
      total_market_value: 0,
      avg_capital_required: 0,
      opportunities_by_class: {},
      scoring_accuracy: 0,
    };

    // ── Persistence timer ────────────────────────────────────
    this._persistTimer = null;

    fs.mkdirSync(EVE_DIR, { recursive: true });
    this.load();

    if (this.options.persistenceIntervalMs > 0) {
      this._persistTimer = setInterval(() => this.save(), this.options.persistenceIntervalMs);
    }
  }

  // ─── Opportunity Management ─────────────────────────────────────────

  /**
   * Register an opportunity for economic scoring.
   * @param {object} data - Opportunity data
   * @returns {Opportunity}
   */
  registerOpportunity(data) {
    const opp = data instanceof Opportunity ? data : new Opportunity(data);
    this.opportunities.set(opp.id, opp);
    this.metrics.total_opportunities = this.opportunities.size;
    this._updateClassCounts();
    return opp;
  }

  /**
   * Register multiple opportunities at once.
   * @param {object[]} items
   * @returns {Opportunity[]}
   */
  registerBatch(items) {
    return items.map(item => this.registerOpportunity(item));
  }

  /**
   * Get an opportunity by ID.
   * @param {string} id
   * @returns {Opportunity|undefined}
   */
  getOpportunity(id) {
    return this.opportunities.get(id);
  }

  /**
   * Remove an opportunity.
   * @param {string} id
   * @returns {boolean}
   */
  removeOpportunity(id) {
    const removed = this.opportunities.delete(id);
    this.scores.delete(id);
    if (removed) {
      this.metrics.total_opportunities = this.opportunities.size;
      this._updateClassCounts();
    }
    return removed;
  }

  // ─── Economic Scoring ──────────────────────────────────────────────

  /**
   * Score a single opportunity using the full economic model.
   *
   * @param {string|Opportunity|object} input - Opportunity ID, instance, or data
   * @returns {EconomicScore}
   */
  score(input) {
    let opp;
    if (typeof input === 'string') {
      opp = this.opportunities.get(input);
      if (!opp) return null;
    } else if (input instanceof Opportunity) {
      opp = input;
    } else {
      opp = new Opportunity(input);
    }

    // 1. Market Factor
    const marketFactor = this._computeMarketFactor(opp);

    // 2. Risk-Adjusted Penalty
    const riskPenalty = this._computeRiskAdjustedPenalty(opp);

    // 3. Liquidity Bonus
    const liquidityBonus = this._computeLiquidityBonus(opp);

    // 4. Capital Efficiency Bonus
    const capitalBonus = this._computeCapitalEfficiencyBonus(opp);

    // 5. Execution Latency Penalty
    const latencyPenalty = this._computeExecutionLatencyPenalty(opp);

    // 6. Data Availability Score
    const dataScore = this._computeDataAvailabilityScore(opp);

    // 7. Compute Expected Value
    const ev = opp.cevi * marketFactor * opp.market_size / 100;

    // 8. Compute ROI
    const capital = Math.max(1, opp.capital_required);
    const roi = (ev - capital) / capital;

    // 9. Compute Risk-Adjusted Yield (Sharpe-like)
    const volatility = Math.max(0.01, opp.historical_volatility);
    const sharpeRatio = (ev / capital - this.options.riskFreeRate) / volatility;
    const riskAdjustedYield = ev * (1 - riskPenalty / 100) / capital;

    // 10. Compute Normalized Score (0-100)
    const rawScore = opp.cevi * marketFactor
      - riskPenalty
      + liquidityBonus
      + capitalBonus
      - latencyPenalty
      + dataScore;

    const normalizedScore = Math.max(0, Math.min(100, rawScore));

    // 11. VaR (95%) and Max Drawdown
    const var95 = this._computeVaR95(opp, ev);
    const maxDrawdown = this._computeMaxDrawdown(opp);

    const score = new EconomicScore({
      opportunity_id: opp.id,
      hypothesis_id: opp.hypothesis_id,
      opportunity_class: opp.opportunity_class,
      target_id: opp.target_id,

      cevi: opp.cevi,
      confidence: opp.confidence,
      market_size: opp.market_size,
      competition_pressure: opp.competition_pressure,
      capital_required: opp.capital_required,
      time_to_revenue_days: opp.time_to_revenue_days,

      market_factor: Math.round(marketFactor * 1000) / 1000,
      risk_adjusted_penalty: Math.round(riskPenalty * 100) / 100,
      liquidity_bonus: Math.round(liquidityBonus * 100) / 100,
      capital_efficiency_bonus: Math.round(capitalBonus * 100) / 100,
      execution_latency_penalty: Math.round(latencyPenalty * 100) / 100,
      data_availability_score: Math.round(dataScore * 100) / 100,

      expected_value: Math.round(ev * 100) / 100,
      roi: Math.round(roi * 10000) / 10000,
      risk_adjusted_yield: Math.round(riskAdjustedYield * 10000) / 10000,
      normalized_score: Math.round(normalizedScore * 100) / 100,

      var_95: Math.round(var95 * 100) / 100,
      max_drawdown: Math.round(maxDrawdown * 1000) / 1000,
      sharpe_ratio: Math.round(sharpeRatio * 1000) / 1000,
    });

    this.scores.set(opp.id, score);
    this.metrics.total_scored++;
    this._updateScoringMetrics();

    return score;
  }

  /**
   * Score all registered opportunities.
   * @returns {EconomicScore[]}
   */
  scoreAll() {
    const results = [];
    for (const [id] of this.opportunities) {
      results.push(this.score(id));
    }
    return results.sort((a, b) => b.normalized_score - a.normalized_score);
  }

  /**
   * Score a batch of opportunities (does not register them).
   * @param {object[]} items
   * @returns {EconomicScore[]}
   */
  scoreBatch(items) {
    return items.map(item => this.score(item)).filter(Boolean)
      .sort((a, b) => b.normalized_score - a.normalized_score);
  }

  // ─── Component Computation ─────────────────────────────────────────

  _computeMarketFactor(opp) {
    let factor = 1.0;

    // Band-based adjustment
    for (const [, band] of Object.entries(MARKET_SIZE_BANDS)) {
      if (opp.market_size >= band.min && opp.market_size < band.max) {
        factor = band.factor;
        break;
      }
    }

    // Growth rate premium (if available from memory graph)
    if (this.memoryGraph) {
      const targetNodes = this.memoryGraph.queryNodes({
        target_id: opp.target_id,
        type: 'finding',
        limit: 20,
      });
      // More confirmed findings on a target → higher market signal quality
      const confirmedCount = targetNodes.filter(n => n.verdict === 'confirmed').length;
      factor *= (1 + Math.min(0.3, confirmedCount * 0.03));
    }

    return factor;
  }

  _computeRiskAdjustedPenalty(opp) {
    // Base risk from volatility
    let penalty = opp.historical_volatility * 20;

    // Tail risk penalty
    penalty += opp.tail_risk * 15;

    // Competition adds execution risk
    const compLevel = COMPETITION_LEVELS[opp.competition_level] ||
                      COMPETITION_LEVELS[this.options.defaultCompetitionLevel];
    penalty += compLevel.penalty * 30;

    // Low confidence = more uncertainty = higher penalty
    if (opp.confidence < 0.3) {
      penalty += (0.3 - opp.confidence) * 40;
    }

    return Math.min(penalty, this.options.maxVar95Penalty);
  }

  _computeLiquidityBonus(opp) {
    let bonus = 0;

    // Faster time to revenue → more liquid
    const ttr = opp.time_to_revenue_days;
    if (ttr <= 7)       bonus += 5.0;
    else if (ttr <= 14) bonus += 3.5;
    else if (ttr <= 30) bonus += 2.0;
    else if (ttr <= 60) bonus += 1.0;
    else                bonus += 0;

    // Opportunity class liquidity profile
    const liquidClasses = [
      OPPORTUNITY_CLASSES.MORPHO_LIQUIDATION,
      OPPORTUNITY_CLASSES.DEFI_YIELD_OPPORTUNITY,
      OPPORTUNITY_CLASSES.DATA_API_MARKETPLACE,
    ];
    if (liquidClasses.includes(opp.opportunity_class)) {
      bonus += 2.0;
    }

    return bonus;
  }

  _computeCapitalEfficiencyBonus(opp) {
    // Higher EV per unit of capital → bonus
    const capital = Math.max(1, opp.capital_required);
    const evPerCapital = (opp.cevi * opp.market_size / 100) / capital;

    let bonus = 0;
    if (evPerCapital > 10)      bonus += 5.0;
    else if (evPerCapital > 5)  bonus += 3.0;
    else if (evPerCapital > 2)  bonus += 1.5;
    else if (evPerCapital > 1)  bonus += 0.5;

    return bonus;
  }

  _computeExecutionLatencyPenalty(opp) {
    // Value decays with time — opportunity cost of delayed execution
    const ttr = opp.time_to_revenue_days;
    const penalty = ttr * this.options.latencyDecayRate;
    return Math.min(penalty, 15); // Cap at 15 points
  }

  _computeDataAvailabilityScore(opp) {
    // Composite of signal quality, coverage, and data availability
    const score = (
      opp.signal_quality * 0.4 +
      opp.coverage * 0.3 +
      opp.data_availability * 0.3
    ) * 5; // Scale to 0-5 range

    return Math.min(score, 5);
  }

  _computeVaR95(opp, ev) {
    // Simplified parametric VaR at 95% confidence
    const vol = Math.max(0.01, opp.historical_volatility);
    const z95 = 1.645; // One-tailed 95%
    return ev * z95 * vol;
  }

  _computeMaxDrawdown(opp) {
    // Estimate max drawdown from tail risk and volatility
    const vol = Math.max(0.01, opp.historical_volatility);
    const dd = vol * (1 + opp.tail_risk * 3);
    return Math.min(dd, this.options.maxDrawdownCap);
  }

  // ─── Query & Ranking ──────────────────────────────────────────────

  /**
   * Get the economic score for an opportunity.
   * @param {string} opportunityId
   * @returns {EconomicScore|null}
   */
  getScore(opportunityId) {
    return this.scores.get(opportunityId) || null;
  }

  /**
   * Get all scores, sorted by normalized_score descending.
   * @param {object} [filter] - Optional filter { opportunity_class, min_score, target_id }
   * @returns {EconomicScore[]}
   */
  getRankedScores(filter = {}) {
    let scores = [...this.scores.values()];

    if (filter.opportunity_class) {
      scores = scores.filter(s => s.opportunity_class === filter.opportunity_class);
    }
    if (filter.min_score !== undefined) {
      scores = scores.filter(s => s.normalized_score >= filter.min_score);
    }
    if (filter.target_id) {
      scores = scores.filter(s => s.target_id === filter.target_id);
    }

    return scores.sort((a, b) => b.normalized_score - a.normalized_score);
  }

  /**
   * Get the top N opportunities by economic score.
   * @param {number} [n=10]
   * @returns {EconomicScore[]}
   */
  getTopOpportunities(n = 10) {
    return this.getRankedScores().slice(0, n);
  }

  /**
   * Get a portfolio summary across all scored opportunities.
   * @returns {object}
   */
  getPortfolioSummary() {
    const scores = [...this.scores.values()];
    if (scores.length === 0) {
      return {
        total_opportunities: 0,
        total_expected_value: 0,
        total_capital_required: 0,
        avg_roi: 0,
        avg_risk_adjusted_yield: 0,
        avg_normalized_score: 0,
        portfolio_var_95: 0,
        class_distribution: {},
      };
    }

    const totalEV = scores.reduce((s, sc) => s + sc.expected_value, 0);
    const totalCapital = scores.reduce((s, sc) => s + sc.capital_required, 0);
    const avgROI = scores.reduce((s, sc) => s + sc.roi, 0) / scores.length;
    const avgRAY = scores.reduce((s, sc) => s + sc.risk_adjusted_yield, 0) / scores.length;
    const avgNorm = scores.reduce((s, sc) => s + sc.normalized_score, 0) / scores.length;

    // Portfolio VaR (simplified: assume 0.3 correlation)
    const individualVar = scores.map(s => s.var_95);
    const portfolioVar = this._computePortfolioVar(individualVar, 0.3);

    const classDist = {};
    for (const sc of scores) {
      classDist[sc.opportunity_class] = (classDist[sc.opportunity_class] || 0) + 1;
    }

    return {
      total_opportunities: scores.length,
      total_expected_value: Math.round(totalEV * 100) / 100,
      total_capital_required: Math.round(totalCapital * 100) / 100,
      avg_roi: Math.round(avgROI * 10000) / 10000,
      avg_risk_adjusted_yield: Math.round(avgRAY * 10000) / 10000,
      avg_normalized_score: Math.round(avgNorm * 100) / 100,
      portfolio_var_95: Math.round(portfolioVar * 100) / 100,
      class_distribution: classDist,
    };
  }

  _computePortfolioVar(individualVars, avgCorrelation) {
    if (individualVars.length === 0) return 0;
    if (individualVars.length === 1) return individualVars[0];

    const n = individualVars.length;
    const sumSq = individualVars.reduce((s, v) => s + v * v, 0);
    const sumAll = individualVars.reduce((s, v) => s + v, 0);

    // Simplified: portfolio variance with constant correlation
    const portfolioVariance = sumSq + avgCorrelation * (sumAll * sumAll / n - sumSq);
    return Math.sqrt(Math.max(0, portfolioVariance));
  }

  // ─── Calibration Feedback ──────────────────────────────────────────

  /**
   * Record a realized outcome for an opportunity to improve scoring.
   * @param {string} opportunityId
   * @param {object} data - { actual_return, actual_cost, realized }
   */
  recordOutcome(opportunityId, data) {
    const score = this.scores.get(opportunityId);
    if (!score) return null;

    const actualReturn = data.actual_return ?? 0;
    const actualCost = data.actual_cost ?? score.capital_required;

    // Feed back to confidence calibrator
    if (this.confidenceCalibrator) {
      this.confidenceCalibrator.recordObservation({
        target_id: score.target_id,
        category: score.opportunity_class,
        predicted: score.expected_value,
        actual: actualReturn,
      });
    }

    return {
      opportunity_id: opportunityId,
      predicted_ev: score.expected_value,
      actual_return: actualReturn,
      prediction_error: score.expected_value - actualReturn,
      roi_error: score.roi - (actualReturn - actualCost) / Math.max(1, actualCost),
    };
  }

  // ─── Metrics ───────────────────────────────────────────────────────

  getMetrics() {
    return { ...this.metrics };
  }

  _updateScoringMetrics() {
    const scores = [...this.scores.values()];
    if (scores.length === 0) return;

    this.metrics.avg_expected_value = Math.round(
      scores.reduce((s, sc) => s + sc.expected_value, 0) / scores.length * 100
    ) / 100;
    this.metrics.avg_roi = Math.round(
      scores.reduce((s, sc) => s + sc.roi, 0) / scores.length * 10000
    ) / 10000;
    this.metrics.avg_risk_adjusted_yield = Math.round(
      scores.reduce((s, sc) => s + sc.risk_adjusted_yield, 0) / scores.length * 10000
    ) / 10000;
    this.metrics.avg_normalized_score = Math.round(
      scores.reduce((s, sc) => s + sc.normalized_score, 0) / scores.length * 100
    ) / 100;
    this.metrics.total_market_value = Math.round(
      scores.reduce((s, sc) => s + sc.market_size, 0) * 100
    ) / 100;
    this.metrics.avg_capital_required = Math.round(
      scores.reduce((s, sc) => s + sc.capital_required, 0) / scores.length * 100
    ) / 100;
  }

  _updateClassCounts() {
    const counts = {};
    for (const [, opp] of this.opportunities) {
      counts[opp.opportunity_class] = (counts[opp.opportunity_class] || 0) + 1;
    }
    this.metrics.opportunities_by_class = counts;
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(EVE_DIR, 'economic-value-state.json');
    const data = {
      version: '1.2',
      saved_at: Date.now(),
      opportunities: [...this.opportunities.entries()].slice(-this.options.maxOpportunities),
      scores: [...this.scores.entries()].slice(-this.options.maxOpportunities),
      metrics: this.metrics,
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(EVE_DIR, 'economic-value-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (data.opportunities) {
        this.opportunities = new Map(
          data.opportunities.map(([k, v]) => [k, new Opportunity(v)])
        );
      }
      if (data.scores) {
        this.scores = new Map(
          data.scores.map(([k, v]) => [k, new EconomicScore(v)])
        );
      }
      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      this._updateClassCounts();
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.opportunities.clear();
    this.scores.clear();
    this.metrics = {
      total_opportunities: 0, total_scored: 0,
      avg_expected_value: 0, avg_roi: 0,
      avg_risk_adjusted_yield: 0, avg_normalized_score: 0,
      total_market_value: 0, avg_capital_required: 0,
      opportunities_by_class: {}, scoring_accuracy: 0,
    };
  }

  shutdown() {
    if (this._persistTimer) clearInterval(this._persistTimer);
    this.save();
  }
}

module.exports = {
  EconomicValueEngine,
  EconomicScore,
  Opportunity,
  MARKET_SIZE_BANDS,
  COMPETITION_LEVELS,
  OPPORTUNITY_CLASSES,
};

