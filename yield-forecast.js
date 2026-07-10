/**
 * BOQA yield-forecast.js — Yield Forecast v0.8
 *
 * Estimates expected bugs, severity distribution and verification
 * success rate for targets, endpoints, and categories before
 * verification runs.
 *
 * Yield forecast combines:
 *   - PredictionEngine outputs (target/endpoint/category yield)
 *   - Historical severity distribution per target/category
 *   - Verification success rates from LearningEngine
 *   - Evidence quality trends from EvidenceQualityEngine
 *   - Campaign effectiveness data from CampaignEngine
 *
 * Forecast outputs:
 *   - expected_bugs:            point estimate of bug count
 *   - severity_distribution:    expected split by severity
 *   - verification_success_rate: predicted verification success
 *   - evidence_readiness:       predicted evidence quality
 *   - confidence_band:          p10/p25/p50/p75/p90 range
 *   - yield_trend:              improving/declining/stable
 *   - time_to_discovery:        estimated hours to first bug
 *
 * The yield forecast is the primary output consumed by the
 * PriorityShaper to re-rank hypotheses and targets.
 *
 * Safe mode: forecasts are analytical only; they inform
 * prioritization but never bypass safe mode constraints.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const FORECAST_DIR = path.join(__dirname, 'output', 'knowledge', 'forecasts');

// ─── Default Severity Distribution ──────────────────────────────────

const DEFAULT_SEVERITY_DIST = {
  critical: 0.05,
  high:     0.15,
  medium:   0.40,
  low:      0.30,
  info:     0.10,
};

// ─── Yield Trend Thresholds ─────────────────────────────────────────

const TREND_IMPROVING_THRESHOLD = 0.10;  // 10% improvement = improving
const TREND_DECLINING_THRESHOLD = -0.10; // 10% decline = declining

// =====================================================================
//  YieldForecast
// =====================================================================

class YieldForecast {
  constructor(data = {}) {
    this.id = data.id || `YF-${crypto.randomUUID().substring(0, 8)}`;
    this.target_id = data.target_id || null;
    this.scope = data.scope || 'target'; // target, endpoint, category, portfolio

    // Core forecast
    this.expected_bugs = data.expected_bugs || 0;
    this.severity_distribution = data.severity_distribution || { ...DEFAULT_SEVERITY_DIST };
    this.verification_success_rate = data.verification_success_rate || 0;
    this.evidence_readiness = data.evidence_readiness || 0;
    this.confidence_band = data.confidence_band || {
      p10: 0, p25: 0, p50: 0, p75: 0, p90: 0,
    };

    // Trend
    this.yield_trend = data.yield_trend || 'stable'; // improving, declining, stable
    this.trend_delta = data.trend_delta || 0;

    // Time estimate
    this.time_to_discovery_hours = data.time_to_discovery_hours || null;

    // Metadata
    this.generated_at = data.generated_at || Date.now();
    this.model_version = data.model_version || '0.8';
    this.data_points = data.data_points || 0;
  }
}

// =====================================================================
//  YieldForecaster
// =====================================================================

class YieldForecaster {
  /**
   * @param {object} options
   * @param {object} [options.predictionEngine]    - PredictionEngine instance
   * @param {object} [options.knowledgeBase]       - KnowledgeBase instance
   * @param {object} [options.brainRegistry]        - BrainRegistry instance
   * @param {object} [options.learningEngine]       - LearningEngine instance
   * @param {object} [options.evidenceQualityEngine] - EvidenceQualityEngine instance
   * @param {object} [options.campaignEngine]       - CampaignEngine instance
   * @param {object} [options.findingMemory]        - FindingMemory instance
   */
  constructor(options = {}) {
    this.predictionEngine = options.predictionEngine || null;
    this.kb = options.knowledgeBase || null;
    this.brainRegistry = options.brainRegistry || null;
    this.learningEngine = options.learningEngine || null;
    this.evidenceQuality = options.evidenceQualityEngine || null;
    this.campaignEngine = options.campaignEngine || null;
    this.findingMemory = options.findingMemory || null;

    /** @type {Map<string, YieldForecast>} target_id → latest forecast */
    this.forecasts = new Map();

    /** @type {YieldForecast|null} portfolio-level forecast */
    this.portfolioForecast = null;

    /** @type {object[]} forecast history */
    this.forecastHistory = [];

    // Ensure directory exists
    fs.mkdirSync(FORECAST_DIR, { recursive: true });

    // Auto-load
    this.load();
  }

  // ─── Target Forecast ────────────────────────────────────────────

  /**
   * Generate a yield forecast for a single target.
   *
   * @param {string} targetId
   * @returns {YieldForecast}
   */
  forecastTarget(targetId) {
    const prediction = this.predictionEngine
      ? this.predictionEngine.predictTarget(targetId)
      : null;

    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;

    // Expected bugs from prediction
    const expectedBugs = prediction ? prediction.predicted_yield : this._estimateBugsFromHistory(targetId);

    // Severity distribution from historical data
    const severityDist = this._computeSeverityDistribution(targetId);

    // Verification success rate from learning engine
    const verificationRate = this._computeVerificationSuccessRate(targetId);

    // Evidence readiness from evidence quality engine
    const evidenceReadiness = this._computeEvidenceReadiness(targetId);

    // Yield trend
    const trend = this._computeYieldTrend(targetId);

    // Time to discovery estimate
    const timeToDiscovery = this._estimateTimeToDiscovery(targetId, brain);

    const forecast = new YieldForecast({
      target_id: targetId,
      scope: 'target',
      expected_bugs: Math.round(expectedBugs * 100) / 100,
      severity_distribution: severityDist,
      verification_success_rate: verificationRate,
      evidence_readiness: evidenceReadiness,
      confidence_band: prediction ? prediction.confidence_band : {
        p10: expectedBugs * 0.3,
        p25: expectedBugs * 0.6,
        p50: expectedBugs,
        p75: expectedBugs * 1.4,
        p90: expectedBugs * 1.7,
      },
      yield_trend: trend.direction,
      trend_delta: trend.delta,
      time_to_discovery_hours: timeToDiscovery,
      data_points: brain ? brain.total_sessions : 0,
    });

    this.forecasts.set(targetId, forecast);
    this.forecastHistory.push({
      forecast_id: forecast.id,
      target_id: targetId,
      expected_bugs: forecast.expected_bugs,
      generated_at: forecast.generated_at,
    });

    // Cap history
    if (this.forecastHistory.length > 5000) {
      this.forecastHistory = this.forecastHistory.slice(-5000);
    }

    return forecast;
  }

  /**
   * Generate yield forecasts for all known targets.
   *
   * @returns {YieldForecast[]}
   */
  forecastAllTargets() {
    const targetIds = this._collectTargetIds();
    const forecasts = [];

    for (const targetId of targetIds) {
      forecasts.push(this.forecastTarget(targetId));
    }

    forecasts.sort((a, b) => b.expected_bugs - a.expected_bugs);
    return forecasts;
  }

  // ─── Portfolio Forecast ─────────────────────────────────────────

  /**
   * Generate a portfolio-level yield forecast.
   *
   * @returns {YieldForecast}
   */
  forecastPortfolio() {
    const targetForecasts = this.forecastAllTargets();

    const totalExpectedBugs = targetForecasts.reduce((s, f) => s + f.expected_bugs, 0);

    // Aggregate severity distribution
    const severityDist = this._aggregateSeverityDistribution(targetForecasts);

    // Weighted average verification success rate
    const totalBugs = targetForecasts.reduce((s, f) => s + f.expected_bugs, 0);
    const avgVerificationRate = totalBugs > 0
      ? targetForecasts.reduce((s, f) => s + f.verification_success_rate * f.expected_bugs, 0) / totalBugs
      : 0;

    // Weighted average evidence readiness
    const avgEvidenceReadiness = totalBugs > 0
      ? targetForecasts.reduce((s, f) => s + f.evidence_readiness * f.expected_bugs, 0) / totalBugs
      : 0;

    this.portfolioForecast = new YieldForecast({
      target_id: 'portfolio',
      scope: 'portfolio',
      expected_bugs: Math.round(totalExpectedBugs * 100) / 100,
      severity_distribution: severityDist,
      verification_success_rate: Math.round(avgVerificationRate * 1000) / 1000,
      evidence_readiness: Math.round(avgEvidenceReadiness * 100) / 100,
      confidence_band: {
        p10: targetForecasts.reduce((s, f) => s + f.confidence_band.p10, 0),
        p25: targetForecasts.reduce((s, f) => s + f.confidence_band.p25, 0),
        p50: targetForecasts.reduce((s, f) => s + f.confidence_band.p50, 0),
        p75: targetForecasts.reduce((s, f) => s + f.confidence_band.p75, 0),
        p90: targetForecasts.reduce((s, f) => s + f.confidence_band.p90, 0),
      },
      data_points: targetForecasts.length,
    });

    return this.portfolioForecast;
  }

  // ─── Category Forecast ─────────────────────────────────────────

  /**
   * Generate a yield forecast for a vulnerability category.
   *
   * @param {string} category
   * @param {string} [targetId] - optional target filter
   * @returns {YieldForecast}
   */
  forecastCategory(category, targetId) {
    const prediction = this.predictionEngine
      ? this.predictionEngine.predictCategories(targetId).find(p => p.category === category)
      : null;

    const expectedBugs = prediction ? prediction.predicted_yield : 0;

    // Category-specific severity distribution
    const categorySeverity = this._categorySeverityDistribution(category);

    // Category verification rate
    const verRate = this._categoryVerificationRate(category);

    const forecast = new YieldForecast({
      target_id: targetId || null,
      scope: 'category',
      expected_bugs: Math.round(expectedBugs * 100) / 100,
      severity_distribution: categorySeverity,
      verification_success_rate: verRate,
      confidence_band: prediction ? prediction.confidence_band : {
        p10: expectedBugs * 0.2,
        p25: expectedBugs * 0.5,
        p50: expectedBugs,
        p75: expectedBugs * 1.5,
        p90: expectedBugs * 2.0,
      },
    });

    return forecast;
  }

  // ─── Query Methods ──────────────────────────────────────────────

  /**
   * Get the latest forecast for a target.
   * @param {string} targetId
   * @returns {YieldForecast|null}
   */
  getTargetForecast(targetId) {
    return this.forecasts.get(targetId) || null;
  }

  /**
   * Get all target forecasts.
   * @returns {YieldForecast[]}
   */
  getAllForecasts() {
    return [...this.forecasts.values()]
      .sort((a, b) => b.expected_bugs - a.expected_bugs);
  }

  /**
   * Get forecaster statistics.
   * @returns {object}
   */
  getStats() {
    const forecasts = [...this.forecasts.values()];
    return {
      total_forecasts: forecasts.length,
      portfolio_expected_bugs: this.portfolioForecast?.expected_bugs || 0,
      avg_expected_bugs: forecasts.length > 0
        ? Math.round(forecasts.reduce((s, f) => s + f.expected_bugs, 0) / forecasts.length * 100) / 100
        : 0,
      forecast_history: this.forecastHistory.length,
      top_target: forecasts.length > 0
        ? { id: forecasts.sort((a, b) => b.expected_bugs - a.expected_bugs)[0].target_id,
            expected_bugs: forecasts.sort((a, b) => b.expected_bugs - a.expected_bugs)[0].expected_bugs }
        : null,
    };
  }

  // ─── Internal Methods ───────────────────────────────────────────

  _estimateBugsFromHistory(targetId) {
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    if (!brain || brain.total_sessions === 0) return 0.5; // default estimate for new targets

    const confirmed = brain.historicalFindings.filter(
      f => f.lifecycle_state === 'confirmed' || f.verdict === 'confirmed'
    ).length;

    return confirmed / Math.max(brain.total_sessions, 1);
  }

  _computeSeverityDistribution(targetId) {
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    if (!brain || brain.historicalFindings.length === 0) return { ...DEFAULT_SEVERITY_DIST };

    const dist = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const findings = brain.historicalFindings;

    for (const f of findings) {
      const sev = f.severity || 'medium';
      if (dist[sev] !== undefined) dist[sev]++;
    }

    // Normalize to proportions
    const total = Object.values(dist).reduce((s, v) => s + v, 0);
    if (total > 0) {
      for (const key of Object.keys(dist)) {
        dist[key] = Math.round((dist[key] / total) * 1000) / 1000;
      }
    }

    return dist;
  }

  _computeVerificationSuccessRate(targetId) {
    if (!this.learningEngine) return 0.5;

    const targetLearning = this.learningEngine.targetLearning.get(targetId);
    if (!targetLearning || targetLearning.observations === 0) return 0.5;

    return targetLearning.confirmed / targetLearning.observations;
  }

  _computeEvidenceReadiness(targetId) {
    if (!this.evidenceQuality) return 50;

    // Average evidence quality for findings on this target
    const stats = this.evidenceQuality.getStats();
    return stats.avg_score || 50;
  }

  _computeYieldTrend(targetId) {
    // Compare recent yield to historical yield
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    if (!brain || brain.total_sessions < 3) return { direction: 'stable', delta: 0 };

    const recentFindings = brain.historicalFindings.filter(f => {
      const ts = f.created_at || f.observed_at || 0;
      return Date.now() - ts < 7 * 86400000; // last 7 days
    });

    const olderFindings = brain.historicalFindings.filter(f => {
      const ts = f.created_at || f.observed_at || 0;
      const age = Date.now() - ts;
      return age >= 7 * 86400000 && age < 14 * 86400000; // 7-14 days ago
    });

    if (olderFindings.length === 0) return { direction: 'stable', delta: 0 };

    const delta = (recentFindings.length - olderFindings.length) / olderFindings.length;

    if (delta >= TREND_IMPROVING_THRESHOLD) return { direction: 'improving', delta: Math.round(delta * 100) / 100 };
    if (delta <= TREND_DECLINING_THRESHOLD) return { direction: 'declining', delta: Math.round(delta * 100) / 100 };
    return { direction: 'stable', delta: Math.round(delta * 100) / 100 };
  }

  _estimateTimeToDiscovery(targetId, brain) {
    if (!brain || brain.historicalFindings.length === 0) return null;

    // Estimate from average time between findings
    const findings = brain.historicalFindings
      .map(f => f.created_at || f.observed_at || 0)
      .filter(ts => ts > 0)
      .sort((a, b) => a - b);

    if (findings.length < 2) return null;

    let totalTime = 0;
    for (let i = 1; i < findings.length; i++) {
      totalTime += findings[i] - findings[i - 1];
    }

    const avgTimeBetweenMs = totalTime / (findings.length - 1);
    return Math.round(avgTimeBetweenMs / 3600000 * 100) / 100; // hours
  }

  _aggregateSeverityDistribution(forecasts) {
    const dist = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

    for (const forecast of forecasts) {
      const weight = forecast.expected_bugs || 1;
      for (const [sev, prop] of Object.entries(forecast.severity_distribution)) {
        dist[sev] = (dist[sev] || 0) + prop * weight;
      }
    }

    // Normalize
    const total = Object.values(dist).reduce((s, v) => s + v, 0);
    if (total > 0) {
      for (const key of Object.keys(dist)) {
        dist[key] = Math.round((dist[key] / total) * 1000) / 1000;
      }
    }

    return dist;
  }

  _categorySeverityDistribution(category) {
    // Category-specific severity profiles
    const profiles = {
      auth_bypass:              { critical: 0.30, high: 0.40, medium: 0.20, low: 0.08, info: 0.02 },
      session_hijacking:        { critical: 0.25, high: 0.35, medium: 0.25, low: 0.10, info: 0.05 },
      csrf:                     { critical: 0.05, high: 0.30, medium: 0.40, low: 0.20, info: 0.05 },
      cookie_security:          { critical: 0.10, high: 0.30, medium: 0.35, low: 0.20, info: 0.05 },
      api_exposure:             { critical: 0.10, high: 0.25, medium: 0.40, low: 0.20, info: 0.05 },
      idor:                     { critical: 0.15, high: 0.35, medium: 0.30, low: 0.15, info: 0.05 },
      xss:                      { critical: 0.05, high: 0.20, medium: 0.45, low: 0.25, info: 0.05 },
      injection:                { critical: 0.30, high: 0.35, medium: 0.20, low: 0.10, info: 0.05 },
      missing_authentication:   { critical: 0.20, high: 0.40, medium: 0.25, low: 0.10, info: 0.05 },
      broken_access_control:    { critical: 0.15, high: 0.35, medium: 0.30, low: 0.15, info: 0.05 },
      sensitive_data_exposure:  { critical: 0.20, high: 0.30, medium: 0.30, low: 0.15, info: 0.05 },
      security_misconfiguration: { critical: 0.05, high: 0.15, medium: 0.40, low: 0.30, info: 0.10 },
      information_leakage:      { critical: 0.05, high: 0.10, medium: 0.35, low: 0.35, info: 0.15 },
      token_handling:           { critical: 0.20, high: 0.35, medium: 0.25, low: 0.15, info: 0.05 },
      cors_misconfiguration:    { critical: 0.05, high: 0.15, medium: 0.45, low: 0.30, info: 0.05 },
      rate_limiting:            { critical: 0.02, high: 0.08, medium: 0.30, low: 0.40, info: 0.20 },
    };

    return profiles[category] || { ...DEFAULT_SEVERITY_DIST };
  }

  _categoryVerificationRate(category) {
    if (!this.learningEngine) return 0.5;

    const scores = this.learningEngine.getHypothesisSuccessScores();
    const catScore = scores.find(s => s.category === category);
    return catScore ? catScore.success_rate : 0.5;
  }

  _collectTargetIds() {
    const ids = new Set();
    if (this.brainRegistry) {
      for (const [id] of this.brainRegistry.brains) ids.add(id);
    }
    if (this.kb) {
      for (const [id] of this.kb.assets) ids.add(id);
    }
    if (this.campaignEngine) {
      for (const [, c] of this.campaignEngine.campaigns) {
        for (const tid of c.target_ids) ids.add(tid);
      }
    }
    return [...ids];
  }

  // ─── Persistence ────────────────────────────────────────────────

  save() {
    const filePath = path.join(FORECAST_DIR, 'yield-forecast.json');

    const data = {
      version: '0.8',
      saved_at: Date.now(),
      forecasts: [...this.forecasts.entries()],
      portfolio_forecast: this.portfolioForecast,
      forecast_history: this.forecastHistory.slice(-500),
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(FORECAST_DIR, 'yield-forecast.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      this.forecasts = new Map(
        (data.forecasts || []).map(([k, v]) => [k, new YieldForecast(v)])
      );
      this.portfolioForecast = data.portfolio_forecast
        ? new YieldForecast(data.portfolio_forecast)
        : null;
      this.forecastHistory = data.forecast_history || [];

      return true;
    } catch (_) {
      return false;
    }
  }
}

module.exports = { YieldForecaster, YieldForecast, FORECAST_DIR, DEFAULT_SEVERITY_DIST };

