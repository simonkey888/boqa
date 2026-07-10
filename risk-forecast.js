/**
 * BOQA risk-forecast.js — Risk Forecast v0.8
 *
 * Forecasts security regression likelihood by target and campaign.
 * Identifies targets at risk of regression (previously fixed bugs
 * reappearing) and campaigns likely to encounter security
 * degradation.
 *
 * Risk forecast inputs:
 *   - FindingMemory: regression history, cross-target patterns
 *   - TargetBrain: verification_history, coverage_trend
 *   - LearningEngine: category/target success rates
 *   - CampaignEngine: campaign effectiveness and history
 *   - PredictionEngine: predicted yields
 *   - KnowledgeBase: findings, validations
 *
 * Risk forecast outputs:
 *   - regression_likelihood:  probability of regression per target
 *   - risk_factors:           contributing factors to regression risk
 *   - at_risk_categories:     vulnerability categories likely to regress
 *   - campaign_risk:          risk level for active campaigns
 *   - risk_trend:             improving/declining/stable
 *   - mitigation_suggestions: recommended actions to reduce risk
 *
 * Regression prediction model:
 *   regression_risk = regression_history_weight × recent_regression_count +
 *                     coverage_regression_weight × coverage_decline_rate +
 *                     pattern_prevalence_weight × cross_target_pattern_count +
 *                     auth_change_weight × auth_complexity_delta
 *
 * Safe mode: risk forecasts are analytical only; they inform
 * monitoring and prioritization but never bypass constraints.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const RISK_FORECAST_DIR = path.join(__dirname, 'output', 'knowledge', 'risk-forecasts');

// ─── Risk Levels ────────────────────────────────────────────────────

const RISK_LEVELS = {
  CRITICAL: 'critical',
  HIGH:     'high',
  MEDIUM:   'medium',
  LOW:      'low',
  MINIMAL:  'minimal',
};

// ─── Default Weights ────────────────────────────────────────────────

const DEFAULT_RISK_WEIGHTS = {
  regression_history:   0.30,
  coverage_decline:     0.20,
  pattern_prevalence:   0.20,
  auth_complexity:      0.15,
  campaign_stress:      0.10,
  evidence_degradation: 0.05,
};

// =====================================================================
//  RiskForecast
// =====================================================================

class RiskForecast {
  constructor(data = {}) {
    this.id = data.id || `RF-${crypto.randomUUID().substring(0, 8)}`;
    this.target_id = data.target_id || null;
    this.scope = data.scope || 'target'; // target, campaign, portfolio

    // Risk assessment
    this.regression_likelihood = data.regression_likelihood || 0; // 0-1
    this.risk_level = data.risk_level || RISK_LEVELS.LOW;
    this.risk_score = data.risk_score || 0; // 0-100

    // Contributing factors
    this.risk_factors = data.risk_factors || {};
    this.at_risk_categories = data.at_risk_categories || [];

    // Trend
    this.risk_trend = data.risk_trend || 'stable'; // improving, declining, stable

    // Campaign-specific
    this.campaign_id = data.campaign_id || null;
    this.campaign_risk = data.campaign_risk || null;

    // Mitigations
    this.mitigation_suggestions = data.mitigation_suggestions || [];

    // Metadata
    this.generated_at = data.generated_at || Date.now();
    this.model_version = data.model_version || '0.8';
  }
}

// =====================================================================
//  RiskForecaster
// =====================================================================

class RiskForecaster {
  /**
   * @param {object} options
   * @param {object} [options.predictionEngine]    - PredictionEngine instance
   * @param {object} [options.knowledgeBase]       - KnowledgeBase instance
   * @param {object} [options.brainRegistry]        - BrainRegistry instance
   * @param {object} [options.learningEngine]       - LearningEngine instance
   * @param {object} [options.campaignEngine]       - CampaignEngine instance
   * @param {object} [options.findingMemory]        - FindingMemory instance
   * @param {object} [options.evidenceQualityEngine] - EvidenceQualityEngine instance
   */
  constructor(options = {}) {
    this.predictionEngine = options.predictionEngine || null;
    this.kb = options.knowledgeBase || null;
    this.brainRegistry = options.brainRegistry || null;
    this.learningEngine = options.learningEngine || null;
    this.campaignEngine = options.campaignEngine || null;
    this.findingMemory = options.findingMemory || null;
    this.evidenceQuality = options.evidenceQualityEngine || null;

    /** @type {Map<string, RiskForecast>} target_id → latest risk forecast */
    this.forecasts = new Map();

    /** @type {Map<string, RiskForecast>} campaign_id → latest campaign risk */
    this.campaignForecasts = new Map();

    /** @type {RiskForecast|null} portfolio-level risk */
    this.portfolioForecast = null;

    /** @type {object[]} forecast history */
    this.forecastHistory = [];

    this.weights = { ...DEFAULT_RISK_WEIGHTS };

    // Ensure directory exists
    fs.mkdirSync(RISK_FORECAST_DIR, { recursive: true });

    // Auto-load
    this.load();
  }

  // ─── Target Risk Forecast ───────────────────────────────────────

  /**
   * Generate a risk forecast for a single target.
   *
   * @param {string} targetId
   * @returns {RiskForecast}
   */
  forecastTarget(targetId) {
    const factors = this._computeRiskFactors(targetId);

    // Compute regression likelihood (0-1)
    let regressionLikelihood = 0;
    for (const [factor, value] of Object.entries(factors)) {
      const weight = this.weights[factor] || 0;
      regressionLikelihood += value * weight;
    }

    regressionLikelihood = Math.min(1.0, Math.max(0, regressionLikelihood));

    // Compute risk score (0-100)
    const riskScore = Math.round(regressionLikelihood * 100);

    // Determine risk level
    const riskLevel = this._determineRiskLevel(riskScore);

    // Identify at-risk categories
    const atRiskCategories = this._identifyAtRiskCategories(targetId);

    // Determine trend
    const trend = this._computeRiskTrend(targetId);

    // Generate mitigations
    const mitigations = this._generateMitigations(targetId, factors, riskLevel);

    const forecast = new RiskForecast({
      target_id: targetId,
      scope: 'target',
      regression_likelihood: Math.round(regressionLikelihood * 1000) / 1000,
      risk_level: riskLevel,
      risk_score: riskScore,
      risk_factors: factors,
      at_risk_categories: atRiskCategories,
      risk_trend: trend,
      mitigation_suggestions: mitigations,
    });

    this.forecasts.set(targetId, forecast);
    this.forecastHistory.push({
      forecast_id: forecast.id,
      target_id: targetId,
      risk_score: riskScore,
      risk_level: riskLevel,
      generated_at: forecast.generated_at,
    });

    if (this.forecastHistory.length > 5000) {
      this.forecastHistory = this.forecastHistory.slice(-5000);
    }

    return forecast;
  }

  /**
   * Generate risk forecasts for all known targets.
   *
   * @returns {RiskForecast[]}
   */
  forecastAllTargets() {
    const targetIds = this._collectTargetIds();
    const forecasts = [];

    for (const targetId of targetIds) {
      forecasts.push(this.forecastTarget(targetId));
    }

    forecasts.sort((a, b) => b.risk_score - a.risk_score);
    return forecasts;
  }

  // ─── Campaign Risk Forecast ─────────────────────────────────────

  /**
   * Generate a risk forecast for a campaign.
   *
   * @param {string} campaignId
   * @returns {RiskForecast}
   */
  forecastCampaign(campaignId) {
    if (!this.campaignEngine) {
      return new RiskForecast({ campaign_id: campaignId, risk_level: RISK_LEVELS.LOW });
    }

    const campaign = this.campaignEngine.get(campaignId);
    if (!campaign) {
      return new RiskForecast({ campaign_id: campaignId, risk_level: RISK_LEVELS.LOW });
    }

    // Aggregate risk across campaign targets
    let totalRisk = 0;
    const targetRisks = [];

    for (const targetId of campaign.target_ids) {
      const targetForecast = this.forecastTarget(targetId);
      totalRisk += targetForecast.risk_score;
      targetRisks.push({
        target_id: targetId,
        risk_score: targetForecast.risk_score,
        risk_level: targetForecast.risk_level,
      });
    }

    const avgRisk = campaign.target_ids.length > 0 ? totalRisk / campaign.target_ids.length : 0;

    // Campaign-specific stress factor
    const budgetUsage = campaign.started_at
      ? (Date.now() - campaign.started_at) / (campaign.budget.max_duration_ms || 86400000)
      : 0;
    const stressFactor = budgetUsage > 0.8 ? 1.2 : budgetUsage > 0.5 ? 1.0 : 0.8;

    const campaignRiskScore = Math.min(100, Math.round(avgRisk * stressFactor));

    const forecast = new RiskForecast({
      target_id: 'campaign',
      scope: 'campaign',
      campaign_id: campaignId,
      campaign_risk: {
        avg_target_risk: Math.round(avgRisk),
        budget_usage: Math.round(budgetUsage * 100),
        stress_factor: Math.round(stressFactor * 100) / 100,
        target_risks: targetRisks,
      },
      regression_likelihood: campaignRiskScore / 100,
      risk_level: this._determineRiskLevel(campaignRiskScore),
      risk_score: campaignRiskScore,
      risk_factors: {
        avg_target_risk: avgRisk / 100,
        budget_stress: budgetUsage,
        effectiveness: campaign.effectiveness.bugs_per_iteration > 0 ? 0.2 : 0.5,
      },
      at_risk_categories: targetRisks.flatMap(tr =>
        this.forecasts.get(tr.target_id)?.at_risk_categories || []
      ),
      mitigation_suggestions: this._campaignMitigations(campaign, campaignRiskScore),
    });

    this.campaignForecasts.set(campaignId, forecast);
    return forecast;
  }

  // ─── Portfolio Risk Forecast ────────────────────────────────────

  /**
   * Generate a portfolio-level risk forecast.
   *
   * @returns {RiskForecast}
   */
  forecastPortfolio() {
    const allForecasts = this.forecastAllTargets();

    const totalTargets = allForecasts.length;
    const avgRisk = totalTargets > 0
      ? allForecasts.reduce((s, f) => s + f.risk_score, 0) / totalTargets
      : 0;

    const criticalCount = allForecasts.filter(f => f.risk_level === RISK_LEVELS.CRITICAL).length;
    const highCount = allForecasts.filter(f => f.risk_level === RISK_LEVELS.HIGH).length;

    // Aggregate at-risk categories
    const categoryCounts = {};
    for (const f of allForecasts) {
      for (const cat of f.at_risk_categories) {
        categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
      }
    }

    const topAtRisk = Object.entries(categoryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([cat, count]) => ({ category: cat, affected_targets: count }));

    this.portfolioForecast = new RiskForecast({
      target_id: 'portfolio',
      scope: 'portfolio',
      regression_likelihood: Math.round(avgRisk / 100 * 1000) / 1000,
      risk_level: this._determineRiskLevel(Math.round(avgRisk)),
      risk_score: Math.round(avgRisk),
      risk_factors: {
        critical_targets: criticalCount / Math.max(totalTargets, 1),
        high_risk_targets: highCount / Math.max(totalTargets, 1),
        avg_risk_score: avgRisk,
      },
      at_risk_categories: topAtRisk,
      risk_trend: this._portfolioRiskTrend(allForecasts),
      mitigation_suggestions: this._portfolioMitigations(allForecasts),
    });

    return this.portfolioForecast;
  }

  // ─── Query Methods ──────────────────────────────────────────────

  getTargetForecast(targetId) {
    return this.forecasts.get(targetId) || null;
  }

  getCampaignForecast(campaignId) {
    return this.campaignForecasts.get(campaignId) || null;
  }

  getAllForecasts() {
    return [...this.forecasts.values()]
      .sort((a, b) => b.risk_score - a.risk_score);
  }

  getStats() {
    const forecasts = [...this.forecasts.values()];
    return {
      total_forecasts: forecasts.length,
      critical_targets: forecasts.filter(f => f.risk_level === RISK_LEVELS.CRITICAL).length,
      high_risk_targets: forecasts.filter(f => f.risk_level === RISK_LEVELS.HIGH).length,
      avg_risk_score: forecasts.length > 0
        ? Math.round(forecasts.reduce((s, f) => s + f.risk_score, 0) / forecasts.length)
        : 0,
      campaign_forecasts: this.campaignForecasts.size,
      portfolio_risk: this.portfolioForecast?.risk_score || 0,
      forecast_history: this.forecastHistory.length,
    };
  }

  // ─── Risk Factor Computation ────────────────────────────────────

  _computeRiskFactors(targetId) {
    return {
      regression_history:   this._factorRegressionHistory(targetId),
      coverage_decline:     this._factorCoverageDecline(targetId),
      pattern_prevalence:   this._factorPatternPrevalence(targetId),
      auth_complexity:      this._factorAuthComplexity(targetId),
      campaign_stress:      this._factorCampaignStress(targetId),
      evidence_degradation: this._factorEvidenceDegradation(targetId),
    };
  }

  _factorRegressionHistory(targetId) {
    if (!this.findingMemory) return 0;

    const regressions = this.findingMemory.getRegressions({ target_id: targetId });
    if (regressions.length === 0) return 0;

    // Recent regressions weighted more heavily
    const now = Date.now();
    let weightedScore = 0;
    for (const reg of regressions) {
      const age = (now - reg.ts) / (30 * 86400000); // months
      weightedScore += 1.0 / (1.0 + age);
    }

    return Math.min(weightedScore / 5, 1.0);
  }

  _factorCoverageDecline(targetId) {
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    if (!brain || brain.coverageTrend.length < 2) return 0;

    const trend = brain.coverageTrend;
    const recent = trend.slice(-5);
    if (recent.length < 2) return 0;

    // Check if coverage is declining
    const first = recent[0].score;
    const last = recent[recent.length - 1].score;
    const decline = first - last;

    if (decline > 0) {
      return Math.min(decline / 20, 1.0); // 20% decline = max factor
    }
    return 0;
  }

  _factorPatternPrevalence(targetId) {
    if (!this.findingMemory) return 0;

    const patterns = this.findingMemory.getPatternsForTarget(targetId);
    const crossTarget = patterns.filter(p => p.target_count >= 3);

    if (crossTarget.length === 0) return 0;

    // High-prevalence patterns suggest industry-wide issues
    const avgConfidence = crossTarget.reduce((s, p) => s + p.confidence, 0) / crossTarget.length;
    return Math.min(avgConfidence, 1.0);
  }

  _factorAuthComplexity(targetId) {
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    if (!brain) return 0;

    const authModels = brain.authModels || [];
    if (authModels.length === 0) return 0;

    // More auth models and hybrid models increase risk
    const hasHybrid = authModels.some(m => m.type === 'hybrid');
    const hasRisks = authModels.some(m => m.risk_flags && m.risk_flags.length > 0);

    let factor = Math.min(authModels.length / 3, 1.0) * 0.3;
    if (hasHybrid) factor += 0.3;
    if (hasRisks) factor += 0.3;

    return Math.min(factor, 1.0);
  }

  _factorCampaignStress(targetId) {
    if (!this.campaignEngine) return 0;

    const campaigns = this.campaignEngine.list({ target_id: targetId, state: 'running' });
    if (campaigns.length === 0) return 0;

    // Multiple concurrent campaigns increase stress
    const stressLevel = Math.min(campaigns.length / 3, 1.0) * 0.5;

    // Budget pressure
    const avgBudgetUsage = campaigns.reduce((s, c) => {
      if (!c.started_at) return s;
      return s + (Date.now() - c.started_at) / (c.budget.max_duration_ms || 86400000);
    }, 0) / campaigns.length;

    return Math.min(stressLevel + avgBudgetUsage * 0.3, 1.0);
  }

  _factorEvidenceDegradation(targetId) {
    if (!this.evidenceQuality) return 0;

    const stats = this.evidenceQuality.getStats();
    // Low evidence readiness suggests risk of findings being challenged
    const readinessRate = stats.readiness_rate || 0;

    if (readinessRate < 0.2) return 0.5;
    if (readinessRate < 0.5) return 0.3;
    return 0;
  }

  _determineRiskLevel(riskScore) {
    if (riskScore >= 80) return RISK_LEVELS.CRITICAL;
    if (riskScore >= 60) return RISK_LEVELS.HIGH;
    if (riskScore >= 35) return RISK_LEVELS.MEDIUM;
    if (riskScore >= 15) return RISK_LEVELS.LOW;
    return RISK_LEVELS.MINIMAL;
  }

  _identifyAtRiskCategories(targetId) {
    const categories = [];

    // Check which categories have regression history
    if (this.findingMemory) {
      const regressions = this.findingMemory.getRegressions({ target_id: targetId });
      for (const reg of regressions) {
        if (reg.category && !categories.includes(reg.category)) {
          categories.push(reg.category);
        }
      }
    }

    // Add categories with low verification success
    if (this.learningEngine) {
      const targetLearning = this.learningEngine.targetLearning.get(targetId);
      if (targetLearning) {
        for (const [cat, rate] of targetLearning.category_rates) {
          if (rate.confirmed / rate.total > 0.3 && !categories.includes(cat)) {
            categories.push(cat);
          }
        }
      }
    }

    return categories.slice(0, 10);
  }

  _computeRiskTrend(targetId) {
    const history = this.forecastHistory.filter(f => f.target_id === targetId);
    if (history.length < 2) return 'stable';

    const recent = history.slice(-5);
    const older = history.slice(-10, -5);

    if (older.length === 0) return 'stable';

    const recentAvg = recent.reduce((s, f) => s + f.risk_score, 0) / recent.length;
    const olderAvg = older.reduce((s, f) => s + f.risk_score, 0) / older.length;

    const delta = recentAvg - olderAvg;
    if (delta > 10) return 'declining'; // risk increasing = declining security
    if (delta < -10) return 'improving';
    return 'stable';
  }

  _generateMitigations(targetId, factors, riskLevel) {
    const mitigations = [];

    if (factors.regression_history > 0.3) {
      mitigations.push({
        action: 'increase_regression_monitoring',
        priority: 'high',
        detail: 'High regression history — increase monitoring frequency and enable automatic regression alerts',
      });
    }

    if (factors.coverage_decline > 0.2) {
      mitigations.push({
        action: 'investigate_coverage_decline',
        priority: 'high',
        detail: 'Coverage is declining — investigate whether endpoints are being removed or access patterns changed',
      });
    }

    if (factors.auth_complexity > 0.5) {
      mitigations.push({
        action: 'audit_auth_implementation',
        priority: 'medium',
        detail: 'Complex auth model detected — schedule focused auth security audit',
      });
    }

    if (factors.pattern_prevalence > 0.5) {
      mitigations.push({
        action: 'apply_cross_target_patterns',
        priority: 'medium',
        detail: 'High-prevalence cross-target patterns detected — review fixes applied on other targets',
      });
    }

    if (riskLevel === RISK_LEVELS.CRITICAL || riskLevel === RISK_LEVELS.HIGH) {
      mitigations.push({
        action: 'escalate_to_security_team',
        priority: 'critical',
        detail: `${riskLevel.toUpperCase()} risk target — escalate for immediate review`,
      });
    }

    return mitigations;
  }

  _campaignMitigations(campaign, riskScore) {
    const mitigations = [];

    if (riskScore > 70) {
      mitigations.push({
        action: 'pause_campaign_review',
        priority: 'high',
        detail: 'High campaign risk — consider pausing and reviewing target health',
      });
    }

    if (campaign.budgetExceeded()) {
      mitigations.push({
        action: 'budget_exceeded_stop',
        priority: 'critical',
        detail: 'Campaign budget exceeded — stop and evaluate results before continuing',
      });
    }

    return mitigations;
  }

  _portfolioRiskTrend(forecasts) {
    const recentHistory = this.forecastHistory.slice(-20);
    if (recentHistory.length < 4) return 'stable';

    const half = Math.floor(recentHistory.length / 2);
    const first = recentHistory.slice(0, half);
    const second = recentHistory.slice(half);

    const avgFirst = first.reduce((s, f) => s + f.risk_score, 0) / first.length;
    const avgSecond = second.reduce((s, f) => s + f.risk_score, 0) / second.length;

    const delta = avgSecond - avgFirst;
    if (delta > 10) return 'declining';
    if (delta < -10) return 'improving';
    return 'stable';
  }

  _portfolioMitigations(forecasts) {
    const mitigations = [];
    const criticalTargets = forecasts.filter(f => f.risk_level === RISK_LEVELS.CRITICAL);

    if (criticalTargets.length > 0) {
      mitigations.push({
        action: 'prioritize_critical_targets',
        priority: 'critical',
        detail: `${criticalTargets.length} targets at critical risk — immediate attention required`,
      });
    }

    // Aggregate at-risk categories
    const catCounts = {};
    for (const f of forecasts) {
      for (const cat of f.at_risk_categories) {
        catCounts[cat] = (catCounts[cat] || 0) + 1;
      }
    }

    const topCat = Object.entries(catCounts).sort((a, b) => b[1] - a[1])[0];
    if (topCat && topCat[1] >= 2) {
      mitigations.push({
        action: 'category_wide_mitigation',
        priority: 'high',
        detail: `Category "${topCat[0]}" at risk across ${topCat[1]} targets — consider systematic fix`,
      });
    }

    return mitigations;
  }

  _collectTargetIds() {
    const ids = new Set();
    if (this.brainRegistry) {
      for (const [id] of this.brainRegistry.brains) ids.add(id);
    }
    if (this.kb) {
      for (const [id] of this.kb.assets) ids.add(id);
    }
    return [...ids];
  }

  // ─── Persistence ────────────────────────────────────────────────

  save() {
    const filePath = path.join(RISK_FORECAST_DIR, 'risk-forecast.json');

    const data = {
      version: '0.8',
      saved_at: Date.now(),
      weights: this.weights,
      forecasts: [...this.forecasts.entries()],
      campaign_forecasts: [...this.campaignForecasts.entries()],
      portfolio_forecast: this.portfolioForecast,
      forecast_history: this.forecastHistory.slice(-500),
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(RISK_FORECAST_DIR, 'risk-forecast.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      this.weights = data.weights || { ...DEFAULT_RISK_WEIGHTS };
      this.forecasts = new Map(
        (data.forecasts || []).map(([k, v]) => [k, new RiskForecast(v)])
      );
      this.campaignForecasts = new Map(
        (data.campaign_forecasts || []).map(([k, v]) => [k, new RiskForecast(v)])
      );
      this.portfolioForecast = data.portfolio_forecast
        ? new RiskForecast(data.portfolio_forecast)
        : null;
      this.forecastHistory = data.forecast_history || [];

      return true;
    } catch (_) {
      return false;
    }
  }
}

module.exports = { RiskForecaster, RiskForecast, RISK_LEVELS, RISK_FORECAST_DIR, DEFAULT_RISK_WEIGHTS };

