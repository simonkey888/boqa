/**
 * BOQA forecast-dashboard.js — Forecast Dashboard v0.8
 *
 * Data module for the predictive discovery dashboard panels.
 * Provides aggregated data feeds for:
 *
 *   - Yield Forecast panel:       predicted yield per target with confidence bands
 *   - Risk Forecast panel:        regression risk per target with trend
 *   - Prediction Confidence panel: prediction accuracy and quality metrics
 *   - Next Best Action panel:     prioritized action recommendations
 *   - Campaign Forecast panel:    recommended campaign shapes
 *
 * This module is consumed by the dashboard app.js via API endpoints
 * and provides pre-computed dashboard-ready data structures that
 * minimize client-side processing.
 *
 * Data feeds are cached and refreshed on configurable intervals.
 *
 * Safe mode: all dashboard data is read-only analytical output.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Refresh Intervals ──────────────────────────────────────────────

const DEFAULT_REFRESH_MS = 30000; // 30 seconds

// =====================================================================
//  ForecastDashboard
// =====================================================================

class ForecastDashboard {
  /**
   * @param {object} options
   * @param {object} [options.predictionEngine]    - PredictionEngine instance
   * @param {object} [options.yieldForecaster]     - YieldForecaster instance
   * @param {object} [options.riskForecaster]      - RiskForecaster instance
   * @param {object} [options.campaignForecaster]  - CampaignForecaster instance
   * @param {object} [options.priorityShaper]      - PriorityShaper instance
   * @param {object} [options.knowledgeBase]       - KnowledgeBase instance
   * @param {object} [options.learningEngine]       - LearningEngine instance
   * @param {object} [options.evidenceQualityEngine] - EvidenceQualityEngine instance
   */
  constructor(options = {}) {
    this.predictionEngine = options.predictionEngine || null;
    this.yieldForecaster = options.yieldForecaster || null;
    this.riskForecaster = options.riskForecaster || null;
    this.campaignForecaster = options.campaignForecaster || null;
    this.priorityShaper = options.priorityShaper || null;
    this.kb = options.knowledgeBase || null;
    this.learningEngine = options.learningEngine || null;
    this.evidenceQuality = options.evidenceQualityEngine || null;

    /** @type {object} cached dashboard data */
    this.cache = {
      yield_forecast: null,
      risk_forecast: null,
      prediction_confidence: null,
      next_best_action: null,
      campaign_forecast: null,
      last_refresh: {
        yield_forecast: 0,
        risk_forecast: 0,
        prediction_confidence: 0,
        next_best_action: 0,
        campaign_forecast: 0,
      },
    };

    this.refreshIntervalMs = options.refreshIntervalMs || DEFAULT_REFRESH_MS;
  }

  // ─── Yield Forecast Data ────────────────────────────────────────

  /**
   * Get yield forecast panel data.
   *
   * @param {boolean} [forceRefresh]
   * @returns {object}
   */
  getYieldForecastData(forceRefresh = false) {
    if (!forceRefresh && this._isCached('yield_forecast')) {
      return this.cache.yield_forecast;
    }

    const data = {
      panel: 'yield_forecast',
      generated_at: Date.now(),

      // Portfolio summary
      portfolio: null,

      // Per-target forecasts
      targets: [],

      // Category forecasts
      top_categories: [],

      // Yield trend
      trend: 'stable',
    };

    // Portfolio forecast
    if (this.yieldForecaster) {
      try {
        const portfolioForecast = this.yieldForecaster.forecastPortfolio();
        data.portfolio = {
          expected_bugs: portfolioForecast.expected_bugs,
          severity_distribution: portfolioForecast.severity_distribution,
          verification_success_rate: portfolioForecast.verification_success_rate,
          evidence_readiness: portfolioForecast.evidence_readiness,
          confidence_band: portfolioForecast.confidence_band,
        };

        // Target forecasts
        const targetForecasts = this.yieldForecaster.getAllForecasts();
        data.targets = targetForecasts.slice(0, 20).map(f => ({
          target_id: f.target_id,
          expected_bugs: f.expected_bugs,
          severity_distribution: f.severity_distribution,
          verification_success_rate: f.verification_success_rate,
          evidence_readiness: f.evidence_readiness,
          confidence_band: f.confidence_band,
          yield_trend: f.yield_trend,
          trend_delta: f.trend_delta,
          time_to_discovery_hours: f.time_to_discovery_hours,
        }));

        data.trend = data.targets.length > 0
          ? data.targets.reduce((best, t) =>
              t.yield_trend === 'improving' ? 'improving' :
              t.yield_trend === 'declining' && best !== 'improving' ? 'declining' : best, 'stable')
          : 'stable';
      } catch (_) {}
    }

    // Category forecasts
    if (this.predictionEngine) {
      try {
        const catPredictions = this.predictionEngine.predictCategories().slice(0, 10);
        data.top_categories = catPredictions.map(p => ({
          category: p.category,
          predicted_yield: p.predicted_yield,
          confidence_band: p.confidence_band,
          prediction_quality: p.prediction_quality,
        }));
      } catch (_) {}
    }

    this.cache.yield_forecast = data;
    this.cache.last_refresh.yield_forecast = Date.now();
    return data;
  }

  // ─── Risk Forecast Data ─────────────────────────────────────────

  /**
   * Get risk forecast panel data.
   *
   * @param {boolean} [forceRefresh]
   * @returns {object}
   */
  getRiskForecastData(forceRefresh = false) {
    if (!forceRefresh && this._isCached('risk_forecast')) {
      return this.cache.risk_forecast;
    }

    const data = {
      panel: 'risk_forecast',
      generated_at: Date.now(),

      // Portfolio risk
      portfolio: null,

      // Per-target risk
      targets: [],

      // At-risk categories
      at_risk_categories: [],

      // Mitigations
      mitigations: [],
    };

    if (this.riskForecaster) {
      try {
        // Portfolio risk
        const portfolioRisk = this.riskForecaster.forecastPortfolio();
        data.portfolio = {
          risk_score: portfolioRisk.risk_score,
          risk_level: portfolioRisk.risk_level,
          regression_likelihood: portfolioRisk.regression_likelihood,
          risk_trend: portfolioRisk.risk_trend,
        };

        // Target risks
        const targetRisks = this.riskForecaster.getAllForecasts();
        data.targets = targetRisks.slice(0, 20).map(f => ({
          target_id: f.target_id,
          risk_score: f.risk_score,
          risk_level: f.risk_level,
          regression_likelihood: f.regression_likelihood,
          risk_factors: f.risk_factors,
          at_risk_categories: f.at_risk_categories,
          risk_trend: f.risk_trend,
          mitigation_count: f.mitigation_suggestions.length,
        }));

        // At-risk categories
        data.at_risk_categories = portfolioRisk.at_risk_categories || [];

        // Top mitigations
        data.mitigations = portfolioRisk.mitigation_suggestions || [];
      } catch (_) {}
    }

    this.cache.risk_forecast = data;
    this.cache.last_refresh.risk_forecast = Date.now();
    return data;
  }

  // ─── Prediction Confidence Data ─────────────────────────────────

  /**
   * Get prediction confidence panel data.
   *
   * @param {boolean} [forceRefresh]
   * @returns {object}
   */
  getPredictionConfidenceData(forceRefresh = false) {
    if (!forceRefresh && this._isCached('prediction_confidence')) {
      return this.cache.prediction_confidence;
    }

    const data = {
      panel: 'prediction_confidence',
      generated_at: Date.now(),

      // Overall accuracy
      accuracy: null,

      // Per-target confidence
      target_confidence: [],

      // Category prediction confidence
      category_confidence: [],

      // Model health
      model_health: null,

      // Shaper metrics
      shaper_metrics: null,
    };

    if (this.predictionEngine) {
      try {
        const accuracy = this.predictionEngine.getAccuracy();
        const stats = this.predictionEngine.getStats();

        data.accuracy = {
          total_predictions: accuracy.total_predictions,
          direction_accuracy: accuracy.total_predictions > 0
            ? Math.round((accuracy.correct_direction / accuracy.total_predictions) * 10000) / 100
            : null,
          mean_absolute_error: accuracy.mean_absolute_error,
          top_target_hit_rate: accuracy.top_target_hit_rate,
          last_computed: accuracy.last_computed,
        };

        // Per-target confidence
        const predictions = this.predictionEngine.getTargetPredictions();
        data.target_confidence = predictions.slice(0, 20).map(p => ({
          target_id: p.target_id,
          predicted_yield: p.predicted_yield,
          confidence_band: p.confidence_band,
          prediction_quality: p.prediction_quality,
          data_freshness_ms: p.data_freshness_ms,
        }));

        // Category confidence
        const catPredictions = this.predictionEngine.getCategoryPredictions();
        data.category_confidence = catPredictions.slice(0, 15).map(p => ({
          category: p.category,
          predicted_yield: p.predicted_yield,
          prediction_quality: p.prediction_quality,
        }));

        // Model health
        data.model_health = {
          total_targets_predicted: stats.target_predictions,
          total_endpoints_predicted: stats.endpoint_predictions,
          total_categories_predicted: stats.category_predictions,
          prediction_freshness_ms: stats.last_prediction_at
            ? Date.now() - stats.last_prediction_at : null,
          weights: stats.weights,
        };
      } catch (_) {}
    }

    // Shaper metrics
    if (this.priorityShaper) {
      try {
        data.shaper_metrics = this.priorityShaper.getStats();
      } catch (_) {}
    }

    this.cache.prediction_confidence = data;
    this.cache.last_refresh.prediction_confidence = Date.now();
    return data;
  }

  // ─── Next Best Action Data ──────────────────────────────────────

  /**
   * Get next best action panel data.
   *
   * @param {boolean} [forceRefresh]
   * @returns {object}
   */
  getNextBestActionData(forceRefresh = false) {
    if (!forceRefresh && this._isCached('next_best_action')) {
      return this.cache.next_best_action;
    }

    const data = {
      panel: 'next_best_action',
      generated_at: Date.now(),

      // Action queue
      actions: [],

      // Summary
      summary: {
        total_actions: 0,
        by_type: {},
        top_priority: null,
      },
    };

    if (this.priorityShaper) {
      try {
        const actions = this.priorityShaper.getNextBestAction(15);
        data.actions = actions.map(a => ({
          id: a.id,
          action_type: a.action_type,
          target_id: a.target_id,
          endpoint: a.endpoint,
          category: a.category,
          priority: a.priority,
          expected_value: a.expected_value,
          reasoning: a.reasoning,
          confidence: a.confidence,
          estimated_effort_ms: a.estimated_effort_ms,
        }));

        data.summary.total_actions = actions.length;

        // Group by type
        const byType = {};
        for (const a of actions) {
          byType[a.action_type] = (byType[a.action_type] || 0) + 1;
        }
        data.summary.by_type = byType;

        if (actions.length > 0) {
          data.summary.top_priority = {
            action_type: actions[0].action_type,
            target_id: actions[0].target_id,
            priority: actions[0].priority,
          };
        }
      } catch (_) {}
    }

    this.cache.next_best_action = data;
    this.cache.last_refresh.next_best_action = Date.now();
    return data;
  }

  // ─── Campaign Forecast Data ─────────────────────────────────────

  /**
   * Get campaign forecast panel data.
   *
   * @param {boolean} [forceRefresh]
   * @returns {object}
   */
  getCampaignForecastData(forceRefresh = false) {
    if (!forceRefresh && this._isCached('campaign_forecast')) {
      return this.cache.campaign_forecast;
    }

    const data = {
      panel: 'campaign_forecast',
      generated_at: Date.now(),

      // Recommended campaign shapes
      recommended_shapes: [],

      // Current vs recommended comparison
      current_vs_recommended: null,

      // Optimal budget
      optimal_budget: null,

      // Best time
      best_time: null,

      // Shape effectiveness
      shape_effectiveness: [],
    };

    if (this.campaignForecaster) {
      try {
        const forecast = this.campaignForecaster.forecast();

        data.recommended_shapes = forecast.recommended_shapes.map(s => ({
          type: s.type,
          name: s.name,
          description: s.description,
          target_count: s.target_ids.length,
          max_workers: s.max_workers,
          duration_hours: Math.round(s.max_duration_ms / 3600000),
          expected_output: s.expected_output,
          effectiveness_score: s.effectiveness_score,
          confidence: s.confidence,
        }));

        data.current_vs_recommended = forecast.current_vs_recommended;
        data.optimal_budget = forecast.optimal_budget;
        data.best_time = forecast.best_time;

        // Shape effectiveness
        const stats = this.campaignForecaster.getStats();
        data.shape_effectiveness = stats.shape_effectiveness.map(([type, score]) => ({
          shape_type: type,
          effectiveness: Math.round(score * 100),
        }));
      } catch (_) {}
    }

    this.cache.campaign_forecast = data;
    this.cache.last_refresh.campaign_forecast = Date.now();
    return data;
  }

  // ─── Full Dashboard Data ────────────────────────────────────────

  /**
   * Get all dashboard panel data in one call.
   *
   * @param {boolean} [forceRefresh]
   * @returns {object}
   */
  getAllData(forceRefresh = false) {
    return {
      yield_forecast: this.getYieldForecastData(forceRefresh),
      risk_forecast: this.getRiskForecastData(forceRefresh),
      prediction_confidence: this.getPredictionConfidenceData(forceRefresh),
      next_best_action: this.getNextBestActionData(forceRefresh),
      campaign_forecast: this.getCampaignForecastData(forceRefresh),
      generated_at: Date.now(),
    };
  }

  // ─── Internal ───────────────────────────────────────────────────

  _isCached(panel) {
    const lastRefresh = this.cache.last_refresh[panel];
    return lastRefresh > 0 && (Date.now() - lastRefresh) < this.refreshIntervalMs;
  }
}

module.exports = { ForecastDashboard, DEFAULT_REFRESH_MS };

