/**
 * BOQA campaign-forecaster.js — Campaign Forecaster v0.8
 *
 * Predicts which campaign shapes maximize discovery output.
 * Analyzes historical campaign data to determine optimal:
 *
 *   - Campaign type (continuous_scan vs goal_based vs coverage)
 *   - Target selection and grouping
 *   - Budget allocation (workers, duration, hypotheses)
 *   - Schedule timing (when to run campaigns)
 *   - Category focus (which vulnerability categories to target)
 *
 * Campaign shape prediction model:
 *   campaign_effectiveness = type_factor × target_match × budget_optimality ×
 *                           timing_factor × category_alignment
 *
 * The forecaster generates:
 *   - Campaign shape recommendations
 *   - Expected output estimates per shape
 *   - Optimal budget allocations
 *   - Best time-to-run estimates
 *   - Shape comparison (which shape would have been better)
 *
 * Safe mode: forecasts are analytical only; campaign execution
 * still requires explicit authorization and respects all constraints.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const CAMPAIGN_FORECAST_DIR = path.join(__dirname, 'output', 'knowledge', 'campaign-forecasts');

// ─── Campaign Shape Types ───────────────────────────────────────────

const CAMPAIGN_SHAPES = {
  CONTINUOUS_WIDE:    'continuous_wide',    // Many targets, continuous, broad scope
  CONTINUOUS_DEEP:    'continuous_deep',    // Few targets, continuous, deep scope
  GOAL_ORIENTED:      'goal_oriented',      // Goal-based, focused on specific finding count
  COVERAGE_DRIVEN:    'coverage_driven',    // Coverage campaign to reach target %
  SCHEDULED_BURST:    'scheduled_burst',    // Scheduled short bursts
  CATEGORY_FOCUSED:   'category_focused',   // Focus on specific vulnerability categories
  REGRESSION_WATCH:   'regression_watch',   // Monitor for regressions on known targets
};

// =====================================================================
//  CampaignShape
// =====================================================================

class CampaignShape {
  constructor(data = {}) {
    this.id = data.id || `SHAPE-${crypto.randomUUID().substring(0, 8)}`;
    this.type = data.type || CAMPAIGN_SHAPES.CONTINUOUS_WIDE;
    this.name = data.name || this.type;
    this.description = data.description || '';

    // Shape parameters
    this.target_ids = data.target_ids || [];
    this.max_workers = data.max_workers || 4;
    this.max_duration_ms = data.max_duration_ms || 86400000;
    this.max_hypotheses_per_run = data.max_hypotheses_per_run || 50;
    this.categories = data.categories || [];
    this.scope = data.scope || {};

    // Schedule
    this.interval_ms = data.interval_ms || 300000;
    this.schedule_type = data.schedule_type || 'continuous'; // continuous, scheduled, burst

    // Expected output (from forecast)
    this.expected_output = data.expected_output || {
      bugs: 0,
      coverage_delta: 0,
      hypotheses: 0,
      verifications: 0,
    };

    // Effectiveness score (0-100)
    this.effectiveness_score = data.effectiveness_score || 0;

    // Confidence
    this.confidence = data.confidence || 0;
  }
}

// =====================================================================
//  CampaignForecastResult
// =====================================================================

class CampaignForecastResult {
  constructor(data = {}) {
    this.id = data.id || `CF-${crypto.randomUUID().substring(0, 8)}`;
    this.generated_at = data.generated_at || Date.now();

    // Recommended shapes
    this.recommended_shapes = data.recommended_shapes || [];

    // Comparison with current campaigns
    this.current_vs_recommended = data.current_vs_recommended || null;

    // Optimal budget allocation
    this.optimal_budget = data.optimal_budget || null;

    // Best time to run
    this.best_time = data.best_time || null;

    // Expected portfolio yield
    this.expected_portfolio_yield = data.expected_portfolio_yield || 0;

    this.model_version = data.model_version || '0.8';
  }
}

// =====================================================================
//  CampaignForecaster
// =====================================================================

class CampaignForecaster {
  /**
   * @param {object} options
   * @param {object} [options.predictionEngine]    - PredictionEngine instance
   * @param {object} [options.yieldForecaster]     - YieldForecaster instance
   * @param {object} [options.riskForecaster]      - RiskForecaster instance
   * @param {object} [options.campaignEngine]      - CampaignEngine instance
   * @param {object} [options.knowledgeBase]       - KnowledgeBase instance
   * @param {object} [options.brainRegistry]        - BrainRegistry instance
   * @param {object} [options.learningEngine]       - LearningEngine instance
   * @param {object} [options.resourceOptimizer]    - ResourceOptimizer instance
   */
  constructor(options = {}) {
    this.predictionEngine = options.predictionEngine || null;
    this.yieldForecaster = options.yieldForecaster || null;
    this.riskForecaster = options.riskForecaster || null;
    this.campaignEngine = options.campaignEngine || null;
    this.kb = options.knowledgeBase || null;
    this.brainRegistry = options.brainRegistry || null;
    this.learningEngine = options.learningEngine || null;
    this.resourceOptimizer = options.resourceOptimizer || null;

    /** @type {CampaignForecastResult|null} latest forecast */
    this.latestForecast = null;

    /** @type {object[]} forecast history */
    this.forecastHistory = [];

    /** @type {Map<string, number>} campaign_type → effectiveness score */
    this.shapeEffectiveness = new Map();

    // Initialize default shape effectiveness
    for (const shape of Object.values(CAMPAIGN_SHAPES)) {
      this.shapeEffectiveness.set(shape, 0.5);
    }

    // Ensure directory exists
    fs.mkdirSync(CAMPAIGN_FORECAST_DIR, { recursive: true });

    // Auto-load
    this.load();
  }

  // ─── Campaign Forecast ──────────────────────────────────────────

  /**
   * Generate a campaign forecast with recommended shapes.
   *
   * @param {object} [options] - { target_ids, max_workers, categories }
   * @returns {CampaignForecastResult}
   */
  forecast(options = {}) {
    const startTime = Date.now();

    // Step 1: Collect available targets
    const targetIds = options.target_ids || this._collectTargetIds();
    const maxWorkers = options.max_workers || 8;

    // Step 2: Generate candidate shapes
    const shapes = this._generateCandidateShapes(targetIds, maxWorkers, options);

    // Step 3: Score each shape (with error resilience)
    for (const shape of shapes) {
      try {
        this._scoreShape(shape);
      } catch (err) {
        // If scoring fails, assign default scores
        shape.effectiveness_score = 30;
        shape.confidence = 0.3;
        shape.expected_output = { bugs: 0, coverage_delta: 5, hypotheses: 0, verifications: 0 };
      }
    }

    // Step 4: Sort by effectiveness
    shapes.sort((a, b) => b.effectiveness_score - a.effectiveness_score);

    // Step 5: Compare with current campaigns
    const currentVsRecommended = this._compareWithCurrent(shapes);

    // Step 6: Compute optimal budget
    const optimalBudget = this._computeOptimalBudget(shapes, maxWorkers);

    // Step 7: Determine best time
    const bestTime = this._computeBestTime(shapes);

    // Step 8: Compute expected portfolio yield
    const expectedYield = shapes.length > 0
      ? shapes[0].expected_output.bugs
      : 0;

    const result = new CampaignForecastResult({
      recommended_shapes: shapes,
      current_vs_recommended: currentVsRecommended,
      optimal_budget: optimalBudget,
      best_time: bestTime,
      expected_portfolio_yield: expectedYield,
    });

    this.latestForecast = result;
    this.forecastHistory.push({
      forecast_id: result.id,
      recommended_type: shapes[0]?.type || null,
      expected_yield: expectedYield,
      generated_at: result.generated_at,
    });

    if (this.forecastHistory.length > 500) {
      this.forecastHistory = this.forecastHistory.slice(-500);
    }

    return result;
  }

  // ─── Shape Generation ───────────────────────────────────────────

  _generateCandidateShapes(targetIds, maxWorkers, options) {
    const shapes = [];
    const categories = options.categories || [];

    // Get target predictions for informed shaping
    const targetPredictions = this.predictionEngine
      ? this.predictionEngine.predictAllTargets()
      : [];

    // Sort targets by predicted yield
    const sortedTargets = [...targetPredictions].sort((a, b) => b.predicted_yield - a.predicted_yield);
    const highYieldTargets = sortedTargets.slice(0, 5).map(t => t.target_id);
    const allTargets = sortedTargets.map(t => t.target_id);

    // Shape 1: Continuous Wide — all targets, broad scope
    shapes.push(new CampaignShape({
      type: CAMPAIGN_SHAPES.CONTINUOUS_WIDE,
      name: 'Continuous Wide Scan',
      description: 'Broad continuous scan across all targets',
      target_ids: allTargets.length > 0 ? allTargets : targetIds,
      max_workers: maxWorkers,
      max_duration_ms: 86400000,
      max_hypotheses_per_run: 50,
      interval_ms: 300000,
      schedule_type: 'continuous',
    }));

    // Shape 2: Continuous Deep — top targets only, deep exploration
    shapes.push(new CampaignShape({
      type: CAMPAIGN_SHAPES.CONTINUOUS_DEEP,
      name: 'Continuous Deep Scan',
      description: 'Deep continuous scan on high-yield targets',
      target_ids: highYieldTargets.length > 0 ? highYieldTargets : targetIds.slice(0, 3),
      max_workers: Math.min(maxWorkers, 4),
      max_duration_ms: 86400000,
      max_hypotheses_per_run: 100,
      interval_ms: 180000,
      schedule_type: 'continuous',
    }));

    // Shape 3: Goal Oriented — target specific bug count
    shapes.push(new CampaignShape({
      type: CAMPAIGN_SHAPES.GOAL_ORIENTED,
      name: 'Goal-Oriented Discovery',
      description: 'Focused discovery targeting 10 confirmed bugs',
      target_ids: highYieldTargets.length > 0 ? highYieldTargets : targetIds.slice(0, 3),
      max_workers: Math.min(maxWorkers, 6),
      max_duration_ms: 43200000, // 12 hours
      max_hypotheses_per_run: 75,
      scope: { finding_target: 10 },
      schedule_type: 'continuous',
    }));

    // Shape 4: Coverage Driven — reach 90% coverage
    shapes.push(new CampaignShape({
      type: CAMPAIGN_SHAPES.COVERAGE_DRIVEN,
      name: 'Coverage Expansion',
      description: 'Drive coverage to 90% across all targets',
      target_ids: allTargets.length > 0 ? allTargets : targetIds,
      max_workers: maxWorkers,
      max_duration_ms: 172800000, // 48 hours
      max_hypotheses_per_run: 40,
      scope: { coverage_target: 90 },
      schedule_type: 'continuous',
    }));

    // Shape 5: Scheduled Burst — periodic short bursts
    shapes.push(new CampaignShape({
      type: CAMPAIGN_SHAPES.SCHEDULED_BURST,
      name: 'Scheduled Burst Scan',
      description: 'Short intensive scans every 2 hours',
      target_ids: allTargets.length > 0 ? allTargets : targetIds,
      max_workers: maxWorkers,
      max_duration_ms: 3600000, // 1 hour per burst
      max_hypotheses_per_run: 30,
      interval_ms: 7200000, // every 2 hours
      schedule_type: 'scheduled',
    }));

    // Shape 6: Category Focused — target specific vulnerability categories
    if (categories.length > 0 || this.learningEngine) {
      const topCategories = this._getTopCategories();
      shapes.push(new CampaignShape({
        type: CAMPAIGN_SHAPES.CATEGORY_FOCUSED,
        name: 'Category-Focused Discovery',
        description: `Focus on ${topCategories.join(', ')}`,
        target_ids: allTargets.length > 0 ? allTargets : targetIds,
        max_workers: Math.min(maxWorkers, 6),
        max_duration_ms: 86400000,
        max_hypotheses_per_run: 60,
        categories: topCategories,
        schedule_type: 'continuous',
      }));
    }

    // Shape 7: Regression Watch — monitor for regressions
    shapes.push(new CampaignShape({
      type: CAMPAIGN_SHAPES.REGRESSION_WATCH,
      name: 'Regression Watch',
      description: 'Monitor for security regressions on known targets',
      target_ids: allTargets.length > 0 ? allTargets : targetIds,
      max_workers: Math.min(maxWorkers, 3),
      max_duration_ms: 604800000, // 7 days
      max_hypotheses_per_run: 20,
      interval_ms: 600000, // every 10 minutes
      schedule_type: 'continuous',
    }));

    return shapes;
  }

  _scoreShape(shape) {
    let score = 0;

    // Type effectiveness from historical data
    const typeEffectiveness = this.shapeEffectiveness.get(shape.type) || 0.5;
    score += typeEffectiveness * 25;

    // Target quality — higher predicted yield targets = better score
    let targetYield;
    try {
      targetYield = this._estimateShapeTargetYield(shape);
    } catch (_) {
      targetYield = 0.5;
    }
    score += targetYield * 25;

    // Budget optimality — is the budget well-matched to the shape?
    let budgetOptimality;
    try {
      budgetOptimality = this._assessBudgetOptimality(shape);
    } catch (_) {
      budgetOptimality = 0.5;
    }
    score += budgetOptimality * 20;

    // Risk alignment — does the shape address high-risk areas?
    let riskAlignment;
    try {
      riskAlignment = this._assessRiskAlignment(shape);
    } catch (_) {
      riskAlignment = 0.3;
    }
    score += riskAlignment * 15;

    // Category alignment — does the shape focus on productive categories?
    let categoryAlignment;
    try {
      categoryAlignment = this._assessCategoryAlignment(shape);
    } catch (_) {
      categoryAlignment = 0.5;
    }
    score += categoryAlignment * 15;

    shape.effectiveness_score = Math.round(Math.min(100, score));
    shape.confidence = this._computeShapeConfidence(shape);

    // Estimate output
    shape.expected_output = {
      bugs: Math.round(targetYield * shape.target_ids.length * 0.5 * 100) / 100,
      coverage_delta: shape.type === CAMPAIGN_SHAPES.COVERAGE_DRIVEN ? 15 :
                      shape.type === CAMPAIGN_SHAPES.CONTINUOUS_WIDE ? 8 : 5,
      hypotheses: shape.max_hypotheses_per_run * 10,
      verifications: shape.max_hypotheses_per_run * 5,
    };
  }

  _estimateShapeTargetYield(shape) {
    if (!this.predictionEngine) return 0.5;

    let totalYield = 0;
    for (const targetId of shape.target_ids) {
      const prediction = this.predictionEngine.getTargetPrediction(targetId);
      totalYield += prediction ? prediction.predicted_yield : 0.5;
    }

    return shape.target_ids.length > 0 ? totalYield / shape.target_ids.length : 0;
  }

  _assessBudgetOptimality(shape) {
    // More workers = better up to a point
    const workerOptimality = shape.max_workers <= 6 ? 0.8 : shape.max_workers <= 8 ? 0.9 : 0.7;

    // Duration should match shape type
    const durationHours = shape.max_duration_ms / 3600000;
    let durationOptimality = 0.5;
    if (shape.type === CAMPAIGN_SHAPES.SCHEDULED_BURST && durationHours <= 2) durationOptimality = 0.9;
    else if (shape.type === CAMPAIGN_SHAPES.CONTINUOUS_DEEP && durationHours >= 12) durationOptimality = 0.9;
    else if (shape.type === CAMPAIGN_SHAPES.REGRESSION_WATCH && durationHours >= 168) durationOptimality = 0.9;
    else if (durationHours >= 6 && durationHours <= 48) durationOptimality = 0.8;

    return (workerOptimality + durationOptimality) / 2;
  }

  _assessRiskAlignment(shape) {
    if (!this.riskForecaster) return 0.5;

    try {
      let riskCoverage = 0;
      for (const targetId of shape.target_ids) {
        const forecast = this.riskForecaster.getTargetForecast(targetId);
        if (forecast && forecast.risk_score > 50) riskCoverage++;
      }

      return shape.target_ids.length > 0 ? riskCoverage / shape.target_ids.length : 0;
    } catch (_) {
      return 0.3;
    }
  }

  _assessCategoryAlignment(shape) {
    if (!this.learningEngine) return 0.5;

    if (shape.categories.length === 0) return 0.5; // broad = neutral

    const scores = this.learningEngine.getHypothesisSuccessScores();
    let totalSuccess = 0;
    for (const cat of shape.categories) {
      const catScore = scores.find(s => s.category === cat);
      totalSuccess += catScore ? catScore.success_rate : 0.2;
    }

    return Math.min(totalSuccess / shape.categories.length * 2, 1.0);
  }

  _computeShapeConfidence(shape) {
    const dataPoints = shape.target_ids.length;
    if (dataPoints >= 5) return 0.8;
    if (dataPoints >= 3) return 0.6;
    return 0.4;
  }

  // ─── Comparison and Optimization ────────────────────────────────

  _compareWithCurrent(recommendedShapes) {
    if (!this.campaignEngine) return null;

    const activeCampaigns = this.campaignEngine.list({ state: 'running' });
    if (activeCampaigns.length === 0) return { status: 'no_active_campaigns' };

    const topRecommended = recommendedShapes[0];
    if (!topRecommended) return null;

    const currentEffectiveness = activeCampaigns.reduce((s, c) =>
      s + (c.effectiveness.avg_verification_success_rate || 0), 0) / activeCampaigns.length;

    return {
      active_campaigns: activeCampaigns.length,
      current_avg_effectiveness: Math.round(currentEffectiveness * 100),
      recommended_effectiveness: topRecommended.effectiveness_score,
      improvement_potential: Math.round((topRecommended.effectiveness_score / 100 - currentEffectiveness) * 100),
    };
  }

  _computeOptimalBudget(shapes, maxWorkers) {
    const topShape = shapes[0];
    if (!topShape) return null;

    return {
      recommended_workers: Math.min(topShape.max_workers, maxWorkers),
      recommended_duration_hours: Math.round(topShape.max_duration_ms / 3600000),
      recommended_hypotheses_per_run: topShape.max_hypotheses_per_run,
      exploration_reserve: Math.max(1, Math.floor(maxWorkers * 0.15)),
      verification_reserve: Math.max(1, Math.floor(maxWorkers * 0.20)),
    };
  }

  _computeBestTime(shapes) {
    // Analyze historical campaign timing effectiveness
    const now = new Date();
    const hourOfDay = now.getHours();

    // Generally, business hours see more traffic and more potential issues
    const businessHoursScore = (hourOfDay >= 9 && hourOfDay <= 17) ? 0.8 : 0.4;
    const offHoursScore = (hourOfDay >= 22 || hourOfDay <= 6) ? 0.7 : 0.3;

    return {
      best_start: businessHoursScore > offHoursScore ? 'business_hours' : 'off_hours',
      business_hours_score: businessHoursScore,
      off_hours_score: offHoursScore,
      recommended_interval_minutes: shapes[0] ? shapes[0].interval_ms / 60000 : 5,
    };
  }

  _getTopCategories() {
    if (!this.learningEngine) return ['auth_bypass', 'csrf', 'cookie_security'];

    const scores = this.learningEngine.getHypothesisSuccessScores();
    return scores.slice(0, 5).map(s => s.category);
  }

  // ─── Shape Effectiveness Learning ───────────────────────────────

  /**
   * Update shape effectiveness based on campaign outcomes.
   *
   * @param {string} shapeType
   * @param {number} effectivenessScore - 0-1
   */
  updateShapeEffectiveness(shapeType, effectivenessScore) {
    const current = this.shapeEffectiveness.get(shapeType) || 0.5;
    const alpha = 0.3; // learning rate
    this.shapeEffectiveness.set(shapeType, current * (1 - alpha) + effectivenessScore * alpha);
  }

  /**
   * Learn from completed campaigns.
   */
  learnFromCampaigns() {
    if (!this.campaignEngine) return;

    const completed = this.campaignEngine.list({ state: 'completed' });
    for (const campaign of completed) {
      const shapeType = this._mapCampaignType(campaign.type);
      const effectiveness = campaign.effectiveness.avg_verification_success_rate || 0;
      this.updateShapeEffectiveness(shapeType, effectiveness);
    }
  }

  _mapCampaignType(campaignType) {
    const mapping = {
      continuous_scan: CAMPAIGN_SHAPES.CONTINUOUS_WIDE,
      scheduled_scan: CAMPAIGN_SHAPES.SCHEDULED_BURST,
      goal_based_scan: CAMPAIGN_SHAPES.GOAL_ORIENTED,
      coverage_campaign: CAMPAIGN_SHAPES.COVERAGE_DRIVEN,
    };
    return mapping[campaignType] || CAMPAIGN_SHAPES.CONTINUOUS_WIDE;
  }

  // ─── Query Methods ──────────────────────────────────────────────

  getLatestForecast() {
    return this.latestForecast;
  }

  getStats() {
    return {
      shape_effectiveness: [...this.shapeEffectiveness.entries()],
      forecast_history: this.forecastHistory.length,
      latest_recommendation: this.latestForecast?.recommended_shapes?.[0]?.type || null,
    };
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
    const filePath = path.join(CAMPAIGN_FORECAST_DIR, 'campaign-forecast.json');

    const data = {
      version: '0.8',
      saved_at: Date.now(),
      shape_effectiveness: [...this.shapeEffectiveness.entries()],
      forecast_history: this.forecastHistory.slice(-200),
      latest_forecast: this.latestForecast,
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(CAMPAIGN_FORECAST_DIR, 'campaign-forecast.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      this.shapeEffectiveness = new Map(data.shape_effectiveness || []);
      this.forecastHistory = data.forecast_history || [];
      this.latestForecast = data.latest_forecast || null;

      return true;
    } catch (_) {
      return false;
    }
  }
}

module.exports = {
  CampaignForecaster,
  CampaignShape,
  CampaignForecastResult,
  CAMPAIGN_SHAPES,
  CAMPAIGN_FORECAST_DIR,
};

