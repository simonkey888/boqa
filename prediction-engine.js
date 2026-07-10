/**
 * BOQA prediction-engine.js — Prediction Engine v0.8
 *
 * Core prediction model that converts target history, findings,
 * coverage, workflow graphs and evidence quality into a forecast
 * model that ranks future bug yield before verification runs.
 *
 * Prediction model inputs:
 *   - TargetBrain: historical_findings, asset_graph, workflow_graph,
 *     auth_models, verification_history, coverage_trend
 *   - LearningEngine: category success rates, verification effectiveness,
 *     target-specific weights
 *   - FindingMemory: cross_target_patterns, similarity_graph
 *   - KnowledgeBase: findings, validations, coverage_maps
 *   - EvidenceQualityEngine: evidence readiness scores
 *   - CampaignEngine: campaign effectiveness data
 *
 * Prediction outputs:
 *   - Target yield predictions: expected bugs per target
 *   - Endpoint yield predictions: expected bugs per endpoint/workflow
 *   - Category yield predictions: expected bugs per vulnerability category
 *   - Workflow yield predictions: expected bugs per workflow
 *   - Confidence bands: p10, p50, p90 estimates
 *
 * Prediction formula:
 *   predicted_yield(target) =
 *     historical_bug_rate × coverage_gap_factor × learning_multiplier ×
 *     pattern_transfer_bonus × regression_risk_factor × auth_complexity_factor
 *
 * Confidence bands computed via bootstrap resampling of historical data.
 *
 * Safe mode: predictions are read-only analytical outputs; they inform
 * prioritization but never bypass authorization or safe mode constraints.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const PREDICTION_DIR = path.join(__dirname, 'output', 'knowledge', 'predictions');

// ─── Default Weights ────────────────────────────────────────────────

const DEFAULT_PREDICTION_WEIGHTS = {
  historical_bug_rate:      0.25,
  coverage_gap_factor:      0.20,
  learning_multiplier:      0.15,
  pattern_transfer_bonus:   0.15,
  regression_risk_factor:   0.10,
  auth_complexity_factor:   0.10,
  campaign_effectiveness:   0.05,
};

// ─── Severity Distribution Defaults ─────────────────────────────────

const DEFAULT_SEVERITY_DISTRIBUTION = {
  critical: 0.05,
  high:     0.15,
  medium:   0.40,
  low:      0.30,
  info:     0.10,
};

// ─── Confidence Band Percentiles ────────────────────────────────────

const CONFIDENCE_PERCENTILES = [10, 25, 50, 75, 90];

// ─── Minimum Data Points for Prediction ─────────────────────────────

const MIN_DATA_FOR_PREDICTION = 3;
const MIN_SESSIONS_FOR_CONFIDENCE = 5;

// =====================================================================
//  Prediction
// =====================================================================

class Prediction {
  constructor(data = {}) {
    this.id = data.id || `PRED-${crypto.randomUUID().substring(0, 8)}`;
    this.target_id = data.target_id || null;
    this.endpoint = data.endpoint || null;
    this.category = data.category || null;
    this.workflow = data.workflow || null;

    // Predicted yield
    this.predicted_yield = data.predicted_yield || 0;
    this.confidence_band = data.confidence_band || {
      p10: 0, p25: 0, p50: 0, p75: 0, p90: 0,
    };

    // Contributing factors
    this.factors = data.factors || {};

    // Metadata
    this.generated_at = data.generated_at || Date.now();
    this.model_version = data.model_version || '0.8';
    this.data_freshness_ms = data.data_freshness_ms || 0;
    this.prediction_quality = data.prediction_quality || 'low'; // low, medium, high
  }
}

// =====================================================================
//  PredictionEngine
// =====================================================================

class PredictionEngine {
  /**
   * @param {object} options
   * @param {object} [options.knowledgeBase]       - KnowledgeBase instance
   * @param {object} [options.brainRegistry]        - BrainRegistry instance
   * @param {object} [options.learningEngine]       - LearningEngine instance
   * @param {object} [options.findingMemory]        - FindingMemory instance
   * @param {object} [options.evidenceQualityEngine] - EvidenceQualityEngine instance
   * @param {object} [options.campaignEngine]       - CampaignEngine instance
   * @param {object} [options.coverageEngine]       - CoverageEngine instance
   * @param {object} [options.resourceOptimizer]    - ResourceOptimizer instance
   */
  constructor(options = {}) {
    this.kb = options.knowledgeBase || null;
    this.brainRegistry = options.brainRegistry || null;
    this.learningEngine = options.learningEngine || null;
    this.findingMemory = options.findingMemory || null;
    this.evidenceQuality = options.evidenceQualityEngine || null;
    this.campaignEngine = options.campaignEngine || null;
    this.coverageEngine = options.coverageEngine || null;
    this.resourceOptimizer = options.resourceOptimizer || null;

    /** @type {Map<string, Prediction>} target_id → latest prediction */
    this.targetPredictions = new Map();

    /** @type {Map<string, Prediction>} endpoint → latest prediction */
    this.endpointPredictions = new Map();

    /** @type {Map<string, Prediction>} category → latest prediction */
    this.categoryPredictions = new Map();

    /** @type {Map<string, Prediction>} workflow → latest prediction */
    this.workflowPredictions = new Map();

    /** @type {object[]} prediction history for accuracy tracking */
    this.predictionHistory = [];

    /** @type {Map<string, object>} prediction_id → actual outcome */
    this.actualOutcomes = new Map();

    /** @type {object} prediction accuracy metrics */
    this.accuracy = {
      total_predictions: 0,
      correct_direction: 0,    // predicted yield direction was correct
      mean_absolute_error: 0,
      mean_squared_error: 0,
      top_target_hit_rate: 0,  // % of time top predicted target actually had highest yield
      last_computed: null,
    };

    this.weights = { ...DEFAULT_PREDICTION_WEIGHTS };
    this.lastPredictionAt = null;

    // Ensure directory exists
    fs.mkdirSync(PREDICTION_DIR, { recursive: true });

    // Auto-load
    this.load();
  }

  // ─── Target Predictions ─────────────────────────────────────────

  /**
   * Generate yield predictions for all known targets.
   *
   * @returns {Prediction[]}
   */
  predictAllTargets() {
    const targetIds = this._collectTargetIds();
    const predictions = [];

    for (const targetId of targetIds) {
      const prediction = this.predictTarget(targetId);
      predictions.push(prediction);
    }

    // Sort by predicted yield descending
    predictions.sort((a, b) => b.predicted_yield - a.predicted_yield);

    // Store
    for (const pred of predictions) {
      this.targetPredictions.set(pred.target_id, pred);
      this.predictionHistory.push({
        prediction_id: pred.id,
        target_id: pred.target_id,
        predicted_yield: pred.predicted_yield,
        confidence_band: pred.confidence_band,
        generated_at: pred.generated_at,
      });
    }

    // Cap prediction history
    if (this.predictionHistory.length > 10000) {
      this.predictionHistory = this.predictionHistory.slice(-10000);
    }

    this.lastPredictionAt = Date.now();
    return predictions;
  }

  /**
   * Generate a yield prediction for a single target.
   *
   * @param {string} targetId
   * @returns {Prediction}
   */
  predictTarget(targetId) {
    const factors = this._computeTargetFactors(targetId);
    const weights = this._getTargetWeights(targetId);

    let predictedYield = 0;
    for (const [factor, value] of Object.entries(factors)) {
      const weight = weights[factor] || 0;
      predictedYield += value * weight;
    }

    // Scale to 0-10 range (expected bugs)
    predictedYield = Math.round(predictedYield * 100) / 100;

    // Compute confidence band
    const confidenceBand = this._computeConfidenceBand(targetId, predictedYield, factors);

    // Determine prediction quality
    const quality = this._assessPredictionQuality(targetId, factors);

    return new Prediction({
      target_id: targetId,
      predicted_yield: predictedYield,
      confidence_band: confidenceBand,
      factors,
      model_version: '0.8',
      data_freshness_ms: this._computeDataFreshness(targetId),
      prediction_quality: quality,
    });
  }

  // ─── Endpoint Predictions ───────────────────────────────────────

  /**
   * Predict which endpoints are most likely to yield bugs.
   *
   * @param {string} targetId
   * @returns {Prediction[]}
   */
  predictEndpoints(targetId) {
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    const assets = this.kb ? this.kb.getAssets(targetId) : null;

    const endpoints = assets?.endpoints || brain?.assetGraph?.endpoints || [];
    const predictions = [];

    for (const endpoint of endpoints) {
      const url = typeof endpoint === 'string' ? endpoint : endpoint.url || endpoint.path;
      if (!url) continue;

      const factors = this._computeEndpointFactors(targetId, url);
      let yield_ = 0;
      for (const [factor, value] of Object.entries(factors)) {
        const weight = this.weights[factor] || 0;
        yield_ += value * weight;
      }

      const prediction = new Prediction({
        target_id: targetId,
        endpoint: url,
        predicted_yield: Math.round(yield_ * 100) / 100,
        confidence_band: this._computeConfidenceBand(targetId, yield_, factors),
        factors,
        prediction_quality: this._assessPredictionQuality(targetId, factors),
      });

      predictions.push(prediction);
      this.endpointPredictions.set(`${targetId}:${url}`, prediction);
    }

    predictions.sort((a, b) => b.predicted_yield - a.predicted_yield);
    return predictions;
  }

  // ─── Category Predictions ───────────────────────────────────────

  /**
   * Predict which vulnerability categories are most likely to yield bugs.
   *
   * @param {string} [targetId] - optional target filter
   * @returns {Prediction[]}
   */
  predictCategories(targetId) {
    const categories = this._collectCategories();
    const predictions = [];

    for (const category of categories) {
      const factors = this._computeCategoryFactors(category, targetId);
      let yield_ = 0;
      for (const [factor, value] of Object.entries(factors)) {
        const weight = this.weights[factor] || 0;
        yield_ += value * weight;
      }

      const prediction = new Prediction({
        target_id: targetId || null,
        category,
        predicted_yield: Math.round(yield_ * 100) / 100,
        confidence_band: this._computeConfidenceBand(targetId, yield_, factors),
        factors,
      });

      predictions.push(prediction);
      this.categoryPredictions.set(category, prediction);
    }

    predictions.sort((a, b) => b.predicted_yield - a.predicted_yield);
    return predictions;
  }

  // ─── Workflow Predictions ───────────────────────────────────────

  /**
   * Predict which workflows are most likely to yield bugs.
   *
   * @param {string} targetId
   * @returns {Prediction[]}
   */
  predictWorkflows(targetId) {
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    const workflows = brain?.workflowGraph || [];

    const predictions = [];
    for (const workflow of workflows) {
      const factors = this._computeWorkflowFactors(targetId, workflow);
      let yield_ = 0;
      for (const [factor, value] of Object.entries(factors)) {
        const weight = this.weights[factor] || 0;
        yield_ += value * weight;
      }

      const name = workflow.name || workflow.id || 'unknown';
      const prediction = new Prediction({
        target_id: targetId,
        workflow: name,
        predicted_yield: Math.round(yield_ * 100) / 100,
        confidence_band: this._computeConfidenceBand(targetId, yield_, factors),
        factors,
      });

      predictions.push(prediction);
      this.workflowPredictions.set(`${targetId}:${name}`, prediction);
    }

    predictions.sort((a, b) => b.predicted_yield - a.predicted_yield);
    return predictions;
  }

  // ─── Outcome Tracking ───────────────────────────────────────────

  /**
   * Record the actual outcome for a prediction to track accuracy.
   *
   * @param {string} targetId
   * @param {number} actualYield - actual bugs found
   */
  recordOutcome(targetId, actualYield) {
    const prediction = this.targetPredictions.get(targetId);
    if (!prediction) return;

    this.actualOutcomes.set(prediction.id, {
      prediction_id: prediction.id,
      target_id: targetId,
      predicted_yield: prediction.predicted_yield,
      actual_yield: actualYield,
      error: Math.abs(prediction.predicted_yield - actualYield),
      direction_correct: (prediction.predicted_yield > 0 && actualYield > 0) ||
                         (prediction.predicted_yield <= 0 && actualYield <= 0),
      recorded_at: Date.now(),
    });

    this._updateAccuracyMetrics();
  }

  /**
   * Compute accuracy metrics from recorded outcomes.
   * @returns {object}
   */
  getAccuracy() {
    return { ...this.accuracy };
  }

  // ─── Query Methods ──────────────────────────────────────────────

  /**
   * Get the latest target predictions.
   * @returns {Prediction[]}
   */
  getTargetPredictions() {
    return [...this.targetPredictions.values()]
      .sort((a, b) => b.predicted_yield - a.predicted_yield);
  }

  /**
   * Get predictions for a specific target.
   * @param {string} targetId
   * @returns {Prediction|null}
   */
  getTargetPrediction(targetId) {
    return this.targetPredictions.get(targetId) || null;
  }

  /**
   * Get endpoint predictions for a target.
   * @param {string} targetId
   * @returns {Prediction[]}
   */
  getEndpointPredictions(targetId) {
    const prefix = `${targetId}:`;
    return [...this.endpointPredictions.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .map(([, v]) => v)
      .sort((a, b) => b.predicted_yield - a.predicted_yield);
  }

  /**
   * Get category predictions.
   * @returns {Prediction[]}
   */
  getCategoryPredictions() {
    return [...this.categoryPredictions.values()]
      .sort((a, b) => b.predicted_yield - a.predicted_yield);
  }

  /**
   * Get prediction engine statistics.
   * @returns {object}
   */
  getStats() {
    return {
      target_predictions: this.targetPredictions.size,
      endpoint_predictions: this.endpointPredictions.size,
      category_predictions: this.categoryPredictions.size,
      workflow_predictions: this.workflowPredictions.size,
      prediction_history: this.predictionHistory.length,
      outcomes_recorded: this.actualOutcomes.size,
      accuracy: this.accuracy,
      last_prediction_at: this.lastPredictionAt,
      weights: this.weights,
    };
  }

  /**
   * Get a summary of all predictions.
   * @returns {object}
   */
  getSummary() {
    const targets = this.getTargetPredictions();
    return {
      total_targets_predicted: targets.length,
      top_target: targets[0] ? { id: targets[0].target_id, yield: targets[0].predicted_yield } : null,
      avg_predicted_yield: targets.length > 0
        ? Math.round(targets.reduce((s, p) => s + p.predicted_yield, 0) / targets.length * 100) / 100
        : 0,
      accuracy: this.accuracy,
      last_updated: this.lastPredictionAt,
    };
  }

  // ─── Factor Computation ─────────────────────────────────────────

  /**
   * Compute all prediction factors for a target.
   * @private
   */
  _computeTargetFactors(targetId) {
    return {
      historical_bug_rate:      this._factorHistoricalBugRate(targetId),
      coverage_gap_factor:      this._factorCoverageGap(targetId),
      learning_multiplier:      this._factorLearningMultiplier(targetId),
      pattern_transfer_bonus:   this._factorPatternTransfer(targetId),
      regression_risk_factor:   this._factorRegressionRisk(targetId),
      auth_complexity_factor:   this._factorAuthComplexity(targetId),
      campaign_effectiveness:   this._factorCampaignEffectiveness(targetId),
    };
  }

  /**
   * Compute endpoint-level prediction factors.
   * @private
   */
  _computeEndpointFactors(targetId, endpoint) {
    const baseFactors = this._computeTargetFactors(targetId);

    // Adjust based on endpoint-specific data
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;

    // Check if endpoint was involved in historical findings
    let endpointBugRate = 0;
    if (brain) {
      const relevantFindings = brain.historicalFindings.filter(f => {
        const endpoints = f.affected_endpoints || [];
        return endpoints.some(e => e.includes(endpoint) || endpoint.includes(e));
      });
      endpointBugRate = brain.historicalFindings.length > 0
        ? relevantFindings.length / brain.historicalFindings.length
        : 0;
    }

    return {
      ...baseFactors,
      historical_bug_rate: baseFactors.historical_bug_rate * 0.6 + endpointBugRate * 0.4,
    };
  }

  /**
   * Compute category-level prediction factors.
   * @private
   */
  _computeCategoryFactors(category, targetId) {
    let successRate = 0;
    let observations = 0;

    // Get category success from learning engine
    if (this.learningEngine) {
      const scores = this.learningEngine.getHypothesisSuccessScores();
      const catScore = scores.find(s => s.category === category);
      if (catScore) {
        successRate = catScore.success_rate;
        observations = catScore.total_observations;
      }
    }

    // Get cross-target pattern bonus for this category
    let patternBonus = 0;
    if (this.findingMemory) {
      const patterns = this.findingMemory.getPatterns({ category, min_targets: 2 });
      patternBonus = patterns.length > 0
        ? patterns.reduce((s, p) => s + p.confidence, 0) / patterns.length * 0.3
        : 0;
    }

    // Exploration bonus for under-explored categories
    const explorationBonus = observations < 5 ? 0.2 : observations < 10 ? 0.1 : 0;

    return {
      historical_bug_rate: successRate,
      coverage_gap_factor: explorationBonus,
      learning_multiplier: successRate > 0.2 ? 1.2 : successRate > 0.1 ? 1.0 : 0.8,
      pattern_transfer_bonus: patternBonus,
      regression_risk_factor: 0,
      auth_complexity_factor: this._categoryAuthComplexity(category),
      campaign_effectiveness: 0,
    };
  }

  /**
   * Compute workflow-level prediction factors.
   * @private
   */
  _computeWorkflowFactors(targetId, workflow) {
    const baseFactors = this._computeTargetFactors(targetId);

    // Workflows with more steps are generally more complex
    const stepCount = workflow.steps?.length || workflow.step_count || 1;
    const complexityBonus = Math.min(stepCount / 10, 1.0) * 0.2;

    return {
      ...baseFactors,
      auth_complexity_factor: baseFactors.auth_complexity_factor + complexityBonus,
    };
  }

  // ─── Individual Factor Methods ──────────────────────────────────

  /**
   * Historical bug rate: confirmed bugs per session for this target.
   * @private
   */
  _factorHistoricalBugRate(targetId) {
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    if (!brain || brain.total_sessions === 0) return 0.1; // default for new targets

    const confirmed = brain.historicalFindings.filter(
      f => f.lifecycle_state === 'confirmed' || f.verdict === 'confirmed'
    ).length;

    return Math.min(confirmed / Math.max(brain.total_sessions, 1), 5.0);
  }

  /**
   * Coverage gap factor: larger gaps = more potential for discovery.
   * @private
   */
  _factorCoverageGap(targetId) {
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    const coverage = this.kb ? this.kb.getCoverage(targetId) : null;

    let currentCoverage = 0;
    if (coverage) {
      currentCoverage = coverage.score || 0;
    } else if (brain && brain.coverageTrend.length > 0) {
      currentCoverage = brain.coverageTrend[brain.coverageTrend.length - 1].score || 0;
    }

    // Gap = 1 - coverage/100, scaled to 0-1
    return Math.max(0, (100 - currentCoverage) / 100);
  }

  /**
   * Learning multiplier: targets where learning shows improvement.
   * @private
   */
  _factorLearningMultiplier(targetId) {
    if (!this.learningEngine) return 1.0;

    const targetWeights = this.learningEngine.getTargetWeights(targetId);
    const baseSuccess = this.learningEngine.currentWeights.historical_success || 0.20;
    const targetSuccess = targetWeights.historical_success || 0.20;

    // If target-specific learning has boosted success, predict higher yield
    if (targetSuccess > baseSuccess) return 1.0 + (targetSuccess - baseSuccess) * 2;
    if (targetSuccess < baseSuccess) return 0.8;
    return 1.0;
  }

  /**
   * Pattern transfer bonus: knowledge from other targets applies here.
   * @private
   */
  _factorPatternTransfer(targetId) {
    if (!this.findingMemory) return 0;

    const patterns = this.findingMemory.getPatternsForTarget(targetId);
    const crossTarget = patterns.filter(p => p.target_count >= 2);

    if (crossTarget.length === 0) return 0;

    // Average confidence of cross-target patterns
    const avgConfidence = crossTarget.reduce((s, p) => s + p.confidence, 0) / crossTarget.length;
    return Math.min(avgConfidence * 0.3, 0.5);
  }

  /**
   * Regression risk: targets with historical regressions are likely to have more.
   * @private
   */
  _factorRegressionRisk(targetId) {
    if (!this.findingMemory) return 0;

    const regressions = this.findingMemory.getRegressions({ target_id: targetId });
    if (regressions.length === 0) return 0;

    // Recent regressions are more predictive
    const recentMs = 30 * 86400000; // 30 days
    const recent = regressions.filter(r => Date.now() - r.ts < recentMs);
    return Math.min(recent.length * 0.15, 0.5);
  }

  /**
   * Auth complexity factor: more auth models = more potential issues.
   * @private
   */
  _factorAuthComplexity(targetId) {
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    if (!brain) return 0.2; // default

    const authModels = brain.authModels || [];
    if (authModels.length === 0) return 0.2;

    // More auth models → more complexity → more potential issues
    // Hybrid models are especially interesting
    const hasHybrid = authModels.some(m => m.type === 'hybrid');
    const baseComplexity = Math.min(authModels.length / 3, 1.0) * 0.3;
    const hybridBonus = hasHybrid ? 0.2 : 0;

    return baseComplexity + hybridBonus;
  }

  /**
   * Campaign effectiveness: targets with active campaigns showing results.
   * @private
   */
  _factorCampaignEffectiveness(targetId) {
    if (!this.campaignEngine) return 0;

    const campaigns = this.campaignEngine.list({ target_id: targetId, state: 'running' });
    if (campaigns.length === 0) return 0;

    // Average effectiveness across active campaigns
    const avgEff = campaigns.reduce((s, c) => s + (c.effectiveness.bugs_per_iteration || 0), 0) / campaigns.length;
    return Math.min(avgEff * 0.5, 0.5);
  }

  /**
   * Auth complexity contribution for a category.
   * @private
   */
  _categoryAuthComplexity(category) {
    const authRelatedCategories = [
      'auth_bypass', 'session_hijacking', 'csrf', 'cookie_security',
      'missing_authentication', 'token_handling',
    ];
    return authRelatedCategories.includes(category) ? 0.4 : 0.1;
  }

  // ─── Confidence Band Computation ────────────────────────────────

  /**
   * Compute confidence bands using bootstrap-like approach.
   *
   * @param {string|null} targetId
   * @param {number} pointEstimate
   * @param {object} factors
   * @returns {object} { p10, p25, p50, p75, p90 }
   * @private
   */
  _computeConfidenceBand(targetId, pointEstimate, factors) {
    // Determine data quality
    const brain = targetId && this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    const sessions = brain ? brain.total_sessions : 0;
    const findings = brain ? brain.historicalFindings.length : 0;

    // Data quality score (0-1)
    const dataQuality = Math.min(
      (sessions / MIN_SESSIONS_FOR_CONFIDENCE) * 0.5 +
      (findings / 10) * 0.5,
      1.0
    );

    // Uncertainty increases with less data
    const uncertaintyBase = 1.0 - dataQuality;
    const spread = pointEstimate * uncertaintyBase * 0.8;

    return {
      p10: Math.max(0, Math.round((pointEstimate - spread * 1.5) * 100) / 100),
      p25: Math.max(0, Math.round((pointEstimate - spread) * 100) / 100),
      p50: Math.round(pointEstimate * 100) / 100,
      p75: Math.round((pointEstimate + spread) * 100) / 100,
      p90: Math.round((pointEstimate + spread * 1.5) * 100) / 100,
    };
  }

  // ─── Helper Methods ─────────────────────────────────────────────

  _collectTargetIds() {
    const ids = new Set();

    if (this.brainRegistry) {
      for (const [id] of this.brainRegistry.brains) {
        ids.add(id);
      }
    }
    if (this.kb) {
      for (const [id] of this.kb.assets) {
        ids.add(id);
      }
    }
    if (this.campaignEngine) {
      for (const [, campaign] of this.campaignEngine.campaigns) {
        for (const tid of campaign.target_ids) {
          ids.add(tid);
        }
      }
    }
    if (this.resourceOptimizer) {
      for (const [id] of this.resourceOptimizer.allocations) {
        ids.add(id);
      }
    }

    return [...ids];
  }

  _collectCategories() {
    const categories = new Set([
      'auth_bypass', 'session_hijacking', 'csrf', 'cookie_security',
      'api_exposure', 'idor', 'insecure_direct_object', 'websocket_hijacking',
      'xss', 'injection', 'missing_authentication', 'broken_access_control',
      'sensitive_data_exposure', 'security_misconfiguration', 'information_leakage',
      'token_handling', 'cors_misconfiguration', 'rate_limiting',
    ]);

    // Add any categories from learning engine
    if (this.learningEngine) {
      for (const [cat] of this.learningEngine.categoryStats) {
        categories.add(cat);
      }
    }

    return [...categories];
  }

  _getTargetWeights(targetId) {
    // Use learning engine target-specific weights if available
    if (this.learningEngine) {
      const targetWeights = this.learningEngine.getTargetWeights(targetId);
      // Map learning weights to prediction weights
      return {
        ...this.weights,
        learning_multiplier: (targetWeights.historical_success || 0.20) / 0.20,
      };
    }
    return { ...this.weights };
  }

  _assessPredictionQuality(targetId, factors) {
    const brain = targetId && this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    const sessions = brain ? brain.total_sessions : 0;

    if (sessions >= MIN_SESSIONS_FOR_CONFIDENCE) return 'high';
    if (sessions >= MIN_DATA_FOR_PREDICTION) return 'medium';
    return 'low';
  }

  _computeDataFreshness(targetId) {
    const brain = targetId && this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    if (!brain || !brain.lastActivityAt) return Infinity;
    return Date.now() - brain.lastActivityAt;
  }

  _updateAccuracyMetrics() {
    const outcomes = [...this.actualOutcomes.values()];
    if (outcomes.length === 0) return;

    this.accuracy.total_predictions = outcomes.length;
    this.accuracy.correct_direction = outcomes.filter(o => o.direction_correct).length;
    this.accuracy.mean_absolute_error = Math.round(
      outcomes.reduce((s, o) => s + o.error, 0) / outcomes.length * 100
    ) / 100;
    this.accuracy.mean_squared_error = Math.round(
      outcomes.reduce((s, o) => s + o.error * o.error, 0) / outcomes.length * 100
    ) / 100;

    // Top target hit rate
    if (outcomes.length >= 5) {
      const topPredictions = this.predictionHistory
        .slice(-outcomes.length)
        .sort((a, b) => b.predicted_yield - a.predicted_yield);
      if (topPredictions.length > 0) {
        const topTarget = topPredictions[0].target_id;
        const topActual = outcomes.reduce((best, o) =>
          o.actual_yield > (best?.actual_yield || 0) ? o : best, null);
        this.accuracy.top_target_hit_rate = topActual && topActual.target_id === topTarget ? 1.0 : 0.0;
      }
    }

    this.accuracy.last_computed = Date.now();
  }

  // ─── Persistence ────────────────────────────────────────────────

  save() {
    const filePath = path.join(PREDICTION_DIR, 'prediction-engine.json');

    const data = {
      version: '0.8',
      saved_at: Date.now(),
      weights: this.weights,
      accuracy: this.accuracy,
      last_prediction_at: this.lastPredictionAt,
      target_predictions: [...this.targetPredictions.entries()],
      category_predictions: [...this.categoryPredictions.entries()],
      prediction_history: this.predictionHistory.slice(-500),
      outcomes: [...this.actualOutcomes.entries()].slice(-500),
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(PREDICTION_DIR, 'prediction-engine.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      this.weights = data.weights || { ...DEFAULT_PREDICTION_WEIGHTS };
      this.accuracy = { ...this.accuracy, ...(data.accuracy || {}) };
      this.lastPredictionAt = data.last_prediction_at || null;

      this.targetPredictions = new Map(
        (data.target_predictions || []).map(([k, v]) => [k, new Prediction(v)])
      );

      this.categoryPredictions = new Map(
        (data.category_predictions || []).map(([k, v]) => [k, new Prediction(v)])
      );

      this.predictionHistory = data.prediction_history || [];
      this.actualOutcomes = new Map(data.outcomes || []);

      return true;
    } catch (_) {
      return false;
    }
  }
}

module.exports = {
  PredictionEngine,
  Prediction,
  DEFAULT_PREDICTION_WEIGHTS,
  PREDICTION_DIR,
  CONFIDENCE_PERCENTILES,
};

