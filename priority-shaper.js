/**
 * BOQA priority-shaper.js — Priority Shaper v0.8
 *
 * Re-ranks hypotheses and targets using predicted yield instead
 * of only observed yield. Integrates with the existing
 * HypothesisPrioritizer and ResourceOptimizer to inject
 * prediction-based adjustments.
 *
 * Priority shaping combines:
 *   - PredictionEngine: predicted yield per target/endpoint/category
 *   - YieldForecaster: expected bugs, severity, verification rates
 *   - RiskForecaster: regression risk per target
 *   - LearningEngine: category/target success weights
 *   - ResourceOptimizer: current allocation state
 *
 * Shaping formula:
 *   shaped_priority = observed_priority × (1 - prediction_weight) +
 *                     predicted_priority × prediction_weight
 *
 * Where:
 *   observed_priority = current EVV or risk_score from existing systems
 *   predicted_priority = yield_forecast × verification_rate × severity_weight
 *   prediction_weight = configurable, starts at 0.3, adjusted by learning
 *
 * The shaper also provides:
 *   - Next-best-action recommendations
 *   - Coverage gap priorities (where to explore next)
 *   - Verification priorities (what to verify next)
 *   - Target reordering based on predicted yield
 *
 * Decision latency target: <= 250ms per ranking operation
 *
 * Safe mode: shaping only adjusts internal priorities; it never
 * bypasses safe mode constraints or authorization boundaries.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const SHAPER_DIR = path.join(__dirname, 'output', 'knowledge', 'shaper');

// ─── Default Configuration ──────────────────────────────────────────

const DEFAULT_SHAPER_CONFIG = {
  prediction_weight: 0.30,        // How much prediction vs observation
  min_prediction_weight: 0.10,
  max_prediction_weight: 0.60,
  risk_weight: 0.20,              // How much risk forecast affects priority
  coverage_gap_weight: 0.15,      // Priority bonus for coverage gaps
  learning_boost_weight: 0.10,    // Priority from learning signals
  exploration_bonus: 0.10,        // Bonus for under-explored areas
  decision_latency_target_ms: 250,
  reweight_interval_ms: 300000,   // 5 minutes
};

// ─── Action Types ───────────────────────────────────────────────────

const ACTION_TYPES = {
  EXPLORE_TARGET:      'explore_target',
  VERIFY_HYPOTHESIS:   'verify_hypothesis',
  DEEP_DIVE_ENDPOINT:  'deep_dive_endpoint',
  MONITOR_REGRESSION:  'monitor_regression',
  CATEGORY_SWEEP:      'category_sweep',
  COVERAGE_GAP:        'coverage_gap',
  REALLOCATE_WORKERS:  'reallocate_workers',
};

// =====================================================================
//  NextBestAction
// =====================================================================

class NextBestAction {
  constructor(data = {}) {
    this.id = data.id || `NBA-${crypto.randomUUID().substring(0, 8)}`;
    this.action_type = data.action_type || ACTION_TYPES.EXPLORE_TARGET;
    this.target_id = data.target_id || null;
    this.endpoint = data.endpoint || null;
    this.category = data.category || null;
    this.priority = data.priority || 0;       // 0-100
    this.expected_value = data.expected_value || 0;
    this.reasoning = data.reasoning || '';
    this.confidence = data.confidence || 0;
    this.estimated_effort_ms = data.estimated_effort_ms || 0;
    this.generated_at = data.generated_at || Date.now();
  }
}

// =====================================================================
//  PriorityShaper
// =====================================================================

class PriorityShaper {
  /**
   * @param {object} options
   * @param {object} [options.predictionEngine]    - PredictionEngine instance
   * @param {object} [options.yieldForecaster]     - YieldForecaster instance
   * @param {object} [options.riskForecaster]      - RiskForecaster instance
   * @param {object} [options.knowledgeBase]       - KnowledgeBase instance
   * @param {object} [options.brainRegistry]        - BrainRegistry instance
   * @param {object} [options.learningEngine]       - LearningEngine instance
   * @param {object} [options.hypothesisPrioritizer] - HypothesisPrioritizer instance
   * @param {object} [options.resourceOptimizer]    - ResourceOptimizer instance
   * @param {object} [options.campaignEngine]       - CampaignEngine instance
   * @param {object} [options.findingMemory]        - FindingMemory instance
   * @param {object} [options.coverageEngine]       - CoverageEngine instance
   * @param {object} [options.config]               - Override default config
   */
  constructor(options = {}) {
    this.predictionEngine = options.predictionEngine || null;
    this.yieldForecaster = options.yieldForecaster || null;
    this.riskForecaster = options.riskForecaster || null;
    this.kb = options.knowledgeBase || null;
    this.brainRegistry = options.brainRegistry || null;
    this.learningEngine = options.learningEngine || null;
    this.hypothesisPrioritizer = options.hypothesisPrioritizer || null;
    this.resourceOptimizer = options.resourceOptimizer || null;
    this.campaignEngine = options.campaignEngine || null;
    this.findingMemory = options.findingMemory || null;
    this.coverageEngine = options.coverageEngine || null;

    this.config = { ...DEFAULT_SHAPER_CONFIG, ...(options.config || {}) };

    /** @type {Map<string, number>} target_id → shaped priority */
    this.shapedPriorities = new Map();

    /** @type {Map<string, number>} hypothesis_id → shaped priority */
    this.shapedHypothesisPriorities = new Map();

    /** @type {NextBestAction[]} next-best-action queue */
    this.actionQueue = [];

    /** @type {number} prediction_weight (adjusted by learning) */
    this.currentPredictionWeight = this.config.prediction_weight;

    /** @type {object[]} shaping history for audit */
    this.shapingHistory = [];

    /** @type {object} metrics */
    this.metrics = {
      total_shapings: 0,
      avg_decision_latency_ms: 0,
      predictions_used: 0,
      observed_only_used: 0,
      actions_generated: 0,
      prediction_accuracy_contribution: 0,
    };

    // Ensure directory exists
    fs.mkdirSync(SHAPER_DIR, { recursive: true });

    // Auto-load
    this.load();

    // Start periodic reweight
    this._reweightTimer = setInterval(() => {
      this._adjustPredictionWeight();
    }, this.config.reweight_interval_ms);
  }

  // ─── Target Priority Shaping ────────────────────────────────────

  /**
   * Re-rank targets using predicted yield instead of only observed yield.
   *
   * @param {string[]} [targetIds] - specific targets, or all known
   * @returns {object[]} shaped target priorities sorted by priority
   */
  shapeTargetPriorities(targetIds) {
    const startTime = Date.now();
    const ids = targetIds || this._collectTargetIds();

    const results = [];

    for (const targetId of ids) {
      const observed = this._getObservedPriority(targetId);
      const predicted = this._getPredictedPriority(targetId);
      const risk = this._getRiskPriority(targetId);

      // Blend observed and predicted
      const blended =
        observed * (1 - this.currentPredictionWeight) +
        predicted * this.currentPredictionWeight +
        risk * this.config.risk_weight;

      // Add coverage gap bonus
      const coverageBonus = this._getCoverageGapBonus(targetId) * this.config.coverage_gap_weight;

      // Add learning boost
      const learningBoost = this._getLearningBoost(targetId) * this.config.learning_boost_weight;

      // Add exploration bonus for under-explored targets
      const explorationBonus = this._getExplorationBonus(targetId) * this.config.exploration_bonus;

      const shapedPriority = Math.round(
        Math.min(100, blended + coverageBonus + learningBoost + explorationBonus)
      );

      this.shapedPriorities.set(targetId, shapedPriority);

      results.push({
        target_id: targetId,
        observed_priority: observed,
        predicted_priority: predicted,
        risk_contribution: risk,
        coverage_bonus: coverageBonus,
        learning_boost: learningBoost,
        exploration_bonus: explorationBonus,
        shaped_priority: shapedPriority,
        prediction_weight_used: this.currentPredictionWeight,
      });
    }

    // Sort by shaped priority
    results.sort((a, b) => b.shaped_priority - a.shaped_priority);

    // Record shaping
    const latencyMs = Date.now() - startTime;
    this.shapingHistory.push({
      type: 'target',
      count: results.length,
      latency_ms: latencyMs,
      prediction_weight: this.currentPredictionWeight,
      ts: Date.now(),
    });

    this.metrics.total_shapings++;
    this.metrics.avg_decision_latency_ms = latencyMs;
    this.metrics.predictions_used += results.length;

    if (this.shapingHistory.length > 1000) {
      this.shapingHistory = this.shapingHistory.slice(-1000);
    }

    return results;
  }

  // ─── Hypothesis Priority Shaping ────────────────────────────────

  /**
   * Re-rank hypotheses using predicted yield.
   *
   * @param {object[]} hypotheses
   * @returns {object[]} re-ranked hypotheses
   */
  shapeHypothesisPriorities(hypotheses) {
    const startTime = Date.now();

    const results = hypotheses.map(hyp => {
      const observedEVV = hyp.expected_value || hyp.evv || hyp.risk_score || 50;

      // Get prediction for this hypothesis
      const prediction = this._getHypothesisPrediction(hyp);

      // Blend
      const shaped =
        observedEVV * (1 - this.currentPredictionWeight) +
        prediction * this.currentPredictionWeight;

      return {
        ...hyp,
        original_evv: observedEVV,
        predicted_evv: prediction,
        shaped_evv: Math.round(shaped * 100) / 100,
        prediction_weight_used: this.currentPredictionWeight,
      };
    });

    // Sort by shaped EVV
    results.sort((a, b) => b.shaped_evv - a.shaped_evv);

    // Cache
    for (const r of results) {
      this.shapedHypothesisPriorities.set(r.id || r.hypothesis_id, r.shaped_evv);
    }

    const latencyMs = Date.now() - startTime;
    this.metrics.total_shapings++;
    this.metrics.avg_decision_latency_ms = latencyMs;

    return results;
  }

  // ─── Next Best Action ───────────────────────────────────────────

  /**
   * Generate next-best-action recommendations.
   *
   * @param {number} [maxActions=10]
   * @returns {NextBestAction[]}
   */
  getNextBestActions(maxActions = 10) {
    const actions = [];

    // 1. Top predicted yield targets → explore
    const targetPredictions = this.predictionEngine
      ? this.predictionEngine.getTargetPredictions().slice(0, 5)
      : [];

    for (const pred of targetPredictions) {
      if (pred.predicted_yield > 0.5) {
        actions.push(new NextBestAction({
          action_type: ACTION_TYPES.EXPLORE_TARGET,
          target_id: pred.target_id,
          priority: Math.round(pred.predicted_yield * 100),
          expected_value: pred.predicted_yield,
          reasoning: `Predicted yield ${pred.predicted_yield.toFixed(2)} bugs (confidence: ${pred.prediction_quality})`,
          confidence: pred.prediction_quality === 'high' ? 0.9 : pred.prediction_quality === 'medium' ? 0.6 : 0.3,
          estimated_effort_ms: 300000, // 5 minutes
        }));
      }
    }

    // 2. High-risk targets → monitor regression
    if (this.riskForecaster) {
      const riskForecasts = this.riskForecaster.getAllForecasts()
        .filter(f => f.risk_level === 'critical' || f.risk_level === 'high')
        .slice(0, 3);

      for (const rf of riskForecasts) {
        actions.push(new NextBestAction({
          action_type: ACTION_TYPES.MONITOR_REGRESSION,
          target_id: rf.target_id,
          priority: rf.risk_score,
          expected_value: rf.regression_likelihood,
          reasoning: `${rf.risk_level.toUpperCase()} regression risk (${rf.risk_score}/100)`,
          confidence: 0.8,
          estimated_effort_ms: 120000,
        }));
      }
    }

    // 3. Coverage gaps → explore
    if (this.kb) {
      const targets = this._collectTargetIds();
      for (const targetId of targets.slice(0, 5)) {
        const coverage = this.kb.getCoverage(targetId);
        if (coverage && coverage.score < 70) {
          actions.push(new NextBestAction({
            action_type: ACTION_TYPES.COVERAGE_GAP,
            target_id: targetId,
            priority: Math.round((100 - coverage.score) * 0.8),
            expected_value: (100 - coverage.score) / 100,
            reasoning: `Coverage at ${coverage.score}% — significant unexplored surface`,
            confidence: 0.7,
            estimated_effort_ms: 600000,
          }));
        }
      }
    }

    // 4. High-yield categories → sweep
    if (this.yieldForecaster) {
      const catPredictions = this.predictionEngine
        ? this.predictionEngine.predictCategories().slice(0, 3)
        : [];

      for (const cat of catPredictions) {
        if (cat.predicted_yield > 0.3) {
          actions.push(new NextBestAction({
            action_type: ACTION_TYPES.CATEGORY_SWEEP,
            category: cat.category,
            priority: Math.round(cat.predicted_yield * 80),
            expected_value: cat.predicted_yield,
            reasoning: `Category ${cat.category} has predicted yield ${cat.predicted_yield.toFixed(2)}`,
            confidence: cat.prediction_quality === 'high' ? 0.8 : 0.5,
            estimated_effort_ms: 900000,
          }));
        }
      }
    }

    // 5. Worker reallocation if needed
    if (this.resourceOptimizer) {
      const alloc = this.resourceOptimizer.computeAllocation();
      const idle = alloc.target_allocations.filter(a => a.state === 'idle');
      if (idle.length > 0) {
        actions.push(new NextBestAction({
          action_type: ACTION_TYPES.REALLOCATE_WORKERS,
          priority: 60,
          expected_value: 0.3,
          reasoning: `${idle.length} idle workers — reallocate to high-yield targets`,
          confidence: 0.7,
          estimated_effort_ms: 30000,
        }));
      }
    }

    // Sort by priority and deduplicate
    actions.sort((a, b) => b.priority - a.priority);
    const seen = new Set();
    const unique = actions.filter(a => {
      const key = `${a.action_type}:${a.target_id || a.category}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    this.actionQueue = unique;
    this.metrics.actions_generated = unique.length;

    return unique.slice(0, maxActions);
  }

  // ─── Query Methods ──────────────────────────────────────────────

  getShapedPriority(targetId) {
    return this.shapedPriorities.get(targetId) || null;
  }

  getShapedHypothesisPriority(hypothesisId) {
    return this.shapedHypothesisPriorities.get(hypothesisId) || null;
  }

  getStats() {
    return {
      ...this.metrics,
      prediction_weight: this.currentPredictionWeight,
      shaped_targets: this.shapedPriorities.size,
      shaped_hypotheses: this.shapedHypothesisPriorities.size,
      action_queue_size: this.actionQueue.length,
      shaping_history: this.shapingHistory.length,
    };
  }

  // ─── Internal Methods ───────────────────────────────────────────

  _getObservedPriority(targetId) {
    // Get current priority from resource optimizer or brain
    if (this.resourceOptimizer) {
      const alloc = this.resourceOptimizer.getAllocation(targetId);
      if (alloc) return Math.min(alloc.ev * 10, 100);
    }

    // Fallback: use brain findings count
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    if (brain) {
      const confirmed = brain.historicalFindings.filter(
        f => f.lifecycle_state === 'confirmed' || f.verdict === 'confirmed'
      ).length;
      return Math.min(confirmed * 10, 100);
    }

    return 30; // default
  }

  _getPredictedPriority(targetId) {
    if (!this.predictionEngine) return 30;

    const prediction = this.predictionEngine.getTargetPrediction(targetId);
    if (!prediction) return 30;

    // Scale predicted yield to 0-100
    return Math.min(prediction.predicted_yield * 20, 100);
  }

  _getRiskPriority(targetId) {
    if (!this.riskForecaster) return 0;

    const forecast = this.riskForecaster.getTargetForecast(targetId);
    if (!forecast) return 0;

    return forecast.risk_score * 0.5; // Scale down risk contribution
  }

  _getCoverageGapBonus(targetId) {
    if (!this.kb) return 0;

    const coverage = this.kb.getCoverage(targetId);
    if (!coverage) return 20; // no coverage data = big bonus

    return Math.max(0, 100 - coverage.score) / 5; // max 20
  }

  _getLearningBoost(targetId) {
    if (!this.learningEngine) return 0;

    const targetLearning = this.learningEngine.targetLearning.get(targetId);
    if (!targetLearning || targetLearning.observations === 0) return 5; // exploration bonus

    const successRate = targetLearning.confirmed / targetLearning.observations;
    // Medium success rate = good potential for learning
    if (successRate > 0.15 && successRate < 0.4) return 10;
    if (successRate >= 0.4) return 5; // already well-mined
    return 3;
  }

  _getExplorationBonus(targetId) {
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;
    if (!brain) return 10; // new target

    const sessions = brain.total_sessions;
    if (sessions === 0) return 15;
    if (sessions < 3) return 10;
    if (sessions < 5) return 5;
    return 0;
  }

  _getHypothesisPrediction(hyp) {
    if (!this.predictionEngine) return hyp.expected_value || hyp.evv || 50;

    // Get category prediction for this hypothesis
    const category = hyp.category || 'unknown';
    const targetId = hyp.target_id || null;

    let basePrediction = hyp.expected_value || hyp.evv || 50;

    // Adjust based on category yield forecast
    const catForecast = this.yieldForecaster
      ? this.yieldForecaster.forecastCategory(category, targetId)
      : null;

    if (catForecast) {
      // If verification rate is high for this category, boost
      if (catForecast.verification_success_rate > 0.3) {
        basePrediction *= 1.1;
      } else if (catForecast.verification_success_rate < 0.1) {
        basePrediction *= 0.8;
      }
    }

    return basePrediction;
  }

  _adjustPredictionWeight() {
    // Adjust prediction weight based on accuracy
    if (!this.predictionEngine) return;

    const accuracy = this.predictionEngine.getAccuracy();
    if (accuracy.total_predictions < 10) return;

    // If predictions are accurate, increase prediction weight
    const directionAccuracy = accuracy.correct_direction / accuracy.total_predictions;

    if (directionAccuracy >= 0.70) {
      this.currentPredictionWeight = Math.min(
        this.config.max_prediction_weight,
        this.currentPredictionWeight + 0.02
      );
    } else if (directionAccuracy < 0.50) {
      this.currentPredictionWeight = Math.max(
        this.config.min_prediction_weight,
        this.currentPredictionWeight - 0.02
      );
    }
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
    const filePath = path.join(SHAPER_DIR, 'priority-shaper.json');

    const data = {
      version: '0.8',
      saved_at: Date.now(),
      config: this.config,
      current_prediction_weight: this.currentPredictionWeight,
      shaped_priorities: [...this.shapedPriorities.entries()],
      shaped_hypothesis_priorities: [...this.shapedHypothesisPriorities.entries()].slice(-500),
      action_queue: this.actionQueue.slice(0, 20),
      metrics: this.metrics,
      shaping_history: this.shapingHistory.slice(-200),
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(SHAPER_DIR, 'priority-shaper.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      this.config = { ...DEFAULT_SHAPER_CONFIG, ...(data.config || {}) };
      this.currentPredictionWeight = data.current_prediction_weight || this.config.prediction_weight;
      this.shapedPriorities = new Map(data.shaped_priorities || []);
      this.shapedHypothesisPriorities = new Map(data.shaped_hypothesis_priorities || []);
      this.actionQueue = (data.action_queue || []).map(a => new NextBestAction(a));
      this.metrics = { ...this.metrics, ...(data.metrics || {}) };
      this.shapingHistory = data.shaping_history || [];

      return true;
    } catch (_) {
      return false;
    }
  }

  shutdown() {
    if (this._reweightTimer) {
      clearInterval(this._reweightTimer);
    }
    this.save();
  }
}

module.exports = {
  PriorityShaper,
  NextBestAction,
  ACTION_TYPES,
  SHAPER_DIR,
  DEFAULT_SHAPER_CONFIG,
};

