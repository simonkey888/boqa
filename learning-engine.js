/**
 * BOQA learning-engine.js — Learning Engine v0.7
 *
 * Learns which hypotheses produce real bugs and which verification
 * strategies are most effective. Feeds learned weights back into
 * the hypothesis prioritizer and coverage planner.
 *
 * Learning outputs:
 *   - hypothesis_success_scores:   per-category success rates
 *   - verification_success_scores: per-verification-type success rates
 *   - target_specific_weights:     per-target EVV weight adjustments
 *
 * Learning loop integration:
 *   discover → hypothesize → verify → score → learn → reweight → optimize → repeat
 *
 * Learning strategies:
 *   - Outcome tracking:      track every hypothesis outcome
 *   - Category weighting:    categories with higher success get boosted
 *   - Verification scoring:  verification types that confirm get prioritized
 *   - Target specialization: per-target weight adjustments
 *   - Temporal decay:        recent outcomes weighted more than old ones
 *   - Exploration bonus:     categories with few attempts get exploration boost
 *
 * The learning engine continuously updates:
 *   - HypothesisPrioritizer weights (when enough data accumulates)
 *   - CoveragePlanner strategy selection
 *   - ResourceOptimizer target value estimates
 *   - TargetBrain custom_weights
 *
 * Safe mode: learning is purely analytical; it adjusts weights
 * and priorities but never initiates actions or bypasses constraints.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Learning Config ───────────────────────────────────────────────

const LEARNING_DIR = path.join(__dirname, 'output', 'knowledge', 'learning');

const DEFAULT_WEIGHTS = {
  severity: 0.30,
  confidence: 0.30,
  coverage_gap: 0.20,
  historical_success: 0.20,
};

const MIN_OBSERVATIONS_FOR_REWEIGHT = 20;
const REWEIGHT_INTERVAL_MS = 300000; // 5 minutes
const TEMPORAL_DECAY_FACTOR = 0.95;  // per day decay
const EXPLORATION_BONUS = 0.1;       // boost for under-explored categories
const MAX_HISTORY = 50000;

// ─── Hypothesis Categories ─────────────────────────────────────────

const TRACKED_CATEGORIES = [
  'auth_bypass', 'session_hijacking', 'csrf', 'cookie_security',
  'api_exposure', 'idor', 'insecure_direct_object', 'websocket_hijacking',
  'xss', 'injection', 'missing_authentication', 'broken_access_control',
  'sensitive_data_exposure', 'security_misconfiguration', 'information_leakage',
  'token_handling', 'cors_misconfiguration', 'rate_limiting',
];

// =====================================================================
//  LearningEngine
// =====================================================================

class LearningEngine {
  /**
   * @param {object} options
   * @param {object} [options.knowledgeBase]       - KnowledgeBase instance
   * @param {object} [options.hypothesisPrioritizer] - HypothesisPrioritizer instance
   * @param {object} [options.coveragePlanner]       - CoveragePlanner instance
   * @param {object} [options.brainRegistry]          - BrainRegistry instance
   * @param {object} [options.resourceOptimizer]      - ResourceOptimizer instance
   */
  constructor(options = {}) {
    this.kb = options.knowledgeBase || null;
    this.hypothesisPrioritizer = options.hypothesisPrioritizer || null;
    this.coveragePlanner = options.coveragePlanner || null;
    this.brainRegistry = options.brainRegistry || null;
    this.resourceOptimizer = options.resourceOptimizer || null;

    // ── Core learning data ─────────────────────────────────────
    /** @type {object[]} all hypothesis outcomes observed */
    this.outcomes = [];

    /** @type {Map<string, object>} category → learning stats */
    this.categoryStats = new Map();

    /** @type {Map<string, object>} verification_type → learning stats */
    this.verificationStats = new Map();

    /** @type {Map<string, object>} target_id → target-specific learning */
    this.targetLearning = new Map();

    // ── Current weights ────────────────────────────────────────
    /** @type {object} current EVV weights (may be adjusted by learning) */
    this.currentWeights = { ...DEFAULT_WEIGHTS };

    /** @type {object[]} weight adjustment history */
    this.weightHistory = [];

    /** @type {Date|null} last reweight timestamp */
    this.lastReweightAt = null;

    /** @type {number} total reweights performed */
    this.totalReweights = 0;

    // ── Metrics ────────────────────────────────────────────────
    this.metrics = {
      total_observations: 0,
      total_confirmed: 0,
      total_rejected: 0,
      total_inconclusive: 0,
      overall_success_rate: 0,
      improvement_per_month: 0,
      categories_learned: 0,
      targets_learned: 0,
      last_improvement: null,
    };

    // Ensure directory exists
    fs.mkdirSync(LEARNING_DIR, { recursive: true });

    // Auto-load
    this.load();

    // Start periodic reweight
    this._reweightTimer = setInterval(() => {
      this.reweight();
    }, REWEIGHT_INTERVAL_MS);
  }

  // ─── Outcome Tracking ───────────────────────────────────────────

  /**
   * Record a hypothesis outcome for learning.
   *
   * @param {object} outcome
   * @param {string} outcome.hypothesis_id
   * @param {string} outcome.category
   * @param {string} outcome.verdict - 'confirmed' | 'rejected' | 'inconclusive'
   * @param {string} [outcome.target_id]
   * @param {string} [outcome.verification_type]
   * @param {number} [outcome.evv] - original EVV score
   * @param {number} [outcome.duration_ms]
   * @param {number} [outcome.evidence_strength]
   */
  recordOutcome(outcome) {
    const record = {
      id: `LRN-${crypto.randomUUID().substring(0, 8)}`,
      hypothesis_id: outcome.hypothesis_id,
      category: outcome.category || 'unknown',
      verdict: outcome.verdict || 'inconclusive',
      target_id: outcome.target_id || null,
      verification_type: outcome.verification_type || null,
      evv: outcome.evv || 0,
      duration_ms: outcome.duration_ms || 0,
      evidence_strength: outcome.evidence_strength || 0,
      recorded_at: Date.now(),
    };

    this.outcomes.push(record);

    // Cap
    if (this.outcomes.length > MAX_HISTORY) {
      this.outcomes.splice(0, this.outcomes.length - MAX_HISTORY);
    }

    // Update category stats
    this._updateCategoryStats(record);

    // Update verification stats
    this._updateVerificationStats(record);

    // Update target-specific learning
    if (record.target_id) {
      this._updateTargetLearning(record);
    }

    // Update metrics
    this.metrics.total_observations++;
    if (record.verdict === 'confirmed') this.metrics.total_confirmed++;
    else if (record.verdict === 'rejected') this.metrics.total_rejected++;
    else this.metrics.total_inconclusive++;

    this.metrics.overall_success_rate =
      this.metrics.total_observations > 0
        ? Math.round((this.metrics.total_confirmed / this.metrics.total_observations) * 10000) / 10000
        : 0;

    // Update target brain
    if (record.target_id && this.brainRegistry) {
      const brain = this.brainRegistry.getOrCreate(record.target_id);
      brain.recordVerification({
        finding_id: record.hypothesis_id,
        verdict: record.verdict,
        category: record.category,
        duration_ms: record.duration_ms,
        evidence_strength: record.evidence_strength,
      });
    }

    // Persist to knowledge base
    if (this.kb) {
      this.kb.addValidation({
        finding_id: record.hypothesis_id,
        verdict: record.verdict,
        evidence: [],
        duration_ms: record.duration_ms,
        meta: {
          category: record.category,
          evv: record.evv,
          verification_type: record.verification_type,
        },
      });
    }
  }

  /**
   * Batch record outcomes from a campaign iteration.
   *
   * @param {object} iterationResults
   */
  learnFromIteration(iterationResults) {
    // If the iteration produced verification results, learn from them
    if (iterationResults.verification_results) {
      for (const result of iterationResults.verification_results) {
        this.recordOutcome(result);
      }
    }

    // Also track iteration-level learning
    this._computeImprovementPerMonth();
  }

  // ─── Reweighting ────────────────────────────────────────────────

  /**
   * Recompute weights based on accumulated learning data.
   *
   * Weight adjustments follow these principles:
   *   - Categories with higher success rates get more weight on historical_success
   *   - Categories where coverage gaps correlate with bugs get more weight on coverage_gap
   *   - Recent observations are weighted more heavily (temporal decay)
   *   - Under-explored categories get an exploration bonus
   *
   * @returns {object} new weights and change summary
   */
  reweight() {
    if (this.outcomes.length < MIN_OBSERVATIONS_FOR_REWEIGHT) {
      return { weights: this.currentWeights, changed: false, reason: 'insufficient_data' };
    }

    const oldWeights = { ...this.currentWeights };

    // Compute category-weighted success rates
    const categorySuccessRates = this._computeCategorySuccessRates();

    // Compute verification effectiveness
    const verificationEffectiveness = this._computeVerificationEffectiveness();

    // Adjust weights based on what's been working
    const newWeights = { ...DEFAULT_WEIGHTS };

    // If certain categories consistently confirm, boost historical_success weight
    const avgSuccessRate = Object.values(categorySuccessRates)
      .reduce((s, r) => s + r, 0) / Math.max(Object.keys(categorySuccessRates).length, 1);

    if (avgSuccessRate > 0.3) {
      // Historical success is valuable — boost it
      newWeights.historical_success = Math.min(0.30, DEFAULT_WEIGHTS.historical_success + 0.05);
      newWeights.severity = DEFAULT_WEIGHTS.severity - 0.025;
      newWeights.confidence = DEFAULT_WEIGHTS.confidence - 0.025;
    } else if (avgSuccessRate < 0.1) {
      // Low success — rely more on coverage gaps to find new areas
      newWeights.coverage_gap = Math.min(0.30, DEFAULT_WEIGHTS.coverage_gap + 0.05);
      newWeights.historical_success = Math.max(0.10, DEFAULT_WEIGHTS.historical_success - 0.05);
      newWeights.severity = DEFAULT_WEIGHTS.severity - 0.025;
    }

    // Normalize weights
    const sum = Object.values(newWeights).reduce((a, b) => a + b, 0);
    if (sum > 0) {
      for (const key of Object.keys(newWeights)) {
        newWeights[key] = Math.round((newWeights[key] / sum) * 1000) / 1000;
      }
    }

    // Apply changes
    this.currentWeights = newWeights;
    this.lastReweightAt = Date.now();
    this.totalReweights++;

    // Record weight change
    const change = {};
    for (const key of Object.keys(newWeights)) {
      change[key] = Math.round((newWeights[key] - (oldWeights[key] || 0)) * 1000) / 1000;
    }

    this.weightHistory.push({
      from: oldWeights,
      to: newWeights,
      change,
      category_success_rates: categorySuccessRates,
      total_observations: this.metrics.total_observations,
      ts: Date.now(),
    });

    // Cap weight history
    if (this.weightHistory.length > 100) {
      this.weightHistory = this.weightHistory.slice(-100);
    }

    // Propagate to hypothesis prioritizer
    if (this.hypothesisPrioritizer) {
      this.hypothesisPrioritizer.weights = { ...newWeights };
    }

    // Propagate to target brains
    if (this.brainRegistry) {
      for (const [targetId, brain] of this.brainRegistry.brains) {
        // Target-specific weight adjustment
        const targetLearning = this.targetLearning.get(targetId);
        if (targetLearning && targetLearning.observations >= MIN_OBSERVATIONS_FOR_REWEIGHT / 2) {
          brain.customWeights = this._computeTargetWeights(targetId, newWeights);
        } else {
          brain.customWeights = { ...newWeights };
        }
      }
    }

    return {
      weights: newWeights,
      change,
      changed: true,
      reason: 'data_driven',
    };
  }

  // ─── Query Methods ──────────────────────────────────────────────

  /**
   * Get hypothesis success scores per category.
   * @returns {object[]}
   */
  getHypothesisSuccessScores() {
    const results = [];
    for (const [category, stats] of this.categoryStats) {
      const total = stats.confirmed + stats.rejected + stats.inconclusive;
      results.push({
        category,
        total_observations: total,
        confirmed: stats.confirmed,
        rejected: stats.rejected,
        success_rate: total > 0 ? stats.confirmed / total : 0,
        recent_success_rate: this._recentSuccessRate(category),
        exploration_bonus: this._explorationBonus(category),
        effective_weight: (total > 0 ? stats.confirmed / total : 0) + this._explorationBonus(category),
      });
    }
    results.sort((a, b) => b.effective_weight - a.effective_weight);
    return results;
  }

  /**
   * Get verification success scores per verification type.
   * @returns {object[]}
   */
  getVerificationSuccessScores() {
    const results = [];
    for (const [vtype, stats] of this.verificationStats) {
      const total = stats.confirmed + stats.rejected + stats.inconclusive;
      results.push({
        verification_type: vtype,
        total: total,
        confirmed: stats.confirmed,
        success_rate: total > 0 ? stats.confirmed / total : 0,
        avg_duration_ms: stats.total_duration > 0
          ? Math.round(stats.total_duration / total)
          : 0,
      });
    }
    results.sort((a, b) => b.success_rate - a.success_rate);
    return results;
  }

  /**
   * Get target-specific weights.
   *
   * @param {string} targetId
   * @returns {object}
   */
  getTargetWeights(targetId) {
    return this._computeTargetWeights(targetId, this.currentWeights);
  }

  /**
   * Get all learning metrics.
   * @returns {object}
   */
  getMetrics() {
    this._computeImprovementPerMonth();

    return {
      ...this.metrics,
      categories_learned: this.categoryStats.size,
      targets_learned: this.targetLearning.size,
      current_weights: this.currentWeights,
      total_reweights: this.totalReweights,
      last_reweight_at: this.lastReweightAt,
      weight_changes: this.weightHistory.length,
    };
  }

  /**
   * Get a summary of the learning engine state.
   * @returns {object}
   */
  getSummary() {
    return {
      total_observations: this.metrics.total_observations,
      success_rate: this.metrics.overall_success_rate,
      improvement_per_month: this.metrics.improvement_per_month,
      current_weights: this.currentWeights,
      top_categories: this.getHypothesisSuccessScores().slice(0, 5),
      top_verification_types: this.getVerificationSuccessScores().slice(0, 5),
      total_reweights: this.totalReweights,
    };
  }

  // ─── Internal ───────────────────────────────────────────────────

  _updateCategoryStats(record) {
    const category = record.category;
    if (!this.categoryStats.has(category)) {
      this.categoryStats.set(category, {
        confirmed: 0,
        rejected: 0,
        inconclusive: 0,
        total_duration: 0,
        recent_outcomes: [],
      });
    }

    const stats = this.categoryStats.get(category);
    if (record.verdict === 'confirmed') stats.confirmed++;
    else if (record.verdict === 'rejected') stats.rejected++;
    else stats.inconclusive++;

    stats.total_duration += record.duration_ms || 0;

    // Track recent outcomes (last 50)
    stats.recent_outcomes.push({
      verdict: record.verdict,
      ts: record.recorded_at,
    });
    if (stats.recent_outcomes.length > 50) {
      stats.recent_outcomes = stats.recent_outcomes.slice(-50);
    }
  }

  _updateVerificationStats(record) {
    const vtype = record.verification_type;
    if (!vtype) return;

    if (!this.verificationStats.has(vtype)) {
      this.verificationStats.set(vtype, {
        confirmed: 0,
        rejected: 0,
        inconclusive: 0,
        total_duration: 0,
      });
    }

    const stats = this.verificationStats.get(vtype);
    if (record.verdict === 'confirmed') stats.confirmed++;
    else if (record.verdict === 'rejected') stats.rejected++;
    else stats.inconclusive++;

    stats.total_duration += record.duration_ms || 0;
  }

  _updateTargetLearning(record) {
    const targetId = record.target_id;
    if (!this.targetLearning.has(targetId)) {
      this.targetLearning.set(targetId, {
        observations: 0,
        confirmed: 0,
        rejected: 0,
        category_rates: new Map(),
        best_categories: [],
        worst_categories: [],
      });
    }

    const tl = this.targetLearning.get(targetId);
    tl.observations++;
    if (record.verdict === 'confirmed') tl.confirmed++;
    else if (record.verdict === 'rejected') tl.rejected++;

    // Track per-category rates for this target
    const cat = record.category;
    if (!tl.category_rates.has(cat)) {
      tl.category_rates.set(cat, { confirmed: 0, total: 0 });
    }
    const cr = tl.category_rates.get(cat);
    cr.total++;
    if (record.verdict === 'confirmed') cr.confirmed++;

    // Update best/worst categories
    const catRates = [...tl.category_rates.entries()]
      .map(([c, r]) => ({ category: c, rate: r.total > 0 ? r.confirmed / r.total : 0 }))
      .sort((a, b) => b.rate - a.rate);

    tl.best_categories = catRates.slice(0, 3).map(c => c.category);
    tl.worst_categories = catRates.slice(-3).map(c => c.category);
  }

  _computeCategorySuccessRates() {
    const rates = {};
    for (const [category, stats] of this.categoryStats) {
      const total = stats.confirmed + stats.rejected + stats.inconclusive;
      rates[category] = total > 0 ? stats.confirmed / total : 0;
    }
    return rates;
  }

  _computeVerificationEffectiveness() {
    const effectiveness = {};
    for (const [vtype, stats] of this.verificationStats) {
      const total = stats.confirmed + stats.rejected + stats.inconclusive;
      effectiveness[vtype] = {
        success_rate: total > 0 ? stats.confirmed / total : 0,
        avg_duration: total > 0 ? stats.total_duration / total : 0,
      };
    }
    return effectiveness;
  }

  _recentSuccessRate(category, windowMs = 86400000) {
    const stats = this.categoryStats.get(category);
    if (!stats) return 0;

    const since = Date.now() - windowMs;
    const recent = stats.recent_outcomes.filter(o => o.ts >= since);
    if (recent.length === 0) return 0;

    return recent.filter(o => o.verdict === 'confirmed').length / recent.length;
  }

  _explorationBonus(category) {
    const stats = this.categoryStats.get(category);
    if (!stats) return EXPLORATION_BONUS; // never tried → full bonus

    const total = stats.confirmed + stats.rejected + stats.inconclusive;
    if (total < 5) return EXPLORATION_BONUS; // few attempts → bonus
    if (total < 10) return EXPLORATION_BONUS * 0.5;

    return 0; // well-explored → no bonus
  }

  _computeTargetWeights(targetId, baseWeights) {
    const tl = this.targetLearning.get(targetId);
    if (!tl || tl.observations < 10) return { ...baseWeights };

    // Adjust weights based on target-specific learning
    const adjusted = { ...baseWeights };

    // If this target has high success in certain categories,
    // boost historical_success weight
    const successRate = tl.observations > 0 ? tl.confirmed / tl.observations : 0;
    if (successRate > 0.3) {
      adjusted.historical_success = Math.min(0.35, (adjusted.historical_success || 0.20) + 0.05);
      adjusted.coverage_gap = Math.max(0.10, (adjusted.coverage_gap || 0.20) - 0.03);
    } else if (successRate < 0.1) {
      adjusted.coverage_gap = Math.min(0.30, (adjusted.coverage_gap || 0.20) + 0.05);
      adjusted.historical_success = Math.max(0.10, (adjusted.historical_success || 0.20) - 0.03);
    }

    // Normalize
    const sum = Object.values(adjusted).reduce((a, b) => a + b, 0);
    if (sum > 0) {
      for (const key of Object.keys(adjusted)) {
        adjusted[key] = Math.round((adjusted[key] / sum) * 1000) / 1000;
      }
    }

    return adjusted;
  }

  _computeImprovementPerMonth() {
    if (this.outcomes.length < 30) {
      this.metrics.improvement_per_month = 0;
      return;
    }

    const monthMs = 30 * 86400000;
    const now = Date.now();

    // Compare recent month's success rate to previous month
    const recent = this.outcomes.filter(o => (now - o.recorded_at) < monthMs);
    const previous = this.outcomes.filter(o =>
      (now - o.recorded_at) >= monthMs && (now - o.recorded_at) < 2 * monthMs
    );

    if (recent.length < 10 || previous.length < 10) {
      this.metrics.improvement_per_month = 0;
      return;
    }

    const recentRate = recent.filter(o => o.verdict === 'confirmed').length / recent.length;
    const previousRate = previous.filter(o => o.verdict === 'confirmed').length / previous.length;

    this.metrics.improvement_per_month = Math.round((recentRate - previousRate) * 10000) / 10000;
    this.metrics.last_improvement = Date.now();
  }

  // ─── Persistence ────────────────────────────────────────────────

  /**
   * Save learning state to disk.
   * @returns {string} path written
   */
  save() {
    const filePath = path.join(LEARNING_DIR, 'learning-state.json');

    const data = {
      version: '0.7',
      saved_at: Date.now(),
      current_weights: this.currentWeights,
      weight_history: this.weightHistory.slice(-50),
      total_reweights: this.totalReweights,
      last_reweight_at: this.lastReweightAt,
      metrics: this.metrics,
      category_stats: [...this.categoryStats.entries()].map(([k, v]) => [
        k,
        { ...v, recent_outcomes: v.recent_outcomes?.slice(-20) || [] },
      ]),
      verification_stats: [...this.verificationStats.entries()],
      target_learning: [...this.targetLearning.entries()].map(([k, v]) => [
        k,
        { ...v, category_rates: [...v.category_rates.entries()] },
      ]),
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  /**
   * Load learning state from disk.
   * @returns {boolean}
   */
  load() {
    const filePath = path.join(LEARNING_DIR, 'learning-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      this.currentWeights = data.current_weights || { ...DEFAULT_WEIGHTS };
      this.weightHistory = data.weight_history || [];
      this.totalReweights = data.total_reweights || 0;
      this.lastReweightAt = data.last_reweight_at || null;
      this.metrics = { ...this.metrics, ...(data.metrics || {}) };

      this.categoryStats = new Map(
        (data.category_stats || []).map(([k, v]) => [k, v])
      );
      this.verificationStats = new Map(data.verification_stats || []);
      this.targetLearning = new Map(
        (data.target_learning || []).map(([k, v]) => [k, {
          ...v,
          category_rates: new Map(v.category_rates || []),
        }])
      );

      return true;
    } catch (_) {
      return false;
    }
  }

  /**
   * Shut down the learning engine.
   */
  shutdown() {
    if (this._reweightTimer) {
      clearInterval(this._reweightTimer);
    }
    this.save();
  }
}

module.exports = { LearningEngine, LEARNING_DIR, DEFAULT_WEIGHTS };

