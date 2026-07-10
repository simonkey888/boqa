/**
 * BOQA confidence-calibrator.js — ConfidenceCalibrator v1.1
 *
 * Fixes EVI inflation and ranking drift through Bayesian calibration
 * and historical prediction error correction. Converts raw EVI scores
 * into Calibrated EVI (CEVI) with uncertainty bands.
 *
 * Calibration model:
 *   CEVI = EVI * calibration_factor(target) -
 *          competition_pressure_penalty +
 *          learning_bonus
 *
 * Where:
 *   calibration_factor = derived from historical prediction accuracy
 *     per target/category. If past EVI predictions for a target
 *     consistently overestimate, calibration_factor < 1.0.
 *
 *   competition_pressure_penalty = models how many other researchers
 *     are likely testing the same surface, reducing expected value.
 *
 *   learning_bonus = rewards targets where the system has learned
 *     from past mistakes and adjusted strategy.
 *
 * Confidence bands:
 *   p10, p50, p90 derived from historical prediction error variance.
 *   Wide bands indicate high uncertainty; narrow bands indicate
 *   well-calibrated predictions.
 *
 * Drift correction:
 *   distance(current_model, historical_success_model) penalizes
 *   EVI when the current scoring model has drifted away from the
 *   model that historically produced validated bugs.
 *
 * Safe mode: calibration only adjusts internal scores; no execution
 * logic is affected.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Constants ──────────────────────────────────────────────────────

const CC_DIR = path.join(__dirname, 'output', 'knowledge', 'calibration');

const DEFAULT_OPTIONS = {
  minObservations: 5,      // minimum observations before calibration kicks in
  maxCalibrationAge: 30 * 24 * 3600000,  // 30 days
  defaultCalibrationFactor: 1.0,
  competitionPressureBase: 0.05,
  learningBonusBase: 0.02,
  driftPenaltyBase: 0.03,
  varianceSmoothing: 0.1,   // EMA smoothing for variance estimation
  persistenceIntervalMs: 300000,
};

// =====================================================================
//  CalibrationRecord
// =====================================================================

class CalibrationRecord {
  constructor(data = {}) {
    this.target_id        = data.target_id || '__global__';
    this.category         = data.category || '__global__';

    // Prediction accuracy tracking
    this.predictions      = [];  // { predicted, actual, ts }
    this.maxPredictions   = 200;

    // Derived calibration factors
    this.calibration_factor   = data.calibration_factor ?? 1.0;
    this.mean_error           = data.mean_error ?? 0;
    this.variance             = data.variance ?? 0;
    this.bias                 = data.bias ?? 0; // systematic over/underestimation

    // Uncertainty bands (from historical variance)
    this.p10_offset           = data.p10_offset ?? -5;
    this.p50_offset           = data.p50_offset ?? 0;
    this.p90_offset           = data.p90_offset ?? 5;

    // Competition model
    this.competition_pressure = data.competition_pressure ?? 0;

    // Learning model
    this.learning_bonus       = data.learning_bonus ?? 0;
    this.learning_observations = data.learning_observations ?? 0;

    // Drift model
    this.drift_score          = data.drift_score ?? 0;
    this.historical_weights   = data.historical_weights || null; // snapshot of weights when bugs were found

    // Metadata
    this.observation_count    = data.observation_count ?? 0;
    this.last_updated         = data.last_updated || Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  CEVIResult
// =====================================================================

class CEVIResult {
  constructor(data = {}) {
    this.target_id        = data.target_id || null;
    this.opportunity_id   = data.opportunity_id || null;
    this.hypothesis_id    = data.hypothesis_id || null;

    this.raw_evi          = data.raw_evi ?? 0;
    this.calibration_factor = data.calibration_factor ?? 1.0;
    this.competition_penalty = data.competition_penalty ?? 0;
    this.learning_bonus   = data.learning_bonus ?? 0;
    this.drift_penalty    = data.drift_penalty ?? 0;

    this.cevi             = data.cevi ?? 0;

    // Uncertainty band
    this.p10              = data.p10 ?? 0;
    this.p50              = data.p50 ?? 0;
    this.p90              = data.p90 ?? 0;

    // Metadata
    this.calibrated_at    = Date.now();
    this.confidence_level = data.confidence_level || 'untrained';
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  ConfidenceCalibrator
// =====================================================================

class ConfidenceCalibrator {
  /**
   * @param {object} options
   * @param {object} [options.memoryGraph] - MemoryGraph instance
   * @param {object} [options.knowledgeBase] - KnowledgeBase instance
   */
  constructor(options = {}) {
    this.memoryGraph = options.memoryGraph || null;
    this.knowledgeBase = options.knowledgeBase || null;
    this.options = { ...DEFAULT_OPTIONS, ...options };

    /** @type {Map<string, CalibrationRecord>} key → CalibrationRecord */
    this.records = new Map();

    // Global calibration record
    this.globalRecord = new CalibrationRecord({ target_id: '__global__', category: '__global__' });

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_calibrations: 0,
      total_observations: 0,
      avg_calibration_factor: 1.0,
      avg_competition_penalty: 0,
      avg_learning_bonus: 0,
      avg_drift_penalty: 0,
      calibrated_targets: 0,
      calibration_accuracy: 0,
    };

    // ── Persistence timer ────────────────────────────────────
    this._persistTimer = null;

    fs.mkdirSync(CC_DIR, { recursive: true });
    this.load();

    if (this.options.persistenceIntervalMs > 0) {
      this._persistTimer = setInterval(() => this.save(), this.options.persistenceIntervalMs);
    }
  }

  // ─── Calibration ───────────────────────────────────────────────────

  /**
   * Calibrate a raw EVI score into CEVI with uncertainty bands.
   *
   * @param {number} rawEVI - Raw EVI score
   * @param {object} [context] - { target_id, category, opportunity_id, hypothesis_id }
   * @returns {CEVIResult}
   */
  calibrate(rawEVI, context = {}) {
    const targetId = context.target_id || '__global__';
    const category = context.category || '__global__';

    // Get or create calibration record
    const key = `${targetId}:${category}`;
    let record = this.records.get(key);
    if (!record) {
      record = new CalibrationRecord({ target_id: targetId, category });
      this.records.set(key, record);
    }

    // Compute calibration factor
    let calibrationFactor = this.options.defaultCalibrationFactor;
    if (record.observation_count >= this.options.minObservations) {
      // Bayesian adjustment: shrink toward global if insufficient data
      const localWeight = Math.min(1, record.observation_count / 50);
      const localFactor = 1 - record.bias;
      const globalFactor = 1 - this.globalRecord.bias;

      calibrationFactor = localWeight * localFactor + (1 - localWeight) * globalFactor;
      calibrationFactor = Math.max(0.3, Math.min(1.5, calibrationFactor));
    }

    record.calibration_factor = calibrationFactor;

    // Compute competition pressure penalty
    const competitionPenalty = this._computeCompetitionPenalty(targetId, category, record);

    // Compute learning bonus
    const learningBonus = this._computeLearningBonus(targetId, category, record);

    // Compute drift penalty
    const driftPenalty = this._computeDriftPenalty(targetId, category, record);

    // Compute CEVI
    const cevi = Math.max(0, Math.min(100,
      rawEVI * calibrationFactor - competitionPenalty + learningBonus - driftPenalty
    ));

    // Compute uncertainty bands from variance
    const stdDev = Math.sqrt(record.variance || 25); // default 25 if no variance
    const p10 = Math.max(0, cevi - 1.28 * stdDev);
    const p50 = cevi;
    const p90 = Math.min(100, cevi + 1.28 * stdDev);

    // Determine confidence level
    let confidenceLevel = 'untrained';
    if (record.observation_count >= 50) confidenceLevel = 'high';
    else if (record.observation_count >= 20) confidenceLevel = 'medium';
    else if (record.observation_count >= this.options.minObservations) confidenceLevel = 'low';

    this.metrics.total_calibrations++;

    return new CEVIResult({
      target_id: targetId,
      opportunity_id: context.opportunity_id || null,
      hypothesis_id: context.hypothesis_id || null,
      raw_evi: rawEVI,
      calibration_factor: Math.round(calibrationFactor * 1000) / 1000,
      competition_penalty: Math.round(competitionPenalty * 1000) / 1000,
      learning_bonus: Math.round(learningBonus * 1000) / 1000,
      drift_penalty: Math.round(driftPenalty * 1000) / 1000,
      cevi: Math.round(cevi * 100) / 100,
      p10: Math.round(p10 * 100) / 100,
      p50: Math.round(p50 * 100) / 100,
      p90: Math.round(p90 * 100) / 100,
      confidence_level: confidenceLevel,
    });
  }

  /**
   * Batch calibrate multiple EVI scores.
   * @param {object[]} items - Array of { evi, target_id, category, ... }
   * @returns {CEVIResult[]}
   */
  calibrateBatch(items) {
    return items.map(item => {
      const evi = item.evi || item.evi_final || item.evi_raw || 0;
      return this.calibrate(evi, item);
    });
  }

  // ─── Observation Ingestion ─────────────────────────────────────────

  /**
   * Record a prediction vs. actual outcome to improve calibration.
   *
   * @param {object} data - { target_id, category, predicted, actual }
   * @returns {CalibrationRecord}
   */
  recordObservation(data) {
    const targetId = data.target_id || '__global__';
    const category = data.category || '__global__';
    const key = `${targetId}:${category}`;

    let record = this.records.get(key);
    if (!record) {
      record = new CalibrationRecord({ target_id: targetId, category });
      this.records.set(key, record);
    }

    const predicted = data.predicted || 0;
    const actual = data.actual || 0;
    const error = predicted - actual;

    record.predictions.push({ predicted, actual, error, ts: Date.now() });
    if (record.predictions.length > record.maxPredictions) {
      record.predictions = record.predictions.slice(-record.maxPredictions);
    }

    record.observation_count++;
    this.metrics.total_observations++;

    // Update statistics using exponential moving average
    const alpha = this.options.varianceSmoothing;
    record.mean_error = record.mean_error * (1 - alpha) + error * alpha;
    record.bias = record.mean_error / Math.max(1, predicted || 1);

    // Update variance (EMA of squared errors)
    const squaredError = error * error;
    record.variance = record.variance * (1 - alpha) + squaredError * alpha;

    // Update uncertainty bands
    const stdDev = Math.sqrt(record.variance);
    record.p10_offset = -1.28 * stdDev;
    record.p50_offset = 0;
    record.p90_offset = 1.28 * stdDev;

    // Update learning bonus
    if (actual > 0) {
      record.learning_observations++;
      record.learning_bonus = Math.min(0.15, record.learning_observations * this.options.learningBonusBase);
    }

    record.last_updated = Date.now();

    // Also update global record
    this.globalRecord.predictions.push({ predicted, actual, error, ts: Date.now() });
    if (this.globalRecord.predictions.length > this.globalRecord.maxPredictions) {
      this.globalRecord.predictions = this.globalRecord.predictions.slice(-this.globalRecord.maxPredictions);
    }
    this.globalRecord.observation_count++;
    this.globalRecord.mean_error = this.globalRecord.mean_error * (1 - alpha) + error * alpha;
    this.globalRecord.bias = this.globalRecord.mean_error / Math.max(1, predicted || 1);
    this.globalRecord.variance = this.globalRecord.variance * (1 - alpha) + squaredError * alpha;

    this._updateMetrics();
    return record;
  }

  // ─── Competition Pressure ─────────────────────────────────────────

  _computeCompetitionPenalty(targetId, category, record) {
    // Base competition from record
    let penalty = record.competition_pressure;

    // If we have MemoryGraph, estimate competition from cross-target patterns
    if (this.memoryGraph) {
      const failurePatterns = this.memoryGraph.detectRepeatedFailures(2);
      const targetPatterns = failurePatterns.filter(p =>
        p.targets.includes(targetId) && p.occurrence_count > 3
      );
      // More patterns = more people testing = more competition
      penalty += targetPatterns.length * this.options.competitionPressureBase;
    }

    // Category-based competition
    const highCompetitionCategories = ['idor', 'xss', 'injection', 'csrf'];
    if (highCompetitionCategories.some(c => (category || '').toLowerCase().includes(c))) {
      penalty += this.options.competitionPressureBase;
    }

    record.competition_pressure = penalty;
    return Math.min(penalty, 15); // Cap at 15 points
  }

  // ─── Learning Bonus ────────────────────────────────────────────────

  _computeLearningBonus(targetId, category, record) {
    let bonus = record.learning_bonus;

    // If MemoryGraph shows we've learned from failures on this target
    if (this.memoryGraph) {
      const targetNodes = this.memoryGraph.queryNodes({ target_id: targetId, type: 'finding', limit: 50 });
      const confirmedFindings = targetNodes.filter(n => n.verdict === 'confirmed');
      if (confirmedFindings.length > 0) {
        bonus = Math.min(0.20, confirmedFindings.length * this.options.learningBonusBase * 2);
      }
    }

    record.learning_bonus = bonus;
    return bonus;
  }

  // ─── Drift Penalty ─────────────────────────────────────────────────

  _computeDriftPenalty(targetId, category, record) {
    let driftScore = record.drift_score;

    // Compute drift as distance between current scoring weights and
    // historical weights that produced validated bugs
    if (record.historical_weights) {
      const currentWeights = this._getCurrentWeights();
      const drift = this._computeWeightDistance(currentWeights, record.historical_weights);
      driftScore = drift * this.options.driftPenaltyBase;
    }

    record.drift_score = driftScore;
    return Math.min(driftScore, 10); // Cap at 10 points
  }

  _getCurrentWeights() {
    // Default EVI weights (can be overridden by DecisionEngine)
    return {
      probability: 0.35,
      capital_efficiency: 0.20,
      competition_inverse: 0.20,
      time_to_revenue_inverse: 0.15,
      automation_score: 0.10,
    };
  }

  _computeWeightDistance(current, historical) {
    const keys = Object.keys(historical);
    let totalDist = 0;
    for (const key of keys) {
      totalDist += Math.abs((current[key] || 0) - (historical[key] || 0));
    }
    return totalDist;
  }

  /**
   * Set the historical weight snapshot for a target.
   * Called when a validated bug is found.
   *
   * @param {string} targetId
   * @param {string} category
   * @param {object} weights
   */
  setHistoricalWeights(targetId, category, weights) {
    const key = `${targetId}:${category}`;
    let record = this.records.get(key);
    if (!record) {
      record = new CalibrationRecord({ target_id: targetId, category });
      this.records.set(key, record);
    }
    record.historical_weights = { ...weights };
    record.last_updated = Date.now();
  }

  // ─── Query ──────────────────────────────────────────────────────────

  getCalibrationRecord(targetId, category) {
    const key = `${targetId || '__global__'}:${category || '__global__'}`;
    return this.records.get(key) || null;
  }

  getMetrics() {
    return { ...this.metrics, record_count: this.records.size };
  }

  _updateMetrics() {
    this.metrics.calibrated_targets = this.records.size;
    if (this.records.size > 0) {
      let totalCalFactor = 0, totalCompPenalty = 0, totalLearnBonus = 0, totalDriftPenalty = 0;
      for (const [, record] of this.records) {
        totalCalFactor += record.calibration_factor;
        totalCompPenalty += record.competition_pressure;
        totalLearnBonus += record.learning_bonus;
        totalDriftPenalty += record.drift_score;
      }
      this.metrics.avg_calibration_factor = Math.round(totalCalFactor / this.records.size * 1000) / 1000;
      this.metrics.avg_competition_penalty = Math.round(totalCompPenalty / this.records.size * 1000) / 1000;
      this.metrics.avg_learning_bonus = Math.round(totalLearnBonus / this.records.size * 1000) / 1000;
      this.metrics.avg_drift_penalty = Math.round(totalDriftPenalty / this.records.size * 1000) / 1000;
    }

    // Calibration accuracy: how close predictions are to actuals
    if (this.globalRecord.predictions.length >= this.options.minObservations) {
      const recent = this.globalRecord.predictions.slice(-50);
      const mae = recent.reduce((s, p) => s + Math.abs(p.error), 0) / recent.length;
      const avgPredicted = recent.reduce((s, p) => s + p.predicted, 0) / recent.length;
      this.metrics.calibration_accuracy = avgPredicted > 0
        ? Math.round(Math.max(0, 1 - mae / avgPredicted) * 1000) / 1000
        : 0;
    }
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(CC_DIR, 'calibration-state.json');
    const data = {
      version: '1.1',
      saved_at: Date.now(),
      records: [...this.records.entries()].slice(-500),
      global_record: this.globalRecord,
      metrics: this.metrics,
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(CC_DIR, 'calibration-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      if (data.records) {
        this.records = new Map(data.records.map(([k, v]) => [k, new CalibrationRecord(v)]));
      }
      if (data.global_record) {
        this.globalRecord = new CalibrationRecord(data.global_record);
      }
      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      this._updateMetrics();
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.records.clear();
    this.globalRecord = new CalibrationRecord({ target_id: '__global__', category: '__global__' });
    this.metrics = {
      total_calibrations: 0, total_observations: 0,
      avg_calibration_factor: 1.0, avg_competition_penalty: 0,
      avg_learning_bonus: 0, avg_drift_penalty: 0,
      calibrated_targets: 0, calibration_accuracy: 0,
    };
  }

  shutdown() {
    if (this._persistTimer) clearInterval(this._persistTimer);
    this.save();
  }
}

module.exports = {
  ConfidenceCalibrator,
  CalibrationRecord,
  CEVIResult,
};

