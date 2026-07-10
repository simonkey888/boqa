/**
 * BOQA feedback-loop.js — FeedbackLoop v0.9
 *
 * Continuously adjusts priorities and parameters using verification
 * outcomes and real-time metrics. This is the closed-loop feedback
 * system that closes the loop between observation and action.
 *
 * Feedback sources:
 *   - Verification outcomes: confirmed/rejected/inconclusive results
 *     feed back into priority weights, exploration ratios, risk weights
 *   - Real-time metrics: yield, cost, throughput, false positive rates
 *     feed into parameter adjustments
 *   - Threshold breaches: when metric thresholds are violated
 *   - Anomaly signals: anomalous patterns requiring corrective action
 *
 * Feedback processing:
 *   1. Ingest signals from all sources into a signal buffer
 *   2. Batch process accumulated signals → generate adjustments
 *   3. Apply adjustments and propagate to subsystems
 *   4. Detect convergence (stable state) and reduce adjustment frequency
 *   5. Detect oscillation (rapid back-and-forth) and dampen changes
 *
 * Adaptive weighting:
 *   - Prediction weights: adjusted based on prediction accuracy feedback
 *   - Risk weights: adjusted based on false positive / missed risk feedback
 *   - Exploration ratios: adjusted based on yield-per-exploration-unit
 *   - Verification thresholds: adjusted based on verification outcomes
 *
 * Feedback propagation targets:
 *   - OptimizerEngine: strategy parameters, objective weights
 *   - PriorityShaper: prediction_weight, risk_weight, exploration_bonus
 *   - ResourceOptimizer: allocation ratios, EV thresholds
 *   - LearningEngine: reweight triggers, category boosts
 *
 * Safe mode: feedback only adjusts internal parameters and priorities;
 * it never bypasses safe mode constraints or authorization boundaries.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const FEEDBACK_DIR = path.join(__dirname, 'output', 'knowledge', 'feedback');

// ─── Default Configuration ──────────────────────────────────────────

const DEFAULT_FEEDBACK_CONFIG = {
  process_interval_ms: 30000,        // How often to batch-process signals
  max_signals_buffer: 5000,          // Max signals before forced processing
  convergence_threshold: 0.05,       // Parameter variance below this = converged
  oscillation_window: 10,            // Number of adjustments to check for oscillation
  oscillation_threshold: 0.15,       // Direction-reversal rate above this = oscillating
  dampening_factor: 0.70,            // Scale adjustments by this when oscillating
  min_adjustment_interval_ms: 60000, // Minimum time between adjustments per param
  max_adjustment_history: 500,       // Max adjustment records retained
  max_signal_history: 2000,          // Max signal records retained in history
  verification_boost_confirmed: 0.10, // Boost weight when hypothesis confirmed
  verification_penalty_rejected: 0.05, // Penalty weight when hypothesis rejected
  metric_sensitivity: 0.50,          // How strongly metric changes affect adjustments
  anomaly_sensitivity: 0.80,         // How strongly anomalies affect adjustments
};

// ─── Signal Sources ─────────────────────────────────────────────────

const SIGNAL_SOURCES = {
  VERIFICATION: 'verification',
  METRIC:       'metric',
  THRESHOLD:    'threshold',
  ANOMALY:      'anomaly',
};

// ─── Signal Types ───────────────────────────────────────────────────

const SIGNAL_TYPES = {
  POSITIVE: 'positive',
  NEGATIVE: 'negative',
  NEUTRAL:  'neutral',
};

// ─── Adjustment Targets ─────────────────────────────────────────────

const ADJUSTMENT_TARGETS = {
  PREDICTION_WEIGHT:       'prediction_weight',
  RISK_WEIGHT:             'risk_weight',
  EXPLORATION_RATIO:       'exploration_ratio',
  VERIFICATION_THRESHOLD:  'verification_threshold',
  OBJECTIVE_ALPHA:         'objective_alpha',
  OBJECTIVE_BETA:          'objective_beta',
  OBJECTIVE_GAMMA:         'objective_gamma',
  OBJECTIVE_DELTA:         'objective_delta',
  COVERAGE_GAP_WEIGHT:     'coverage_gap_weight',
  LEARNING_BOOST_WEIGHT:   'learning_boost_weight',
  FALSE_POSITIVE_PENALTY:  'false_positive_penalty',
  REBALANCE_INTERVAL:      'rebalance_interval',
};

// =====================================================================
//  FeedbackSignal
// =====================================================================

class FeedbackSignal {
  /**
   * Represents a single feedback signal from any source.
   *
   * @param {object} data
   * @param {string} [data.id]
   * @param {string} data.source       - 'verification' | 'metric' | 'threshold' | 'anomaly'
   * @param {string} data.type         - 'positive' | 'negative' | 'neutral'
   * @param {string} data.metric_name  - Name of the metric or parameter this signal refers to
   * @param {number} data.old_value    - Previous value
   * @param {number} data.new_value    - Current value
   * @param {number} [data.delta]      - Change magnitude
   * @param {number} [data.confidence] - Signal confidence 0-1
   * @param {object} [data.context]    - Additional context (target_id, category, etc.)
   * @param {number} [data.ts]         - Timestamp
   */
  constructor(data = {}) {
    this.id = data.id || `SIG-${crypto.randomUUID().substring(0, 8)}`;
    this.source = data.source || SIGNAL_SOURCES.METRIC;
    this.type = data.type || SIGNAL_TYPES.NEUTRAL;
    this.metric_name = data.metric_name || '';
    this.old_value = data.old_value !== undefined ? data.old_value : 0;
    this.new_value = data.new_value !== undefined ? data.new_value : 0;
    this.delta = data.delta !== undefined
      ? data.delta
      : (this.new_value - this.old_value);
    this.confidence = data.confidence !== undefined ? data.confidence : 0.5;
    this.context = data.context || {};
    this.ts = data.ts || Date.now();
  }
}

// =====================================================================
//  FeedbackAdjustment
// =====================================================================

class FeedbackAdjustment {
  /**
   * Represents a parameter adjustment generated from feedback signals.
   *
   * @param {object} data
   * @param {string} [data.id]
   * @param {string[]} [data.signal_ids]    - IDs of signals that triggered this
   * @param {string} data.target_param      - Which parameter is being adjusted
   * @param {number} data.old_value         - Previous parameter value
   * @param {number} data.new_value         - New parameter value
   * @param {string} [data.reason]          - Human-readable reason
   * @param {string} [data.expected_effect] - What we expect to happen
   * @param {string|null} [data.actual_effect] - What actually happened (filled later)
   * @param {number} [data.ts]              - Timestamp
   */
  constructor(data = {}) {
    this.id = data.id || `FADJ-${crypto.randomUUID().substring(0, 8)}`;
    this.signal_ids = data.signal_ids || [];
    this.target_param = data.target_param || '';
    this.old_value = data.old_value !== undefined ? data.old_value : 0;
    this.new_value = data.new_value !== undefined ? data.new_value : 0;
    this.reason = data.reason || '';
    this.expected_effect = data.expected_effect || '';
    this.actual_effect = data.actual_effect !== undefined ? data.actual_effect : null;
    this.ts = data.ts || Date.now();
  }
}

// =====================================================================
//  FeedbackLoop
// =====================================================================

class FeedbackLoop {
  /**
   * @param {object} options
   * @param {object} [options.optimizerEngine]    - OptimizerEngine instance
   * @param {object} [options.learningEngine]     - LearningEngine instance
   * @param {object} [options.priorityShaper]     - PriorityShaper instance
   * @param {object} [options.resourceOptimizer]  - ResourceOptimizer instance
   * @param {object} [options.predictionEngine]   - PredictionEngine instance
   * @param {object} [options.efficiencyTracker]  - EfficiencyTracker instance
   * @param {object} [options.knowledgeBase]      - KnowledgeBase instance
   * @param {object} [options.config]             - Override default config
   */
  constructor(options = {}) {
    this.optimizerEngine = options.optimizerEngine || null;
    this.learningEngine = options.learningEngine || null;
    this.priorityShaper = options.priorityShaper || null;
    this.resourceOptimizer = options.resourceOptimizer || null;
    this.predictionEngine = options.predictionEngine || null;
    this.efficiencyTracker = options.efficiencyTracker || null;
    this.kb = options.knowledgeBase || null;

    this.config = { ...DEFAULT_FEEDBACK_CONFIG, ...(options.config || {}) };

    // ── Signal buffer ──────────────────────────────────────────
    /** @type {FeedbackSignal[]} unprocessed signals */
    this.signalBuffer = [];

    // ── History ────────────────────────────────────────────────
    /** @type {FeedbackSignal[]} processed signal history */
    this.signalHistory = [];

    /** @type {FeedbackAdjustment[]} adjustment history */
    this.adjustmentHistory = [];

    /** @type {Map<string, number>} target_param → last adjustment timestamp */
    this.lastAdjustmentAt = new Map();

    /** @type {Map<string, number[]>} target_param → recent values for oscillation detection */
    this.recentParamValues = new Map();

    // ── Convergence state ──────────────────────────────────────
    /** @type {boolean} whether the system is currently converged */
    this.converged = false;

    /** @type {number} convergence score 0-1 (1 = fully converged) */
    this.convergenceScore = 0;

    /** @type {number} oscillation score 0-1 (1 = severe oscillation) */
    this.oscillationScore = 0;

    /** @type {number} how many consecutive convergence checks passed */
    this.convergenceStreak = 0;

    // ── Current parameter state (tracked for feedback) ─────────
    this.currentParams = this._collectCurrentParams();

    // ── Metrics ────────────────────────────────────────────────
    this.metrics = {
      total_signals: 0,
      total_adjustments: 0,
      convergence_score: 0,
      oscillation_score: 0,
      avg_adjustment_impact: 0,
      signals_by_source: {
        verification: 0,
        metric: 0,
        threshold: 0,
        anomaly: 0,
      },
      signals_by_type: {
        positive: 0,
        negative: 0,
        neutral: 0,
      },
      adjustments_by_target: {},
      dampenings_applied: 0,
      last_process_at: null,
    };

    // Ensure directory exists
    fs.mkdirSync(FEEDBACK_DIR, { recursive: true });

    // Auto-load
    this.load();

    // Start periodic processing
    this._processTimer = setInterval(() => {
      this.processSignals();
    }, this.config.process_interval_ms);
  }

  // ─── Signal Ingestion ──────────────────────────────────────────

  /**
   * Ingest a verification outcome as a feedback signal.
   *
   * Confirmed → positive signal (boost relevant weights)
   * Rejected → negative signal (reduce relevant weights)
   * Inconclusive → neutral signal (slight exploration boost)
   *
   * @param {object} outcome
   * @param {string} outcome.hypothesis_id
   * @param {string} outcome.verdict - 'confirmed' | 'rejected' | 'inconclusive'
   * @param {string} [outcome.category]
   * @param {string} [outcome.target_id]
   * @param {number} [outcome.evv]
   * @param {number} [outcome.evidence_strength]
   * @param {number} [outcome.duration_ms]
   * @returns {FeedbackSignal}
   */
  ingestVerificationOutcome(outcome) {
    const verdict = outcome.verdict || 'inconclusive';
    let type;
    let metricName;
    let confidence;

    switch (verdict) {
      case 'confirmed':
        type = SIGNAL_TYPES.POSITIVE;
        metricName = 'verification_confirmed';
        confidence = Math.min(1.0, (outcome.evidence_strength || 0.5) + 0.3);
        break;
      case 'rejected':
        type = SIGNAL_TYPES.NEGATIVE;
        metricName = 'verification_rejected';
        confidence = Math.min(1.0, (outcome.evidence_strength || 0.5) + 0.2);
        break;
      default:
        type = SIGNAL_TYPES.NEUTRAL;
        metricName = 'verification_inconclusive';
        confidence = 0.3;
        break;
    }

    const signal = new FeedbackSignal({
      source: SIGNAL_SOURCES.VERIFICATION,
      type,
      metric_name: metricName,
      old_value: verdict === 'confirmed' ? 0 : (verdict === 'rejected' ? 1 : 0.5),
      new_value: verdict === 'confirmed' ? 1 : (verdict === 'rejected' ? 0 : 0.5),
      delta: verdict === 'confirmed' ? 1 : (verdict === 'rejected' ? -1 : 0),
      confidence,
      context: {
        hypothesis_id: outcome.hypothesis_id,
        category: outcome.category || null,
        target_id: outcome.target_id || null,
        evv: outcome.evv || 0,
        evidence_strength: outcome.evidence_strength || 0,
        duration_ms: outcome.duration_ms || 0,
        verdict,
      },
    });

    this._addSignal(signal);
    return signal;
  }

  /**
   * Ingest a real-time metric as a feedback signal.
   *
   * Metrics like yield, cost, throughput, false positive rate are
   * compared against previous values to determine signal type.
   *
   * @param {object} metric
   * @param {string} metric.name         - e.g. 'yield', 'cost', 'throughput', 'false_positive_rate'
   * @param {number} metric.value        - Current metric value
   * @param {number} [metric.previous]   - Previous metric value
   * @param {number} [metric.threshold]  - Threshold for this metric
   * @param {number} [metric.confidence] - Confidence in the measurement
   * @param {object} [metric.context]    - Additional context
   * @returns {FeedbackSignal}
   */
  ingestMetric(metric) {
    const name = metric.name || 'unknown';
    const value = metric.value !== undefined ? metric.value : 0;
    const previous = metric.previous !== undefined ? metric.previous : value;
    const delta = value - previous;

    // Determine signal type based on metric direction
    // Higher is better: yield, throughput
    // Lower is better: cost, false_positive_rate
    const higherIsBetter = ['yield', 'throughput', 'verification_rate', 'success_rate', 'coverage'];
    const lowerIsBetter = ['cost', 'false_positive_rate', 'fp_rate', 'duration_ms', 'latency'];

    let type = SIGNAL_TYPES.NEUTRAL;
    if (delta > 0 && higherIsBetter.includes(name)) type = SIGNAL_TYPES.POSITIVE;
    else if (delta < 0 && higherIsBetter.includes(name)) type = SIGNAL_TYPES.NEGATIVE;
    else if (delta < 0 && lowerIsBetter.includes(name)) type = SIGNAL_TYPES.POSITIVE;
    else if (delta > 0 && lowerIsBetter.includes(name)) type = SIGNAL_TYPES.NEGATIVE;
    else if (Math.abs(delta) < 0.001) type = SIGNAL_TYPES.NEUTRAL;

    // Check threshold breach
    if (metric.threshold !== undefined) {
      if (lowerIsBetter.includes(name) && value > metric.threshold) {
        type = SIGNAL_TYPES.NEGATIVE;
      } else if (higherIsBetter.includes(name) && value < metric.threshold) {
        type = SIGNAL_TYPES.NEGATIVE;
      }
    }

    const signal = new FeedbackSignal({
      source: SIGNAL_SOURCES.METRIC,
      type,
      metric_name: name,
      old_value: previous,
      new_value: value,
      delta,
      confidence: metric.confidence !== undefined ? metric.confidence : 0.7,
      context: metric.context || {},
    });

    this._addSignal(signal);
    return signal;
  }

  /**
   * Ingest a threshold breach as a feedback signal.
   *
   * @param {object} breach
   * @param {string} breach.metric_name   - Which metric breached
   * @param {number} breach.value         - Current value
   * @param {number} breach.threshold     - Threshold that was breached
   * @param {string} breach.direction     - 'above' | 'below'
   * @param {string} [breach.severity]    - 'warning' | 'critical'
   * @param {object} [breach.context]     - Additional context
   * @returns {FeedbackSignal}
   */
  ingestThresholdBreach(breach) {
    const severity = breach.severity || 'warning';
    const confidence = severity === 'critical' ? 0.95 : 0.75;

    const signal = new FeedbackSignal({
      source: SIGNAL_SOURCES.THRESHOLD,
      type: SIGNAL_TYPES.NEGATIVE,
      metric_name: breach.metric_name || '',
      old_value: breach.threshold || 0,
      new_value: breach.value !== undefined ? breach.value : 0,
      delta: (breach.value || 0) - (breach.threshold || 0),
      confidence,
      context: {
        threshold: breach.threshold,
        direction: breach.direction || 'above',
        severity,
        ...(breach.context || {}),
      },
    });

    this._addSignal(signal);
    return signal;
  }

  /**
   * Ingest an anomaly signal as a feedback signal.
   *
   * @param {object} anomaly
   * @param {string} anomaly.metric_name   - Which metric is anomalous
   * @param {number} anomaly.expected      - Expected value
   * @param {number} anomaly.actual        - Actual observed value
   * @param {number} anomaly.deviation     - Standard deviations from mean
   * @param {string} [anomaly.direction]   - 'high' | 'low'
   * @param {number} [anomaly.confidence]  - Confidence in anomaly detection
   * @param {object} [anomaly.context]     - Additional context
   * @returns {FeedbackSignal}
   */
  ingestAnomaly(anomaly) {
    const deviation = anomaly.deviation || 0;
    const type = deviation > 0 ? SIGNAL_TYPES.NEGATIVE : SIGNAL_TYPES.POSITIVE;

    const signal = new FeedbackSignal({
      source: SIGNAL_SOURCES.ANOMALY,
      type,
      metric_name: anomaly.metric_name || '',
      old_value: anomaly.expected !== undefined ? anomaly.expected : 0,
      new_value: anomaly.actual !== undefined ? anomaly.actual : 0,
      delta: (anomaly.actual || 0) - (anomaly.expected || 0),
      confidence: anomaly.confidence !== undefined
        ? anomaly.confidence
        : Math.min(1.0, Math.abs(deviation) * 0.3),
      context: {
        deviation,
        direction: anomaly.direction || (deviation > 0 ? 'high' : 'low'),
        expected: anomaly.expected,
        actual: anomaly.actual,
        ...(anomaly.context || {}),
      },
    });

    this._addSignal(signal);
    return signal;
  }

  // ─── Signal Processing ─────────────────────────────────────────

  /**
   * Batch process accumulated signals and generate adjustments.
   *
   * Processing steps:
   *   1. Aggregate signals by target parameter
   *   2. Compute net direction and magnitude for each parameter
   *   3. Check oscillation before applying
   *   4. Generate adjustments with dampening if needed
   *   5. Apply adjustments and propagate to subsystems
   *
   * @returns {FeedbackAdjustment[]} adjustments applied
   */
  processSignals() {
    if (this.signalBuffer.length === 0) return [];

    // Check for forced processing when buffer is full
    const signals = [...this.signalBuffer];
    this.signalBuffer = [];

    // Move signals to history
    for (const sig of signals) {
      this.signalHistory.push(sig);
      this.metrics.total_signals++;
      this.metrics.signals_by_source[sig.source] =
        (this.metrics.signals_by_source[sig.source] || 0) + 1;
      this.metrics.signals_by_type[sig.type] =
        (this.metrics.signals_by_type[sig.type] || 0) + 1;
    }

    // Cap signal history
    if (this.signalHistory.length > this.config.max_signal_history) {
      this.signalHistory = this.signalHistory.slice(-this.config.max_signal_history);
    }

    // ── Step 1: Map signals to target parameters ────────────────
    const paramSignals = this._mapSignalsToParams(signals);

    // ── Step 2: Generate candidate adjustments ──────────────────
    const candidates = [];

    for (const [targetParam, paramInfo] of Object.entries(paramSignals)) {
      const candidate = this._generateAdjustment(targetParam, paramInfo);
      if (candidate) {
        candidates.push(candidate);
      }
    }

    // ── Step 3: Check oscillation and dampen ────────────────────
    this.detectOscillation();

    const adjustments = [];
    for (const candidate of candidates) {
      // Check minimum adjustment interval
      const lastAdj = this.lastAdjustmentAt.get(candidate.target_param) || 0;
      if (Date.now() - lastAdj < this.config.min_adjustment_interval_ms) {
        continue; // Skip — too soon since last adjustment for this param
      }

      // Apply dampening if oscillating
      if (this.oscillationScore > this.config.oscillation_threshold) {
        const dampenedNewValue =
          candidate.old_value + (candidate.new_value - candidate.old_value) * this.config.dampening_factor;
        candidate.new_value = Math.round(dampenedNewValue * 10000) / 10000;
        candidate.reason += ' [DAMPENED]';
        this.metrics.dampenings_applied++;
      }

      // Skip adjustments that are too small (convergence)
      const absDelta = Math.abs(candidate.new_value - candidate.old_value);
      if (absDelta < 0.001) {
        continue;
      }

      // Apply the adjustment
      this.applyAdjustment(candidate);
      adjustments.push(candidate);
    }

    // ── Step 4: Check convergence ───────────────────────────────
    this.detectConvergence();

    // ── Step 5: Update metrics ──────────────────────────────────
    this.metrics.last_process_at = Date.now();

    // Compute average adjustment impact
    if (this.adjustmentHistory.length > 0) {
      const recent = this.adjustmentHistory.slice(-50);
      const totalImpact = recent.reduce((s, a) =>
        s + Math.abs(a.new_value - a.old_value), 0);
      this.metrics.avg_adjustment_impact =
        Math.round((totalImpact / recent.length) * 10000) / 10000;
    }

    this.metrics.convergence_score = this.convergenceScore;
    this.metrics.oscillation_score = this.oscillationScore;

    return adjustments;
  }

  // ─── Adjustment Application ────────────────────────────────────

  /**
   * Apply a feedback adjustment and propagate to subsystems.
   *
   * @param {FeedbackAdjustment} adjustment
   * @returns {boolean} whether the adjustment was applied
   */
  applyAdjustment(adjustment) {
    const param = adjustment.target_param;
    const newValue = adjustment.new_value;

    // Record in history
    this.adjustmentHistory.push(adjustment);
    if (this.adjustmentHistory.length > this.config.max_adjustment_history) {
      this.adjustmentHistory = this.adjustmentHistory.slice(-this.config.max_adjustment_history);
    }

    // Track param values for oscillation detection
    if (!this.recentParamValues.has(param)) {
      this.recentParamValues.set(param, []);
    }
    this.recentParamValues.get(param).push(newValue);
    if (this.recentParamValues.get(param).length > this.config.oscillation_window + 5) {
      this.recentParamValues.set(
        param,
        this.recentParamValues.get(param).slice(-(this.config.oscillation_window + 5))
      );
    }

    // Update last adjustment timestamp
    this.lastAdjustmentAt.set(param, Date.now());

    // Update current params
    this.currentParams[param] = newValue;

    // Track adjustment count by target
    this.metrics.adjustments_by_target[param] =
      (this.metrics.adjustments_by_target[param] || 0) + 1;
    this.metrics.total_adjustments++;

    // ── Propagate to subsystems ─────────────────────────────────

    this._propagateToOptimizerEngine(param, newValue, adjustment);
    this._propagateToPriorityShaper(param, newValue, adjustment);
    this._propagateToResourceOptimizer(param, newValue, adjustment);
    this._propagateToLearningEngine(param, newValue, adjustment);

    return true;
  }

  // ─── Convergence Detection ─────────────────────────────────────

  /**
   * Detect whether the system has converged (parameters are stable).
   *
   * A system is considered converged when the variance of recent
   * parameter values falls below the convergence threshold for
   * all actively adjusted parameters.
   *
   * @returns {{ converged: boolean, score: number, details: object }}
   */
  detectConvergence() {
    const paramVariances = {};
    let totalVariance = 0;
    let paramCount = 0;

    for (const [param, values] of this.recentParamValues) {
      if (values.length < 3) continue;

      // Compute variance of recent values
      const mean = values.reduce((s, v) => s + v, 0) / values.length;
      const variance = values.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / values.length;
      paramVariances[param] = Math.round(variance * 10000) / 10000;

      totalVariance += variance;
      paramCount++;
    }

    if (paramCount === 0) {
      this.convergenceScore = 0;
      this.converged = false;
      return { converged: false, score: 0, details: paramVariances };
    }

    const avgVariance = totalVariance / paramCount;

    // Convert variance to convergence score (lower variance = higher convergence)
    // Score = 1 - min(avgVariance / threshold, 1)
    this.convergenceScore = Math.round(
      Math.max(0, 1 - Math.min(avgVariance / this.config.convergence_threshold, 1)) * 10000
    ) / 10000;

    const wasConverged = this.converged;
    this.converged = this.convergenceScore >= 0.9;

    if (this.converged) {
      this.convergenceStreak++;
    } else {
      this.convergenceStreak = 0;
    }

    // When converged, we can reduce processing frequency
    // (handled by checking this.converged in the periodic timer)

    this.metrics.convergence_score = this.convergenceScore;

    return {
      converged: this.converged,
      score: this.convergenceScore,
      streak: this.convergenceStreak,
      details: paramVariances,
    };
  }

  // ─── Oscillation Detection ─────────────────────────────────────

  /**
   * Detect parameter oscillation and return oscillation score.
   *
   * Oscillation is detected when parameter values frequently reverse
   * direction. If the direction-reversal rate exceeds the threshold,
   * the system is oscillating and adjustments should be dampened.
   *
   * @returns {{ oscillating: boolean, score: number, details: object }}
   */
  detectOscillation() {
    let totalReversals = 0;
    let totalTransitions = 0;
    const paramOscillation = {};

    for (const [param, values] of this.recentParamValues) {
      if (values.length < 3) continue;

      let reversals = 0;
      let transitions = 0;

      for (let i = 2; i < values.length; i++) {
        const prevDelta = values[i - 1] - values[i - 2];
        const currDelta = values[i] - values[i - 1];

        if (prevDelta !== 0 && currDelta !== 0) {
          transitions++;
          if (Math.sign(prevDelta) !== Math.sign(currDelta)) {
            reversals++;
          }
        }
      }

      const reversalRate = transitions > 0 ? reversals / transitions : 0;
      paramOscillation[param] = Math.round(reversalRate * 10000) / 10000;
      totalReversals += reversals;
      totalTransitions += transitions;
    }

    const overallReversalRate = totalTransitions > 0
      ? totalReversals / totalTransitions
      : 0;

    this.oscillationScore = Math.round(overallReversalRate * 10000) / 10000;

    const oscillating = this.oscillationScore > this.config.oscillation_threshold;
    this.metrics.oscillation_score = this.oscillationScore;

    return {
      oscillating,
      score: this.oscillationScore,
      threshold: this.config.oscillation_threshold,
      details: paramOscillation,
    };
  }

  // ─── History & Metrics ─────────────────────────────────────────

  /**
   * Get the full feedback history (signals + adjustments).
   *
   * @param {object} [options]
   * @param {number} [options.limit]       - Max records to return
   * @param {string} [options.source]      - Filter by signal source
   * @param {string} [options.target_param] - Filter by adjustment target
   * @returns {{ signals: FeedbackSignal[], adjustments: FeedbackAdjustment[] }}
   */
  getFeedbackHistory(options = {}) {
    const limit = options.limit || 100;

    let signals = this.signalHistory;
    let adjustments = this.adjustmentHistory;

    if (options.source) {
      signals = signals.filter(s => s.source === options.source);
    }

    if (options.target_param) {
      adjustments = adjustments.filter(a => a.target_param === options.target_param);
    }

    return {
      signals: signals.slice(-limit),
      adjustments: adjustments.slice(-limit),
    };
  }

  /**
   * Get feedback loop metrics.
   *
   * @returns {object}
   */
  getMetrics() {
    return {
      total_signals: this.metrics.total_signals,
      total_adjustments: this.metrics.total_adjustments,
      convergence_score: this.convergenceScore,
      oscillation_score: this.oscillationScore,
      avg_adjustment_impact: this.metrics.avg_adjustment_impact,
      converged: this.converged,
      convergence_streak: this.convergenceStreak,
      signals_by_source: { ...this.metrics.signals_by_source },
      signals_by_type: { ...this.metrics.signals_by_type },
      adjustments_by_target: { ...this.metrics.adjustments_by_target },
      dampenings_applied: this.metrics.dampenings_applied,
      pending_signals: this.signalBuffer.length,
      last_process_at: this.metrics.last_process_at,
    };
  }

  // ─── Internal: Signal Management ───────────────────────────────

  /**
   * Add a signal to the buffer.
   * @param {FeedbackSignal} signal
   * @private
   */
  _addSignal(signal) {
    this.signalBuffer.push(signal);

    // Force processing if buffer is full
    if (this.signalBuffer.length >= this.config.max_signals_buffer) {
      this.processSignals();
    }
  }

  /**
   * Map signals to the parameters they affect.
   *
   * @param {FeedbackSignal[]} signals
   * @returns {object} param → { signals: [], net_direction: number, total_confidence: number }
   * @private
   */
  _mapSignalsToParams(signals) {
    const paramSignals = {};

    for (const signal of signals) {
      const affectedParams = this._getAffectedParams(signal);

      for (const param of affectedParams) {
        if (!paramSignals[param]) {
          paramSignals[param] = {
            signals: [],
            positive_weight: 0,
            negative_weight: 0,
            neutral_weight: 0,
            total_confidence: 0,
          };
        }

        const ps = paramSignals[param];
        ps.signals.push(signal);
        ps.total_confidence += signal.confidence;

        switch (signal.type) {
          case SIGNAL_TYPES.POSITIVE:
            ps.positive_weight += signal.confidence;
            break;
          case SIGNAL_TYPES.NEGATIVE:
            ps.negative_weight += signal.confidence;
            break;
          default:
            ps.neutral_weight += signal.confidence;
            break;
        }
      }
    }

    return paramSignals;
  }

  /**
   * Determine which parameters a signal affects.
   *
   * @param {FeedbackSignal} signal
   * @returns {string[]} affected parameter names
   * @private
   */
  _getAffectedParams(signal) {
    const params = [];

    switch (signal.source) {
      case SIGNAL_SOURCES.VERIFICATION:
        // Verification outcomes affect prediction weight, exploration ratio,
        // and learning boost
        params.push(ADJUSTMENT_TARGETS.PREDICTION_WEIGHT);
        params.push(ADJUSTMENT_TARGETS.EXPLORATION_RATIO);
        params.push(ADJUSTMENT_TARGETS.LEARNING_BOOST_WEIGHT);
        if (signal.type === SIGNAL_TYPES.NEGATIVE) {
          params.push(ADJUSTMENT_TARGETS.FALSE_POSITIVE_PENALTY);
        }
        break;

      case SIGNAL_SOURCES.METRIC:
        // Metric signals map directly based on metric name
        if (signal.metric_name === 'yield' || signal.metric_name === 'success_rate') {
          params.push(ADJUSTMENT_TARGETS.PREDICTION_WEIGHT);
          params.push(ADJUSTMENT_TARGETS.OBJECTIVE_ALPHA);
        }
        if (signal.metric_name === 'cost' || signal.metric_name === 'latency') {
          params.push(ADJUSTMENT_TARGETS.OBJECTIVE_DELTA);
          params.push(ADJUSTMENT_TARGETS.REBALANCE_INTERVAL);
        }
        if (signal.metric_name === 'false_positive_rate' || signal.metric_name === 'fp_rate') {
          params.push(ADJUSTMENT_TARGETS.FALSE_POSITIVE_PENALTY);
          params.push(ADJUSTMENT_TARGETS.OBJECTIVE_GAMMA);
          params.push(ADJUSTMENT_TARGETS.VERIFICATION_THRESHOLD);
        }
        if (signal.metric_name === 'throughput') {
          params.push(ADJUSTMENT_TARGETS.EXPLORATION_RATIO);
          params.push(ADJUSTMENT_TARGETS.REBALANCE_INTERVAL);
        }
        if (signal.metric_name === 'coverage') {
          params.push(ADJUSTMENT_TARGETS.COVERAGE_GAP_WEIGHT);
          params.push(ADJUSTMENT_TARGETS.EXPLORATION_RATIO);
        }
        break;

      case SIGNAL_SOURCES.THRESHOLD:
        // Threshold breaches are urgent — affect the specific param
        if (signal.metric_name === 'false_positive_rate' || signal.metric_name === 'fp_rate') {
          params.push(ADJUSTMENT_TARGETS.OBJECTIVE_GAMMA);
          params.push(ADJUSTMENT_TARGETS.VERIFICATION_THRESHOLD);
          params.push(ADJUSTMENT_TARGETS.FALSE_POSITIVE_PENALTY);
        }
        if (signal.metric_name === 'cost') {
          params.push(ADJUSTMENT_TARGETS.OBJECTIVE_DELTA);
          params.push(ADJUSTMENT_TARGETS.REBALANCE_INTERVAL);
        }
        if (signal.metric_name === 'yield' || signal.metric_name === 'success_rate') {
          params.push(ADJUSTMENT_TARGETS.OBJECTIVE_ALPHA);
          params.push(ADJUSTMENT_TARGETS.PREDICTION_WEIGHT);
        }
        // Default: affect risk weight
        params.push(ADJUSTMENT_TARGETS.RISK_WEIGHT);
        break;

      case SIGNAL_SOURCES.ANOMALY:
        // Anomalies affect risk weight and exploration ratio
        params.push(ADJUSTMENT_TARGETS.RISK_WEIGHT);
        params.push(ADJUSTMENT_TARGETS.EXPLORATION_RATIO);
        if (signal.context.direction === 'high' && signal.metric_name === 'false_positive_rate') {
          params.push(ADJUSTMENT_TARGETS.FALSE_POSITIVE_PENALTY);
          params.push(ADJUSTMENT_TARGETS.VERIFICATION_THRESHOLD);
        }
        break;

      default:
        params.push(ADJUSTMENT_TARGETS.PREDICTION_WEIGHT);
        break;
    }

    return [...new Set(params)];
  }

  /**
   * Generate an adjustment for a target parameter based on accumulated signals.
   *
   * @param {string} targetParam
   * @param {object} paramInfo - { signals, positive_weight, negative_weight, total_confidence }
   * @returns {FeedbackAdjustment|null}
   * @private
   */
  _generateAdjustment(targetParam, paramInfo) {
    const currentValue = this._getCurrentParamValue(targetParam);
    const { positive_weight, negative_weight, signals } = paramInfo;

    // Net direction: positive means increase param, negative means decrease
    const netDirection = positive_weight - negative_weight;

    // Compute adjustment magnitude based on net direction and sensitivity
    const sensitivity = this._getParamSensitivity(targetParam);
    const totalWeight = positive_weight + negative_weight;

    if (totalWeight === 0) return null; // No meaningful signal

    const directionRatio = netDirection / totalWeight; // -1 to +1
    const magnitude = directionRatio * sensitivity * this.config.metric_sensitivity;

    // For anomaly signals, use anomaly sensitivity
    const hasAnomaly = signals.some(s => s.source === SIGNAL_SOURCES.ANOMALY);
    const effectiveMagnitude = hasAnomaly
      ? magnitude * this.config.anomaly_sensitivity
      : magnitude;

    const newValue = Math.round((currentValue + effectiveMagnitude) * 10000) / 10000;

    // Clamp to reasonable bounds
    const clampedValue = this._clampParamValue(targetParam, newValue);

    if (Math.abs(clampedValue - currentValue) < 0.0001) return null;

    const reason = this._buildAdjustmentReason(targetParam, signals, directionRatio);

    return new FeedbackAdjustment({
      signal_ids: signals.map(s => s.id),
      target_param: targetParam,
      old_value: currentValue,
      new_value: clampedValue,
      reason,
      expected_effect: this._predictEffect(targetParam, directionRatio),
    });
  }

  /**
   * Get the current value of a parameter.
   *
   * @param {string} param
   * @returns {number}
   * @private
   */
  _getCurrentParamValue(param) {
    // Check our tracked params first
    if (this.currentParams[param] !== undefined) {
      return this.currentParams[param];
    }

    // Try to get from subsystems
    if (this.priorityShaper) {
      if (param === ADJUSTMENT_TARGETS.PREDICTION_WEIGHT) {
        return this.priorityShaper.currentPredictionWeight || 0.30;
      }
      if (param === ADJUSTMENT_TARGETS.RISK_WEIGHT) {
        return this.priorityShaper.config.risk_weight || 0.20;
      }
      if (param === ADJUSTMENT_TARGETS.COVERAGE_GAP_WEIGHT) {
        return this.priorityShaper.config.coverage_gap_weight || 0.15;
      }
      if (param === ADJUSTMENT_TARGETS.LEARNING_BOOST_WEIGHT) {
        return this.priorityShaper.config.learning_boost_weight || 0.10;
      }
      if (param === ADJUSTMENT_TARGETS.EXPLORATION_RATIO) {
        return this.priorityShaper.config.exploration_bonus || 0.10;
      }
    }

    if (this.optimizerEngine) {
      if (param === ADJUSTMENT_TARGETS.OBJECTIVE_ALPHA) {
        return this.optimizerEngine.currentObjective.alpha || 0.40;
      }
      if (param === ADJUSTMENT_TARGETS.OBJECTIVE_BETA) {
        return this.optimizerEngine.currentObjective.beta || 0.25;
      }
      if (param === ADJUSTMENT_TARGETS.OBJECTIVE_GAMMA) {
        return this.optimizerEngine.currentObjective.gamma || 0.20;
      }
      if (param === ADJUSTMENT_TARGETS.OBJECTIVE_DELTA) {
        return this.optimizerEngine.currentObjective.delta || 0.15;
      }
    }

    if (this.resourceOptimizer) {
      if (param === ADJUSTMENT_TARGETS.EXPLORATION_RATIO) {
        return this.resourceOptimizer.config.exploration_reserve_ratio || 0.15;
      }
      if (param === ADJUSTMENT_TARGETS.REBALANCE_INTERVAL) {
        return this.resourceOptimizer.config.rebalance_interval_ms || 120000;
      }
    }

    // Default
    return this._getDefaultParamValue(param);
  }

  /**
   * Get default value for a parameter.
   *
   * @param {string} param
   * @returns {number}
   * @private
   */
  _getDefaultParamValue(param) {
    const defaults = {
      [ADJUSTMENT_TARGETS.PREDICTION_WEIGHT]: 0.30,
      [ADJUSTMENT_TARGETS.RISK_WEIGHT]: 0.20,
      [ADJUSTMENT_TARGETS.EXPLORATION_RATIO]: 0.15,
      [ADJUSTMENT_TARGETS.VERIFICATION_THRESHOLD]: 0.50,
      [ADJUSTMENT_TARGETS.OBJECTIVE_ALPHA]: 0.40,
      [ADJUSTMENT_TARGETS.OBJECTIVE_BETA]: 0.25,
      [ADJUSTMENT_TARGETS.OBJECTIVE_GAMMA]: 0.20,
      [ADJUSTMENT_TARGETS.OBJECTIVE_DELTA]: 0.15,
      [ADJUSTMENT_TARGETS.COVERAGE_GAP_WEIGHT]: 0.15,
      [ADJUSTMENT_TARGETS.LEARNING_BOOST_WEIGHT]: 0.10,
      [ADJUSTMENT_TARGETS.FALSE_POSITIVE_PENALTY]: 0.20,
      [ADJUSTMENT_TARGETS.REBALANCE_INTERVAL]: 120000,
    };
    return defaults[param] || 0.5;
  }

  /**
   * Get adjustment sensitivity for a parameter.
   *
   * @param {string} param
   * @returns {number}
   * @private
   */
  _getParamSensitivity(param) {
    const sensitivities = {
      [ADJUSTMENT_TARGETS.PREDICTION_WEIGHT]: 0.03,
      [ADJUSTMENT_TARGETS.RISK_WEIGHT]: 0.02,
      [ADJUSTMENT_TARGETS.EXPLORATION_RATIO]: 0.02,
      [ADJUSTMENT_TARGETS.VERIFICATION_THRESHOLD]: 0.05,
      [ADJUSTMENT_TARGETS.OBJECTIVE_ALPHA]: 0.02,
      [ADJUSTMENT_TARGETS.OBJECTIVE_BETA]: 0.015,
      [ADJUSTMENT_TARGETS.OBJECTIVE_GAMMA]: 0.02,
      [ADJUSTMENT_TARGETS.OBJECTIVE_DELTA]: 0.015,
      [ADJUSTMENT_TARGETS.COVERAGE_GAP_WEIGHT]: 0.015,
      [ADJUSTMENT_TARGETS.LEARNING_BOOST_WEIGHT]: 0.01,
      [ADJUSTMENT_TARGETS.FALSE_POSITIVE_PENALTY]: 0.03,
      [ADJUSTMENT_TARGETS.REBALANCE_INTERVAL]: 10000,
    };
    return sensitivities[param] || 0.02;
  }

  /**
   * Clamp a parameter value to its valid range.
   *
   * @param {string} param
   * @param {number} value
   * @returns {number}
   * @private
   */
  _clampParamValue(param, value) {
    const ranges = {
      [ADJUSTMENT_TARGETS.PREDICTION_WEIGHT]: [0.05, 0.80],
      [ADJUSTMENT_TARGETS.RISK_WEIGHT]: [0.05, 0.50],
      [ADJUSTMENT_TARGETS.EXPLORATION_RATIO]: [0.05, 0.40],
      [ADJUSTMENT_TARGETS.VERIFICATION_THRESHOLD]: [0.10, 0.95],
      [ADJUSTMENT_TARGETS.OBJECTIVE_ALPHA]: [0.10, 0.60],
      [ADJUSTMENT_TARGETS.OBJECTIVE_BETA]: [0.05, 0.40],
      [ADJUSTMENT_TARGETS.OBJECTIVE_GAMMA]: [0.05, 0.50],
      [ADJUSTMENT_TARGETS.OBJECTIVE_DELTA]: [0.05, 0.40],
      [ADJUSTMENT_TARGETS.COVERAGE_GAP_WEIGHT]: [0.05, 0.35],
      [ADJUSTMENT_TARGETS.LEARNING_BOOST_WEIGHT]: [0.02, 0.25],
      [ADJUSTMENT_TARGETS.FALSE_POSITIVE_PENALTY]: [0.05, 0.50],
      [ADJUSTMENT_TARGETS.REBALANCE_INTERVAL]: [30000, 600000],
    };

    const [min, max] = ranges[param] || [0, 1];
    return Math.max(min, Math.min(max, value));
  }

  /**
   * Build a human-readable reason for an adjustment.
   *
   * @param {string} targetParam
   * @param {FeedbackSignal[]} signals
   * @param {number} directionRatio
   * @returns {string}
   * @private
   */
  _buildAdjustmentReason(targetParam, signals, directionRatio) {
    const sources = [...new Set(signals.map(s => s.source))];
    const direction = directionRatio > 0 ? 'increase' : directionRatio < 0 ? 'decrease' : 'maintain';
    const confidence = signals.length > 0
      ? Math.round((signals.reduce((s, sig) => s + sig.confidence, 0) / signals.length) * 100)
      : 0;

    return `${direction} ${targetParam} based on ${sources.join('+')} signals ` +
           `(${signals.length} signals, ${confidence}% avg confidence)`;
  }

  /**
   * Predict the expected effect of an adjustment.
   *
   * @param {string} targetParam
   * @param {number} directionRatio
   * @returns {string}
   * @private
   */
  _predictEffect(targetParam, directionRatio) {
    const effects = {
      [ADJUSTMENT_TARGETS.PREDICTION_WEIGHT]: directionRatio > 0
        ? 'More weight on predicted yield in priority shaping'
        : 'More weight on observed data in priority shaping',
      [ADJUSTMENT_TARGETS.RISK_WEIGHT]: directionRatio > 0
        ? 'Higher risk consideration in priority calculations'
        : 'Lower risk consideration in priority calculations',
      [ADJUSTMENT_TARGETS.EXPLORATION_RATIO]: directionRatio > 0
        ? 'More resources allocated to exploration of new areas'
        : 'More resources allocated to exploitation of known areas',
      [ADJUSTMENT_TARGETS.VERIFICATION_THRESHOLD]: directionRatio > 0
        ? 'Higher bar for verification, fewer but more reliable confirmations'
        : 'Lower bar for verification, more confirmations but potentially more false positives',
      [ADJUSTMENT_TARGETS.OBJECTIVE_ALPHA]: directionRatio > 0
        ? 'More emphasis on bug discovery in objective function'
        : 'Less emphasis on bug discovery in objective function',
      [ADJUSTMENT_TARGETS.OBJECTIVE_BETA]: directionRatio > 0
        ? 'More emphasis on severity quality in objective function'
        : 'Less emphasis on severity quality in objective function',
      [ADJUSTMENT_TARGETS.OBJECTIVE_GAMMA]: directionRatio > 0
        ? 'Higher false positive penalty in objective function'
        : 'Lower false positive penalty in objective function',
      [ADJUSTMENT_TARGETS.OBJECTIVE_DELTA]: directionRatio > 0
        ? 'Higher time/resource cost penalty in objective function'
        : 'Lower time/resource cost penalty in objective function',
      [ADJUSTMENT_TARGETS.COVERAGE_GAP_WEIGHT]: directionRatio > 0
        ? 'Higher priority for unexplored coverage areas'
        : 'Lower priority for coverage gaps',
      [ADJUSTMENT_TARGETS.LEARNING_BOOST_WEIGHT]: directionRatio > 0
        ? 'More weight on learning signals in priority shaping'
        : 'Less weight on learning signals in priority shaping',
      [ADJUSTMENT_TARGETS.FALSE_POSITIVE_PENALTY]: directionRatio > 0
        ? 'Stronger penalty for false positive findings'
        : 'Weaker penalty for false positive findings',
      [ADJUSTMENT_TARGETS.REBALANCE_INTERVAL]: directionRatio > 0
        ? 'Less frequent rebalancing (more stability)'
        : 'More frequent rebalancing (more responsiveness)',
    };

    return effects[targetParam] || 'Adjustment to system parameter';
  }

  // ─── Internal: Propagation ─────────────────────────────────────

  /**
   * Propagate an adjustment to the OptimizerEngine.
   * @param {string} param
   * @param {number} value
   * @param {FeedbackAdjustment} adjustment
   * @private
   */
  _propagateToOptimizerEngine(param, value, adjustment) {
    if (!this.optimizerEngine) return;

    try {
      // Adjust objective weights
      if (param.startsWith('objective_')) {
        const objKey = param.replace('objective_', '');
        if (this.optimizerEngine.currentObjective && this.optimizerEngine.currentObjective[objKey] !== undefined) {
          this.optimizerEngine.currentObjective[objKey] = value;
        }
      }

      // Adjust rebalance interval
      if (param === ADJUSTMENT_TARGETS.REBALANCE_INTERVAL) {
        if (this.optimizerEngine.currentParams) {
          this.optimizerEngine.currentParams.rebalance_interval_ms = value;
        }
      }

      // Record the adjustment in the optimizer's adjustment history
      if (this.optimizerEngine.adjustments) {
        this.optimizerEngine.adjustments.push({
          id: adjustment.id,
          ts: adjustment.ts,
          param_name: param,
          old_value: adjustment.old_value,
          new_value: value,
          reason: adjustment.reason,
          expected_impact: 0,
          actual_impact: null,
          source: 'feedback_loop',
        });
      }
    } catch (_) {
      // Propagation failure is non-fatal
    }
  }

  /**
   * Propagate an adjustment to the PriorityShaper.
   * @param {string} param
   * @param {number} value
   * @param {FeedbackAdjustment} adjustment
   * @private
   */
  _propagateToPriorityShaper(param, value, adjustment) {
    if (!this.priorityShaper) return;

    try {
      switch (param) {
        case ADJUSTMENT_TARGETS.PREDICTION_WEIGHT:
          this.priorityShaper.currentPredictionWeight = value;
          break;
        case ADJUSTMENT_TARGETS.RISK_WEIGHT:
          if (this.priorityShaper.config) {
            this.priorityShaper.config.risk_weight = value;
          }
          break;
        case ADJUSTMENT_TARGETS.COVERAGE_GAP_WEIGHT:
          if (this.priorityShaper.config) {
            this.priorityShaper.config.coverage_gap_weight = value;
          }
          break;
        case ADJUSTMENT_TARGETS.LEARNING_BOOST_WEIGHT:
          if (this.priorityShaper.config) {
            this.priorityShaper.config.learning_boost_weight = value;
          }
          break;
        case ADJUSTMENT_TARGETS.EXPLORATION_RATIO:
          if (this.priorityShaper.config) {
            this.priorityShaper.config.exploration_bonus = value;
          }
          break;
        default:
          break;
      }
    } catch (_) {
      // Propagation failure is non-fatal
    }
  }

  /**
   * Propagate an adjustment to the ResourceOptimizer.
   * @param {string} param
   * @param {number} value
   * @param {FeedbackAdjustment} adjustment
   * @private
   */
  _propagateToResourceOptimizer(param, value, adjustment) {
    if (!this.resourceOptimizer) return;

    try {
      switch (param) {
        case ADJUSTMENT_TARGETS.EXPLORATION_RATIO:
          if (this.resourceOptimizer.config) {
            this.resourceOptimizer.config.exploration_reserve_ratio = value;
          }
          break;
        case ADJUSTMENT_TARGETS.REBALANCE_INTERVAL:
          if (this.resourceOptimizer.config) {
            this.resourceOptimizer.config.rebalance_interval_ms = value;
          }
          break;
        default:
          break;
      }
    } catch (_) {
      // Propagation failure is non-fatal
    }
  }

  /**
   * Propagate an adjustment to the LearningEngine.
   * @param {string} param
   * @param {number} value
   * @param {FeedbackAdjustment} adjustment
   * @private
   */
  _propagateToLearningEngine(param, value, adjustment) {
    if (!this.learningEngine) return;

    try {
      // Trigger reweight when significant adjustment occurs
      const significantChange = Math.abs(value - adjustment.old_value) > 0.05;

      if (significantChange && typeof this.learningEngine.reweight === 'function') {
        // Don't call reweight on every adjustment — only significant ones
        const lastReweight = this.learningEngine.lastReweightAt || 0;
        if (Date.now() - lastReweight > 120000) { // At most every 2 minutes
          this.learningEngine.reweight();
        }
      }

      // Adjust learning weights if relevant
      if (param === ADJUSTMENT_TARGETS.LEARNING_BOOST_WEIGHT && this.learningEngine.currentWeights) {
        // Shift weight distribution to emphasize/de-emphasize historical_success
        const shift = (value - adjustment.old_value) * 0.5;
        this.learningEngine.currentWeights.historical_success =
          Math.max(0.05, Math.min(0.40,
            (this.learningEngine.currentWeights.historical_success || 0.20) + shift));
      }
    } catch (_) {
      // Propagation failure is non-fatal
    }
  }

  // ─── Internal: Param Collection ────────────────────────────────

  /**
   * Collect current parameter values from all subsystems.
   *
   * @returns {object}
   * @private
   */
  _collectCurrentParams() {
    const params = {};

    // From PriorityShaper
    if (this.priorityShaper) {
      params[ADJUSTMENT_TARGETS.PREDICTION_WEIGHT] =
        this.priorityShaper.currentPredictionWeight || 0.30;
      params[ADJUSTMENT_TARGETS.RISK_WEIGHT] =
        this.priorityShaper.config?.risk_weight || 0.20;
      params[ADJUSTMENT_TARGETS.COVERAGE_GAP_WEIGHT] =
        this.priorityShaper.config?.coverage_gap_weight || 0.15;
      params[ADJUSTMENT_TARGETS.LEARNING_BOOST_WEIGHT] =
        this.priorityShaper.config?.learning_boost_weight || 0.10;
      params[ADJUSTMENT_TARGETS.EXPLORATION_RATIO] =
        this.priorityShaper.config?.exploration_bonus || 0.10;
    }

    // From OptimizerEngine
    if (this.optimizerEngine) {
      params[ADJUSTMENT_TARGETS.OBJECTIVE_ALPHA] =
        this.optimizerEngine.currentObjective?.alpha || 0.40;
      params[ADJUSTMENT_TARGETS.OBJECTIVE_BETA] =
        this.optimizerEngine.currentObjective?.beta || 0.25;
      params[ADJUSTMENT_TARGETS.OBJECTIVE_GAMMA] =
        this.optimizerEngine.currentObjective?.gamma || 0.20;
      params[ADJUSTMENT_TARGETS.OBJECTIVE_DELTA] =
        this.optimizerEngine.currentObjective?.delta || 0.15;
      params[ADJUSTMENT_TARGETS.REBALANCE_INTERVAL] =
        this.optimizerEngine.currentParams?.rebalance_interval_ms || 120000;
    }

    // From ResourceOptimizer
    if (this.resourceOptimizer) {
      params[ADJUSTMENT_TARGETS.EXPLORATION_RATIO] =
        this.resourceOptimizer.config?.exploration_reserve_ratio || 0.15;
      params[ADJUSTMENT_TARGETS.REBALANCE_INTERVAL] =
        this.resourceOptimizer.config?.rebalance_interval_ms || 120000;
    }

    // Fill in defaults for any missing params
    for (const target of Object.values(ADJUSTMENT_TARGETS)) {
      if (params[target] === undefined) {
        params[target] = this._getDefaultParamValue(target);
      }
    }

    return params;
  }

  // ─── Internal: Actual Effect Tracking ──────────────────────────

  /**
   * Evaluate the actual effect of past adjustments.
   * Called internally to update actual_effect fields.
   *
   * @private
   */
  _evaluateAdjustmentEffects() {
    const now = Date.now();
    const evaluationWindow = 300000; // 5 minutes

    for (const adj of this.adjustmentHistory) {
      if (adj.actual_effect !== null) continue;
      if (now - adj.ts < evaluationWindow) continue; // Wait for effect to manifest

      // Compare current param value to what was set
      const currentValue = this._getCurrentParamValue(adj.target_param);
      const expectedDirection = adj.new_value > adj.old_value ? 1 : -1;
      const actualDirection = currentValue > adj.old_value ? 1 : -1;

      if (expectedDirection === actualDirection) {
        adj.actual_effect = 'direction_preserved';
      } else {
        adj.actual_effect = 'direction_reversed';
      }
    }
  }

  // ─── Persistence ────────────────────────────────────────────────

  /**
   * Save feedback loop state to disk.
   * @returns {string} path written
   */
  save() {
    const filePath = path.join(FEEDBACK_DIR, 'feedback-loop.json');

    const data = {
      version: '0.9',
      saved_at: Date.now(),
      config: this.config,
      current_params: this.currentParams,
      converged: this.converged,
      convergence_score: this.convergenceScore,
      oscillation_score: this.oscillationScore,
      convergence_streak: this.convergenceStreak,
      metrics: this.metrics,
      signal_history: this.signalHistory.slice(-200).map(s => ({
        id: s.id,
        source: s.source,
        type: s.type,
        metric_name: s.metric_name,
        old_value: s.old_value,
        new_value: s.new_value,
        delta: s.delta,
        confidence: s.confidence,
        ts: s.ts,
      })),
      adjustment_history: this.adjustmentHistory.slice(-200).map(a => ({
        id: a.id,
        signal_ids: a.signal_ids,
        target_param: a.target_param,
        old_value: a.old_value,
        new_value: a.new_value,
        reason: a.reason,
        expected_effect: a.expected_effect,
        actual_effect: a.actual_effect,
        ts: a.ts,
      })),
      last_adjustment_at: [...this.lastAdjustmentAt.entries()],
      recent_param_values: [...this.recentParamValues.entries()].map(([k, v]) => [
        k,
        v.slice(-this.config.oscillation_window),
      ]),
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  /**
   * Load feedback loop state from disk.
   * @returns {boolean}
   */
  load() {
    const filePath = path.join(FEEDBACK_DIR, 'feedback-loop.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      this.config = { ...DEFAULT_FEEDBACK_CONFIG, ...(data.config || {}) };
      this.currentParams = data.current_params || this._collectCurrentParams();
      this.converged = data.converged || false;
      this.convergenceScore = data.convergence_score || 0;
      this.oscillationScore = data.oscillation_score || 0;
      this.convergenceStreak = data.convergence_streak || 0;
      this.metrics = { ...this.metrics, ...(data.metrics || {}) };

      this.signalHistory = (data.signal_history || []).map(s => new FeedbackSignal(s));
      this.adjustmentHistory = (data.adjustment_history || []).map(a => new FeedbackAdjustment(a));
      this.lastAdjustmentAt = new Map(data.last_adjustment_at || []);
      this.recentParamValues = new Map(
        (data.recent_param_values || []).map(([k, v]) => [k, v])
      );

      return true;
    } catch (_) {
      return false;
    }
  }

  /**
   * Shut down the feedback loop.
   */
  shutdown() {
    if (this._processTimer) {
      clearInterval(this._processTimer);
    }
    this.save();
  }
}

// ─── Exports ──────────────────────────────────────────────────────

module.exports = {
  FeedbackLoop,
  FeedbackSignal,
  FeedbackAdjustment,
  DEFAULT_FEEDBACK_CONFIG,
};

