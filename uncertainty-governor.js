/**
 * BOQA uncertainty-governor.js — UncertaintyGovernor v1.3
 *
 * Forces confidence bounds before any decision is allowed. This is
 * the primary hardening gate of the v1.3 Decision Intelligence
 * Hardening Layer, preventing over-optimization collapse by requiring
 * sufficient certainty before action.
 *
 * Core principle: uncertainty_first_decisioning
 *   - Every decision must pass through an uncertainty gate
 *   - If variance is too high → downgrade all actions to WATCH
 *   - Overconfidence is penalized, not rewarded
 *   - Null decision band enforced (sometimes the best action is none)
 *
 * Gating logic:
 *   1. Compute confidence band from CEVI scores + historical accuracy
 *   2. Assess signal density (enough data to decide?)
 *   3. Check variance across recent decisions
 *   4. Apply hard constraint: no_action_if_confidence < 0.6
 *   5. If decision_lock_flag → all actions forced to WATCH or HOLD
 *
 * Outputs:
 *   - confidence_band: { p10, p50, p90, width } for each opportunity
 *   - decision_lock_flag: boolean — if true, no action decisions allowed
 *   - overconfidence_penalty: numeric penalty for narrow bands on sparse data
 *
 * Safe mode: this module only gates decisions; it never executes actions.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const UG_DIR = path.join(__dirname, 'output', 'knowledge', 'uncertainty-governor');

// ─── Constants ──────────────────────────────────────────────────────

const GATE_STATES = {
  OPEN:    'open',      // Decisions allowed
  THROTTLED: 'throttled', // Only WATCH/HOLD/SIMULATE allowed
  LOCKED:  'locked',    // Only WATCH/HOLD allowed
};

const DEFAULT_OPTIONS = {
  minConfidenceForAction: 0.6,     // Hard floor: no action below this
  minConfidenceForSimulate: 0.4,   // SIMULATE requires at least this
  highVarianceThreshold: 0.35,     // Variance above this = high uncertainty
  lowSignalDensityThreshold: 3,    // Min signals before trusting a decision
  overconfidencePenaltyRate: 0.15, // Penalty per unit of unwarranted confidence
  maxBandWidthForAction: 40,       // Max p10-p90 spread for action decisions
  temporalWindowMs: 3600000,       // 1-hour window for variance assessment
  persistenceIntervalMs: 300000,
};

// =====================================================================
//  ConfidenceBand
// =====================================================================

class ConfidenceBand {
  constructor(data = {}) {
    this.opportunity_id     = data.opportunity_id || null;
    this.p10                = data.p10 ?? 0;
    this.p50                = data.p50 ?? 0;
    this.p90                = data.p90 ?? 0;
    this.width              = data.width ?? 0;        // p90 - p10
    this.signal_density     = data.signal_density ?? 0;
    this.historical_accuracy = data.historical_accuracy ?? 0.5;
    this.overconfidence_penalty = data.overconfidence_penalty ?? 0;
    this.gate_state         = data.gate_state || GATE_STATES.OPEN;
    this.gate_reason        = data.gate_reason || '';
    this.computed_at        = Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  UncertaintyGovernor
// =====================================================================

class UncertaintyGovernor {
  /**
   * @param {object} options
   * @param {object} [options.confidenceCalibrator] - ConfidenceCalibrator instance
   * @param {object} [options.memoryGraph] - MemoryGraph instance
   */
  constructor(options = {}) {
    this.confidenceCalibrator = options.confidenceCalibrator || null;
    this.memoryGraph = options.memoryGraph || null;
    this.options = { ...DEFAULT_OPTIONS, ...options };

    /** @type {Map<string, ConfidenceBand>} opportunity_id → ConfidenceBand */
    this.bands = new Map();

    // Global decision lock
    this.globalDecisionLock = false;
    this.globalLockReason = '';

    // Recent gate decisions for variance tracking
    this.gateHistory = [];
    this.maxGateHistory = 500;

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_gated: 0,
      total_locked: 0,
      total_throttled: 0,
      total_open: 0,
      avg_confidence_band_width: 0,
      avg_signal_density: 0,
      overconfidence_detections: 0,
      decision_lock_activations: 0,
      calibration_error: 0,
    };

    // ── Persistence timer ────────────────────────────────────
    this._persistTimer = null;

    fs.mkdirSync(UG_DIR, { recursive: true });
    this.load();

    if (this.options.persistenceIntervalMs > 0) {
      this._persistTimer = setInterval(() => this.save(), this.options.persistenceIntervalMs);
    }
  }

  // ─── Uncertainty Gating ────────────────────────────────────────────

  /**
   * Gate a single opportunity through the uncertainty filter.
   * Returns a ConfidenceBand with gate_state and decision_lock_flag.
   *
   * @param {object} data
   * @param {string} data.opportunity_id
   * @param {number} data.cevi - CEVI score
   * @param {number} [data.cevi_p10] - CEVI p10 band
   * @param {number} [data.cevi_p90] - CEVI p90 band
   * @param {number} [data.confidence] - Confidence level [0, 1]
   * @param {number} [data.signal_density] - Number of supporting signals
   * @param {string} [data.target_id]
   * @param {string} [data.category]
   * @returns {ConfidenceBand}
   */
  gate(data) {
    const oppId = data.opportunity_id;
    const cevi = data.cevi ?? 0;
    const ceviP10 = data.cevi_p10 ?? cevi * 0.85;
    const ceviP90 = data.cevi_p90 ?? cevi * 1.15;
    const confidence = data.confidence ?? 0.5;
    const signalDensity = data.signal_density ?? 0;

    // 1. Compute band width
    const bandWidth = Math.abs(ceviP90 - ceviP10);

    // 2. Adjust confidence from historical accuracy
    let historicalAccuracy = 0.5;
    if (this.confidenceCalibrator) {
      const record = this.confidenceCalibrator.getCalibrationRecord(
        data.target_id, data.category
      );
      if (record && record.observation_count >= 5) {
        historicalAccuracy = 1 - Math.abs(record.bias);
      }
    }

    // 3. Compute signal density from memory graph if not provided
    let effectiveSignalDensity = signalDensity;
    if (effectiveSignalDensity === 0 && this.memoryGraph && data.target_id) {
      const nodes = this.memoryGraph.queryNodes({
        target_id: data.target_id,
        type: 'finding',
        limit: 50,
      });
      effectiveSignalDensity = nodes.length;
    }

    // 4. Compute overconfidence penalty
    // If confidence is high but signal density is low → overconfident
    let overconfidencePenalty = 0;
    if (confidence > 0.7 && effectiveSignalDensity < this.options.lowSignalDensityThreshold) {
      const excessConfidence = confidence - 0.7;
      const densityDeficit = 1 - (effectiveSignalDensity / this.options.lowSignalDensityThreshold);
      overconfidencePenalty = excessConfidence * densityDeficit * this.options.overconfidencePenaltyRate * 10;
    }

    // 5. Widen band for low signal density
    let adjustedP10 = ceviP10 - overconfidencePenalty;
    let adjustedP90 = ceviP90;
    if (effectiveSignalDensity < this.options.lowSignalDensityThreshold) {
      const densityFactor = 1 + (this.options.lowSignalDensityThreshold - effectiveSignalDensity) * 0.1;
      adjustedP10 = ceviP10 / densityFactor;
      adjustedP90 = ceviP90 * densityFactor;
    }
    const adjustedBandWidth = Math.abs(adjustedP90 - adjustedP10);

    // 6. Determine gate state
    let gateState = GATE_STATES.OPEN;
    let gateReason = '';

    // Hard constraint: no_action_if_confidence < 0.6
    if (confidence < this.options.minConfidenceForAction) {
      if (confidence < this.options.minConfidenceForSimulate) {
        gateState = GATE_STATES.LOCKED;
        gateReason = `Confidence ${confidence.toFixed(2)} below minimum ${this.options.minConfidenceForSimulate} for any action`;
      } else {
        gateState = GATE_STATES.THROTTLED;
        gateReason = `Confidence ${confidence.toFixed(2)} below action threshold ${this.options.minConfidenceForAction}`;
      }
    }

    // High variance → downgrade
    if (adjustedBandWidth > this.options.maxBandWidthForAction && gateState === GATE_STATES.OPEN) {
      gateState = GATE_STATES.THROTTLED;
      gateReason = `Band width ${adjustedBandWidth.toFixed(1)} exceeds max ${this.options.maxBandWidthForAction} for action`;
    }

    // Low signal density → at minimum throttle
    if (effectiveSignalDensity < this.options.lowSignalDensityThreshold &&
        gateState === GATE_STATES.OPEN) {
      gateState = GATE_STATES.THROTTLED;
      gateReason = `Signal density ${effectiveSignalDensity} below threshold ${this.options.lowSignalDensityThreshold}`;
    }

    // Overconfidence detected
    if (overconfidencePenalty > 0) {
      if (gateState === GATE_STATES.OPEN) {
        gateState = GATE_STATES.THROTTLED;
        gateReason = `Overconfidence detected: penalty ${overconfidencePenalty.toFixed(2)}`;
      }
      this.metrics.overconfidence_detections++;
    }

    // Global decision lock override
    if (this.globalDecisionLock) {
      gateState = GATE_STATES.LOCKED;
      gateReason = `Global decision lock active: ${this.globalLockReason}`;
    }

    const band = new ConfidenceBand({
      opportunity_id: oppId,
      p10: Math.round(Math.max(0, adjustedP10) * 100) / 100,
      p50: Math.round(cevi * 100) / 100,
      p90: Math.round(Math.min(100, adjustedP90) * 100) / 100,
      width: Math.round(adjustedBandWidth * 100) / 100,
      signal_density: effectiveSignalDensity,
      historical_accuracy: Math.round(historicalAccuracy * 1000) / 1000,
      overconfidence_penalty: Math.round(overconfidencePenalty * 100) / 100,
      gate_state: gateState,
      gate_reason: gateReason,
    });

    this.bands.set(oppId, band);

    // Update metrics
    this.metrics.total_gated++;
    if (gateState === GATE_STATES.LOCKED) this.metrics.total_locked++;
    else if (gateState === GATE_STATES.THROTTLED) this.metrics.total_throttled++;
    else this.metrics.total_open++;

    // Record gate history
    this.gateHistory.push({
      opportunity_id: oppId,
      gate_state: gateState,
      confidence,
      band_width: adjustedBandWidth,
      timestamp: Date.now(),
    });
    if (this.gateHistory.length > this.maxGateHistory) {
      this.gateHistory = this.gateHistory.slice(-this.maxGateHistory);
    }

    this._updateMetrics();
    return band;
  }

  /**
   * Gate a batch of opportunities.
   * @param {object[]} items
   * @returns {ConfidenceBand[]}
   */
  gateBatch(items) {
    return items.map(item => this.gate(item));
  }

  // ─── Decision Lock ─────────────────────────────────────────────────

  /**
   * Activate global decision lock — downgrades all actions to WATCH/HOLD.
   * @param {string} reason
   */
  activateDecisionLock(reason) {
    this.globalDecisionLock = true;
    this.globalLockReason = reason;
    this.metrics.decision_lock_activations++;
  }

  /**
   * Deactivate global decision lock.
   */
  deactivateDecisionLock() {
    this.globalDecisionLock = false;
    this.globalLockReason = '';
  }

  /**
   * Check if global decision lock is active.
   * @returns {boolean}
   */
  isDecisionLocked() {
    return this.globalDecisionLock;
  }

  // ─── Policy Filtering ──────────────────────────────────────────────

  /**
   * Apply uncertainty gating to a policy decision.
   * Maps gate_state to allowed policy modes.
   *
   * @param {string} opportunityId
   * @param {string} proposedPolicy - The policy proposed by DecisionPolicyEngine
   * @returns {{ allowed: boolean, policy: string, reason: string }}
   */
  filterPolicy(opportunityId, proposedPolicy) {
    const band = this.bands.get(opportunityId);

    // If no band computed yet, gate first
    if (!band) {
      return {
        allowed: false,
        policy: 'WATCH',
        reason: 'No uncertainty assessment — defaulting to WATCH',
      };
    }

    const allowedPolicies = this._getAllowedPolicies(band.gate_state);

    if (allowedPolicies.includes(proposedPolicy)) {
      return {
        allowed: true,
        policy: proposedPolicy,
        reason: `Policy ${proposedPolicy} allowed under gate state ${band.gate_state}`,
      };
    }

    // Downgrade to highest allowed policy
    const downgradedPolicy = this._downgradePolicy(proposedPolicy, allowedPolicies);
    return {
      allowed: false,
      policy: downgradedPolicy,
      reason: `Policy ${proposedPolicy} not allowed under gate state ${band.gate_state} (band width: ${band.width}). Downgraded to ${downgradedPolicy}. ${band.gate_reason}`,
    };
  }

  _getAllowedPolicies(gateState) {
    switch (gateState) {
      case GATE_STATES.OPEN:
        return ['WATCH', 'SIMULATE', 'BUILD', 'DEPLOY', 'HOLD', 'IGNORE'];
      case GATE_STATES.THROTTLED:
        return ['WATCH', 'SIMULATE', 'HOLD', 'IGNORE'];
      case GATE_STATES.LOCKED:
        return ['WATCH', 'HOLD'];
      default:
        return ['WATCH', 'HOLD'];
    }
  }

  _downgradePolicy(proposedPolicy, allowedPolicies) {
    // Priority order for downgrade: DEPLOY→SIMULATE, BUILD→SIMULATE, SIMULATE→WATCH, etc.
    const downgradeMap = {
      'DEPLOY': 'SIMULATE',
      'BUILD': 'SIMULATE',
      'SIMULATE': 'WATCH',
      'WATCH': 'HOLD',
      'IGNORE': 'IGNORE',
    };

    let current = proposedPolicy;
    while (!allowedPolicies.includes(current) && downgradeMap[current]) {
      current = downgradeMap[current];
    }

    return allowedPolicies.includes(current) ? current : 'HOLD';
  }

  // ─── Variance Assessment ───────────────────────────────────────────

  /**
   * Assess variance across recent gate decisions.
   * High variance = unstable decision environment → recommend throttling.
   *
   * @returns {{ variance: number, recommendation: string, recent_flips: number }}
   */
  assessVariance() {
    const now = Date.now();
    const window = this.options.temporalWindowMs;
    const recent = this.gateHistory.filter(g => now - g.timestamp < window);

    if (recent.length < 3) {
      return { variance: 0, recommendation: 'insufficient_data', recent_flips: 0 };
    }

    // Count gate state flips (OPEN→THROTTLED, THROTTLED→LOCKED, etc.)
    let flips = 0;
    for (let i = 1; i < recent.length; i++) {
      if (recent[i].gate_state !== recent[i - 1].gate_state) flips++;
    }

    // Compute confidence variance
    const confidences = recent.map(g => g.confidence);
    const mean = confidences.reduce((s, c) => s + c, 0) / confidences.length;
    const variance = confidences.reduce((s, c) => s + (c - mean) ** 2, 0) / confidences.length;

    let recommendation = 'normal';
    if (variance > this.options.highVarianceThreshold) {
      recommendation = 'high_variance_throttle';
    }
    if (flips > recent.length * 0.5) {
      recommendation = 'oscillation_detected';
    }

    return {
      variance: Math.round(variance * 1000) / 1000,
      recommendation,
      recent_flips: flips,
    };
  }

  // ─── Query ──────────────────────────────────────────────────────────

  getBand(opportunityId) {
    return this.bands.get(opportunityId) || null;
  }

  getAllBands() {
    return [...this.bands.values()];
  }

  getMetrics() {
    return { ...this.metrics, global_decision_lock: this.globalDecisionLock };
  }

  _updateMetrics() {
    const bands = [...this.bands.values()];
    if (bands.length > 0) {
      this.metrics.avg_confidence_band_width = Math.round(
        bands.reduce((s, b) => s + b.width, 0) / bands.length * 100
      ) / 100;
      this.metrics.avg_signal_density = Math.round(
        bands.reduce((s, b) => s + b.signal_density, 0) / bands.length * 100
      ) / 100;
    }
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(UG_DIR, 'uncertainty-governor-state.json');
    const data = {
      version: '1.3',
      saved_at: Date.now(),
      global_decision_lock: this.globalDecisionLock,
      global_lock_reason: this.globalLockReason,
      bands: [...this.bands.entries()].slice(-500),
      gate_history: this.gateHistory.slice(-200),
      metrics: this.metrics,
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(UG_DIR, 'uncertainty-governor-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (data.global_decision_lock !== undefined) this.globalDecisionLock = data.global_decision_lock;
      if (data.global_lock_reason) this.globalLockReason = data.global_lock_reason;
      if (data.bands) {
        this.bands = new Map(data.bands.map(([k, v]) => [k, new ConfidenceBand(v)]));
      }
      if (data.gate_history) this.gateHistory = data.gate_history;
      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      this._updateMetrics();
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.bands.clear();
    this.globalDecisionLock = false;
    this.globalLockReason = '';
    this.gateHistory = [];
    this.metrics = {
      total_gated: 0, total_locked: 0, total_throttled: 0, total_open: 0,
      avg_confidence_band_width: 0, avg_signal_density: 0,
      overconfidence_detections: 0, decision_lock_activations: 0,
      calibration_error: 0,
    };
    const filePath = path.join(UG_DIR, 'uncertainty-governor-state.json');
    try { fs.unlinkSync(filePath); } catch (_) {}
  }

  shutdown() {
    if (this._persistTimer) clearInterval(this._persistTimer);
    this.save();
  }
}

module.exports = {
  UncertaintyGovernor,
  ConfidenceBand,
  GATE_STATES,
};

