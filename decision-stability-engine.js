/**
 * BOQA decision-stability-engine.js — DecisionStabilityEngine v1.3
 *
 * Prevents oscillation between strategies across decision runs.
 * Uses temporal smoothing and hysteresis thresholds to ensure
 * that decisions don't flip-flop between policies on every cycle.
 *
 * Core principle: calibrate_before_rank
 *   - Decisions must be stable across multiple evaluation cycles
 *   - A decision that flips from SIMULATE→WATCH→SIMULATE is unstable
 *   - Hysteresis: the threshold to enter a state differs from the
 *     threshold to leave it, preventing rapid toggling
 *   - Temporal smoothing: current decision = weighted average of
 *     recent decisions, not just the latest evaluation
 *
 * Stability metrics:
 *   - strategy_stability_index: fraction of cycles where decision didn't change
 *   - oscillation_count: number of policy flips in recent window
 *   - smooth_decision_vector: the stabilized decision output
 *
 * Output: stable_decision_vector
 *   For each opportunity, the engine outputs:
 *   - stable_policy: the smoothed, hysteresis-protected policy
 *   - confidence_in_stability: how confident we are that this decision will hold
 *   - flip_count_recent: how many times this decision changed recently
 *
 * Safe mode: stability filtering only adjusts internal decision states;
 * no real-world actions are taken.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const DSE_DIR = path.join(__dirname, 'output', 'knowledge', 'stability');

// ─── Constants ──────────────────────────────────────────────────────

const DEFAULT_OPTIONS = {
  smoothingWindow: 5,           // Number of recent decisions to smooth over
  smoothingWeights: [0.4, 0.25, 0.15, 0.12, 0.08], // Recency-weighted
  hysteresisMargin: 0.15,       // 15% margin required to change state
  oscillationThreshold: 3,      // 3 flips in window = oscillation detected
  minCyclesBeforeChange: 2,     // Must see N consistent signals before changing
  stabilityWindowCycles: 10,    // How many cycles to track for stability index
  persistenceIntervalMs: 300000,
};

// Policy strength ordering for smoothing
const POLICY_STRENGTH = {
  HOLD: 0,
  IGNORE: 0.5,
  WATCH: 1,
  SIMULATE: 2,
  BUILD: 3,
  DEPLOY: 4,
};

// =====================================================================
//  DecisionRecord
// =====================================================================

class DecisionRecord {
  constructor(data = {}) {
    this.opportunity_id    = data.opportunity_id || null;
    this.policy            = data.policy || 'WATCH';
    this.economic_score    = data.economic_score ?? 0;
    this.confidence        = data.confidence ?? 0.5;
    this.cycle             = data.cycle ?? 0;
    this.timestamp         = data.timestamp || Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  StableDecision
// =====================================================================

class StableDecision {
  constructor(data = {}) {
    this.opportunity_id       = data.opportunity_id || null;
    this.stable_policy        = data.stable_policy || 'WATCH';
    this.raw_policy           = data.raw_policy || 'WATCH';
    this.confidence_in_stability = data.confidence_in_stability ?? 0;
    this.flip_count_recent    = data.flip_count_recent ?? 0;
    this.is_oscillating       = data.is_oscillating ?? false;
    this.smoothed_score       = data.smoothed_score ?? 0;
    this.smoothing_applied    = data.smoothing_applied ?? false;
    this.hysteresis_applied   = data.hysteresis_applied ?? false;
    this.computed_at          = Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  DecisionStabilityEngine
// =====================================================================

class DecisionStabilityEngine {
  constructor(options = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };

    /**
     * @type {Map<string, DecisionRecord[]>}
     * opportunity_id → array of recent decision records (most recent last)
     */
    this.decisionHistory = new Map();

    /** @type {Map<string, StableDecision>} opportunity_id → latest stable decision */
    this.stableDecisions = new Map();

    // Cycle counter
    this.cycleCount = 0;

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_stabilized: 0,
      total_oscillations_detected: 0,
      total_hysteresis_applied: 0,
      total_smoothing_applied: 0,
      stability_index: 0,
      avg_confidence_in_stability: 0,
    };

    // ── Persistence timer ────────────────────────────────────
    this._persistTimer = null;

    fs.mkdirSync(DSE_DIR, { recursive: true });
    this.load();

    if (this.options.persistenceIntervalMs > 0) {
      this._persistTimer = setInterval(() => this.save(), this.options.persistenceIntervalMs);
    }
  }

  // ─── Stabilization ─────────────────────────────────────────────────

  /**
   * Record a new raw decision and compute the stabilized output.
   *
   * @param {object} data
   * @param {string} data.opportunity_id
   * @param {string} data.policy - Raw policy from DecisionPolicyEngine
   * @param {number} [data.economic_score]
   * @param {number} [data.confidence]
   * @returns {StableDecision}
   */
  stabilize(data) {
    this.cycleCount++;
    const oppId = data.opportunity_id;
    const rawPolicy = data.policy || 'WATCH';
    const score = data.economic_score ?? 0;
    const confidence = data.confidence ?? 0.5;

    // Record decision
    if (!this.decisionHistory.has(oppId)) {
      this.decisionHistory.set(oppId, []);
    }
    const history = this.decisionHistory.get(oppId);
    history.push(new DecisionRecord({
      opportunity_id: oppId,
      policy: rawPolicy,
      economic_score: score,
      confidence,
      cycle: this.cycleCount,
    }));

    // Trim to window size
    const window = this.options.stabilityWindowCycles;
    if (history.length > window) {
      this.decisionHistory.set(oppId, history.slice(-window));
    }

    // 1. Detect oscillation
    const flipCount = this._countFlips(oppId);
    const isOscillating = flipCount >= this.options.oscillationThreshold;

    // 2. Apply temporal smoothing
    const smoothedPolicy = this._temporalSmoothing(oppId);
    const smoothedScore = this._temporalScoreSmoothing(oppId);
    const smoothingApplied = smoothedPolicy !== rawPolicy;

    // 3. Apply hysteresis
    const prevStable = this.stableDecisions.get(oppId);
    let finalPolicy = smoothedPolicy;
    let hysteresisApplied = false;

    if (prevStable && prevStable.stable_policy !== smoothedPolicy) {
      // Check if the change is significant enough (hysteresis margin)
      const prevStrength = POLICY_STRENGTH[prevStable.stable_policy] ?? 0;
      const newStrength = POLICY_STRENGTH[smoothedPolicy] ?? 0;
      const changeMagnitude = Math.abs(newStrength - prevStrength);

      if (changeMagnitude > 0) {
        // Require consistent signals before changing
        const consistentCount = this._countConsistent(oppId, smoothedPolicy);
        if (consistentCount < this.options.minCyclesBeforeChange) {
          // Not enough consistent signals — keep previous stable policy
          finalPolicy = prevStable.stable_policy;
          hysteresisApplied = true;
        } else {
          // Check hysteresis margin
          const marginRequired = this.options.hysteresisMargin;
          const currentMargin = Math.abs(score - (prevStable.smoothed_score || score)) / Math.max(1, Math.abs(prevStable.smoothed_score || score));
          if (marginRequired > 0 && currentMargin < marginRequired) {
            finalPolicy = prevStable.stable_policy;
            hysteresisApplied = true;
          }
        }
      }
    }

    // If oscillating, force to the most conservative recent policy
    if (isOscillating) {
      finalPolicy = this._mostConservativeRecent(oppId);
    }

    // Compute confidence in stability
    const totalDecisions = history.length;
    const sameAsFinal = history.filter(h => h.policy === finalPolicy).length;
    const stabilityConfidence = totalDecisions > 0 ? sameAsFinal / totalDecisions : 0;

    const stableDecision = new StableDecision({
      opportunity_id: oppId,
      stable_policy: finalPolicy,
      raw_policy: rawPolicy,
      confidence_in_stability: Math.round(stabilityConfidence * 1000) / 1000,
      flip_count_recent: flipCount,
      is_oscillating: isOscillating,
      smoothed_score: Math.round(smoothedScore * 100) / 100,
      smoothing_applied: smoothingApplied,
      hysteresis_applied: hysteresisApplied,
    });

    this.stableDecisions.set(oppId, stableDecision);

    // Update metrics
    this.metrics.total_stabilized++;
    if (isOscillating) this.metrics.total_oscillations_detected++;
    if (hysteresisApplied) this.metrics.total_hysteresis_applied++;
    if (smoothingApplied) this.metrics.total_smoothing_applied++;
    this._updateMetrics();

    return stableDecision;
  }

  /**
   * Stabilize a batch of decisions.
   * @param {object[]} items
   * @returns {StableDecision[]}
   */
  stabilizeBatch(items) {
    return items.map(item => this.stabilize(item));
  }

  // ─── Internal Methods ──────────────────────────────────────────────

  _countFlips(oppId) {
    const history = this.decisionHistory.get(oppId) || [];
    if (history.length < 2) return 0;

    let flips = 0;
    for (let i = 1; i < history.length; i++) {
      if (history[i].policy !== history[i - 1].policy) flips++;
    }
    return flips;
  }

  _temporalSmoothing(oppId) {
    const history = this.decisionHistory.get(oppId) || [];
    if (history.length === 0) return 'WATCH';
    if (history.length === 1) return history[0].policy;

    // Weighted vote: most recent decisions weighted more
    const weights = this.options.smoothingWeights;
    const policyScores = {};

    for (let i = 0; i < history.length; i++) {
      const idx = Math.min(i, weights.length - 1);
      // Invert index: most recent gets highest weight
      const weightIdx = weights.length - 1 - Math.max(0, history.length - 1 - i);
      const weight = weights[Math.min(weightIdx, weights.length - 1)] || weights[weights.length - 1];
      const policy = history[i].policy;
      const strength = POLICY_STRENGTH[policy] ?? 0;
      policyScores[policy] = (policyScores[policy] || 0) + weight * strength;
    }

    // Select policy with highest weighted score
    let bestPolicy = 'WATCH';
    let bestScore = -1;
    for (const [policy, score] of Object.entries(policyScores)) {
      if (score > bestScore) {
        bestScore = score;
        bestPolicy = policy;
      }
    }

    return bestPolicy;
  }

  _temporalScoreSmoothing(oppId) {
    const history = this.decisionHistory.get(oppId) || [];
    if (history.length === 0) return 0;

    const weights = this.options.smoothingWeights;
    let totalScore = 0;
    let totalWeight = 0;

    for (let i = 0; i < history.length; i++) {
      const weightIdx = weights.length - 1 - Math.max(0, history.length - 1 - i);
      const weight = weights[Math.min(weightIdx, weights.length - 1)] || weights[weights.length - 1];
      totalScore += history[i].economic_score * weight;
      totalWeight += weight;
    }

    return totalWeight > 0 ? totalScore / totalWeight : 0;
  }

  _countConsistent(oppId, targetPolicy) {
    const history = this.decisionHistory.get(oppId) || [];
    const window = this.options.smoothingWindow;
    const recent = history.slice(-window);
    return recent.filter(h => h.policy === targetPolicy).length;
  }

  _mostConservativeRecent(oppId) {
    const history = this.decisionHistory.get(oppId) || [];
    const recent = history.slice(-this.options.smoothingWindow);

    if (recent.length === 0) return 'WATCH';

    // Return the most conservative (lowest strength) policy seen recently
    let minStrength = Infinity;
    let mostConservative = 'WATCH';
    for (const h of recent) {
      const strength = POLICY_STRENGTH[h.policy] ?? 0;
      if (strength < minStrength) {
        minStrength = strength;
        mostConservative = h.policy;
      }
    }
    return mostConservative;
  }

  // ─── Query ──────────────────────────────────────────────────────────

  getStableDecision(opportunityId) {
    return this.stableDecisions.get(opportunityId) || null;
  }

  getAllStableDecisions() {
    return [...this.stableDecisions.values()];
  }

  /**
   * Compute the strategy stability index across all opportunities.
   * Stability index = fraction of opportunities where stable_policy == raw_policy.
   * @returns {number}
   */
  computeStabilityIndex() {
    const decisions = [...this.stableDecisions.values()];
    if (decisions.length === 0) return 1;

    const stable = decisions.filter(d => d.stable_policy === d.raw_policy);
    return Math.round(stable.length / decisions.length * 1000) / 1000;
  }

  getMetrics() {
    return { ...this.metrics, stability_index: this.computeStabilityIndex(), cycle_count: this.cycleCount };
  }

  _updateMetrics() {
    const decisions = [...this.stableDecisions.values()];
    if (decisions.length > 0) {
      this.metrics.stability_index = this.computeStabilityIndex();
      this.metrics.avg_confidence_in_stability = Math.round(
        decisions.reduce((s, d) => s + d.confidence_in_stability, 0) / decisions.length * 1000
      ) / 1000;
    }
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(DSE_DIR, 'stability-state.json');
    const data = {
      version: '1.3',
      saved_at: Date.now(),
      cycle_count: this.cycleCount,
      decision_history: [...this.decisionHistory.entries()].slice(-200).map(([k, v]) => [k, v.slice(-20)]),
      stable_decisions: [...this.stableDecisions.entries()].slice(-200),
      metrics: this.metrics,
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(DSE_DIR, 'stability-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (data.cycle_count) this.cycleCount = data.cycle_count;
      if (data.decision_history) {
        this.decisionHistory = new Map(
          data.decision_history.map(([k, v]) => [k, v.map(r => new DecisionRecord(r))])
        );
      }
      if (data.stable_decisions) {
        this.stableDecisions = new Map(
          data.stable_decisions.map(([k, v]) => [k, new StableDecision(v)])
        );
      }
      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      this._updateMetrics();
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.decisionHistory.clear();
    this.stableDecisions.clear();
    this.cycleCount = 0;
    this.metrics = {
      total_stabilized: 0, total_oscillations_detected: 0,
      total_hysteresis_applied: 0, total_smoothing_applied: 0,
      stability_index: 0, avg_confidence_in_stability: 0,
    };
    const filePath = path.join(DSE_DIR, 'stability-state.json');
    try { fs.unlinkSync(filePath); } catch (_) {}
  }

  shutdown() {
    if (this._persistTimer) clearInterval(this._persistTimer);
    this.save();
  }
}

module.exports = {
  DecisionStabilityEngine,
  StableDecision,
  DecisionRecord,
  POLICY_STRENGTH,
};

