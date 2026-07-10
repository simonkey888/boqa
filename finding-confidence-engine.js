/**
 * BOQA finding-confidence-engine.js — Finding Confidence Engine (S6-5)
 *
 * Computes an objective confidence score for each bug finding using
 * a weighted formula:
 *
 *   confidence = replay_success × 0.30
 *              + verification_score × 0.30
 *              + signal_strength × 0.20
 *              + repeatability × 0.20
 *
 * Output levels: LOW, MEDIUM, HIGH, VERY_HIGH
 *
 * Each component is independently measurable and the score is
 * transparent — the reasoning chain is preserved so auditors can
 * understand why a finding received its score.
 */

const crypto = require('crypto');

// ─── Confidence Levels ───────────────────────────────────────────────

const CONFIDENCE_LEVELS = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  VERY_HIGH: 'VERY_HIGH',
};

// ─── Component Weights ───────────────────────────────────────────────

const WEIGHTS = {
  replay_success: 0.30,
  verification_score: 0.30,
  signal_strength: 0.20,
  repeatability: 0.20,
};

// ─── Level Thresholds ────────────────────────────────────────────────

const LEVEL_THRESHOLDS = {
  [CONFIDENCE_LEVELS.VERY_HIGH]: 85,
  [CONFIDENCE_LEVELS.HIGH]: 70,
  [CONFIDENCE_LEVELS.MEDIUM]: 50,
  [CONFIDENCE_LEVELS.LOW]: 0,
};

class FindingConfidenceEngine {
  /**
   * @param {object} opts
   * @param {object} opts.verificationEngine - ReplayVerificationEngine
   * @param {object} opts.replayConfirmation - AutomaticReplayConfirmation
   * @param {object} opts.weights            - Override default weights
   * @param {object} opts.thresholds         - Override default level thresholds
   */
  constructor(opts = {}) {
    this.verificationEngine = opts.verificationEngine || null;
    this.replayConfirmation = opts.replayConfirmation || null;
    this.weights = { ...WEIGHTS, ...(opts.weights || {}) };
    this.thresholds = { ...LEVEL_THRESHOLDS, ...(opts.thresholds || {}) };

    this._scores = new Map();
    this._stats = {
      total_scored: 0,
      by_level: { LOW: 0, MEDIUM: 0, HIGH: 0, VERY_HIGH: 0 },
      avg_score: 0,
      avg_replay_success: 0,
      avg_verification_score: 0,
      avg_signal_strength: 0,
      avg_repeatability: 0,
    };
  }

  /**
   * Score a bug candidate.
   *
   * @param {object} candidate - Bug candidate from RealBugDetector
   * @param {object} ctx       - BOQA context
   * @returns {object} { score, level, components, reasoning }
   */
  score(candidate, ctx) {
    const components = {
      replay_success: this._computeReplaySuccess(candidate, ctx),
      verification_score: this._computeVerificationScore(candidate, ctx),
      signal_strength: this._computeSignalStrength(candidate, ctx),
      repeatability: this._computeRepeatability(candidate, ctx),
    };

    // Weighted sum
    const rawScore =
      components.replay_success * this.weights.replay_success +
      components.verification_score * this.weights.verification_score +
      components.signal_strength * this.weights.signal_strength +
      components.repeatability * this.weights.repeatability;

    const score = Math.round(Math.min(Math.max(rawScore, 0), 100));
    const level = this._scoreToLevel(score);

    const result = {
      id: crypto.randomUUID(),
      candidate_id: candidate.id,
      score,
      level,
      components,
      weights: this.weights,
      reasoning: this._buildReasoning(candidate, components, score, level),
      scored_at: Date.now(),
    };

    this._scores.set(candidate.id, result);

    // Update stats
    this._stats.total_scored++;
    this._stats.by_level[level]++;
    this._stats.avg_score = this._updateAvg(this._stats.avg_score, score);
    this._stats.avg_replay_success = this._updateAvg(this._stats.avg_replay_success, components.replay_success);
    this._stats.avg_verification_score = this._updateAvg(this._stats.avg_verification_score, components.verification_score);
    this._stats.avg_signal_strength = this._updateAvg(this._stats.avg_signal_strength, components.signal_strength);
    this._stats.avg_repeatability = this._updateAvg(this._stats.avg_repeatability, components.repeatability);

    return result;
  }

  // ─── Component Computation ────────────────────────────────────────

  /**
   * Replay success: Was the bug successfully replayed?
   * 100 = replay confirmed the bug deterministically
   * 50  = replay partially confirmed
   * 0   = no replay or replay failed
   */
  _computeReplaySuccess(candidate, ctx) {
    // Check if there's a confirmation result
    if (this.replayConfirmation) {
      const confirmation = this.replayConfirmation.getConfirmation(candidate.id);
      if (confirmation) {
        if (confirmation.state === 'confirmed') return 100;
        if (confirmation.state === 'inconclusive') return 50;
        if (confirmation.state === 'rejected') return 10;
        if (confirmation.state === 'failed') return 0;
      }
    }

    // Check if candidate has replay info attached
    if (candidate._replaySuccess !== undefined) {
      return candidate._replaySuccess ? 100 : 0;
    }

    // No replay data — penalize heavily
    return 0;
  }

  /**
   * Verification score: How well did the verification engine match?
   * 100 = exact_match
   * 80  = acceptable_match
   * 60  = partial_match
   * 0   = mismatch
   */
  _computeVerificationScore(candidate, ctx) {
    // Check for attached verification result
    if (candidate._verificationResult) {
      const vr = candidate._verificationResult;
      if (vr.verdict === 'exact_match') return 100;
      if (vr.verdict === 'acceptable_match') return 80;
      if (vr.verdict === 'partial_match') return 60;
      if (vr.score !== undefined) return Math.round(vr.score * 100);
    }

    // Check for confidence score already on candidate
    if (candidate.confidence_score !== undefined) {
      return candidate.confidence_score;
    }

    // Use initial confidence as proxy
    if (candidate.initial_confidence !== undefined) {
      return candidate.initial_confidence;
    }

    return 0;
  }

  /**
   * Signal strength: How strong is the observed signal?
   * Based on: number of evidence points, severity, anomaly count.
   */
  _computeSignalStrength(candidate, ctx) {
    let score = 0;

    // Signal strength from detector
    const strengthMap = {
      very_strong: 100,
      strong: 75,
      moderate: 50,
      weak: 25,
    };
    if (candidate.signal_strength) {
      score = strengthMap[candidate.signal_strength] || 50;
    }

    // Adjust based on evidence quality
    if (candidate.evidence) {
      const evidenceKeys = Object.keys(candidate.evidence);
      score = Math.min(100, score + evidenceKeys.length * 5);
    }

    // Adjust based on category severity (some categories are inherently more severe)
    const severityBoost = {
      auth_inconsistency: 15,
      http_failure: 10,
      cookie_anomaly: 5,
      state_corruption: 10,
      race_condition: 5,
      dom_anomaly: 0,
      navigation_failure: 5,
      console_error: 0,
      unexpected_redirect: 10,
      storage_anomaly: 0,
    };
    score = Math.min(100, score + (severityBoost[candidate.category] || 0));

    return score;
  }

  /**
   * Repeatability: Can the bug be observed multiple times?
   * Based on: observation count, consistency across runs.
   */
  _computeRepeatability(candidate, ctx) {
    let score = 0;

    // Check for repetition count
    if (candidate.observation_count) {
      score = Math.min(100, 30 + candidate.observation_count * 20);
    } else if (candidate._repeatCount) {
      score = Math.min(100, 30 + candidate._repeatCount * 20);
    } else {
      // Single observation — base repeatability is low
      score = 25;
    }

    // Boost if the same pattern was seen in anomaly engine
    if (this.verificationEngine || ctx.anomalyEngine) {
      const anomalies = ctx.agent?.anomaly?.getAnomalies() || [];
      const matchingAnomalies = anomalies.filter(a =>
        a.rule && a.detail && candidate.reasoning &&
        a.detail.includes(candidate.category.replace('_', ' '))
      );
      if (matchingAnomalies.length > 0) {
        score = Math.min(100, score + matchingAnomalies.length * 15);
      }
    }

    return score;
  }

  // ─── Helpers ──────────────────────────────────────────────────────

  _scoreToLevel(score) {
    if (score >= this.thresholds[CONFIDENCE_LEVELS.VERY_HIGH]) return CONFIDENCE_LEVELS.VERY_HIGH;
    if (score >= this.thresholds[CONFIDENCE_LEVELS.HIGH]) return CONFIDENCE_LEVELS.HIGH;
    if (score >= this.thresholds[CONFIDENCE_LEVELS.MEDIUM]) return CONFIDENCE_LEVELS.MEDIUM;
    return CONFIDENCE_LEVELS.LOW;
  }

  _buildReasoning(candidate, components, score, level) {
    const parts = [];

    if (components.replay_success === 0) {
      parts.push('No replay confirmation available (replay_success=0, weight=30%)');
    } else if (components.replay_success >= 100) {
      parts.push('Bug successfully reproduced via deterministic replay');
    } else {
      parts.push(`Partial replay confirmation (${components.replay_success}/100)`);
    }

    if (components.verification_score >= 80) {
      parts.push('Verification score indicates strong match');
    } else if (components.verification_score >= 50) {
      parts.push('Verification score indicates moderate match');
    } else {
      parts.push('Verification score is weak — finding may be environment-specific');
    }

    if (components.signal_strength >= 75) {
      parts.push('Strong signal detected with multiple evidence points');
    } else {
      parts.push(`Signal strength is ${candidate.signal_strength || 'unknown'}`);
    }

    if (components.repeatability >= 70) {
      parts.push('Bug observed multiple times — high repeatability');
    } else {
      parts.push('Bug observed only once — repeatability uncertain');
    }

    return parts.join('. ') + '.';
  }

  _updateAvg(current, value) {
    if (this._stats.total_scored <= 1) return value;
    return Math.round(current * (this._stats.total_scored - 1) / this._stats.total_scored + value / this._stats.total_scored);
  }

  /**
   * Get score for a candidate.
   */
  getScore(candidateId) {
    return this._scores.get(candidateId) || null;
  }

  /**
   * Get all scores.
   */
  getAllScores() {
    return [...this._scores.values()];
  }

  /**
   * Get engine statistics.
   */
  getStats() {
    return { ...this._stats, weights: this.weights, thresholds: this.thresholds };
  }

  /**
   * Reset all state.
   */
  reset() {
    this._scores.clear();
    this._stats = {
      total_scored: 0,
      by_level: { LOW: 0, MEDIUM: 0, HIGH: 0, VERY_HIGH: 0 },
      avg_score: 0,
      avg_replay_success: 0,
      avg_verification_score: 0,
      avg_signal_strength: 0,
      avg_repeatability: 0,
    };
  }
}

module.exports = { FindingConfidenceEngine, CONFIDENCE_LEVELS, WEIGHTS };

