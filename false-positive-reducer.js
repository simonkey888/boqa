/**
 * BOQA false-positive-reducer.js — False Positive Reduction Engine (S6-6)
 *
 * Reduces false positive bug reports through:
 *   - Multiple executions of the same detection
 *   - Cross-validation across independent observations
 *   - Retry before reporting (re-observe before escalating)
 *   - Noise filtering (suppress known benign patterns)
 *   - Confidence penalties for inconsistent signals
 *
 * Works in conjunction with FindingConfidenceEngine: the FPR validates
 * candidates before they are scored, and confidence penalties feed back
 * into the confidence score.
 */

const crypto = require('crypto');

// ─── Validation States ───────────────────────────────────────────────

const VALIDATION_STATES = {
  PENDING: 'pending',
  VALIDATING: 'validating',
  CONFIRMED: 'confirmed',
  FALSE_POSITIVE: 'false_positive',
  NEEDS_REVIEW: 'needs_review',
};

// ─── Known Benign Patterns ───────────────────────────────────────────

const BENIGN_PATTERNS = [
  // Common browser extension noise
  { pattern: /chrome-extension:\/\//i, category: 'browser_extension', confidence_penalty: 100 },
  { pattern: /moz-extension:\/\//i, category: 'browser_extension', confidence_penalty: 100 },
  // Development tool noise
  { pattern: /webpack-internal:\/\//i, category: 'dev_tool', confidence_penalty: 80 },
  { pattern: /\/__webpack_hmr/i, category: 'dev_tool', confidence_penalty: 80 },
  { pattern: /\/socket\.io\/\?EIO/i, category: 'dev_tool', confidence_penalty: 30 },
  // Common analytics and tracking (not bugs)
  { pattern: /google-analytics\.com/i, category: 'analytics', confidence_penalty: 20 },
  { pattern: /googletagmanager\.com/i, category: 'analytics', confidence_penalty: 20 },
  { pattern: /facebook\.net\/.*\/fbevents/i, category: 'analytics', confidence_penalty: 20 },
  // Common CDN and infrastructure
  { pattern: /cdn\./i, category: 'cdn', confidence_penalty: 5 },
  { pattern: /cloudfront\.net/i, category: 'cdn', confidence_penalty: 5 },
  // Service worker lifecycle noise
  { pattern: /service-worker.*install/i, category: 'sw_lifecycle', confidence_penalty: 40 },
];

class FalsePositiveReducer {
  /**
   * @param {object} opts
   * @param {object} opts.realBugDetector     - RealBugDetector for re-detection
   * @param {object} opts.confidenceEngine    - FindingConfidenceEngine
   * @param {object} opts.replayConfirmation  - AutomaticReplayConfirmation
   * @param {number} opts.validationRounds    - Number of validation rounds per candidate
   * @param {number} opts.confirmationThreshold - Minimum consistent observations to confirm
   * @param {number} opts.fpThreshold         - Observations below this → false positive
   * @param {number} opts.reviewThreshold     - Between fp and confirmation → needs review
   */
  constructor(opts = {}) {
    this.realBugDetector = opts.realBugDetector || null;
    this.confidenceEngine = opts.confidenceEngine || null;
    this.replayConfirmation = opts.replayConfirmation || null;

    this.validationRounds = opts.validationRounds || 3;
    this.confirmationThreshold = opts.confirmationThreshold || 2; // 2 of 3 rounds must observe
    this.fpThreshold = opts.fpThreshold || 0; // 0 of 3 rounds = FP
    this.reviewThreshold = opts.reviewThreshold || 1; // 1 of 3 rounds = review

    this._validations = new Map(); // candidateId → validation record
    this._benignPatterns = [...BENIGN_PATTERNS];
    this._stats = {
      total_validated: 0,
      confirmed: 0,
      false_positives: 0,
      needs_review: 0,
      avg_rounds: 0,
      noise_filtered: 0,
      confidence_penalties_applied: 0,
    };
  }

  /**
   * Validate a list of bug candidates. For each candidate, runs
   * multiple observation rounds and cross-validates results.
   *
   * @param {Array} candidates - Bug candidates from RealBugDetector
   * @param {object} agent     - Agent instance
   * @param {object} ctx       - BOQA context
   * @returns {object} { confirmed, false_positives, needs_review }
   */
  async validate(candidates, agent, ctx) {
    const confirmed = [];
    const false_positives = [];
    const needs_review = [];

    for (const candidate of candidates) {
      // Step 1: Noise filtering — skip known benign patterns
      const noiseResult = this._filterNoise(candidate);
      if (noiseResult.filtered) {
        this._stats.noise_filtered++;
        false_positives.push({
          ...candidate,
          validation_state: VALIDATION_STATES.FALSE_POSITIVE,
          fp_reason: `Noise filtered: ${noiseResult.reason}`,
          confidence_penalty: noiseResult.confidence_penalty,
        });
        continue;
      }

      // Step 2: Apply confidence penalties for near-benign patterns
      if (noiseResult.confidence_penalty > 0) {
        candidate.initial_confidence = Math.max(0, (candidate.initial_confidence || 0) - noiseResult.confidence_penalty);
        this._stats.confidence_penalties_applied++;
      }

      // Step 3: Multi-round validation
      const validation = await this._runValidationRounds(candidate, agent, ctx);
      this._validations.set(candidate.id, validation);

      // Step 4: Classify based on consistency
      const consistentObservations = validation.rounds.filter(r => r.observed).length;

      if (consistentObservations >= this.confirmationThreshold) {
        confirmed.push({
          ...candidate,
          validation_state: VALIDATION_STATES.CONFIRMED,
          _validation: validation,
          _repeatCount: consistentObservations,
        });
        this._stats.confirmed++;
      } else if (consistentObservations <= this.fpThreshold) {
        false_positives.push({
          ...candidate,
          validation_state: VALIDATION_STATES.FALSE_POSITIVE,
          fp_reason: `Not reproducible across ${this.validationRounds} rounds (observed ${consistentObservations}/${this.validationRounds})`,
          _validation: validation,
        });
        this._stats.false_positives++;
      } else {
        needs_review.push({
          ...candidate,
          validation_state: VALIDATION_STATES.NEEDS_REVIEW,
          review_reason: `Inconsistent observations (${consistentObservations}/${this.validationRounds} rounds)`,
          _validation: validation,
          _repeatCount: consistentObservations,
        });
        this._stats.needs_review++;
      }

      this._stats.total_validated++;
    }

    // Update average rounds
    this._stats.avg_rounds = this._stats.total_validated > 0
      ? this.validationRounds
      : 0;

    return { confirmed, false_positives, needs_review };
  }

  /**
   * Run validation rounds for a single candidate.
   */
  async _runValidationRounds(candidate, agent, ctx) {
    const validation = {
      candidate_id: candidate.id,
      started_at: Date.now(),
      completed_at: null,
      rounds: [],
      consistent_observations: 0,
      inconsistent_observations: 0,
    };

    for (let round = 1; round <= this.validationRounds; round++) {
      const roundResult = {
        round,
        started_at: Date.now(),
        observed: false,
        confidence_delta: 0,
        details: null,
      };

      try {
        // Re-detect using RealBugDetector if available
        if (this.realBugDetector && agent) {
          const detection = this.realBugDetector.detect(agent, ctx);
          const matchingCandidate = detection.candidates.find(c =>
            c.category === candidate.category &&
            c.context_hash === candidate.context_hash
          );

          roundResult.observed = !!matchingCandidate;
          roundResult.details = matchingCandidate ? {
            confidence: matchingCandidate.initial_confidence,
            signal_strength: matchingCandidate.signal_strength,
          } : null;

          // Track confidence delta
          if (matchingCandidate && candidate.initial_confidence) {
            roundResult.confidence_delta = matchingCandidate.initial_confidence - candidate.initial_confidence;
          }
        } else {
          // Without detector: single-round "optimistic" validation
          // If we have replay confirmation, trust it
          if (this.replayConfirmation) {
            const confirmation = this.replayConfirmation.getConfirmation(candidate.id);
            roundResult.observed = confirmation && confirmation.state === 'confirmed';
          } else {
            // Cannot re-validate — mark as observed (single observation)
            roundResult.observed = true;
          }
        }
      } catch (err) {
        roundResult.observed = false;
        roundResult.details = { error: err.message };
      }

      roundResult.completed_at = Date.now();
      validation.rounds.push(roundResult);

      if (roundResult.observed) {
        validation.consistent_observations++;
      } else {
        validation.inconsistent_observations++;
      }
    }

    validation.completed_at = Date.now();
    return validation;
  }

  /**
   * Filter known noise patterns.
   */
  _filterNoise(candidate) {
    const textToCheck = [
      candidate.url || '',
      candidate.reasoning || '',
      JSON.stringify(candidate.evidence || {}),
    ].join(' ');

    for (const bp of this._benignPatterns) {
      if (bp.pattern.test(textToCheck)) {
        return {
          filtered: bp.confidence_penalty >= 50,
          reason: bp.category,
          confidence_penalty: bp.confidence_penalty,
          pattern: bp.pattern.source,
        };
      }
    }

    return { filtered: false, reason: null, confidence_penalty: 0 };
  }

  /**
   * Add a custom benign pattern.
   */
  addBenignPattern(pattern, category, confidencePenalty) {
    this._benignPatterns.push({
      pattern,
      category,
      confidence_penalty: confidencePenalty,
    });
  }

  /**
   * Get validation for a candidate.
   */
  getValidation(candidateId) {
    return this._validations.get(candidateId) || null;
  }

  /**
   * Get reducer statistics.
   */
  getStats() {
    return {
      ...this._stats,
      benign_patterns: this._benignPatterns.length,
      validation_rounds: this.validationRounds,
      confirmation_threshold: this.confirmationThreshold,
      fp_rate: this._stats.total_validated > 0
        ? (this._stats.false_positives / this._stats.total_validated * 100).toFixed(1) + '%'
        : '0%',
    };
  }

  /**
   * Reset all state.
   */
  reset() {
    this._validations.clear();
    this._stats = {
      total_validated: 0, confirmed: 0, false_positives: 0,
      needs_review: 0, avg_rounds: 0, noise_filtered: 0,
      confidence_penalties_applied: 0,
    };
  }
}

module.exports = { FalsePositiveReducer, VALIDATION_STATES, BENIGN_PATTERNS };

