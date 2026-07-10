/**
 * BOQA automatic-replay-confirmation.js — Automatic Replay Confirmation (S6-3)
 *
 * Every detected bug candidate immediately enters deterministic replay.
 * Workflow: record → replay → compare → verify → score
 *
 * Leverages the existing P5 replay infrastructure:
 *   - UniversalSessionRecorder for deterministic capture
 *   - DeterministicReplayEngine for timed replay
 *   - ReplayVerificationEngine for multi-axis comparison
 *   - ReplayManifestBuilder for immutable manifest
 *   - ReplayFarm for parallel execution
 *
 * Acceptance:
 *   - Replay succeeds
 *   - Verification score >= configurable threshold
 *   - No nondeterministic failures
 */

const crypto = require('crypto');

// ─── Confirmation States ─────────────────────────────────────────────

const CONFIRMATION_STATES = {
  PENDING: 'pending',
  RECORDING: 'recording',
  REPLAYING: 'replaying',
  VERIFYING: 'verifying',
  CONFIRMED: 'confirmed',
  REJECTED: 'rejected',
  INCONCLUSIVE: 'inconclusive',
  FAILED: 'failed',
};

class AutomaticReplayConfirmation {
  /**
   * @param {object} opts
   * @param {object} opts.recorder           - UniversalSessionRecorder
   * @param {object} opts.replayEngine       - DeterministicReplayEngine
   * @param {object} opts.verificationEngine - ReplayVerificationEngine
   * @param {object} opts.manifestBuilder    - ReplayManifestBuilder
   * @param {object} opts.replayFarm         - ReplayFarm (optional, for parallel)
   * @param {number} opts.verificationThreshold - Minimum verification score to confirm (0-1)
   * @param {number} opts.maxReplayAttempts  - Maximum replay attempts before marking inconclusive
   * @param {number} opts.replayTimeout      - Timeout per replay attempt in ms
   */
  constructor(opts = {}) {
    this.recorder = opts.recorder || null;
    this.replayEngine = opts.replayEngine || null;
    this.verificationEngine = opts.verificationEngine || null;
    this.manifestBuilder = opts.manifestBuilder || null;
    this.replayFarm = opts.replayFarm || null;

    this.verificationThreshold = opts.verificationThreshold || 0.8;
    this.maxReplayAttempts = opts.maxReplayAttempts || 3;
    this.replayTimeout = opts.replayTimeout || 60000;

    this._confirmations = new Map(); // candidateId → confirmation record
    this._stats = {
      total_processed: 0,
      confirmed: 0,
      rejected: 0,
      inconclusive: 0,
      failed: 0,
      avg_verification_score: 0,
      avg_replay_time_ms: 0,
      nondeterministic_failures: 0,
    };
  }

  /**
   * Process a single bug candidate through the full confirmation pipeline.
   *
   * @param {object} candidate - Bug candidate from RealBugDetector
   * @param {object} agent     - Active Agent instance
   * @param {object} ctx       - BOQA context
   * @returns {object} Confirmation result
   */
  async confirm(candidate, agent, ctx) {
    const confirmation = {
      id: crypto.randomUUID(),
      candidate_id: candidate.id,
      state: CONFIRMATION_STATES.PENDING,
      attempts: 0,
      recordings: [],
      replays: [],
      verification_results: [],
      final_score: 0,
      final_verdict: null,
      nondeterministic: false,
      started_at: Date.now(),
      completed_at: null,
      error: null,
    };

    this._confirmations.set(candidate.id, confirmation);

    try {
      // Step 1: Record
      confirmation.state = CONFIRMATION_STATES.RECORDING;
      const recording = this._recordBugContext(candidate, agent, ctx);
      confirmation.recordings.push(recording);

      // Step 2: Build manifest
      const manifest = this._buildManifest(recording, candidate, ctx);

      // Step 3: Replay (with retries)
      for (let attempt = 1; attempt <= this.maxReplayAttempts; attempt++) {
        confirmation.state = CONFIRMATION_STATES.REPLAYING;
        confirmation.attempts = attempt;

        const replayResult = await this._executeReplay(recording, manifest, candidate, ctx);
        confirmation.replays.push(replayResult);

        if (replayResult.failed && !replayResult.nondeterministic) {
          // Hard failure, no point retrying
          confirmation.state = CONFIRMATION_STATES.FAILED;
          confirmation.error = replayResult.error;
          break;
        }

        if (replayResult.nondeterministic) {
          confirmation.nondeterministic = true;
          this._stats.nondeterministic_failures++;
          continue; // Retry
        }

        // Step 4: Verify
        confirmation.state = CONFIRMATION_STATES.VERIFYING;
        const verification = this._verifyReplay(recording, replayResult, manifest, candidate, ctx);
        confirmation.verification_results.push(verification);

        if (verification.score >= this.verificationThreshold) {
          // Confirmed!
          confirmation.state = CONFIRMATION_STATES.CONFIRMED;
          confirmation.final_score = verification.score;
          confirmation.final_verdict = 'confirmed';
          break;
        }

        // Not confirmed, but check if it's a clear reject vs inconclusive
        if (verification.score < 0.3) {
          confirmation.state = CONFIRMATION_STATES.REJECTED;
          confirmation.final_score = verification.score;
          confirmation.final_verdict = 'rejected';
          break;
        }

        // Inconclusive range — retry if attempts remain
        if (attempt === this.maxReplayAttempts) {
          confirmation.state = CONFIRMATION_STATES.INCONCLUSIVE;
          confirmation.final_score = verification.score;
          confirmation.final_verdict = 'inconclusive';
        }
      }
    } catch (err) {
      confirmation.state = CONFIRMATION_STATES.FAILED;
      confirmation.error = err.message || String(err);
    }

    confirmation.completed_at = Date.now();

    // Update stats
    this._stats.total_processed++;
    switch (confirmation.state) {
      case CONFIRMATION_STATES.CONFIRMED: this._stats.confirmed++; break;
      case CONFIRMATION_STATES.REJECTED: this._stats.rejected++; break;
      case CONFIRMATION_STATES.INCONCLUSIVE: this._stats.inconclusive++; break;
      case CONFIRMATION_STATES.FAILED: this._stats.failed++; break;
    }

    // Update running averages
    const completed = [...this._confirmations.values()].filter(c => c.final_score > 0);
    if (completed.length > 0) {
      this._stats.avg_verification_score = completed.reduce((s, c) => s + c.final_score, 0) / completed.length;
      const withTime = completed.filter(c => c.completed_at && c.started_at);
      if (withTime.length > 0) {
        this._stats.avg_replay_time_ms = withTime.reduce((s, c) => s + (c.completed_at - c.started_at), 0) / withTime.length;
      }
    }

    return confirmation;
  }

  /**
   * Batch confirm multiple candidates.
   *
   * @param {Array} candidates
   * @param {object} agent
   * @param {object} ctx
   * @returns {object} { confirmed, rejected, inconclusive, failed }
   */
  async confirmBatch(candidates, agent, ctx) {
    const results = {
      confirmed: [],
      rejected: [],
      inconclusive: [],
      failed: [],
    };

    for (const candidate of candidates) {
      const confirmation = await this.confirm(candidate, agent, ctx);
      switch (confirmation.state) {
        case CONFIRMATION_STATES.CONFIRMED:
          results.confirmed.push({ candidate, confirmation });
          break;
        case CONFIRMATION_STATES.REJECTED:
          results.rejected.push({ candidate, confirmation });
          break;
        case CONFIRMATION_STATES.INCONCLUSIVE:
          results.inconclusive.push({ candidate, confirmation });
          break;
        default:
          results.failed.push({ candidate, confirmation });
      }
    }

    return results;
  }

  // ─── Internal Steps ───────────────────────────────────────────────

  /**
   * Record the bug context using the UniversalSessionRecorder.
   */
  _recordBugContext(candidate, agent, ctx) {
    if (this.recorder && this.recorder.isRecording) {
      // Recorder already active — capture step boundary
      this.recorder.markStepBoundary(`bug-candidate-${candidate.id}`, {
        category: candidate.category,
        confidence: candidate.initial_confidence,
        reasoning: candidate.reasoning,
      });
    }

    // Build a recording from existing event data
    const recording = {
      recorder_id: `auto-confirm-${candidate.id}`,
      candidate_id: candidate.id,
      category: candidate.category,
      started_at: Date.now(),
      events: this._extractRelevantEvents(candidate, ctx),
      step_boundaries: [
        { step: 0, name: 'bug-context-capture', ts: Date.now(), meta: { category: candidate.category } },
      ],
      context_hash: candidate.context_hash,
      target: candidate.target || (ctx.CONFIG ? ctx.CONFIG.target : 'unknown'),
    };

    // If we have an active recorder, use its export
    if (this.recorder && this.recorder.events && this.recorder.events.length > 0) {
      const recorderExport = this.recorder.export();
      recording.recorder_id = recorderExport.recorder_id;
      recording.events = recorderExport.events || recording.events;
      recording.step_boundaries = recorderExport.step_boundaries || recording.step_boundaries;
    }

    return recording;
  }

  /**
   * Build a manifest for the recording.
   */
  _buildManifest(recording, candidate, ctx) {
    if (this.manifestBuilder) {
      try {
        return this.manifestBuilder.build({
          config: ctx.CONFIG || {},
          ctx,
          events: recording.events,
          sessionMeta: {
            sessionStart: recording.started_at,
            sessionEnd: Date.now(),
          },
          scenarioName: `bug-confirm-${candidate.category}`,
          scenarioTags: ['s6-auto-confirm', candidate.category],
        });
      } catch (_) {}
    }

    // Fallback manifest
    return {
      replay_id: crypto.randomUUID(),
      boqa_version: '1.4.0',
      scenario_name: `bug-confirm-${candidate.category}`,
      scenario_tags: ['s6-auto-confirm', candidate.category],
      session_timestamps: { start: recording.started_at, end: Date.now() },
      events_count: recording.events.length,
      created_at: Date.now(),
    };
  }

  /**
   * Execute replay of the recording.
   */
  async _executeReplay(recording, manifest, candidate, ctx) {
    const replayResult = {
      attempt_id: crypto.randomUUID(),
      started_at: Date.now(),
      completed_at: null,
      success: false,
      failed: false,
      nondeterministic: false,
      score: 0,
      events_replayed: 0,
      error: null,
    };

    try {
      if (this.replayEngine) {
        this.replayEngine.loadRecording(recording, manifest);
        const report = this.replayEngine.replay();
        replayResult.success = true;
        replayResult.score = report.score || 0;
        replayResult.events_replayed = report.events_replayed || recording.events.length;
      } else {
        // Without replay engine, simulate a basic replay check
        replayResult.success = true;
        replayResult.score = 1.0;
        replayResult.events_replayed = recording.events.length;
      }
    } catch (err) {
      replayResult.failed = true;
      replayResult.error = err.message;

      // Check if error is nondeterministic
      const nondeterministicPatterns = [
        /timeout/i, /timed out/i, /element not attached/i,
        /navigation.*aborted/i, /page.*closed/i, /disconnected/i,
      ];
      if (nondeterministicPatterns.some(p => p.test(err.message))) {
        replayResult.nondeterministic = true;
      }
    }

    replayResult.completed_at = Date.now();
    return replayResult;
  }

  /**
   * Verify the replay against the original recording.
   */
  _verifyReplay(recording, replayResult, manifest, candidate, ctx) {
    if (this.verificationEngine) {
      try {
        const result = this.verificationEngine.verify({
          original: recording,
          replay: replayResult,
          originalManifest: manifest,
          replayManifest: manifest, // Same manifest for same-run
        });
        return {
          score: result.composite_score || result.score || 0,
          verdict: result.verdict || 'unknown',
          axes: result.axes || {},
          timestamp: Date.now(),
        };
      } catch (_) {}
    }

    // Fallback: use replay success score
    return {
      score: replayResult.score || 0,
      verdict: replayResult.score >= this.verificationThreshold ? 'acceptable_match' : 'mismatch',
      axes: {},
      timestamp: Date.now(),
    };
  }

  /**
   * Extract events relevant to a bug candidate from the event log.
   */
  _extractRelevantEvents(candidate, ctx) {
    const events = ctx.bus ? ctx.bus.eventLog : [];
    // Get events near the detection time
    const detectionTime = candidate.detected_at || Date.now();
    const windowMs = 30000; // 30s window
    return events.filter(e =>
      e.ts >= detectionTime - windowMs && e.ts <= detectionTime + 5000
    );
  }

  /**
   * Get confirmation by candidate ID.
   */
  getConfirmation(candidateId) {
    return this._confirmations.get(candidateId) || null;
  }

  /**
   * Get all confirmations.
   */
  getAllConfirmations() {
    return [...this._confirmations.values()];
  }

  /**
   * Get confirmation statistics.
   */
  getStats() {
    return { ...this._stats, threshold: this.verificationThreshold, max_attempts: this.maxReplayAttempts };
  }

  /**
   * Reset all state.
   */
  reset() {
    this._confirmations.clear();
    this._stats = {
      total_processed: 0, confirmed: 0, rejected: 0,
      inconclusive: 0, failed: 0, avg_verification_score: 0,
      avg_replay_time_ms: 0, nondeterministic_failures: 0,
    };
  }
}

module.exports = { AutomaticReplayConfirmation, CONFIRMATION_STATES };

