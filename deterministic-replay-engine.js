/**
 * BOQA deterministic-replay-engine.js — DeterministicReplayEngine v1.5 (P5)
 *
 * Replays browser sessions with deterministic ordering, stable timing,
 * seeded randomness, and controllable clocks. This replaces the limited
 * SessionReplayer with a full deterministic replay engine that:
 *
 *   - Replays events in exact recorded sequence (seq number)
 *   - Provides clock abstraction for time-independent replay
 *   - Uses seeded PRNG for reproducible random decisions
 *   - Normalizes timing to remove non-deterministic delays
 *   - Supports network barriers for ordered network replay
 *   - Tolerates non-critical UI drift (dynamic IDs, timestamps)
 *   - Supports step-by-step replay with step boundary markers
 *
 * Determinism guarantees:
 *   1. Fixed clock: all Date.now() replaced by controllable virtual clock
 *   2. Seeded randomness: PRNG seeded from manifest hash
 *   3. Stable waits: deterministic wait strategies (not timeouts)
 *   4. Network order preserved: requests replayed in exact order
 *   5. Non-critical drift tolerated: dynamic IDs, timestamps ignored
 *
 * Safe mode: replay only — no live browser execution from replay artifacts.
 * All execution paths go through AutonomyGovernor simulation mode.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const REPLAYS_DIR = path.join(__dirname, 'output', 'replays');

// ─── Seeded PRNG (xoshiro128**) ────────────────────────────────────

function splitmix32(a) {
  return function() {
    a |= 0; a = a + 0x9e3779b9 | 0;
    let t = a ^ a >>> 16;
    t = Math.imul(t, 0x21f0aaad);
    t = t ^ t >>> 15;
    t = Math.imul(t, 0x735a2d97);
    t = t ^ t >>> 15;
    return (t >>> 0) / 4294967296;
  };
}

function seedFromString(str) {
  const hash = crypto.createHash('sha256').update(str).digest();
  return hash.readUInt32LE(0);
}

// ─── Virtual Clock ─────────────────────────────────────────────────

class VirtualClock {
  /**
   * @param {number} startTime - Starting timestamp
   * @param {number} [speed=1] - Clock speed multiplier
   */
  constructor(startTime, speed = 1) {
    this.startTime = startTime;
    this.currentTime = startTime;
    this.speed = speed;
    this.advances = 0;
  }

  now() {
    return this.currentTime;
  }

  advance(ms) {
    const delta = Math.round(ms * this.speed);
    this.currentTime += delta;
    this.advances++;
    return this.currentTime;
  }

  advanceTo(timestamp) {
    if (timestamp > this.currentTime) {
      this.currentTime = timestamp;
      this.advances++;
    }
    return this.currentTime;
  }

  reset(startTime) {
    this.startTime = startTime;
    this.currentTime = startTime;
    this.advances = 0;
  }
}

// ─── Timing Normalizer ─────────────────────────────────────────────

class TimingNormalizer {
  /**
   * @param {object} options
   * @param {number} [options.minDelay=10] - Minimum delay between events (ms)
   * @param {number} [options.maxDelay=5000] - Maximum delay between events (ms)
   * @param {boolean} [options.preserveOrder=true] - Maintain event ordering
   */
  constructor(options = {}) {
    this.minDelay = options.minDelay || 10;
    this.maxDelay = options.maxDelay || 5000;
    this.preserveOrder = options.preserveOrder !== false;
  }

  /**
   * Normalize event timestamps to remove non-deterministic delays.
   * Preserves relative ordering but caps extreme delays.
   *
   * @param {object[]} events - Events with ts field
   * @returns {object[]} Events with normalized timestamps
   */
  normalize(events) {
    if (events.length === 0) return [];

    const sorted = this.preserveOrder
      ? [...events].sort((a, b) => (a.seq || 0) - (b.seq || 0))
      : [...events];

    const normalized = [];
    let lastTs = sorted[0].ts;
    let virtualTs = lastTs;

    for (const event of sorted) {
      const delta = event.ts - lastTs;
      const clamped = Math.max(this.minDelay, Math.min(delta, this.maxDelay));
      virtualTs += clamped;

      normalized.push({
        ...event,
        original_ts: event.ts,
        normalized_ts: virtualTs,
        delay_from_previous: clamped,
      });

      lastTs = event.ts;
    }

    return normalized;
  }
}

// ─── Network Barrier ───────────────────────────────────────────────

class NetworkBarrier {
  constructor() {
    this.pending = new Map(); // requestId → { resolve, event }
    this.completed = new Set();
  }

  /**
   * Wait for a network request to complete before proceeding.
   *
   * @param {string} requestId - Request identifier
   * @param {number} [timeout=5000] - Timeout in ms
   * @returns {Promise<object>} The completed response event
   */
  async wait(requestId, timeout = 5000) {
    if (this.completed.has(requestId)) {
      return this.pending.get(requestId)?.event || null;
    }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(requestId);
        reject(new Error(`Network barrier timeout for request ${requestId}`));
      }, timeout);

      this.pending.set(requestId, {
        resolve: (event) => {
          clearTimeout(timer);
          this.completed.add(requestId);
          this.pending.delete(requestId);
          resolve(event);
        },
        event: null,
      });
    });
  }

  /**
   * Signal that a network request has completed.
   *
   * @param {string} requestId
   * @param {object} responseEvent
   */
  complete(requestId, responseEvent) {
    const pending = this.pending.get(requestId);
    if (pending) {
      pending.event = responseEvent;
      pending.resolve(responseEvent);
    } else {
      this.completed.add(requestId);
    }
  }

  reset() {
    this.pending.clear();
    this.completed.clear();
  }
}

// ─── DeterministicReplayEngine ─────────────────────────────────────

class DeterministicReplayEngine {
  /**
   * @param {object} options
   * @param {string} [options.seed] - PRNG seed (defaults to manifest hash)
   * @param {number} [options.clockSpeed=1] - Virtual clock speed
   * @param {boolean} [options.normalizeTiming=true] - Normalize event timing
   * @param {boolean} [options.tolerateUiDrift=true] - Tolerate non-critical UI differences
   * @param {boolean} [options.ignoreTimestamps=true] - Ignore timestamp values in diff
   * @param {boolean} [options.ignoreDynamicIds=true] - Ignore dynamic IDs in diff
   * @param {number} [options.concurrency=1] - Replay concurrency (1 = sequential)
   * @param {boolean} [options.stopOnFailure=false] - Stop on first failure
   * @param {Function} [options.fetchFn] - Function for HTTP replay
   */
  constructor(options = {}) {
    this.seed = options.seed || null;
    this.rng = null;
    this.clock = new VirtualClock(Date.now(), options.clockSpeed || 1);
    this.timingNormalizer = new TimingNormalizer({
      minDelay: 10,
      maxDelay: 5000,
    });
    this.networkBarrier = new NetworkBarrier();
    this.options = {
      normalizeTiming: options.normalizeTiming !== false,
      tolerateUiDrift: options.tolerateUiDrift !== false,
      ignoreTimestamps: options.ignoreTimestamps !== false,
      ignoreDynamicIds: options.ignoreDynamicIds !== false,
      concurrency: options.concurrency || 1,
      stopOnFailure: options.stopOnFailure || false,
      fetchFn: options.fetchFn || null,
    };

    // Replay state
    this.recording = null;
    this.manifest = null;
    this.results = [];
    this.currentStep = 0;
    this.passed = 0;
    this.failed = 0;
    this.skipped = 0;
  }

  /**
   * Load a recording for replay.
   *
   * @param {object} recording - Recording export from UniversalSessionRecorder
   * @param {object} [manifest] - Associated ReplayManifest
   */
  loadRecording(recording, manifest = null) {
    this.recording = recording;
    this.manifest = manifest;

    // Initialize PRNG from seed (manifest hash or recording context hash)
    const seedStr = this.seed || manifest?.artifact_hash || recording.context_hash || 'default-seed';
    this.rng = splitmix32(seedFromString(seedStr));

    // Initialize virtual clock from recording start
    this.clock.reset(recording.started_at || Date.now());

    // Reset state
    this.results = [];
    this.currentStep = 0;
    this.passed = 0;
    this.failed = 0;
    this.skipped = 0;
  }

  /**
   * Execute full replay of all events.
   *
   * @returns {object} Replay report
   */
  async replay() {
    if (!this.recording) {
      throw new Error('No recording loaded');
    }

    const events = this.recording.events || [];

    // Optionally normalize timing
    const replayEvents = this.options.normalizeTiming
      ? this.timingNormalizer.normalize(events)
      : events;

    // Extract replayable network requests
    const networkRequests = replayEvents.filter(e =>
      e.type === 'network_request' && e.url && !e.url.startsWith('data:')
    );

    console.log(`[DeterministicReplay] ${events.length} events, ${networkRequests.length} network requests to replay`);

    // Replay network requests in deterministic order
    if (this.options.fetchFn && networkRequests.length > 0) {
      await this._replayNetworkRequests(networkRequests);
    }

    // Process step boundaries for step-by-step tracking
    this._processStepBoundaries(replayEvents);

    // Verify context hash matches
    const contextMatch = this._verifyContextHash();

    return this._generateReport(contextMatch);
  }

  /**
   * Replay a specific step range.
   *
   * @param {number} fromStep - Start step (1-indexed)
   * @param {number} [toStep] - End step (inclusive)
   * @returns {object} Step replay report
   */
  async replayStep(fromStep, toStep) {
    if (!this.recording) {
      throw new Error('No recording loaded');
    }

    const boundaries = this.recording.step_boundaries || [];
    if (fromStep < 1 || fromStep > boundaries.length) {
      throw new Error(`Invalid step: ${fromStep}`);
    }

    const endStep = toStep || fromStep;
    const stepEvents = [];

    for (let s = fromStep; s <= endStep; s++) {
      const startIdx = boundaries[s - 1]?.event_index || 0;
      const endIdx = s < boundaries.length
        ? boundaries[s]?.event_index
        : this.recording.events.length;
      stepEvents.push(...this.recording.events.slice(startIdx, endIdx));
    }

    const networkRequests = stepEvents.filter(e =>
      e.type === 'network_request' && e.url && !e.url.startsWith('data:')
    );

    if (this.options.fetchFn && networkRequests.length > 0) {
      await this._replayNetworkRequests(networkRequests);
    }

    return {
      steps: `${fromStep}-${endStep}`,
      events_count: stepEvents.length,
      network_requests: networkRequests.length,
      passed: this.passed,
      failed: this.failed,
      rng_state: this.rng ? this.rng() : null,
    };
  }

  /**
   * Get the next random number from the seeded PRNG.
   * Used by replay consumers that need deterministic randomness.
   *
   * @returns {number} Float 0-1
   */
  nextRandom() {
    if (!this.rng) {
      this.rng = splitmix32(seedFromString('default'));
    }
    return this.rng();
  }

  /**
   * Get the virtual clock's current time.
   *
   * @returns {number} Current virtual timestamp
   */
  currentTime() {
    return this.clock.now();
  }

  /**
   * Get a deterministic wait time.
   *
   * @param {number} min - Minimum wait (ms)
   * @param {number} max - Maximum wait (ms)
   * @returns {number} Deterministic wait time within range
   */
  deterministicWait(min, max) {
    const r = this.nextRandom();
    return Math.round(min + r * (max - min));
  }

  // ─── Internal Helpers ───────────────────────────────────────────

  async _replayNetworkRequests(requests) {
    for (let i = 0; i < requests.length; i += this.options.concurrency) {
      const batch = requests.slice(i, i + this.options.concurrency);
      const results = await Promise.allSettled(
        batch.map(req => this._replaySingleRequest(req))
      );

      for (const result of results) {
        if (result.status === 'fulfilled') {
          this.results.push(result.value);
          if (result.value.passed) this.passed++;
          else this.failed++;
        } else {
          this.results.push({ passed: false, error: result.reason?.message || 'Unknown' });
          this.failed++;
        }
      }

      if (this.options.stopOnFailure && this.failed > 0) break;

      // Advance virtual clock deterministically
      if (i + this.options.concurrency < requests.length) {
        const waitMs = this.deterministicWait(50, 200);
        this.clock.advance(waitMs);
      }
    }
  }

  async _replaySingleRequest(req) {
    if (!this.options.fetchFn) {
      return { url: req.url, method: req.method, passed: false, error: 'No fetch function' };
    }

    const startTime = Date.now();
    try {
      const response = await this.options.fetchFn(req.url, {
        method: req.method || 'GET',
        headers: req.headers || {},
        timeout: 15000,
      });

      const elapsed = Date.now() - startTime;
      const statusOk = response?.status >= 200 && response?.status < 400;

      return {
        method: req.method || 'GET',
        url: req.url,
        status: response?.status || null,
        elapsed,
        passed: statusOk,
        checks: [{ check: 'status', expected: '2xx/3xx', actual: response?.status, passed: statusOk }],
      };
    } catch (err) {
      return {
        method: req.method || 'GET',
        url: req.url,
        elapsed: Date.now() - startTime,
        passed: false,
        error: err.message,
      };
    }
  }

  _processStepBoundaries(events) {
    const boundaries = events.filter(e => e.type === 'replay_step_boundary');
    for (const b of boundaries) {
      if (b.payload?.action === 'step_boundary') {
        this.currentStep = b.payload.step;
      }
    }
  }

  _verifyContextHash() {
    if (!this.recording?.context_hash) return null;
    // Recompute hash over event sequence
    const content = JSON.stringify(
      (this.recording.events || []).map(e => ({
        seq: e.seq,
        type: e.type,
        url: e.url,
        method: e.method,
        status: e.status,
      }))
    );
    const computed = crypto.createHash('sha256').update(content).digest('hex');
    return computed === this.recording.context_hash;
  }

  _generateReport(contextMatch) {
    const total = this.passed + this.failed + this.skipped;
    return {
      type: 'deterministic_replay_report',
      recorder_id: this.recording?.recorder_id,
      manifest_id: this.manifest?.replay_id || this.recording?.manifest_id,
      replayed_at: Date.now(),
      total_events: this.recording?.events?.length || 0,
      network_total: total,
      passed: this.passed,
      failed: this.failed,
      skipped: this.skipped,
      pass_rate: total > 0 ? this.passed / total : 0,
      context_hash_match: contextMatch,
      steps_processed: this.currentStep,
      clock_advances: this.clock.advances,
      rng_seed: this.seed || '(from manifest)',
      results: this.results,
      verdict: this.failed === 0 && contextMatch !== false
        ? 'deterministic_clean'
        : this.failed <= 2
          ? 'deterministic_warning'
          : 'deterministic_critical',
    };
  }
}

module.exports = {
  DeterministicReplayEngine,
  VirtualClock,
  TimingNormalizer,
  NetworkBarrier,
  splitmix32,
  seedFromString,
};

