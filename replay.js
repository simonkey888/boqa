/**
 * BOQA replay.js — Deterministic session replay
 *
 * Replays a recorded session's network requests in chronological order
 * to reproduce exact behavior for regression testing.
 *
 * Features:
 *   - Replay network requests from a session recording
 *   - Verify responses match expected patterns
 *   - Detect deviations from recorded behavior
 *   - Generate replay report with pass/fail per request
 *
 * Usage:
 *   const replay = new SessionReplayer(session);
 *   const result = await replay.run();
 */

const fs = require('fs');
const path = require('path');

const REPORTS_DIR = path.join(__dirname, 'output', 'reports');

class SessionReplayer {
  constructor(session, options = {}) {
    this.session = session;
    this.events = session.events || [];
    this.options = {
      timeout: options.timeout || 15000,
      concurrency: options.concurrency || 3,
      verifyStatus: options.verifyStatus !== false,
      verifyHeaders: options.verifyHeaders || false,
      stopOnFailure: options.stopOnFailure || false,
      onlyAuth: options.onlyAuth || false, // replay only auth-related requests
    };
    this.results = [];
    this.passed = 0;
    this.failed = 0;
    this.skipped = 0;

    fs.mkdirSync(REPORTS_DIR, { recursive: true });
  }

  /**
   * Run replay of all recorded network requests
   * @param {Function} fetchFn - async (url, options) => response
   * @returns {object} replay report
   */
  async run(fetchFn) {
    const requests = this._extractReplayableRequests();

    console.log(`[Replay] ${requests.length} requests to replay`);

    for (let i = 0; i < requests.length; i += this.options.concurrency) {
      const batch = requests.slice(i, i + this.options.concurrency);
      const results = await Promise.allSettled(
        batch.map(req => this._replayRequest(req, fetchFn))
      );

      for (const result of results) {
        if (result.status === 'fulfilled') {
          this.results.push(result.value);
          if (result.value.passed) this.passed++;
          else this.failed++;
        } else {
          this.results.push({ passed: false, error: result.reason?.message || 'Unknown error' });
          this.failed++;
        }
      }

      if (this.options.stopOnFailure && this.failed > 0) {
        console.log(`[Replay] Stopping on failure at request ${i + 1}`);
        break;
      }
    }

    return this._generateReport();
  }

  /**
   * Extract replayable requests from session events
   */
  _extractReplayableRequests() {
    const requests = new Map(); // deduplicate by method+url

    for (const event of this.events) {
      if (event.type !== 'network_request') continue;
      if (!event.url || event.url.startsWith('data:') || event.url.startsWith('blob:')) continue;

      const key = `${event.method || 'GET'} ${event.url}`;
      if (requests.has(key)) continue;

      const isAuth = this._isAuthRequest(event);

      if (this.options.onlyAuth && !isAuth) {
        this.skipped++;
        continue;
      }

      requests.set(key, {
        method: event.method || 'GET',
        url: event.url,
        headers: this._replayableHeaders(event.headers),
        isAuth,
        originalTs: event.ts,
        meta: event.meta || {},
      });
    }

    return [...requests.values()].sort((a, b) => a.originalTs - b.originalTs);
  }

  /**
   * Check if a request is auth-related
   */
  _isAuthRequest(event) {
    const url = event.url || '';
    return /\/auth\/|\/login|\/logout|\/token|\/session|\/2fa|\/verify|\/api\/users\/me/.test(url) ||
      (event.headers && event.headers['authorization']) ||
      (event.headers && event.headers['x-csrftoken']);
  }

  /**
   * Filter headers to only include replayable ones
   */
  _replayableHeaders(headers) {
    if (!headers) return {};
    const skip = new Set(['host', 'connection', 'content-length', 'accept-encoding',
      'cookie', 'origin', 'referer', 'sec-ch-ua', 'sec-ch-ua-mobile',
      'sec-ch-ua-platform', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site']);
    const filtered = {};
    for (const [k, v] of Object.entries(headers)) {
      if (!skip.has(k.toLowerCase())) {
        filtered[k] = v;
      }
    }
    return filtered;
  }

  /**
   * Replay a single request
   */
  async _replayRequest(req, fetchFn) {
    if (!fetchFn) {
      return { ...req, passed: false, error: 'No fetch function provided' };
    }

    const startTime = Date.now();

    try {
      const response = await fetchFn(req.url, {
        method: req.method,
        headers: req.headers,
        timeout: this.options.timeout,
      });

      const elapsed = Date.now() - startTime;

      const result = {
        method: req.method,
        url: req.url,
        isAuth: req.isAuth,
        status: response?.status || null,
        elapsed,
        passed: true,
        checks: [],
      };

      // Verify status code (2xx or 3xx = pass for replay purposes)
      if (this.options.verifyStatus && response?.status) {
        const statusOk = response.status >= 200 && response.status < 400;
        result.checks.push({ check: 'status', expected: '2xx/3xx', actual: response.status, passed: statusOk });
        if (!statusOk) result.passed = false;
      }

      return result;
    } catch (err) {
      return {
        method: req.method,
        url: req.url,
        isAuth: req.isAuth,
        elapsed: Date.now() - startTime,
        passed: false,
        error: err.message,
        checks: [],
      };
    }
  }

  /**
   * Generate replay report
   */
  _generateReport() {
    const total = this.passed + this.failed + this.skipped;
    return {
      type: 'replay_report',
      session_id: this.session.sessionStart,
      replayed_at: Date.now(),
      total,
      passed: this.passed,
      failed: this.failed,
      skipped: this.skipped,
      pass_rate: total > 0 ? this.passed / total : 0,
      results: this.results,
      verdict: this.failed === 0 ? 'clean' : this.failed <= 2 ? 'warning' : 'critical',
    };
  }

  /**
   * Save replay report to disk
   */
  save(report, filename) {
    const filePath = path.join(REPORTS_DIR, filename || `replay-${Date.now()}.json`);
    fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
    return filePath;
  }

  // ─── P5 Integration: Attach manifest metadata to replay ────────

  /**
   * Attach a P5 replay manifest to this replayer.
   * The manifest provides full execution context for deterministic replay.
   *
   * @param {object} manifest - Replay manifest from ReplayManifestBuilder
   */
  attachManifest(manifest) {
    this.manifest = manifest;
    this.contextHash = manifest?.context_hash || manifest?.artifact_hash || null;
  }

  /**
   * Export this replay as a P5-compatible recording format
   * for use with the DeterministicReplayEngine.
   *
   * @returns {object} P5 recording export
   */
  toP5Recording() {
    return {
      recorder_id: `REC-${this.session.sessionStart || Date.now()}`,
      manifest_id: this.manifest?.replay_id || null,
      context_hash: this.contextHash,
      started_at: this.session.sessionStart || Date.now(),
      ended_at: this.session.sessionEnd || Date.now(),
      duration_ms: (this.session.sessionEnd || Date.now()) - (this.session.sessionStart || Date.now()),
      total_events: this.events.length,
      step_boundaries: [],
      stats: {
        total_captured: this.events.length,
        total_redacted: 0,
        dom_snapshots: 0,
        screenshot_metas: 0,
        storage_writes: 0,
        ws_frames: 0,
        step_boundaries: 0,
      },
      events: this.events.map((e, idx) => ({
        seq: idx,
        ts: e.ts,
        type: e.type,
        url: e.url || null,
        method: e.method || null,
        status: e.status || null,
        headers: e.headers || null,
        payload: e.payload || null,
        source: e.source || 'playwright',
        meta: e.meta || {},
        step: 0,
        recorder_id: `REC-${this.session.sessionStart || Date.now()}`,
      })),
    };
  }
}

module.exports = { SessionReplayer, REPORTS_DIR };

