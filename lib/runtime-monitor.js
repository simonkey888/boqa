/**
 * BOQA lib/runtime-monitor.js — Production Runtime Observability (P5)
 *
 * Lightweight monitoring that tracks key runtime signals for post-deploy confidence.
 * Designed for Northflank deployment — no external deps, just in-process tracking
 * with /api/runtime/metrics endpoint exposure.
 *
 * Signals tracked:
 *   - Agent availability (is browser connected?)
 *   - Replay success rate
 *   - Redaction failure count
 *   - Artifact signing failure count
 *   - Memory growth trend
 *   - Open handle count estimate
 *   - Health status changes
 */

const os = require('os');

class RuntimeMonitor {
  constructor(options = {}) {
    this.maxHistory = options.maxHistory || 1440; // 24h at 1 sample/min
    this.samplingIntervalMs = options.samplingIntervalMs || 60000; // 1 minute

    // Counters
    this.counters = {
      replay_attempts: 0,
      replay_successes: 0,
      replay_failures: 0,
      redaction_attempts: 0,
      redaction_failures: 0,
      signing_attempts: 0,
      signing_failures: 0,
      encryption_attempts: 0,
      encryption_failures: 0,
      health_checks: 0,
      health_degraded: 0,
      api_requests: 0,
      api_errors: 0,
    };

    // Time series (circular buffer)
    this.memoryHistory = [];
    this.healthHistory = [];

    // State
    this.startTime = Date.now();
    this.lastHealthStatus = null;
    this._timer = null;
  }

  /**
   * Start periodic sampling.
   */
  start() {
    if (this._timer) return;
    this._timer = setInterval(() => this._sample(), this.samplingIntervalMs);
    this._timer.unref?.(); // Don't keep process alive
  }

  /**
   * Stop periodic sampling.
   */
  stop() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  /**
   * Record a replay outcome.
   */
  recordReplay(success) {
    this.counters.replay_attempts++;
    if (success) {
      this.counters.replay_successes++;
    } else {
      this.counters.replay_failures++;
    }
  }

  /**
   * Record a redaction outcome.
   */
  recordRedaction(success) {
    this.counters.redaction_attempts++;
    if (!success) this.counters.redaction_failures++;
  }

  /**
   * Record a signing outcome.
   */
  recordSigning(success) {
    this.counters.signing_attempts++;
    if (!success) this.counters.signing_failures++;
  }

  /**
   * Record an encryption outcome.
   */
  recordEncryption(success) {
    this.counters.encryption_attempts++;
    if (!success) this.counters.encryption_failures++;
  }

  /**
   * Record a health check result.
   */
  recordHealth(status) {
    this.counters.health_checks++;
    if (status === 'degraded') this.counters.health_degraded++;

    if (status !== this.lastHealthStatus) {
      this.healthHistory.push({
        from: this.lastHealthStatus,
        to: status,
        ts: Date.now(),
      });
      if (this.healthHistory.length > this.maxHistory) {
        this.healthHistory.shift();
      }
    }
    this.lastHealthStatus = status;
  }

  /**
   * Record an API request.
   */
  recordApiRequest(isError) {
    this.counters.api_requests++;
    if (isError) this.counters.api_errors++;
  }

  /**
   * Take a memory sample.
   */
  _sample() {
    const mem = process.memoryUsage();
    this.memoryHistory.push({
      rss: mem.rss,
      heapUsed: mem.heapUsed,
      heapTotal: mem.heapTotal,
      external: mem.external,
      ts: Date.now(),
    });
    if (this.memoryHistory.length > this.maxHistory) {
      this.memoryHistory.shift();
    }
  }

  /**
   * Get current metrics snapshot.
   */
  getMetrics() {
    const mem = process.memoryUsage();
    const uptime = Date.now() - this.startTime;

    // Calculate replay success rate
    const replayRate = this.counters.replay_attempts > 0
      ? this.counters.replay_successes / this.counters.replay_attempts
      : 1.0; // No attempts = 100% (vacuously true)

    // Memory growth detection
    let memoryGrowthMbPerHour = 0;
    if (this.memoryHistory.length >= 2) {
      const first = this.memoryHistory[0];
      const last = this.memoryHistory[this.memoryHistory.length - 1];
      const hours = (last.ts - first.ts) / 3600000;
      if (hours > 0) {
        memoryGrowthMbPerHour = (last.heapUsed - first.heapUsed) / (1024 * 1024) / hours;
      }
    }

    // Open handles estimate (active handles from process._getActiveHandles)
    let openHandles = 0;
    try {
      openHandles = process._getActiveHandles?.()?.length || 0;
    } catch (_) {}

    let activeRequests = 0;
    try {
      activeRequests = process._getActiveRequests?.()?.length || 0;
    } catch (_) {}

    return {
      uptime_ms: uptime,
      uptime_human: this._formatDuration(uptime),
      agent_status: this.lastHealthStatus || 'unknown',
      replay: {
        success_rate: Math.round(replayRate * 10000) / 100, // percentage with 2 decimals
        attempts: this.counters.replay_attempts,
        successes: this.counters.replay_successes,
        failures: this.counters.replay_failures,
      },
      security: {
        redaction_failure_rate: this.counters.redaction_attempts > 0
          ? Math.round((this.counters.redaction_failures / this.counters.redaction_attempts) * 10000) / 100
          : 0,
        signing_failure_rate: this.counters.signing_attempts > 0
          ? Math.round((this.counters.signing_failures / this.counters.signing_attempts) * 10000) / 100
          : 0,
        encryption_failure_rate: this.counters.encryption_attempts > 0
          ? Math.round((this.counters.encryption_failures / this.counters.encryption_attempts) * 10000) / 100
          : 0,
        redaction_failures: this.counters.redaction_failures,
        signing_failures: this.counters.signing_failures,
        encryption_failures: this.counters.encryption_failures,
      },
      memory: {
        rss_mb: Math.round(mem.rss / (1024 * 1024) * 100) / 100,
        heap_used_mb: Math.round(mem.heapUsed / (1024 * 1024) * 100) / 100,
        heap_total_mb: Math.round(mem.heapTotal / (1024 * 1024) * 100) / 100,
        growth_mb_per_hour: Math.round(memoryGrowthMbPerHour * 100) / 100,
        samples: this.memoryHistory.length,
      },
      handles: {
        active_handles: openHandles,
        active_requests: activeRequests,
      },
      api: {
        total_requests: this.counters.api_requests,
        error_rate: this.counters.api_requests > 0
          ? Math.round((this.counters.api_errors / this.counters.api_requests) * 10000) / 100
          : 0,
      },
      health: {
        checks: this.counters.health_checks,
        degraded_count: this.counters.health_degraded,
        transitions: this.healthHistory.length,
        last_transition: this.healthHistory.length > 0
          ? this.healthHistory[this.healthHistory.length - 1]
          : null,
      },
      alerts: this._generateAlerts(replayRate, memoryGrowthMbPerHour),
    };
  }

  /**
   * Generate alerts based on current metrics.
   */
  _generateAlerts(replayRate, memoryGrowth) {
    const alerts = [];

    if (this.lastHealthStatus === 'degraded') {
      alerts.push({ level: 'warning', signal: 'agent_status', message: 'Agent is in degraded mode' });
    }

    if (this.counters.replay_attempts > 10 && replayRate < 0.9) {
      alerts.push({ level: 'critical', signal: 'replay_success_rate', message: `Replay success rate below 90%: ${(replayRate * 100).toFixed(1)}%` });
    }

    if (this.counters.redaction_failures > 0) {
      alerts.push({ level: 'warning', signal: 'redaction_failures', message: `${this.counters.redaction_failures} redaction failures detected` });
    }

    if (this.counters.signing_failures > 0) {
      alerts.push({ level: 'warning', signal: 'signing_failures', message: `${this.counters.signing_failures} signing failures detected` });
    }

    if (memoryGrowth > 10) {
      alerts.push({ level: 'critical', signal: 'memory_growth', message: `Memory growing at ${memoryGrowth.toFixed(1)} MB/hour` });
    } else if (memoryGrowth > 5) {
      alerts.push({ level: 'warning', signal: 'memory_growth', message: `Memory growing at ${memoryGrowth.toFixed(1)} MB/hour` });
    }

    return alerts;
  }

  _formatDuration(ms) {
    const s = Math.floor(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return `${h}h ${m}m ${sec}s`;
  }

  /**
   * Reset all counters and history.
   */
  reset() {
    for (const key of Object.keys(this.counters)) {
      this.counters[key] = 0;
    }
    this.memoryHistory = [];
    this.healthHistory = [];
    this.lastHealthStatus = null;
    this.startTime = Date.now();
  }
}

module.exports = { RuntimeMonitor };

