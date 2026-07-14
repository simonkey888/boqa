'use strict';

/**
 * scheduler-multi-target.js
 *
 * Fase 14 — Conservative multi-target scheduler.
 *
 * v1 rules:
 *   - Max 1 target active simultaneously
 *   - Session max: 15 minutes
 *   - Cooldown per target: 30 minutes
 *
 * Sequence per target:
 *   scope validation → fresh browser context → passive navigation →
 *   asset observation → safe hypothesis generation → non-destructive
 *   verification → false-positive reduction → canonicalization →
 *   reportability gate → bounty estimation → persist results →
 *   destroy browser context → next target
 *
 * Abort conditions:
 *   - Scope changes
 *   - Program paused
 *   - More than 3 HTTP 429 responses
 *   - More than 5 HTTP 403 responses
 *   - Significant latency increase
 *   - robots/program rules require it
 *   - authorization_status != authorized
 */

const { TargetRegistry } = require('./target-registry');

class MultiTargetScheduler {
  constructor(opts = {}) {
    this.registry = opts.registry || new TargetRegistry();
    this.maxConcurrentTargets = 1;
    this.sessionMaxMs = 15 * 60 * 1000;       // 15 minutes
    this.cooldownMs = 30 * 60 * 1000;          // 30 minutes
    this.max429 = 3;
    this.max403 = 5;
    this.latencySpikeThresholdMs = 5000;

    this.active = null;
    this.lastRunAt = new Map();  // targetId → timestamp
    this.stats = {
      targets_scanned: 0,
      sessions_completed: 0,
      sessions_aborted: 0,
      bugs_canonicalized: 0,
    };
  }

  /**
   * Pick the next target eligible for scanning.
   * Returns target or null if none eligible.
   */
  pickNext() {
    const now = Date.now();
    // FASE C — only fully-verified targets are eligible
    const eligible = this.registry.executable().filter(t => {
      const last = this.lastRunAt.get(t.id) || 0;
      return (now - last) >= this.cooldownMs;
    });
    if (eligible.length === 0) return null;
    // Pick the one with the oldest last-run timestamp
    eligible.sort((a, b) => (this.lastRunAt.get(a.id) || 0) - (this.lastRunAt.get(b.id) || 0));
    return eligible[0];
  }

  /**
   * Run a single scan session for the given target.
   * The actual scanning is delegated to `agent.run(target, opts)`.
   *
   * @param {object} target - registered target
   * @param {object} agent - BOQA agent instance with .run() method
   * @returns {object} session result
   */
  async runSession(target, agent) {
    if (!target) throw new Error('runSession: target required');
    if (!agent || typeof agent.run !== 'function') throw new Error('runSession: agent.run required');
    if (this.active !== null) {
      throw new Error(`runSession: another target is already active (${this.active})`);
    }
    // FASE C — Use the stricter isExecutable() check from TargetRegistry.
    // This rejects targets that are pending_verification, disabled, missing
    // authorization_source_url, missing scope_allowlist, or missing valid
    // authorization_checked_at.
    if (!this.registry.isExecutable(target)) {
      return {
        target_id: target.id,
        aborted: true,
        reason: `target_not_executable (status=${target.authorization_status}, enabled=${target.enabled}, has_auth_url=${!!target.authorization_source_url}, scope_count=${target.scope_allowlist?.length || 0}, has_checked_at=${!!target.authorization_checked_at})`,
      };
    }

    this.active = target.id;
    const sessionStart = Date.now();
    const counters = { http_429: 0, http_403: 0, requests: 0 };
    const abortReasons = [];

    try {
      // Pre-flight scope validation (also enforces isExecutable internally)
      const scopeCheck = this.registry.verifyScope(target.id, target.url);
      if (!scopeCheck.in_scope) {
        return { target_id: target.id, aborted: true, reason: `scope_validation_failed: ${scopeCheck.reason}` };
      }

      // Fresh agent run with conservative limits
      const result = await Promise.race([
        agent.run(target, {
          max_requests_per_minute: target.max_requests_per_minute,
          max_concurrency: target.max_concurrency,
          max_depth: target.max_depth,
          allow_authenticated_testing: target.allow_authenticated_testing,
          allowed_methods: target.allowed_methods,
          on_request: (req) => this._onRequest(counters, req, abortReasons),
          on_response: (res) => this._onResponse(counters, res, abortReasons),
          should_abort: () => abortReasons.length > 0 || (Date.now() - sessionStart) > this.sessionMaxMs,
        }),
        new Promise((_, reject) => setTimeout(() => reject(new Error('session_timeout')), this.sessionMaxMs)),
      ]);

      this.stats.sessions_completed++;
      this.stats.targets_scanned++;
      this.lastRunAt.set(target.id, Date.now());
      return {
        target_id: target.id,
        aborted: false,
        duration_ms: Date.now() - sessionStart,
        result,
        counters,
      };
    } catch (err) {
      this.stats.sessions_aborted++;
      this.lastRunAt.set(target.id, Date.now());
      return {
        target_id: target.id,
        aborted: true,
        reason: err.message,
        duration_ms: Date.now() - sessionStart,
        counters,
      };
    } finally {
      this.active = null;
    }
  }

  _onRequest(counters, req, abortReasons) {
    counters.requests++;
  }

  _onResponse(counters, res, abortReasons) {
    if (res?.status === 429) {
      counters.http_429++;
      if (counters.http_429 > this.max429) {
        abortReasons.push(`exceeded_max_429 (${counters.http_429})`);
      }
    }
    if (res?.status === 403) {
      counters.http_403++;
      if (counters.http_403 > this.max403) {
        abortReasons.push(`exceeded_max_403 (${counters.http_403})`);
      }
    }
  }

  /**
   * Whether the scheduler can accept another session right now.
   */
  isIdle() {
    return this.active === null;
  }

  getStats() {
    return { ...this.stats, active: this.active };
  }
}

module.exports = { MultiTargetScheduler };
