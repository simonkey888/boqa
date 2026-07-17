'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const HUNTER_STATES = Object.freeze(['STOPPED', 'STARTING', 'ACTIVE', 'DEGRADED', 'BLOCKED', 'ERROR']);
const VALID_STATES = new Set(HUNTER_STATES);

function toIso(value) {
  return Number.isFinite(value) && value > 0 ? new Date(value).toISOString() : null;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((out, key) => {
      out[key] = canonicalize(value[key]);
      return out;
    }, {});
  }
  return value;
}

function writeJsonAtomic(filePath, value) {
  const directory = path.dirname(filePath);
  fs.mkdirSync(directory, { recursive: true });
  const tempPath = `${filePath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tempPath, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  fs.renameSync(tempPath, filePath);
}

function isProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

function sanitizeCycleResult(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const allowed = [
    'scheduler_status',
    'engine_status',
    'controls_completed',
    'validated_findings',
    'reportable_findings',
    'blocked_by_policy',
    'evidence_integrity_status',
    'last_error',
  ];
  return Object.fromEntries(allowed.filter((key) => raw[key] !== undefined).map((key) => [key, raw[key]]));
}

class HunterRuntime {
  constructor(options = {}) {
    if (typeof options.cycleRunner !== 'function') throw new Error('HUNTER_CYCLE_RUNNER_REQUIRED');
    if (typeof options.policyProvider !== 'function') throw new Error('HUNTER_POLICY_PROVIDER_REQUIRED');

    this.cycleRunner = options.cycleRunner;
    this.policyProvider = options.policyProvider;
    this.now = options.now || Date.now;
    this.setTimeoutFn = options.setTimeoutFn || setTimeout;
    this.clearTimeoutFn = options.clearTimeoutFn || clearTimeout;
    this.setIntervalFn = options.setIntervalFn || setInterval;
    this.clearIntervalFn = options.clearIntervalFn || clearInterval;
    this.statePath = options.statePath || path.join(process.cwd(), 'output', 'hunter-state.json');
    this.lockPath = options.lockPath || path.join(process.cwd(), 'output', 'hunter-runtime.lock');
    this.intervalMs = Math.max(10_000, Number(options.intervalMs || process.env.BOQA_HUNTER_INTERVAL_MS || 300_000));
    this.heartbeatIntervalMs = Math.max(1_000, Number(options.heartbeatIntervalMs || process.env.BOQA_HUNTER_HEARTBEAT_MS || 15_000));
    this.heartbeatFreshnessMs = Math.max(
      this.heartbeatIntervalMs * 3,
      Number(options.heartbeatFreshnessMs || process.env.BOQA_HUNTER_HEARTBEAT_FRESHNESS_MS || 60_000)
    );
    this.cycleFreshnessMs = Math.max(
      this.intervalMs * 2,
      Number(options.cycleFreshnessMs || process.env.BOQA_HUNTER_CYCLE_FRESHNESS_MS || this.intervalMs * 2 + 60_000)
    );
    this.cycleTimeoutMs = Math.max(1_000, Number(options.cycleTimeoutMs || process.env.BOQA_HUNTER_CYCLE_TIMEOUT_MS || 120_000));
    this.lockStaleMs = Math.max(
      this.cycleTimeoutMs * 2,
      Number(options.lockStaleMs || process.env.BOQA_HUNTER_LOCK_STALE_MS || 600_000)
    );
    this.releaseSha = options.releaseSha || process.env.BOQA_RELEASE_SHA || null;
    this.schedulerTimer = null;
    this.heartbeatTimer = null;
    this.cyclePromise = null;
    this.lockFd = null;
    this.lockToken = null;
    this.stopping = false;
    this.state = this._loadState();
  }

  _emptyState() {
    return {
      schema_version: 1,
      state: 'STOPPED',
      reason: 'not_started',
      scheduler_status: 'STOPPED',
      policy_status: 'UNKNOWN',
      storage_status: 'UNKNOWN',
      lock_status: 'RELEASED',
      heartbeat_at: null,
      last_started_at: null,
      last_completed_at: null,
      next_scheduled_at: null,
      last_duration_ms: null,
      last_result: null,
      cycle_count: 0,
      consecutive_failures: 0,
      authorized_assets: 0,
      policy_digest: null,
      release_sha: this.releaseSha,
      recovered_after_restart: false,
      recent_cycles: [],
      invariant_checked_at: null,
      updated_at: toIso(this.now()),
    };
  }

  _loadState() {
    try {
      const parsed = JSON.parse(fs.readFileSync(this.statePath, 'utf8'));
      return {
        ...this._emptyState(),
        ...parsed,
        state: 'STOPPED',
        reason: 'process_restarted',
        scheduler_status: 'STOPPED',
        lock_status: 'RELEASED',
        next_scheduled_at: null,
        recovered_after_restart: true,
      };
    } catch (_) {
      return this._emptyState();
    }
  }

  _persist() {
    this.state.updated_at = toIso(this.now());
    writeJsonAtomic(this.statePath, this.state);
  }

  _setState(state, reason) {
    if (!VALID_STATES.has(state)) throw new Error(`HUNTER_STATE_INVALID:${state}`);
    this.state.state = state;
    this.state.reason = reason || null;
  }

  _verifyStorage() {
    const directory = path.dirname(this.statePath);
    fs.mkdirSync(directory, { recursive: true });
    const probe = path.join(directory, `.hunter-storage-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
    fs.writeFileSync(probe, 'ok', { flag: 'wx', mode: 0o600 });
    fs.unlinkSync(probe);
    this.state.storage_status = 'READY';
    return true;
  }

  _readLock() {
    try {
      return JSON.parse(fs.readFileSync(this.lockPath, 'utf8'));
    } catch (_) {
      return null;
    }
  }

  _ownsLock() {
    const existing = this._readLock();
    return Boolean(
      existing &&
      existing.pid === process.pid &&
      existing.token &&
      this.lockToken &&
      existing.token === this.lockToken
    );
  }

  _acquireLock() {
    fs.mkdirSync(path.dirname(this.lockPath), { recursive: true });
    const create = () => {
      const token = crypto.randomBytes(16).toString('hex');
      const fd = fs.openSync(this.lockPath, 'wx', 0o600);
      fs.writeFileSync(fd, `${JSON.stringify({
        schema_version: 1,
        pid: process.pid,
        token,
        acquired_at: toIso(this.now()),
        release_sha: this.releaseSha,
      })}\n`);
      fs.fsyncSync(fd);
      this.lockFd = fd;
      this.lockToken = token;
      this.state.lock_status = 'ACQUIRED';
    };

    try {
      create();
      return;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }

    const existing = this._readLock();
    const acquiredAt = existing?.acquired_at ? Date.parse(existing.acquired_at) : NaN;
    const stale = !isProcessAlive(existing?.pid) && (!Number.isFinite(acquiredAt) || this.now() - acquiredAt > this.lockStaleMs);
    if (!stale) {
      const error = new Error('HUNTER_LOCK_HELD');
      error.code = 'HUNTER_LOCK_HELD';
      throw error;
    }
    fs.unlinkSync(this.lockPath);
    create();
  }

  _verifyLockOwnership() {
    if (!this._ownsLock()) {
      this.state.lock_status = 'LOST';
      const error = new Error('HUNTER_LOCK_LOST');
      error.code = 'HUNTER_LOCK_LOST';
      throw error;
    }
    this.state.lock_status = 'ACQUIRED';
    return true;
  }

  _releaseLock() {
    if (this.lockFd !== null) {
      try { fs.closeSync(this.lockFd); } catch (_) {}
      this.lockFd = null;
    }
    const existing = this._readLock();
    if (existing?.token && existing.token === this.lockToken) {
      try { fs.unlinkSync(this.lockPath); } catch (_) {}
    }
    this.lockToken = null;
    this.state.lock_status = 'RELEASED';
  }

  _loadPolicy() {
    const policy = this.policyProvider();
    if (!policy || policy.status !== 'READY' || !Array.isArray(policy.authorized_assets) || policy.authorized_assets.length === 0) {
      const error = new Error(policy?.reason || 'NO_AUTHORIZED_ASSETS');
      error.code = 'POLICY_BLOCKED';
      throw error;
    }
    const publicAssets = policy.authorized_assets.map((asset) => ({
      id: String(asset.id),
      type: String(asset.type),
      environment: String(asset.environment_type || 'unknown'),
      checks: Array.isArray(asset.checks) ? [...asset.checks].sort() : [],
    }));
    this.state.policy_status = 'READY';
    this.state.authorized_assets = publicAssets.length;
    this.state.policy_digest = sha256(JSON.stringify(canonicalize(publicAssets)));
    return policy;
  }

  _verifyInvariants() {
    this._verifyStorage();
    this._verifyLockOwnership();
    const policy = this._loadPolicy();
    this.state.invariant_checked_at = toIso(this.now());
    return policy;
  }

  _recordInvariantFailure(error) {
    if (error.code === 'POLICY_BLOCKED') {
      this.state.policy_status = 'BLOCKED';
      this._setState('BLOCKED', error.message);
    } else if (error.code === 'HUNTER_LOCK_LOST' || error.code === 'HUNTER_LOCK_HELD') {
      this._setState('BLOCKED', error.code);
    } else {
      this.state.storage_status = 'ERROR';
      this._setState('ERROR', error.code || error.message);
    }
  }

  _heartbeat() {
    if (this.stopping || this.state.scheduler_status !== 'RUNNING') return;
    try {
      this._verifyInvariants();
      this.state.heartbeat_at = toIso(this.now());
      this._evaluateState();
    } catch (error) {
      this._recordInvariantFailure(error);
      this.state.scheduler_status = 'STOPPED';
    }
    this._persist();
  }

  _freshness() {
    const now = this.now();
    const heartbeatMs = this.state.heartbeat_at ? Date.parse(this.state.heartbeat_at) : NaN;
    const completedMs = this.state.last_completed_at ? Date.parse(this.state.last_completed_at) : NaN;
    const invariantMs = this.state.invariant_checked_at ? Date.parse(this.state.invariant_checked_at) : NaN;
    return {
      heartbeat_fresh: Number.isFinite(heartbeatMs) && now - heartbeatMs <= this.heartbeatFreshnessMs,
      cycle_fresh: Number.isFinite(completedMs) && now - completedMs <= this.cycleFreshnessMs,
      invariants_fresh: Number.isFinite(invariantMs) && now - invariantMs <= this.heartbeatFreshnessMs,
      heartbeat_age_ms: Number.isFinite(heartbeatMs) ? Math.max(0, now - heartbeatMs) : null,
      cycle_age_ms: Number.isFinite(completedMs) ? Math.max(0, now - completedMs) : null,
      invariant_age_ms: Number.isFinite(invariantMs) ? Math.max(0, now - invariantMs) : null,
      heartbeat_freshness_ms: this.heartbeatFreshnessMs,
      cycle_freshness_ms: this.cycleFreshnessMs,
    };
  }

  _evaluateState() {
    if (this.state.state === 'BLOCKED' || this.state.state === 'ERROR' || this.state.state === 'STOPPED') return;
    const freshness = this._freshness();
    if (this.state.lock_status !== 'ACQUIRED' || !this._ownsLock()) {
      this._setState('DEGRADED', 'runtime_lock_not_verified');
    } else if (this.state.scheduler_status !== 'RUNNING') {
      this._setState('DEGRADED', 'scheduler_not_running');
    } else if (!freshness.heartbeat_fresh || !freshness.invariants_fresh) {
      this._setState('DEGRADED', 'heartbeat_or_invariants_stale');
    } else if (!this.state.last_completed_at) {
      this._setState('STARTING', 'awaiting_first_completed_cycle');
    } else if (!freshness.cycle_fresh) {
      this._setState('DEGRADED', 'last_cycle_stale');
    } else if (this.state.last_result?.status !== 'COMPLETED') {
      this._setState('DEGRADED', 'last_cycle_not_completed');
    } else if (this.state.policy_status !== 'READY' || this.state.storage_status !== 'READY') {
      this._setState('DEGRADED', 'dependency_not_ready');
    } else {
      this._setState('ACTIVE', 'recent_cycle_verified');
    }
  }

  _schedule(delayMs = this.intervalMs) {
    if (this.stopping || this.state.state === 'BLOCKED' || this.state.state === 'ERROR') return;
    if (this.schedulerTimer) this.clearTimeoutFn(this.schedulerTimer);
    this.state.next_scheduled_at = toIso(this.now() + delayMs);
    this.schedulerTimer = this.setTimeoutFn(() => {
      this.schedulerTimer = null;
      this.runCycle('scheduled').catch(() => {});
    }, delayMs);
    this.schedulerTimer.unref?.();
    this._persist();
  }

  async start() {
    if (this.state.scheduler_status === 'RUNNING') return this.internalStatus();
    this.stopping = false;
    this._setState('STARTING', 'initializing_runtime');
    this.state.scheduler_status = 'STARTING';
    try {
      this._verifyStorage();
      this._acquireLock();
      this._verifyInvariants();
      this.state.scheduler_status = 'RUNNING';
      this.state.heartbeat_at = toIso(this.now());
      this.heartbeatTimer = this.setIntervalFn(() => this._heartbeat(), this.heartbeatIntervalMs);
      this.heartbeatTimer.unref?.();
      await this.runCycle('startup');
    } catch (error) {
      this.state.scheduler_status = 'STOPPED';
      this._recordInvariantFailure(error);
      this._releaseLock();
      try { this._persist(); } catch (_) {}
    }
    return this.internalStatus();
  }

  preflightManual() {
    if (this.cyclePromise) return { allowed: false, reason: 'CYCLE_ALREADY_RUNNING' };
    if (this.state.scheduler_status !== 'RUNNING') return { allowed: false, reason: 'RUNTIME_NOT_RUNNING' };
    try {
      this._verifyInvariants();
      this._evaluateState();
      if (this.state.state === 'BLOCKED' || this.state.state === 'ERROR') {
        return { allowed: false, reason: this.state.reason || this.state.state };
      }
      return { allowed: true, reason: 'AUTHORIZED' };
    } catch (error) {
      this._recordInvariantFailure(error);
      this._persist();
      return { allowed: false, reason: error.code || error.message };
    }
  }

  async runCycle(trigger = 'manual') {
    if (this.cyclePromise) return { accepted: false, status: 'BLOCKED', reason: 'CYCLE_ALREADY_RUNNING' };
    const preflight = this.preflightManual();
    if (!preflight.allowed) return { accepted: false, status: 'BLOCKED', reason: preflight.reason };

    this.cyclePromise = (async () => {
      const startedMs = this.now();
      const cycleId = `cyc-${startedMs}-${crypto.randomBytes(5).toString('hex')}`;
      this.state.last_started_at = toIso(startedMs);
      this.state.next_scheduled_at = null;
      this._setState('STARTING', 'cycle_running');
      this.state.heartbeat_at = toIso(this.now());
      this._persist();

      let result;
      let timeoutHandle;
      try {
        const policy = this._verifyInvariants();
        const timeout = new Promise((_, reject) => {
          timeoutHandle = this.setTimeoutFn(() => {
            const error = new Error('HUNTER_CYCLE_TIMEOUT');
            error.code = 'HUNTER_CYCLE_TIMEOUT';
            reject(error);
          }, this.cycleTimeoutMs);
          timeoutHandle.unref?.();
        });
        const raw = await Promise.race([
          Promise.resolve(this.cycleRunner({ cycle_id: cycleId, trigger, policy })),
          timeout,
        ]);
        const completed = raw?.scheduler_status !== 'ERROR' && raw?.engine_status !== 'BLOCKED_BY_POLICY';
        result = {
          status: completed ? 'COMPLETED' : 'ERROR',
          trigger,
          cycle_id: cycleId,
          details: sanitizeCycleResult(raw),
        };
        if (!completed) {
          const error = new Error('HUNTER_CYCLE_REPORTED_FAILURE');
          error.code = 'HUNTER_CYCLE_REPORTED_FAILURE';
          error.result = result;
          throw error;
        }
        this.state.consecutive_failures = 0;
      } catch (error) {
        result = error.result || {
          status: error.code === 'POLICY_BLOCKED' ? 'BLOCKED' : 'ERROR',
          trigger,
          cycle_id: cycleId,
          error: error.code || error.message,
        };
        this.state.consecutive_failures += 1;
        this._recordInvariantFailure(error);
      } finally {
        if (timeoutHandle) this.clearTimeoutFn(timeoutHandle);
      }

      const completedMs = this.now();
      this.state.last_completed_at = toIso(completedMs);
      this.state.last_duration_ms = Math.max(0, completedMs - startedMs);
      this.state.last_result = result;
      this.state.cycle_count += 1;
      this.state.recent_cycles = [{
        cycle_id: cycleId,
        trigger,
        started_at: toIso(startedMs),
        completed_at: toIso(completedMs),
        duration_ms: this.state.last_duration_ms,
        status: result.status,
      }, ...this.state.recent_cycles].slice(0, 20);

      if (result.status === 'COMPLETED') {
        this.state.heartbeat_at = toIso(this.now());
        this._evaluateState();
      }
      this._persist();
      if (!this.stopping && result.status === 'COMPLETED') this._schedule(this.intervalMs);
      return { accepted: true, result, hunter: this.publicStatus() };
    })();

    try {
      return await this.cyclePromise;
    } finally {
      this.cyclePromise = null;
    }
  }

  async stop(reason = 'shutdown') {
    this.stopping = true;
    if (this.schedulerTimer) this.clearTimeoutFn(this.schedulerTimer);
    if (this.heartbeatTimer) this.clearIntervalFn(this.heartbeatTimer);
    this.schedulerTimer = null;
    this.heartbeatTimer = null;
    if (this.cyclePromise) {
      try { await this.cyclePromise; } catch (_) {}
    }
    this.state.scheduler_status = 'STOPPED';
    this.state.next_scheduled_at = null;
    this._releaseLock();
    this._setState('STOPPED', reason);
    this._persist();
    return this.internalStatus();
  }

  publicStatus() {
    this._evaluateState();
    return {
      state: this.state.state,
      reason: this.state.reason,
      freshness: this._freshness(),
      heartbeat_at: this.state.heartbeat_at,
      last_started_at: this.state.last_started_at,
      last_completed_at: this.state.last_completed_at,
      next_scheduled_at: this.state.next_scheduled_at,
      last_duration_ms: this.state.last_duration_ms,
      release_sha: this.state.release_sha,
      timestamp: toIso(this.now()),
    };
  }

  internalStatus() {
    this._evaluateState();
    return {
      ...this.state,
      freshness: this._freshness(),
      timestamp: toIso(this.now()),
    };
  }
}

module.exports = {
  HunterRuntime,
  HUNTER_STATES,
  canonicalize,
  writeJsonAtomic,
};
