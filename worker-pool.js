/**
 * BOQA worker-pool.js — Distributed Playwright/CDP Worker Pool
 *
 * v0.5: Worker Pool Manager
 *   - Manages distributed Playwright/CDP execution for the BOQA system
 *   - Worker lifecycle: spawn → assign → release/fail → terminate
 *   - Auto-scaling based on scheduler queue depth
 *   - Heartbeat monitoring with 3-miss tolerance
 *   - Persistence to output/workers/pool.json
 *   - Safe mode: target validation via targetManager
 *   - Events: worker:spawned, worker:terminated, worker:assigned,
 *             worker:released, worker:error, worker:heartbeat_missed,
 *             pool:scaled, pool:shutdown
 *
 * Workers are conceptual units — each manages a Playwright browser context.
 * The WorkerPool tracks lifecycle; the caller (server.js) bridges to the Agent.
 */

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Constants ──────────────────────────────────────────────────────

const WORKER_ID_PREFIX = 'WRK-';
const POOL_DIR = path.join(__dirname, 'output', 'workers');
const POOL_FILE = path.join(POOL_DIR, 'pool.json');

const VALID_STATUSES = new Set(['idle', 'busy', 'error', 'terminated']);
const VALID_MODES = new Set(['live', 'baseline', 'compare', 'verification']);

const DEFAULTS = {
  maxWorkers: 10,
  workerIdleTimeout: 300000,  // 5 minutes
  heartbeatInterval: 15000,   // 15 seconds
  heartbeatMissThreshold: 3,
};

// ─── Worker ID Generator ────────────────────────────────────────────

let _workerCounter = 0;

function generateWorkerId() {
  _workerCounter++;
  const seq = String(_workerCounter).padStart(4, '0');
  const rand = crypto.randomBytes(2).toString('hex').toUpperCase();
  return `${WORKER_ID_PREFIX}${seq}-${rand}`;
}

// ─── WorkerPool Class ───────────────────────────────────────────────

class WorkerPool extends EventEmitter {
  /**
   * @param {object} options
   * @param {number} options.maxWorkers          - Maximum concurrent workers (default: 10)
   * @param {number} options.workerIdleTimeout   - Idle timeout in ms before termination (default: 300000)
   * @param {number} options.heartbeatInterval   - Heartbeat check interval in ms (default: 15000)
   * @param {object} options.targetManager       - Target manager for authorization checks
   */
  constructor(options = {}) {
    super();

    this.maxWorkers = options.maxWorkers || DEFAULTS.maxWorkers;
    this.workerIdleTimeout = options.workerIdleTimeout || DEFAULTS.workerIdleTimeout;
    this.heartbeatInterval = options.heartbeatInterval || DEFAULTS.heartbeatInterval;
    this.heartbeatMissThreshold = options.heartbeatMissThreshold || DEFAULTS.heartbeatMissThreshold;
    this.targetManager = options.targetManager || null;

    this.workers = new Map();          // workerId → worker object
    this.heartbeatTimer = null;
    this.idleTimeoutTimers = new Map(); // workerId → timeout handle
    this.shuttingDown = false;

    // Ensure persistence directory exists
    fs.mkdirSync(POOL_DIR, { recursive: true });

    // Attempt to load previous state
    this._loadState();
  }

  // ─── Worker Lifecycle ───────────────────────────────────────────

  /**
   * Spawn a new worker.
   * Generates a WRK-XXXX ID. The worker is a conceptual unit that
   * will manage a Playwright browser context (bridged by the caller).
   *
   * @returns {object} The spawned worker object
   * @throws {Error} If pool is at maxWorkers capacity
   */
  spawn() {
    if (this.shuttingDown) {
      throw new Error('Cannot spawn workers during shutdown');
    }

    const activeCount = this._activeWorkerCount();
    if (activeCount >= this.maxWorkers) {
      throw new Error(`Worker pool at capacity (${this.maxWorkers}/${this.maxWorkers})`);
    }

    const now = Date.now();
    const worker = {
      id: generateWorkerId(),
      status: 'idle',
      currentJob: null,
      lastHeartbeat: now,
      startedAt: now,
      sessionsCompleted: 0,
      sessionsFailed: 0,
      metadata: {},
      sessionDurations: [],
    };

    this.workers.set(worker.id, worker);

    // Start idle timeout for this worker
    this._startIdleTimeout(worker.id);

    this.emit('worker:spawned', { workerId: worker.id, timestamp: now });
    this._persistState();

    return worker;
  }

  /**
   * Terminate a worker.
   * If the worker is busy, the current job is marked as failed first.
   * All resources are cleaned up.
   *
   * @param {string} workerId - ID of the worker to terminate
   * @returns {object} The terminated worker object
   * @throws {Error} If worker not found or already terminated
   */
  terminate(workerId) {
    const worker = this.workers.get(workerId);
    if (!worker) {
      throw new Error(`Worker not found: ${workerId}`);
    }
    if (worker.status === 'terminated') {
      throw new Error(`Worker already terminated: ${workerId}`);
    }

    // If busy, fail the current job first
    if (worker.status === 'busy' && worker.currentJob) {
      this.failWorker(workerId, new Error('Worker terminated while job in progress'));
    }

    // Clean up idle timeout
    this._clearIdleTimeout(workerId);

    const now = Date.now();
    worker.status = 'terminated';
    worker.currentJob = null;
    worker.lastHeartbeat = now;

    this.emit('worker:terminated', {
      workerId: worker.id,
      timestamp: now,
      sessionsCompleted: worker.sessionsCompleted,
      sessionsFailed: worker.sessionsFailed,
      uptime: now - worker.startedAt,
    });
    this._persistState();

    return worker;
  }

  // ─── Job Assignment ─────────────────────────────────────────────

  /**
   * Assign a job to an idle worker.
   * Validates the worker is idle and the target is authorized.
   *
   * @param {string} workerId - ID of the worker to assign
   * @param {object} job      - Job object with: id, type, target_id, mode
   * @returns {object} The updated worker object
   * @throws {Error} If worker not found, not idle, or target unauthorized
   */
  assignJob(workerId, job) {
    const worker = this.workers.get(workerId);
    if (!worker) {
      throw new Error(`Worker not found: ${workerId}`);
    }
    if (worker.status !== 'idle') {
      throw new Error(`Worker ${workerId} is not idle (status: ${worker.status})`);
    }

    // Validate job structure
    if (!job || !job.id || !job.type || !job.target_id || !job.mode) {
      throw new Error('Job must have: id, type, target_id, mode');
    }

    // Validate mode
    if (!VALID_MODES.has(job.mode)) {
      throw new Error(`Invalid job mode: ${job.mode}. Valid modes: ${[...VALID_MODES].join(', ')}`);
    }

    // Safe mode: validate target authorization
    if (this.targetManager && typeof this.targetManager.isAuthorized === 'function') {
      if (!this.targetManager.isAuthorized(job.target_id)) {
        throw new Error(`Target not authorized: ${job.target_id}. Worker refuses unauthorized targets.`);
      }
    }

    // Clear idle timeout — worker is now busy
    this._clearIdleTimeout(workerId);

    const now = Date.now();
    worker.status = 'busy';
    worker.currentJob = {
      id: job.id,
      type: job.type,
      target_id: job.target_id,
      mode: job.mode,
      assignedAt: now,
    };
    worker.lastHeartbeat = now;
    worker.metadata.currentJobType = job.type;
    worker.metadata.currentJobMode = job.mode;

    this.emit('worker:assigned', {
      workerId: worker.id,
      jobId: job.id,
      jobType: job.type,
      targetId: job.target_id,
      mode: job.mode,
      timestamp: now,
    });
    this._persistState();

    return worker;
  }

  /**
   * Release a worker after successful job completion.
   * Updates worker stats and sets status back to idle.
   *
   * @param {string} workerId - ID of the worker to release
   * @param {object} result   - Result object from the completed job
   * @returns {object} The updated worker object
   * @throws {Error} If worker not found or not busy
   */
  releaseWorker(workerId, result = {}) {
    const worker = this.workers.get(workerId);
    if (!worker) {
      throw new Error(`Worker not found: ${workerId}`);
    }
    if (worker.status !== 'busy') {
      throw new Error(`Worker ${workerId} is not busy (status: ${worker.status})`);
    }

    const now = Date.now();
    const jobDuration = worker.currentJob ? (now - worker.currentJob.assignedAt) : 0;

    worker.sessionsCompleted++;
    worker.sessionDurations.push(jobDuration);
    worker.status = 'idle';
    worker.currentJob = null;
    worker.lastHeartbeat = now;

    // Clean up job metadata
    delete worker.metadata.currentJobType;
    delete worker.metadata.currentJobMode;

    // Store result metadata if provided
    if (result && typeof result === 'object') {
      worker.metadata.lastResult = {
        duration: jobDuration,
        completedAt: now,
        findings: result.findings || 0,
        events: result.events || 0,
      };
    }

    // Restart idle timeout
    this._startIdleTimeout(workerId);

    this.emit('worker:released', {
      workerId: worker.id,
      duration: jobDuration,
      sessionsCompleted: worker.sessionsCompleted,
      timestamp: now,
    });
    this._persistState();

    return worker;
  }

  /**
   * Mark a worker as error after job failure.
   * Increments sessions_failed counter.
   *
   * @param {string} workerId - ID of the failed worker
   * @param {Error}  error    - The error that caused the failure
   * @returns {object} The updated worker object
   * @throws {Error} If worker not found
   */
  failWorker(workerId, error) {
    const worker = this.workers.get(workerId);
    if (!worker) {
      throw new Error(`Worker not found: ${workerId}`);
    }

    const now = Date.now();
    const jobDuration = worker.currentJob ? (now - worker.currentJob.assignedAt) : 0;

    worker.sessionsFailed++;
    worker.status = 'error';
    worker.lastHeartbeat = now;

    // Record the error
    worker.metadata.lastError = {
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : null,
      failedAt: now,
      jobDuration,
    };

    // If there was a current job, track the failed session duration
    if (jobDuration > 0) {
      worker.sessionDurations.push(jobDuration);
    }

    // Clear current job reference
    const failedJob = worker.currentJob;
    worker.currentJob = null;
    delete worker.metadata.currentJobType;
    delete worker.metadata.currentJobMode;

    // Clear idle timeout since worker is in error state
    this._clearIdleTimeout(workerId);

    this.emit('worker:error', {
      workerId: worker.id,
      error: worker.metadata.lastError,
      failedJob: failedJob ? failedJob.id : null,
      sessionsFailed: worker.sessionsFailed,
      timestamp: now,
    });
    this._persistState();

    return worker;
  }

  // ─── Worker Queries ─────────────────────────────────────────────

  /**
   * Get a worker by ID.
   *
   * @param {string} workerId
   * @returns {object|null} Worker object or null if not found
   */
  getWorker(workerId) {
    return this.workers.get(workerId) || null;
  }

  /**
   * List workers, optionally filtered by status.
   *
   * @param {string} [filter] - Optional status filter (idle|busy|error|terminated)
   * @returns {array} Array of worker objects
   */
  listWorkers(filter) {
    const all = [...this.workers.values()];
    if (!filter) return all;
    if (!VALID_STATUSES.has(filter)) {
      throw new Error(`Invalid filter status: ${filter}. Valid: ${[...VALID_STATUSES].join(', ')}`);
    }
    return all.filter(w => w.status === filter);
  }

  /**
   * Return all idle workers.
   *
   * @returns {array}
   */
  getIdleWorkers() {
    return this.listWorkers('idle');
  }

  /**
   * Return all busy workers.
   *
   * @returns {array}
   */
  getBusyWorkers() {
    return this.listWorkers('busy');
  }

  /**
   * Return pool statistics.
   *
   * @returns {object} Pool stats including utilization, totals, averages
   */
  getPoolStats() {
    const all = [...this.workers.values()];
    const total = all.length;

    const idle = all.filter(w => w.status === 'idle').length;
    const busy = all.filter(w => w.status === 'busy').length;
    const error = all.filter(w => w.status === 'error').length;
    const terminated = all.filter(w => w.status === 'terminated').length;

    const totalSessionsCompleted = all.reduce((sum, w) => sum + w.sessionsCompleted, 0);
    const totalSessionsFailed = all.reduce((sum, w) => sum + w.sessionsFailed, 0);

    // Average session duration across all workers
    const allDurations = all.flatMap(w => w.sessionDurations);
    const avgSessionDuration = allDurations.length > 0
      ? allDurations.reduce((sum, d) => sum + d, 0) / allDurations.length
      : 0;

    // Utilization rate: busy / (total non-terminated) * 100
    const activeWorkers = total - terminated;
    const utilizationRate = activeWorkers > 0
      ? (busy / activeWorkers) * 100
      : 0;

    return {
      total,
      idle,
      busy,
      error,
      terminated,
      totalSessionsCompleted,
      totalSessionsFailed,
      avgSessionDuration,
      utilizationRate: Math.round(utilizationRate * 100) / 100,
      maxWorkers: this.maxWorkers,
    };
  }

  // ─── Scaling ────────────────────────────────────────────────────

  /**
   * Scale pool to exactly `count` active (non-terminated) workers.
   * Spawns new workers or terminates excess idle workers as needed.
   *
   * @param {number} count - Target number of active workers
   * @returns {object} Scaling result: { spawned, terminated, target }
   */
  scaleTo(count) {
    if (count < 0) count = 0;
    if (count > this.maxWorkers) count = this.maxWorkers;

    const activeWorkers = this._activeWorkerCount();
    const result = { spawned: [], terminated: [], target: count };

    if (activeWorkers < count) {
      // Need to spawn more workers
      const toSpawn = count - activeWorkers;
      for (let i = 0; i < toSpawn; i++) {
        try {
          const worker = this.spawn();
          result.spawned.push(worker.id);
        } catch (err) {
          // Hit max capacity, stop spawning
          break;
        }
      }
    } else if (activeWorkers > count) {
      // Need to terminate excess idle workers
      const toTerminate = activeWorkers - count;
      const idleWorkers = this.getIdleWorkers();

      // Terminate idle workers first (oldest first)
      const sorted = idleWorkers.sort((a, b) => a.startedAt - b.startedAt);
      for (let i = 0; i < toTerminate && i < sorted.length; i++) {
        try {
          this.terminate(sorted[i].id);
          result.terminated.push(sorted[i].id);
        } catch (err) {
          // Cannot terminate, skip
          break;
        }
      }
    }

    this.emit('pool:scaled', {
      target: count,
      spawned: result.spawned.length,
      terminated: result.terminated.length,
      activeWorkers: this._activeWorkerCount(),
      timestamp: Date.now(),
    });
    this._persistState();

    return result;
  }

  /**
   * Auto-scale based on scheduler queue depth.
   *   - If pending > idle * 2: scale up by min(5, pending - idle)
   *   - If idle > pending * 2: scale down by min(3, idle - pending)
   *
   * @param {object} scheduler - Scheduler with a `pendingCount` property or method
   * @returns {object|null} Scaling result or null if no scaling needed
   */
  autoScale(scheduler) {
    if (!scheduler) return null;
    if (this.shuttingDown) return null;

    // Get pending job count from scheduler
    let pendingJobs = 0;
    if (typeof scheduler.pendingCount === 'function') {
      pendingJobs = scheduler.pendingCount();
    } else if (typeof scheduler.pendingCount === 'number') {
      pendingJobs = scheduler.pendingCount;
    } else if (Array.isArray(scheduler.queue)) {
      pendingJobs = scheduler.queue.length;
    }

    const idleWorkers = this.getIdleWorkers().length;
    const busyWorkers = this.getBusyWorkers().length;

    // Scale up: pending jobs exceed idle capacity
    if (pendingJobs > idleWorkers * 2) {
      const scaleUpBy = Math.min(5, pendingJobs - idleWorkers);
      if (scaleUpBy > 0) {
        const activeCount = this._activeWorkerCount();
        const targetCount = Math.min(activeCount + scaleUpBy, this.maxWorkers);
        if (targetCount > activeCount) {
          return this.scaleTo(targetCount);
        }
      }
    }

    // Scale down: too many idle workers for the pending load
    if (idleWorkers > pendingJobs * 2 && pendingJobs >= 0) {
      const scaleDownBy = Math.min(3, idleWorkers - pendingJobs);
      if (scaleDownBy > 0) {
        const activeCount = this._activeWorkerCount();
        const targetCount = Math.max(activeCount - scaleDownBy, busyWorkers);
        if (targetCount < activeCount) {
          return this.scaleTo(targetCount);
        }
      }
    }

    return null;
  }

  // ─── Heartbeat Monitoring ───────────────────────────────────────

  /**
   * Start heartbeat monitoring.
   * Workers that miss 3 consecutive heartbeats are marked as error.
   */
  startHeartbeat() {
    if (this.heartbeatTimer) return; // Already running

    this.heartbeatTimer = setInterval(() => {
      this._checkHeartbeats();
    }, this.heartbeatInterval);
  }

  /**
   * Stop heartbeat monitoring.
   */
  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  /**
   * Update a worker's heartbeat timestamp.
   * Called externally by the Playwright agent bridge to signal liveness.
   *
   * @param {string} workerId
   * @throws {Error} If worker not found
   */
  pulse(workerId) {
    const worker = this.workers.get(workerId);
    if (!worker) {
      throw new Error(`Worker not found: ${workerId}`);
    }
    worker.lastHeartbeat = Date.now();
    // Reset missed heartbeat counter
    if (worker.metadata._missedHeartbeats) {
      worker.metadata._missedHeartbeats = 0;
    }
  }

  /**
   * Internal: check all workers for missed heartbeats.
   */
  _checkHeartbeats() {
    const now = Date.now();
    const threshold = this.heartbeatInterval * this.heartbeatMissThreshold;

    for (const [workerId, worker] of this.workers) {
      // Skip terminated or already-errored workers
      if (worker.status === 'terminated' || worker.status === 'error') continue;

      const elapsed = now - worker.lastHeartbeat;

      if (elapsed > threshold) {
        // Track missed heartbeats
        worker.metadata._missedHeartbeats = (worker.metadata._missedHeartbeats || 0) + 1;

        if (worker.metadata._missedHeartbeats >= this.heartbeatMissThreshold) {
          this.emit('worker:heartbeat_missed', {
            workerId,
            missedCount: worker.metadata._missedHeartbeats,
            lastHeartbeat: worker.lastHeartbeat,
            elapsed,
            timestamp: now,
          });

          // Mark worker as error
          this.failWorker(workerId, new Error(
            `Worker missed ${worker.metadata._missedHeartbeats} heartbeats (last: ${elapsed}ms ago)`
          ));
        }
      }
    }
  }

  // ─── Graceful Shutdown ──────────────────────────────────────────

  /**
   * Gracefully shut down the pool.
   * Stops heartbeat monitoring, clears idle timeouts, terminates all workers.
   * Busy workers have their jobs marked as failed before termination.
   *
   * @returns {object} Shutdown summary
   */
  shutdown() {
    this.shuttingDown = true;

    // Stop heartbeat monitoring
    this.stopHeartbeat();

    // Clear all idle timeout timers
    for (const [workerId] of this.idleTimeoutTimers) {
      this._clearIdleTimeout(workerId);
    }

    const now = Date.now();
    const summary = {
      workersTerminated: 0,
      jobsFailed: 0,
      sessionsCompleted: 0,
      sessionsFailed: 0,
      timestamp: now,
    };

    // Terminate all workers (busy ones get their jobs failed first)
    for (const [workerId, worker] of this.workers) {
      if (worker.status === 'terminated') continue;

      if (worker.status === 'busy') {
        summary.jobsFailed++;
      }

      try {
        this.terminate(workerId);
        summary.workersTerminated++;
        summary.sessionsCompleted += worker.sessionsCompleted;
        summary.sessionsFailed += worker.sessionsFailed;
      } catch (err) {
        // Worker may already be terminated, skip
      }
    }

    this.emit('pool:shutdown', summary);
    this._persistState();

    this.shuttingDown = false;
    return summary;
  }

  // ─── Persistence ────────────────────────────────────────────────

  /**
   * Persist pool state to output/workers/pool.json.
   */
  save() {
    this._persistState();
  }

  /**
   * Load pool state from disk.
   */
  load() {
    this._loadState();
  }

  /**
   * Internal: write pool state to disk.
   */
  _persistState() {
    try {
      const state = {
        version: '0.5.0',
        savedAt: Date.now(),
        maxWorkers: this.maxWorkers,
        workerIdleTimeout: this.workerIdleTimeout,
        heartbeatInterval: this.heartbeatInterval,
        workerCounter: _workerCounter,
        workers: [...this.workers.values()].map(w => ({
          id: w.id,
          status: w.status,
          currentJob: w.currentJob,
          lastHeartbeat: w.lastHeartbeat,
          startedAt: w.startedAt,
          sessionsCompleted: w.sessionsCompleted,
          sessionsFailed: w.sessionsFailed,
          metadata: { ...w.metadata },
          sessionDurations: w.sessionDurations,
        })),
        stats: this.getPoolStats(),
      };

      // Atomic write: write to temp file then rename
      const tmpPath = POOL_FILE + '.tmp';
      fs.writeFileSync(tmpPath, JSON.stringify(state, null, 2));
      fs.renameSync(tmpPath, POOL_FILE);
    } catch (err) {
      // Persistence failure should not crash the pool
      this.emit('worker:error', {
        workerId: 'pool',
        error: { message: `Failed to persist pool state: ${err.message}`, failedAt: Date.now() },
        timestamp: Date.now(),
      });
    }
  }

  /**
   * Internal: load pool state from disk.
   */
  _loadState() {
    try {
      if (!fs.existsSync(POOL_FILE)) return;

      const raw = fs.readFileSync(POOL_FILE, 'utf8');
      const state = JSON.parse(raw);

      if (!state || !Array.isArray(state.workers)) return;

      // Restore worker counter to avoid ID collisions
      if (typeof state.workerCounter === 'number') {
        _workerCounter = state.workerCounter;
      }

      // Restore workers (only non-terminated ones with refreshed status)
      // Cap loaded active workers to maxWorkers capacity
      const now = Date.now();
      let activeLoaded = 0;
      for (const w of state.workers) {
        if (!w.id || !VALID_STATUSES.has(w.status)) continue;

        // Always load terminated workers (they don't count against capacity)
        if (w.status === 'terminated') {
          const worker = {
            id: w.id,
            status: 'terminated',
            currentJob: null,
            lastHeartbeat: now,
            startedAt: w.startedAt || now,
            sessionsCompleted: w.sessionsCompleted || 0,
            sessionsFailed: w.sessionsFailed || 0,
            metadata: w.metadata || {},
            sessionDurations: w.sessionDurations || [],
          };
          this.workers.set(worker.id, worker);
          continue;
        }

        // Respect maxWorkers capacity for active workers
        if (activeLoaded >= this.maxWorkers) continue;

        // Workers that were busy are now in error (their jobs were interrupted)
        const restoredStatus = w.status === 'busy' ? 'error' : w.status;

        const worker = {
          id: w.id,
          status: restoredStatus,
          currentJob: null,  // Jobs do not survive restart
          lastHeartbeat: now,
          startedAt: w.startedAt || now,
          sessionsCompleted: w.sessionsCompleted || 0,
          sessionsFailed: w.sessionsFailed || 0,
          metadata: w.metadata || {},
          sessionDurations: w.sessionDurations || [],
        };

        // If we changed status from busy to error, increment failed
        if (w.status === 'busy') {
          worker.sessionsFailed++;
          worker.metadata.lastError = {
            message: 'Job interrupted by pool restart',
            failedAt: now,
          };
        }

        this.workers.set(worker.id, worker);
        activeLoaded++;

        // Start idle timeout for idle workers
        if (worker.status === 'idle') {
          this._startIdleTimeout(worker.id);
        }
      }
    } catch (err) {
      // Load failure should not crash the pool — start fresh
    }
  }

  // ─── Idle Timeout Management ────────────────────────────────────

  /**
   * Start idle timeout for a worker.
   * If the worker remains idle beyond workerIdleTimeout, it is terminated.
   *
   * @param {string} workerId
   */
  _startIdleTimeout(workerId) {
    this._clearIdleTimeout(workerId);

    const timer = setTimeout(() => {
      const worker = this.workers.get(workerId);
      if (worker && worker.status === 'idle') {
        try {
          this.terminate(workerId);
        } catch (err) {
          // Worker may have already been terminated
        }
      }
    }, this.workerIdleTimeout);

    // Don't keep process alive for idle timeouts
    if (timer.unref) timer.unref();

    this.idleTimeoutTimers.set(workerId, timer);
  }

  /**
   * Clear idle timeout for a worker.
   *
   * @param {string} workerId
   */
  _clearIdleTimeout(workerId) {
    const timer = this.idleTimeoutTimers.get(workerId);
    if (timer) {
      clearTimeout(timer);
      this.idleTimeoutTimers.delete(workerId);
    }
  }

  // ─── Internal Helpers ───────────────────────────────────────────

  /**
   * Count active (non-terminated) workers.
   *
   * @returns {number}
   */
  _activeWorkerCount() {
    let count = 0;
    for (const worker of this.workers.values()) {
      if (worker.status !== 'terminated') count++;
    }
    return count;
  }
}

// ─── Module Export ──────────────────────────────────────────────────

module.exports = { WorkerPool };

