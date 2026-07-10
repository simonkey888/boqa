/**
 * BOQA scheduler.js — Scheduler Module
 *
 * Queues scans, revalidations, and regression runs for the BOQA system.
 * Manages job lifecycle with priority-based scheduling, concurrency control,
 * automatic retries, periodic revalidation schedules, and persistent state.
 *
 * Worker Architecture:
 *   controller: 1, workers: N, queue: builtin
 *   modes: live, baseline, compare, verification
 *
 * Safe mode: only allows jobs for targets with authorization_status === 'approved'.
 *            Accepts a targetManager reference in the constructor and validates on enqueue.
 *
 * v0.5
 */

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Constants ─────────────────────────────────────────────────────

const VALID_JOB_TYPES = new Set(['scan', 'revalidation', 'regression', 'verification']);
const VALID_MODES = new Set(['live', 'baseline', 'compare', 'verification']);
const VALID_STATUSES = new Set(['queued', 'running', 'completed', 'failed', 'cancelled']);

const OUTPUT_DIR = path.join(__dirname, 'output', 'scheduler');
const QUEUE_FILE = path.join(OUTPUT_DIR, 'queue.json');

const DEBOUNCE_SAVE_MS = 5000;

// ─── Job Schema ────────────────────────────────────────────────────

// {
//   id: "JOB-XXXX",
//   type: "scan|revalidation|regression|verification",
//   target_id: "TGT-XXXX",
//   mode: "live|baseline|compare|verification",
//   status: "queued|running|completed|failed|cancelled",
//   priority: 0-100,
//   created_at: timestamp,
//   started_at: timestamp|null,
//   completed_at: timestamp|null,
//   result: {},
//   error: "string|null",
//   retries: 0,
//   max_retries: 3,
//   metadata: {},
// }

// ─── Scheduler ─────────────────────────────────────────────────────

class Scheduler extends EventEmitter {
  /**
   * Initialize the scheduler
   * @param {object} options - Configuration options
   * @param {number} [options.maxConcurrent=5] - Maximum concurrent running jobs
   * @param {number} [options.defaultPriority=50] - Default priority for enqueued jobs
   * @param {number} [options.retryDelay=30000] - Delay in ms before retrying a failed job
   * @param {number} [options.pollInterval=1000] - Interval in ms for the scheduler poll loop
   * @param {object} [options.targetManager=null] - Target manager reference for authorization checks
   */
  constructor(options = {}) {
    super();

    this.maxConcurrent = options.maxConcurrent || 5;
    this.defaultPriority = options.defaultPriority !== undefined ? options.defaultPriority : 50;
    this.retryDelay = options.retryDelay !== undefined ? options.retryDelay : 30000;
    this.pollInterval = options.pollInterval !== undefined ? options.pollInterval : 1000;
    this.targetManager = options.targetManager || null;

    /** @type {Map<string, object>} jobId → job */
    this.jobs = new Map();

    /** @type {string[]} Ordered list of queued job IDs (highest priority first, then FIFO) */
    this.queue = [];

    /** @type {Set<string>} Set of currently running job IDs */
    this.running = new Set();

    /** @type {Map<string, NodeJS.Timeout>} scheduleId → interval timer */
    this.schedules = new Map();

    /** @type {number} Monotonic counter for JOB-XXXX IDs */
    this._jobCounter = 0;

    /** @type {NodeJS.Timeout|null} Poll loop timer */
    this._pollTimer = null;

    /** @type {boolean} Whether the scheduler poll loop is active */
    this._started = false;

    /** @type {NodeJS.Timeout|null} Debounced save timer */
    this._saveTimer = null;

    // Ensure output directory exists
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }

  // ─── Job Lifecycle ───────────────────────────────────────────

  /**
   * Add a job to the scheduler queue
   * @param {object} jobConfig - Job configuration
   * @param {string} jobConfig.target_id - Target identifier (must be authorized)
   * @param {string} jobConfig.type - Job type: scan, revalidation, regression, verification
   * @param {string} jobConfig.mode - Job mode: live, baseline, compare, verification
   * @param {number} [jobConfig.priority] - Priority 0 (lowest) to 100 (highest)
   * @param {number} [jobConfig.max_retries=3] - Maximum retry attempts on failure
   * @param {object} [jobConfig.metadata={}] - Additional metadata
   * @returns {object} The created job object
   * @throws {Error} If validation fails
   */
  enqueue(jobConfig) {
    // Validate target_id
    if (!jobConfig.target_id || typeof jobConfig.target_id !== 'string') {
      throw new Error(`Invalid target_id: ${jobConfig.target_id}`);
    }

    // Validate type
    if (!VALID_JOB_TYPES.has(jobConfig.type)) {
      throw new Error(`Invalid job type: "${jobConfig.type}". Must be one of: ${[...VALID_JOB_TYPES].join(', ')}`);
    }

    // Validate mode
    if (!VALID_MODES.has(jobConfig.mode)) {
      throw new Error(`Invalid job mode: "${jobConfig.mode}". Must be one of: ${[...VALID_MODES].join(', ')}`);
    }

    // Safe mode: verify target authorization
    if (this.targetManager) {
      const target = this.targetManager.getTarget
        ? this.targetManager.getTarget(jobConfig.target_id)
        : this.targetManager.get
          ? this.targetManager.get(jobConfig.target_id)
          : null;

      if (!target) {
        throw new Error(`Target not found: ${jobConfig.target_id}`);
      }

      if (target.authorization_status !== 'approved') {
        throw new Error(`Target "${jobConfig.target_id}" is not authorized (status: ${target.authorization_status}). Only approved targets are allowed.`);
      }
    }

    // Validate priority range
    const priority = jobConfig.priority !== undefined ? jobConfig.priority : this.defaultPriority;
    if (priority < 0 || priority > 100) {
      throw new Error(`Invalid priority: ${priority}. Must be between 0 and 100.`);
    }

    // Generate job ID
    this._jobCounter++;
    const jobId = `JOB-${String(this._jobCounter).padStart(4, '0')}`;

    const now = Date.now();

    const job = {
      id: jobId,
      type: jobConfig.type,
      target_id: jobConfig.target_id,
      mode: jobConfig.mode,
      status: 'queued',
      priority: priority,
      created_at: now,
      started_at: null,
      completed_at: null,
      result: {},
      error: null,
      retries: 0,
      max_retries: jobConfig.max_retries !== undefined ? jobConfig.max_retries : 3,
      metadata: jobConfig.metadata || {},
    };

    this.jobs.set(jobId, job);
    this._insertIntoQueue(jobId);

    this.emit('job:queued', job);
    this._debouncedSave();

    return job;
  }

  /**
   * Dequeue the next highest-priority job and mark it as running
   * @returns {object|null} The dequeued job, or null if no queued jobs
   */
  dequeue() {
    if (this.queue.length === 0) {
      return null;
    }

    if (this.running.size >= this.maxConcurrent) {
      return null;
    }

    const jobId = this.queue.shift();
    const job = this.jobs.get(jobId);

    if (!job || job.status !== 'queued') {
      // Stale entry, try next
      return this.dequeue();
    }

    job.status = 'running';
    job.started_at = Date.now();

    this.running.add(jobId);

    this.emit('job:started', job);
    this._debouncedSave();

    return job;
  }

  /**
   * Mark a job as completed with a result
   * @param {string} jobId - The job ID to complete
   * @param {object} [result={}] - The result data
   * @returns {object|null} The updated job, or null if not found
   */
  complete(jobId, result = {}) {
    const job = this.jobs.get(jobId);
    if (!job) return null;

    job.status = 'completed';
    job.completed_at = Date.now();
    job.result = result || {};

    this.running.delete(jobId);

    this.emit('job:completed', job);
    this._debouncedSave();

    return job;
  }

  /**
   * Mark a job as failed. If retries remain, re-queue after retryDelay.
   * @param {string} jobId - The job ID that failed
   * @param {string} [error=''] - Error description
   * @returns {object|null} The updated job, or null if not found
   */
  fail(jobId, error = '') {
    const job = this.jobs.get(jobId);
    if (!job) return null;

    this.running.delete(jobId);

    if (job.retries < job.max_retries) {
      // Retry: increment counter and re-queue after delay
      job.retries++;
      job.error = error || null;

      this.emit('job:retry', job);

      // Schedule re-queue after retryDelay
      setTimeout(() => {
        if (job.status === 'failed' || this.jobs.has(jobId)) {
          job.status = 'queued';
          job.started_at = null;
          job.completed_at = null;
          this._insertIntoQueue(jobId);
          this._debouncedSave();
        }
      }, this.retryDelay);

      // Mark as failed temporarily until retry kicks in
      job.status = 'failed';
      job.completed_at = Date.now();

      this._debouncedSave();
      return job;
    }

    // No more retries — stays failed
    job.status = 'failed';
    job.error = error || null;
    job.completed_at = Date.now();

    this.emit('job:failed', job);
    this._debouncedSave();

    return job;
  }

  /**
   * Cancel a job by ID
   * @param {string} jobId - The job ID to cancel
   * @returns {object|null} The cancelled job, or null if not found
   */
  cancel(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) return null;

    // Remove from queue if still queued
    const queueIndex = this.queue.indexOf(jobId);
    if (queueIndex !== -1) {
      this.queue.splice(queueIndex, 1);
    }

    // Remove from running set
    this.running.delete(jobId);

    job.status = 'cancelled';
    job.completed_at = Date.now();

    this.emit('job:cancelled', job);
    this._debouncedSave();

    return job;
  }

  // ─── Query Methods ───────────────────────────────────────────

  /**
   * Get a job by ID
   * @param {string} jobId - The job ID
   * @returns {object|undefined} The job object, or undefined if not found
   */
  getJob(jobId) {
    return this.jobs.get(jobId);
  }

  /**
   * List jobs with optional filtering
   * @param {object} [filter={}] - Filter criteria
   * @param {string} [filter.status] - Filter by status
   * @param {string} [filter.type] - Filter by type
   * @param {string} [filter.target_id] - Filter by target ID
   * @param {string} [filter.mode] - Filter by mode
   * @returns {object[]} Array of matching jobs
   */
  listJobs(filter = {}) {
    const results = [];

    for (const job of this.jobs.values()) {
      if (filter.status && job.status !== filter.status) continue;
      if (filter.type && job.type !== filter.type) continue;
      if (filter.target_id && job.target_id !== filter.target_id) continue;
      if (filter.mode && job.mode !== filter.mode) continue;

      results.push(job);
    }

    return results;
  }

  /**
   * Get queue statistics
   * @returns {object} Stats object with totals, breakdowns, and performance metrics
   */
  getQueueStats() {
    const now = Date.now();

    const byStatus = {
      queued: 0,
      running: 0,
      completed: 0,
      failed: 0,
      cancelled: 0,
    };

    const byType = {
      scan: 0,
      revalidation: 0,
      regression: 0,
      verification: 0,
    };

    let totalWaitTime = 0;
    let waitCount = 0;
    let totalExecTime = 0;
    let execCount = 0;
    let completedInWindow = 0;
    const windowMs = 60000; // 1 minute throughput window

    for (const job of this.jobs.values()) {
      // Count by status
      if (byStatus[job.status] !== undefined) {
        byStatus[job.status]++;
      }

      // Count by type
      if (byType[job.type] !== undefined) {
        byType[job.type]++;
      }

      // Calculate wait time (created_at → started_at)
      if (job.started_at !== null) {
        totalWaitTime += (job.started_at - job.created_at);
        waitCount++;
      }

      // Calculate execution time (started_at → completed_at)
      if (job.started_at !== null && job.completed_at !== null) {
        totalExecTime += (job.completed_at - job.started_at);
        execCount++;
      }

      // Throughput: completed jobs in the last minute
      if (job.status === 'completed' && job.completed_at && (now - job.completed_at) <= windowMs) {
        completedInWindow++;
      }
    }

    return {
      total: this.jobs.size,
      by_status: byStatus,
      by_type: byType,
      avg_wait_time_ms: waitCount > 0 ? Math.round(totalWaitTime / waitCount) : 0,
      avg_execution_time_ms: execCount > 0 ? Math.round(totalExecTime / execCount) : 0,
      throughput_per_min: completedInWindow,
    };
  }

  /**
   * Get the number of queued (pending) jobs
   * @returns {number}
   */
  getPendingCount() {
    return this.queue.length;
  }

  /**
   * Get the number of currently running jobs
   * @returns {number}
   */
  getRunningCount() {
    return this.running.size;
  }

  // ─── Priority Management ─────────────────────────────────────

  /**
   * Change the priority of a queued job
   * @param {string} jobId - The job ID
   * @param {number} newPriority - New priority value (0-100)
   * @returns {object|null} The updated job, or null if not found
   * @throws {Error} If priority is out of range or job is not queued
   */
  prioritize(jobId, newPriority) {
    if (newPriority < 0 || newPriority > 100) {
      throw new Error(`Invalid priority: ${newPriority}. Must be between 0 and 100.`);
    }

    const job = this.jobs.get(jobId);
    if (!job) return null;

    if (job.status !== 'queued') {
      throw new Error(`Cannot change priority of job "${jobId}" with status "${job.status}". Only queued jobs can be reprioritized.`);
    }

    // Remove from current position in queue
    const queueIndex = this.queue.indexOf(jobId);
    if (queueIndex !== -1) {
      this.queue.splice(queueIndex, 1);
    }

    // Update priority and re-insert
    job.priority = newPriority;
    this._insertIntoQueue(jobId);

    this._debouncedSave();

    return job;
  }

  // ─── Periodic Scheduling ─────────────────────────────────────

  /**
   * Schedule periodic revalidation jobs for a target
   * @param {string} targetId - Target to revalidate periodically
   * @param {number} interval - Interval in milliseconds between revalidation jobs
   * @param {object} [options={}] - Additional options
   * @param {number} [options.priority=50] - Priority for scheduled jobs
   * @param {string} [options.mode='verification'] - Mode for scheduled jobs
   * @param {object} [options.metadata={}] - Additional metadata
   * @returns {string} Schedule ID for later cancellation
   */
  scheduleRevalidation(targetId, interval, options = {}) {
    const scheduleId = `sched-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36) + '-' + Math.random().toString(36).substring(2, 6)}`;

    const jobPriority = options.priority !== undefined ? options.priority : this.defaultPriority;
    const jobMode = options.mode || 'verification';
    const jobMetadata = {
      ...options.metadata,
      _scheduled: true,
      _schedule_id: scheduleId,
      _interval: interval,
    };

    const timer = setInterval(() => {
      try {
        this.enqueue({
          target_id: targetId,
          type: 'revalidation',
          mode: jobMode,
          priority: jobPriority,
          metadata: { ...jobMetadata, _scheduled_at: Date.now() },
        });
      } catch (err) {
        // If enqueue fails (e.g., target no longer authorized), emit warning
        this.emit('job:failed', {
          id: null,
          type: 'revalidation',
          target_id: targetId,
          error: `Scheduled revalidation failed: ${err.message}`,
          _schedule_id: scheduleId,
        });
      }
    }, interval);

    // Store unref'd so the timer doesn't prevent process exit
    if (timer.unref) timer.unref();

    this.schedules.set(scheduleId, {
      id: scheduleId,
      target_id: targetId,
      interval: interval,
      timer: timer,
      options: { priority: jobPriority, mode: jobMode, metadata: jobMetadata },
      created_at: Date.now(),
    });

    return scheduleId;
  }

  /**
   * Cancel a periodic schedule
   * @param {string} scheduleId - The schedule ID to cancel
   * @returns {boolean} True if the schedule was found and cancelled
   */
  cancelSchedule(scheduleId) {
    const schedule = this.schedules.get(scheduleId);
    if (!schedule) return false;

    clearInterval(schedule.timer);
    this.schedules.delete(scheduleId);

    return true;
  }

  // ─── Scheduler Control ───────────────────────────────────────

  /**
   * Start the scheduler poll loop
   * On each poll: dequeue a job if a slot is available, emit 'job:start' event
   */
  start() {
    if (this._started) return;

    this._started = true;

    const poll = () => {
      if (!this._started) return;

      // Dequeue jobs while slots are available
      while (this.running.size < this.maxConcurrent && this.queue.length > 0) {
        const job = this.dequeue();
        if (job) {
          this.emit('job:start', job);
        } else {
          break;
        }
      }

      this._pollTimer = setTimeout(poll, this.pollInterval);
      if (this._pollTimer.unref) this._pollTimer.unref();
    };

    poll();
  }

  /**
   * Stop the scheduler poll loop and cancel all running jobs
   */
  stop() {
    this._started = false;

    if (this._pollTimer) {
      clearTimeout(this._pollTimer);
      this._pollTimer = null;
    }

    // Cancel all running jobs
    for (const jobId of [...this.running]) {
      this.cancel(jobId);
    }

    // Cancel all periodic schedules
    for (const [scheduleId] of this.schedules) {
      this.cancelSchedule(scheduleId);
    }

    // Flush any pending save
    if (this._saveTimer) {
      clearTimeout(this._saveTimer);
      this._saveTimer = null;
      this._saveNow();
    }
  }

  // ─── Persistence ─────────────────────────────────────────────

  /**
   * Persist queue state to disk
   * @returns {string} The file path written
   */
  save() {
    const state = {
      version: '0.5.0',
      saved_at: Date.now(),
      job_counter: this._jobCounter,
      jobs: [...this.jobs.values()],
      queue: this.queue,
      running: [...this.running],
      schedules: [...this.schedules.values()].map(s => ({
        id: s.id,
        target_id: s.target_id,
        interval: s.interval,
        options: s.options,
        created_at: s.created_at,
      })),
    };

    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
    fs.writeFileSync(QUEUE_FILE, JSON.stringify(state, null, 2));

    return QUEUE_FILE;
  }

  /**
   * Load queue state from disk
   * @returns {boolean} True if state was loaded successfully
   */
  load() {
    if (!fs.existsSync(QUEUE_FILE)) {
      return false;
    }

    try {
      const raw = fs.readFileSync(QUEUE_FILE, 'utf8');
      const state = JSON.parse(raw);

      if (!state || !Array.isArray(state.jobs)) {
        return false;
      }

      // Restore jobs
      this.jobs.clear();
      for (const job of state.jobs) {
        this.jobs.set(job.id, job);
      }

      // Restore queue (re-validate that jobs are still queued)
      this.queue = [];
      if (Array.isArray(state.queue)) {
        for (const jobId of state.queue) {
          const job = this.jobs.get(jobId);
          if (job && job.status === 'queued') {
            this.queue.push(jobId);
          }
        }
      }

      // If the saved queue is empty but we have queued jobs, rebuild it
      if (this.queue.length === 0) {
        this._rebuildQueue();
      }

      // Restore running set (jobs that were running are now treated as cancelled on restart)
      this.running.clear();
      if (Array.isArray(state.running)) {
        for (const jobId of state.running) {
          const job = this.jobs.get(jobId);
          if (job && job.status === 'running') {
            // On restart, mark previously running jobs as cancelled
            job.status = 'cancelled';
            job.completed_at = job.completed_at || Date.now();
            job.error = job.error || 'Scheduler restarted while job was running';
          }
        }
      }

      // Restore counter
      this._jobCounter = state.job_counter || this.jobs.size;

      // Restore periodic schedules (without timers — caller must re-schedule)
      // We store schedule metadata but don't auto-restart intervals
      // because the caller should decide whether to re-schedule.

      return true;
    } catch (err) {
      return false;
    }
  }

  // ─── Internal Helpers ────────────────────────────────────────

  /**
   * Insert a job ID into the priority queue at the correct position.
   * Queue is sorted by priority descending (highest first), then by
   * creation time ascending (FIFO within same priority).
   * @param {string} jobId - The job ID to insert
   * @private
   */
  _insertIntoQueue(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) return;

    // Binary search for insertion point
    let lo = 0;
    let hi = this.queue.length;

    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      const midJob = this.jobs.get(this.queue[mid]);

      if (!midJob) {
        lo = mid + 1;
        continue;
      }

      // Higher priority goes first (descending)
      if (midJob.priority > job.priority) {
        lo = mid + 1;
      } else if (midJob.priority < job.priority) {
        hi = mid;
      } else {
        // Same priority: FIFO by created_at (ascending)
        if (midJob.created_at <= job.created_at) {
          lo = mid + 1;
        } else {
          hi = mid;
        }
      }
    }

    this.queue.splice(lo, 0, jobId);
  }

  /**
   * Rebuild the priority queue from all queued jobs
   * @private
   */
  _rebuildQueue() {
    this.queue = [];

    const queuedJobs = [];
    for (const job of this.jobs.values()) {
      if (job.status === 'queued') {
        queuedJobs.push(job);
      }
    }

    // Sort by priority descending, then by created_at ascending
    queuedJobs.sort((a, b) => {
      if (b.priority !== a.priority) {
        return b.priority - a.priority;
      }
      return a.created_at - b.created_at;
    });

    for (const job of queuedJobs) {
      this.queue.push(job.id);
    }
  }

  /**
   * Debounced save — coalesces multiple state changes within 5 seconds
   * into a single disk write.
   * @private
   */
  _debouncedSave() {
    if (this._saveTimer) {
      clearTimeout(this._saveTimer);
    }

    this._saveTimer = setTimeout(() => {
      this._saveNow();
    }, DEBOUNCE_SAVE_MS);

    if (this._saveTimer.unref) this._saveTimer.unref();
  }

  /**
   * Immediately save to disk (used by debounced save and flush)
   * @private
   */
  _saveNow() {
    this._saveTimer = null;
    try {
      this.save();
    } catch (err) {
      // Persistence failure should not crash the scheduler
      this.emit('error', err);
    }
  }
}

module.exports = { Scheduler };

