/**
 * BOQA replay-farm.js — ReplayFarm v1.5 (P5)
 *
 * Parallelized replay execution with isolated workers and retry policies.
 * The farm manages a queue of replay jobs, distributes them to workers,
 * handles failures with configurable retry policies, and enforces
 * resource limits.
 *
 * Architecture:
 *   ReplayFarm
 *   ├── Job Queue (FIFO with priority)
 *   ├── Worker Pool (isolated workers)
 *   ├── Failure Isolation (failed jobs don't affect others)
 *   ├── Retry Policy (configurable retries with backoff)
 *   └── Resource Limits (concurrency, memory, time)
 *
 * Safe mode: all replay is simulation-only, no live execution.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const REPLAYS_DIR = path.join(__dirname, 'output', 'replays');

// ─── Job States ────────────────────────────────────────────────────

const JOB_STATES = {
  QUEUED: 'queued',
  RUNNING: 'running',
  COMPLETED: 'completed',
  FAILED: 'failed',
  RETRYING: 'retrying',
  CANCELLED: 'cancelled',
  TIMED_OUT: 'timed_out',
};

// ─── Retry Policy ──────────────────────────────────────────────────

const DEFAULT_RETRY_POLICY = {
  maxRetries: 2,
  backoffMs: 1000,
  backoffMultiplier: 2,
  retryableErrors: ['timeout', 'network_error', 'temporary_failure'],
};

// ─── ReplayFarm ────────────────────────────────────────────────────

class ReplayFarm {
  /**
   * @param {object} options
   * @param {number} [options.maxWorkers=3] - Maximum concurrent workers
   * @param {number} [options.jobTimeout=60000] - Timeout per job (ms)
   * @param {object} [options.retryPolicy] - Retry configuration
   * @param {number} [options.maxQueueSize=100] - Maximum queued jobs
   * @param {object} [options.deterministicReplayEngine] - Engine instance for replay
   */
  constructor(options = {}) {
    this.maxWorkers = options.maxWorkers || 3;
    this.jobTimeout = options.jobTimeout || 60000;
    this.retryPolicy = { ...DEFAULT_RETRY_POLICY, ...options.retryPolicy };
    this.maxQueueSize = options.maxQueueSize || 100;
    this.replayEngine = options.deterministicReplayEngine || null;

    // Job management
    this.queue = []; // ordered job list
    this.jobs = new Map(); // jobId → job
    this.workers = new Map(); // workerId → worker state
    this.activeJobs = new Map(); // workerId → jobId

    // Stats
    this.stats = {
      total_submitted: 0,
      total_completed: 0,
      total_failed: 0,
      total_retried: 0,
      total_cancelled: 0,
      total_timed_out: 0,
      avg_duration_ms: 0,
    };

    // Initialize worker slots
    for (let i = 0; i < this.maxWorkers; i++) {
      this.workers.set(`worker-${i}`, {
        id: `worker-${i}`,
        status: 'idle',
        currentJob: null,
        jobsCompleted: 0,
        jobsFailed: 0,
      });
    }
  }

  /**
   * Submit a replay job to the farm.
   *
   * @param {object} params
   * @param {object} params.recording - Recording to replay
   * @param {object} [params.manifest] - Associated manifest
   * @param {string} [params.scenarioName] - Scenario name
   * @param {number} [params.priority=5] - Priority (1=highest, 10=lowest)
   * @param {object} [params.replayOptions] - Options for DeterministicReplayEngine
   * @returns {object} Job descriptor
   */
  submit(params = {}) {
    if (this.queue.length >= this.maxQueueSize) {
      throw new Error('Queue is full');
    }

    const jobId = `JOB-${crypto.randomUUID().substring(0, 8)}`;
    const job = {
      id: jobId,
      recording: params.recording,
      manifest: params.manifest || null,
      scenarioName: params.scenarioName || 'unnamed',
      priority: params.priority || 5,
      replayOptions: params.replayOptions || {},
      state: JOB_STATES.QUEUED,
      submittedAt: Date.now(),
      startedAt: null,
      completedAt: null,
      result: null,
      error: null,
      retries: 0,
      workerId: null,
    };

    this.jobs.set(jobId, job);

    // Insert into priority queue (lower number = higher priority)
    let insertIdx = this.queue.length;
    for (let i = 0; i < this.queue.length; i++) {
      if (job.priority < this.queue[i].priority) {
        insertIdx = i;
        break;
      }
    }
    this.queue.splice(insertIdx, 0, jobId);

    this.stats.total_submitted++;

    return {
      job_id: jobId,
      state: job.state,
      queue_position: this.queue.indexOf(jobId),
    };
  }

  /**
   * Process the next jobs in the queue.
   * This is the main execution loop — call repeatedly or on a timer.
   *
   * @returns {object[]} Completed job results
   */
  async tick() {
    const completedResults = [];

    // Find idle workers and assign jobs
    for (const [workerId, worker] of this.workers) {
      if (worker.status === 'idle' && this.queue.length > 0) {
        const jobId = this.queue.shift();
        const job = this.jobs.get(jobId);
        if (job) {
          await this._assignJob(workerId, job);
        }
      }
    }

    // Check for completed/timed-out jobs
    for (const [workerId, worker] of this.workers) {
      if (worker.status === 'busy' && worker.currentJob) {
        const job = this.jobs.get(worker.currentJob);
        if (job && job.state === JOB_STATES.RUNNING) {
          // Check timeout
          if (Date.now() - job.startedAt > this.jobTimeout) {
            await this._completeJob(workerId, job, null, 'timeout');
            this.stats.total_timed_out++;
          }
        }
      }
    }

    return completedResults;
  }

  /**
   * Run all queued jobs to completion.
   *
   * @returns {object[]} All job results
   */
  async runAll() {
    const results = [];

    while (this.queue.length > 0 || this._hasActiveJobs()) {
      const tickResults = await this.tick();

      // Process active jobs
      for (const [workerId, worker] of this.workers) {
        if (worker.status === 'busy' && worker.currentJob) {
          const job = this.jobs.get(worker.currentJob);
          if (job && job.state === JOB_STATES.RUNNING) {
            try {
              const result = await this._executeJob(job);
              await this._completeJob(workerId, job, result);
              results.push(result);
            } catch (err) {
              await this._completeJob(workerId, job, null, err.message);
            }
          }
        }
      }

      // Small yield to prevent CPU spin
      if (this.queue.length > 0 || this._hasActiveJobs()) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    }

    return results;
  }

  /**
   * Run a single job immediately (bypasses queue).
   *
   * @param {object} params - Same as submit()
   * @returns {object} Job result
   */
  async runOne(params = {}) {
    const jobInfo = this.submit({ ...params, priority: 1 });
    const job = this.jobs.get(jobInfo.job_id);

    // Find an idle worker
    let workerId = null;
    for (const [wid, worker] of this.workers) {
      if (worker.status === 'idle') {
        workerId = wid;
        break;
      }
    }

    if (!workerId) {
      // Force assign to first worker
      workerId = 'worker-0';
    }

    await this._assignJob(workerId, job);

    try {
      const result = await this._executeJob(job);
      await this._completeJob(workerId, job, result);
      return result;
    } catch (err) {
      await this._completeJob(workerId, job, null, err.message);
      return { job_id: job.id, state: JOB_STATES.FAILED, error: err.message };
    }
  }

  /**
   * Cancel a queued or running job.
   */
  cancel(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) return false;

    if (job.state === JOB_STATES.QUEUED) {
      this.queue = this.queue.filter(id => id !== jobId);
      job.state = JOB_STATES.CANCELLED;
      this.stats.total_cancelled++;
      return true;
    }

    if (job.state === JOB_STATES.RUNNING) {
      // Mark for cancellation — worker will check on next tick
      job.state = JOB_STATES.CANCELLED;
      this.stats.total_cancelled++;
      return true;
    }

    return false;
  }

  /**
   * Get job status.
   */
  getJob(jobId) {
    return this.jobs.get(jobId) || null;
  }

  /**
   * Get farm status.
   */
  getStatus() {
    const queuedByPriority = {};
    for (const jobId of this.queue) {
      const job = this.jobs.get(jobId);
      if (job) {
        queuedByPriority[job.priority] = (queuedByPriority[job.priority] || 0) + 1;
      }
    }

    return {
      workers: {
        total: this.maxWorkers,
        idle: [...this.workers.values()].filter(w => w.status === 'idle').length,
        busy: [...this.workers.values()].filter(w => w.status === 'busy').length,
      },
      queue: {
        size: this.queue.length,
        max_size: this.maxQueueSize,
        by_priority: queuedByPriority,
      },
      stats: { ...this.stats },
      jobs: {
        total: this.jobs.size,
        by_state: this._jobsByState(),
      },
    };
  }

  // ─── Internal ────────────────────────────────────────────────────

  async _assignJob(workerId, job) {
    const worker = this.workers.get(workerId);
    if (!worker) return;

    worker.status = 'busy';
    worker.currentJob = job.id;
    job.state = JOB_STATES.RUNNING;
    job.startedAt = Date.now();
    job.workerId = workerId;

    this.activeJobs.set(workerId, job.id);
  }

  async _executeJob(job) {
    // Create a DeterministicReplayEngine for this job
    const { DeterministicReplayEngine } = require('./deterministic-replay-engine');
    const engine = this.replayEngine || new DeterministicReplayEngine(job.replayOptions);

    engine.loadRecording(job.recording, job.manifest);
    const report = await engine.replay();

    return {
      job_id: job.id,
      scenario_name: job.scenarioName,
      state: JOB_STATES.COMPLETED,
      report,
      executed_at: Date.now(),
      duration_ms: Date.now() - job.startedAt,
    };
  }

  async _completeJob(workerId, job, result, error = null) {
    const worker = this.workers.get(workerId);
    if (!worker) return;

    if (error) {
      // Check if retryable
      const isRetryable = this.retryPolicy.retryableErrors.some(
        e => error.includes(e) || error === 'timeout'
      );

      if (isRetryable && job.retries < this.retryPolicy.maxRetries) {
        job.retries++;
        job.state = JOB_STATES.RETRYING;
        this.stats.total_retried++;

        // Calculate backoff
        const backoff = this.retryPolicy.backoffMs *
          Math.pow(this.retryPolicy.backoffMultiplier, job.retries - 1);

        // Re-queue with delay
        await new Promise(resolve => setTimeout(resolve, backoff));
        this.queue.unshift(job.id); // Priority re-queue
      } else {
        job.state = JOB_STATES.FAILED;
        job.error = error;
        job.completedAt = Date.now();
        this.stats.total_failed++;
        worker.jobsFailed++;
      }
    } else {
      job.state = JOB_STATES.COMPLETED;
      job.result = result;
      job.completedAt = Date.now();
      this.stats.total_completed++;
      worker.jobsCompleted++;
    }

    // Free worker
    worker.status = 'idle';
    worker.currentJob = null;
    this.activeJobs.delete(workerId);

    // Update avg duration
    if (job.completedAt && job.startedAt) {
      const duration = job.completedAt - job.startedAt;
      const total = this.stats.total_completed;
      this.stats.avg_duration_ms = Math.round(
        (this.stats.avg_duration_ms * (total - 1) + duration) / total
      );
    }
  }

  _hasActiveJobs() {
    return [...this.workers.values()].some(w => w.status === 'busy');
  }

  _jobsByState() {
    const byState = {};
    for (const job of this.jobs.values()) {
      byState[job.state] = (byState[job.state] || 0) + 1;
    }
    return byState;
  }

  /**
   * Reset farm state.
   */
  reset() {
    this.queue = [];
    this.jobs.clear();
    this.activeJobs.clear();
    for (const [workerId, worker] of this.workers) {
      worker.status = 'idle';
      worker.currentJob = null;
    }
    this.stats = {
      total_submitted: 0,
      total_completed: 0,
      total_failed: 0,
      total_retried: 0,
      total_cancelled: 0,
      total_timed_out: 0,
      avg_duration_ms: 0,
    };
  }
}

module.exports = {
  ReplayFarm,
  JOB_STATES,
  DEFAULT_RETRY_POLICY,
};

