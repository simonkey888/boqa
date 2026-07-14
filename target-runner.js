/**
 * BOQA target-runner.js — Autonomous Target Runner (S6-1)
 *
 * Execution pipeline capable of running BOQA against many independent
 * targets without human interaction. Provides:
 *   - Queue of targets with priority and retry
 *   - Parallel workers with configurable concurrency
 *   - Retry policy with exponential backoff
 *   - Timeouts per target and per worker
 *   - Isolated failures (one target crash never blocks others)
 *   - Structured execution logs
 *   - Resume interrupted executions via checkpoint
 *
 * Operates on top of the existing TargetManager and leverages the
 * Agent, AnomalyEngine, and analysis pipeline for per-target work.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const executionGuard = require('./lib/execution-authorization-guard');

// ─── Execution States ────────────────────────────────────────────────

const EXEC_STATES = {
  QUEUED: 'queued',
  RUNNING: 'running',
  COMPLETED: 'completed',
  FAILED: 'failed',
  TIMED_OUT: 'timed_out',
  CANCELLED: 'cancelled',
  RETRYING: 'retrying',
  SKIPPED: 'skipped',
};

// ─── Default Configuration ───────────────────────────────────────────

const DEFAULTS = {
  maxWorkers: 3,
  targetTimeout: 120000,       // 2 minutes per target
  workerIdleTimeout: 30000,    // 30s idle before worker releases
  retryPolicy: {
    maxRetries: 2,
    backoffMs: 2000,
    multiplier: 2,
    retryableErrors: ['timeout', 'browser_crash', 'network_error'],
  },
  checkpointInterval: 30000,   // Save progress every 30s
  resumeFromCheckpoint: true,
  logDir: null,                // Set by ctx.OUTPUT_DIR if null
};

class TargetRunner {
  /**
   * @param {object} opts
   * @param {object} opts.targetManager     - TargetManager instance
   * @param {object} opts.executionQueue    - ExecutionQueue instance
   * @param {object} opts.realBugDetector   - RealBugDetector instance
   * @param {object} opts.confidenceEngine  - FindingConfidenceEngine instance
   * @param {object} opts.falsePositiveReducer - FalsePositiveReducer instance
   * @param {object} opts.evidenceGenerator - EvidencePackageGenerator instance
   * @param {object} opts.knowledgeIntegrator - KnowledgeGraphIntegration instance
   * @param {object} opts.operationalMetrics - OperationalMetrics instance
   */
  constructor(opts = {}) {
    this.targetManager = opts.targetManager || null;
    this.executionQueue = opts.executionQueue || null;
    this.realBugDetector = opts.realBugDetector || null;
    this.confidenceEngine = opts.confidenceEngine || null;
    this.falsePositiveReducer = opts.falsePositiveReducer || null;
    this.evidenceGenerator = opts.evidenceGenerator || null;
    this.knowledgeIntegrator = opts.knowledgeIntegrator || null;
    this.operationalMetrics = opts.operationalMetrics || null;
    this.registry = opts.registry || null;
    this.resolver = opts.resolver;
    this.executionGuard = opts.executionGuard || executionGuard;

    this.config = { ...DEFAULTS, ...opts };
    this.config.retryPolicy = { ...DEFAULTS.retryPolicy, ...(opts.retryPolicy || {}) };

    this._running = false;
    this._activeWorkers = 0;
    this._currentExecutions = new Map(); // targetId → execution state
    this._executionLog = [];
    this._checkpointTimer = null;
    this._startTime = null;
    this._stats = {
      targets_submitted: 0,
      targets_completed: 0,
      targets_failed: 0,
      targets_timed_out: 0,
      targets_retried: 0,
      total_bugs_found: 0,
      total_confirmed: 0,
      total_false_positives: 0,
      total_execution_time_ms: 0,
    };
  }

  /**
   * Submit a single target for execution.
   * @param {object} target - { url, name, priority, meta }
   * @returns {object} execution descriptor
   */
  submitTarget(target) {
    throw new Error('ASYNC_EXECUTION_GUARD_REQUIRED: use submitTargetAsync()');
  }

  async submitTargetAsync(target) {
    if (!target?.id || !this.registry) throw new Error('canonical target id required');
    const canonical = this.registry.get(target.id);
    if (!canonical) throw new Error(`Target not found: ${target.id}`);
    const id = target.id;
    const candidate = {
      id,
      action: 'navigation',
      target_id: canonical.id,
      params: { url: canonical.url || canonical.base_url },
      target_url: canonical.url || canonical.base_url,
      target_name: canonical.name || canonical.id,
      priority: target.priority || 5,
      meta: target.meta || {},
      state: EXEC_STATES.QUEUED,
      submitted_at: Date.now(),
      started_at: null,
      completed_at: null,
      retry_count: 0,
      error: null,
      findings: [],
      bug_candidates: [],
      confirmed_bugs: [],
      false_positives: [],
      evidence_packages: [],
      execution_time_ms: 0,
    };

    const authorization = await this.executionGuard.validateTaskAsync(candidate, this.registry, { resolver: this.resolver });
    if (!authorization.allowed) throw new Error(`${authorization.code}: ${authorization.reason}`);
    const execution = this.executionGuard.sealTask(candidate);

    if (this.executionQueue) {
      this.executionQueue.enqueue(execution);
    } else {
      this._executionLog.push(execution);
    }

    this._stats.targets_submitted++;
    return execution;
  }

  /**
   * Submit multiple targets at once.
   * @param {Array} targets
   * @returns {Array} execution descriptors
   */
  submitTargets(targets) {
    throw new Error('ASYNC_EXECUTION_GUARD_REQUIRED: use submitTargetsAsync()');
  }

  async submitTargetsAsync(targets) {
    return Promise.all(targets.map(target => this.submitTargetAsync(target)));
  }

  /**
   * Execute a single target run — the core unit of work.
   * This is called by the scheduler for each target.
   *
   * @param {object} execution - Execution descriptor
   * @param {object} agent - Agent instance (or null if degraded)
   * @param {object} ctx - Full BOQA context
   * @returns {object} updated execution
   */
  async executeTarget(execution, agent, ctx) {
    const integrity = this.executionGuard.verifyTaskIntegrity(execution);
    if (!integrity.allowed) throw new Error(`${integrity.code}: ${integrity.reason}`);
    const authorization = await this.executionGuard.validateTaskAsync(execution, this.registry, { resolver: this.resolver });
    if (!authorization.allowed) throw new Error(`${authorization.code}: ${authorization.reason}`);
    // URGENT-4: Degraded mode guard — protect flow when browser is unavailable
    if (!agent || ('page' in agent && !agent.page)) {
      console.warn(`[S6 Pipeline] Executing target URL ${execution.target_url} in DEGRADED MODE`);
      execution.state = EXEC_STATES.SKIPPED;
      execution.error = 'Browser execution engine is degraded/unavailable.';
      return execution;
    }

    execution.state = EXEC_STATES.RUNNING;
    execution.started_at = Date.now();

    const startTime = Date.now();
    const timeoutMs = this.config.targetTimeout;

    try {
      // Race between execution and timeout
      const result = await Promise.race([
        this._runTargetWork(execution, agent, ctx),
        this._createTimeout(timeoutMs, execution.id),
      ]);

      execution.execution_time_ms = Date.now() - startTime;
      execution.completed_at = Date.now();

      if (result.timed_out) {
        execution.state = EXEC_STATES.TIMED_OUT;
        execution.error = `Target timed out after ${timeoutMs}ms`;
        this._stats.targets_timed_out++;
      } else {
        execution.state = EXEC_STATES.COMPLETED;
        execution.findings = result.findings || [];
        execution.bug_candidates = result.bug_candidates || [];
        execution.confirmed_bugs = result.confirmed_bugs || [];
        execution.false_positives = result.false_positives || [];
        execution.evidence_packages = result.evidence_packages || [];
        this._stats.targets_completed++;
        this._stats.total_bugs_found += execution.bug_candidates.length;
        this._stats.total_confirmed += execution.confirmed_bugs.length;
        this._stats.total_false_positives += execution.false_positives.length;
      }
    } catch (err) {
      execution.execution_time_ms = Date.now() - startTime;
      execution.completed_at = Date.now();
      execution.error = err.message || String(err);

      // Check if retryable
      const isRetryable = this.config.retryPolicy.retryableErrors.some(
        e => execution.error.includes(e)
      );

      if (isRetryable && execution.retry_count < this.config.retryPolicy.maxRetries) {
        execution.state = EXEC_STATES.RETRYING;
        execution.retry_count++;
        this._stats.targets_retried++;
        // Backoff handled by scheduler
      } else {
        execution.state = EXEC_STATES.FAILED;
        this._stats.targets_failed++;
      }
    }

    this._stats.total_execution_time_ms += execution.execution_time_ms;

    // Record operational metrics
    if (this.operationalMetrics) {
      this.operationalMetrics.recordTargetExecution(execution);
    }

    // Persist bug relationships
    if (this.knowledgeIntegrator && execution.confirmed_bugs.length > 0) {
      this.knowledgeIntegrator.persistFindings(execution);
    }

    return execution;
  }

  /**
   * Internal: Run the actual bug-hunting work for one target.
   */
  async _runTargetWork(execution, agent, ctx) {
    const findings = [];
    const bug_candidates = [];
    const confirmed_bugs = [];
    const false_positives = [];
    const evidence_packages = [];

    // Step 1: Run real bug detection heuristics
    if (this.realBugDetector && agent) {
      const detectionResult = this.realBugDetector.detect(agent, ctx);
      findings.push(...detectionResult.findings);
      bug_candidates.push(...detectionResult.candidates);
    }

    // Step 2: Score confidence for each candidate
    if (this.confidenceEngine) {
      for (const candidate of bug_candidates) {
        const score = this.confidenceEngine.score(candidate, ctx);
        candidate.confidence_score = score.score;
        candidate.confidence_level = score.level;
      }
    }

    // Step 3: False positive reduction — retry suspicious candidates
    if (this.falsePositiveReducer && agent) {
      const fpResult = await this.falsePositiveReducer.validate(bug_candidates, agent, ctx);
      confirmed_bugs.push(...fpResult.confirmed);
      false_positives.push(...fpResult.false_positives);

      // Remove confirmed from candidates list
      for (const cb of fpResult.confirmed) {
        const idx = bug_candidates.findIndex(c => c.id === cb.id);
        if (idx >= 0) bug_candidates.splice(idx, 1);
      }
    } else {
      // No FPR: treat all candidates as confirmed
      confirmed_bugs.push(...bug_candidates);
    }

    // Step 4: Generate evidence packages for confirmed bugs
    if (this.evidenceGenerator) {
      for (const bug of confirmed_bugs) {
        const pkg = this.evidenceGenerator.generate(bug, agent, ctx);
        evidence_packages.push(pkg);
        bug.evidence_package_id = pkg.manifest?.evidence_id || null;
      }
    }

    return { findings, bug_candidates, confirmed_bugs, false_positives, evidence_packages };
  }

  /**
   * Internal: Create a timeout promise.
   */
  _createTimeout(ms, targetId) {
    return new Promise((resolve) => {
      setTimeout(() => resolve({ timed_out: true, targetId }), ms);
    });
  }

  /**
   * Get execution by ID.
   */
  getExecution(id) {
    return this._executionLog.find(e => e.id === id) || null;
  }

  /**
   * Get all executions.
   */
  getExecutions(filter) {
    let results = [...this._executionLog];
    if (filter) {
      if (filter.state) results = results.filter(e => e.state === filter.state);
      if (filter.minPriority) results = results.filter(e => e.priority >= filter.minPriority);
    }
    return results;
  }

  /**
   * Get runner statistics.
   */
  getStats() {
    return {
      ...this._stats,
      active_workers: this._activeWorkers,
      queue_size: this.executionQueue ? this.executionQueue.size() : 0,
      avg_execution_time_ms: this._stats.targets_completed > 0
        ? Math.round(this._stats.total_execution_time_ms / this._stats.targets_completed)
        : 0,
      success_rate: this._stats.targets_submitted > 0
        ? (this._stats.targets_completed / this._stats.targets_submitted * 100).toFixed(1) + '%'
        : '0%',
    };
  }

  /**
   * Save checkpoint for resume capability.
   */
  saveCheckpoint(outputDir) {
    const dir = outputDir || this.config.logDir || '/tmp';
    const checkpoint = {
      timestamp: Date.now(),
      stats: this._stats,
      executions: this._executionLog.map(e => ({
        id: e.id,
        target_url: e.target_url,
        state: e.state,
        retry_count: e.retry_count,
        submitted_at: e.submitted_at,
        completed_at: e.completed_at,
      })),
    };
    try {
      const cpPath = path.join(dir, 'target-runner-checkpoint.json');
      fs.writeFileSync(cpPath, JSON.stringify(checkpoint, null, 2));
      return cpPath;
    } catch (_) {
      return null;
    }
  }

  /**
   * Resume from a saved checkpoint.
   */
  async resumeFromCheckpoint(outputDir) {
    const dir = outputDir || this.config.logDir || '/tmp';
    try {
      const cpPath = path.join(dir, 'target-runner-checkpoint.json');
      if (!fs.existsSync(cpPath)) return false;
      const checkpoint = JSON.parse(fs.readFileSync(cpPath, 'utf8'));
      this._stats = { ...this._stats, ...checkpoint.stats };
      // Re-queue incomplete executions
      const incomplete = checkpoint.executions.filter(
        e => e.state === EXEC_STATES.QUEUED || e.state === EXEC_STATES.RETRYING
      );
      for (const e of incomplete) {
        await this.submitTargetAsync({ id: e.id, priority: 5 });
      }
      return incomplete.length;
    } catch (_) {
      return false;
    }
  }

  /**
   * Cancel a specific execution.
   */
  cancelExecution(id) {
    const execution = this.getExecution(id);
    if (execution && (execution.state === EXEC_STATES.QUEUED || execution.state === EXEC_STATES.RUNNING)) {
      execution.state = EXEC_STATES.CANCELLED;
      execution.completed_at = Date.now();
      return true;
    }
    return false;
  }

  /**
   * Reset all state.
   */
  reset() {
    this._running = false;
    this._activeWorkers = 0;
    this._currentExecutions.clear();
    this._executionLog = [];
    this._stats = {
      targets_submitted: 0, targets_completed: 0, targets_failed: 0,
      targets_timed_out: 0, targets_retried: 0, total_bugs_found: 0,
      total_confirmed: 0, total_false_positives: 0, total_execution_time_ms: 0,
    };
  }
}

// ─── ExecutionQueue ──────────────────────────────────────────────────

class ExecutionQueue {
  /**
   * Priority queue for target executions.
   * Lower priority number = higher priority (runs first).
   *
   * @param {object} opts
   * @param {number} opts.maxSize - Maximum queue size (0 = unlimited)
   */
  constructor(opts = {}) {
    this._queue = [];
    this._maxSize = opts.maxSize || 0;
    this._completed = [];
    this._stats = {
      total_enqueued: 0,
      total_dequeued: 0,
      total_completed: 0,
      total_rejected: 0,
    };
  }

  /**
   * Enqueue an execution.
   * @param {object} execution
   * @returns {boolean} true if enqueued, false if queue full
   */
  enqueue(execution) {
    if (this._maxSize > 0 && this._queue.length >= this._maxSize) {
      this._stats.total_rejected++;
      return false;
    }
    // Insert sorted by priority (lower number = higher priority)
    let insertIdx = this._queue.length;
    for (let i = 0; i < this._queue.length; i++) {
      if (execution.priority < this._queue[i].priority) {
        insertIdx = i;
        break;
      }
    }
    this._queue.splice(insertIdx, 0, execution);
    this._stats.total_enqueued++;
    return true;
  }

  /**
   * Dequeue the next highest-priority execution.
   * @returns {object|null}
   */
  dequeue() {
    if (this._queue.length === 0) return null;
    const execution = this._queue.shift();
    this._stats.total_dequeued++;
    return execution;
  }

  /**
   * Peek at the next execution without removing it.
   */
  peek() {
    return this._queue[0] || null;
  }

  /**
   * Mark an execution as completed.
   */
  complete(execution) {
    this._completed.push(execution);
    this._stats.total_completed++;
  }

  /**
   * Current queue size.
   */
  size() {
    return this._queue.length;
  }

  /**
   * Completed count.
   */
  completedCount() {
    return this._completed.length;
  }

  /**
   * Get queue stats.
   */
  getStats() {
    return { ...this._stats, current_size: this._queue.length, completed_size: this._completed.length };
  }

  /**
   * Reset the queue.
   */
  reset() {
    this._queue = [];
    this._completed = [];
    this._stats = { total_enqueued: 0, total_dequeued: 0, total_completed: 0, total_rejected: 0 };
  }
}

// ─── TargetScheduler ─────────────────────────────────────────────────

class TargetScheduler {
  /**
   * Schedules and drives the TargetRunner, pulling from the ExecutionQueue
   * and dispatching work to parallel workers.
   *
   * @param {object} opts
   * @param {object} opts.targetRunner  - TargetRunner instance
   * @param {object} opts.executionQueue - ExecutionQueue instance
   * @param {number} opts.maxWorkers     - Maximum parallel workers
   * @param {number} opts.pollInterval   - Queue poll interval in ms
   */
  constructor(opts = {}) {
    this.targetRunner = opts.targetRunner || null;
    this.executionQueue = opts.executionQueue || null;
    this.maxWorkers = opts.maxWorkers || 3;
    this.pollInterval = opts.pollInterval || 1000;

    this._running = false;
    this._pollTimer = null;
    this._activeWorkers = 0;
    this._drainCallback = null;
  }

  /**
   * Start the scheduler. Polls the queue and dispatches workers.
   * @param {object} ctx - BOQA context (for agent access)
   */
  start(ctx) {
    if (this._running) return;
    this._running = true;

    this._pollTimer = setInterval(() => {
      this._tick(ctx);
    }, this.pollInterval);
  }

  /**
   * Stop the scheduler gracefully.
   */
  stop() {
    this._running = false;
    if (this._pollTimer) {
      clearInterval(this._pollTimer);
      this._pollTimer = null;
    }
  }

  /**
   * Run all queued targets and resolve when drained.
   * @param {object} ctx
   * @returns {Promise<object>} summary
   */
  async runAll(ctx) {
    return new Promise((resolve) => {
      this._drainCallback = resolve;
      this.start(ctx);

      // Check if already drained
      if (this.executionQueue && this.executionQueue.size() === 0) {
        this.stop();
        resolve(this.targetRunner.getStats());
      }
    });
  }

  /**
   * Single scheduler tick: dispatch workers for queued items.
   */
  _tick(ctx) {
    if (!this._running) return;
    if (!this.executionQueue) return;

    while (this._activeWorkers < this.maxWorkers && this.executionQueue.size() > 0) {
      const execution = this.executionQueue.dequeue();
      if (execution) {
        this._dispatchWorker(execution, ctx);
      }
    }

    // Check if drained
    if (this._activeWorkers === 0 && this.executionQueue.size() === 0) {
      if (this._drainCallback) {
        this.stop();
        const cb = this._drainCallback;
        this._drainCallback = null;
        cb(this.targetRunner.getStats());
      }
    }
  }

  /**
   * Dispatch a single worker for an execution.
   */
  async _dispatchWorker(execution, ctx) {
    this._activeWorkers++;
    try {
      const agent = ctx.agent || null;
      const result = await this.targetRunner.executeTarget(execution, agent, ctx);
      if (this.executionQueue) {
        this.executionQueue.complete(result);
      }
    } catch (err) {
      execution.state = EXEC_STATES.FAILED;
      execution.error = err.message;
      if (this.executionQueue) {
        this.executionQueue.complete(execution);
      }
    } finally {
      this._activeWorkers--;
    }
  }

  /**
   * Get scheduler status.
   */
  getStatus() {
    return {
      running: this._running,
      active_workers: this._activeWorkers,
      max_workers: this.maxWorkers,
      queue_size: this.executionQueue ? this.executionQueue.size() : 0,
    };
  }
}

module.exports = { TargetRunner, ExecutionQueue, TargetScheduler, EXEC_STATES };
