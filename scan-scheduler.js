/**
 * BOQA scan-scheduler.js — ScanScheduler v0.9
 *
 * Schedules and parallelizes scanning tasks across targets and
 * campaigns. The scheduler converts optimization decisions into
 * concrete scan schedules, managing:
 *
 *   - Task queue: prioritized queue of scan tasks
 *   - Parallel execution: run multiple scans concurrently
 *   - Dependency ordering: respect task dependencies
 *   - Time windows: schedule scans for optimal time windows
 *   - Resource constraints: respect worker and budget limits
 *   - Retry logic: handle failed scans with backoff
 *   - Priority boosting: elevate tasks based on predictions
 *
 * Scheduling strategy:
 *   priority(task) = base_priority × prediction_boost ×
 *                    risk_multiplier × urgency_factor ×
 *                    dependency_readiness
 *
 * Where:
 *   base_priority      = from PriorityShaper (observed + predicted blend)
 *   prediction_boost   = yield_forecast / max_yield (0.5-2.0)
 *   risk_multiplier    = 1 + risk_score / 200 (1.0-1.5)
 *   urgency_factor     = deadline proximity scaling (1.0-2.0)
 *   dependency_readiness = 1.0 if deps met, 0.0 if not
 *
 * The scheduler supports:
 *   - Immediate scheduling (run now)
 *   - Deferred scheduling (run at optimal time)
 *   - Recurring scheduling (periodic re-scans)
 *   - Campaign scheduling (batch of related scans)
 *
 * Safe mode: scheduling only orchestrates authorized scan tasks;
 * it never initiates actions outside safe mode boundaries.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const SCHEDULER_DIR = path.join(__dirname, 'output', 'knowledge', 'scheduler');

// ─── Task States ────────────────────────────────────────────────────

const TASK_STATES = {
  PENDING:    'pending',
  QUEUED:     'queued',
  RUNNING:    'running',
  COMPLETED:  'completed',
  FAILED:     'failed',
  CANCELLED:  'cancelled',
  RETRYING:   'retrying',
  DEFERRED:   'deferred',
};

// ─── Task Types ─────────────────────────────────────────────────────

const TASK_TYPES = {
  FULL_SCAN:        'full_scan',
  TARGET_EXPLORE:   'target_explore',
  HYPOTHESIS_VERIFY:'hypothesis_verify',
  COVERAGE_SCAN:    'coverage_scan',
  REGRESSION_CHECK: 'regression_check',
  CATEGORY_SWEEP:   'category_sweep',
  DEEP_DIVE:        'deep_dive',
  BASELINE_CAPTURE: 'baseline_capture',
};

// ─── Default Scheduler Config ───────────────────────────────────────

const DEFAULT_SCHEDULER_CONFIG = {
  max_concurrent: 8,
  max_queue_size: 200,
  retry_limit: 3,
  retry_backoff_ms: 30000,
  schedule_tick_ms: 10000,      // 10 seconds
  deferred_check_ms: 60000,     // 1 minute
  max_task_duration_ms: 3600000, // 1 hour
  priority_decay_per_hour: 0.05,
  min_priority: 1,
  max_priority: 100,
};

// =====================================================================
//  ScanTask
// =====================================================================

class ScanTask {
  constructor(data = {}) {
    this.id = data.id || `TASK-${crypto.randomUUID().substring(0, 8)}`;
    this.type = data.type || TASK_TYPES.FULL_SCAN;
    this.target_id = data.target_id || null;
    this.campaign_id = data.campaign_id || null;
    this.category = data.category || null;
    this.endpoint = data.endpoint || null;

    // Priority and scheduling
    this.base_priority = data.base_priority || 50;
    this.computed_priority = data.computed_priority || 50;
    this.prediction_boost = data.prediction_boost || 1.0;
    this.risk_multiplier = data.risk_multiplier || 1.0;
    this.urgency_factor = data.urgency_factor || 1.0;

    // Dependencies
    this.depends_on = data.depends_on || [];  // task IDs
    this.dependency_readiness = data.dependency_readiness || 1.0;

    // Schedule
    this.scheduled_at = data.scheduled_at || null;   // when to run (null = now)
    this.started_at = data.started_at || null;
    this.completed_at = data.completed_at || null;
    this.deadline = data.deadline || null;

    // Recurring
    this.recurring = data.recurring || false;
    this.recur_interval_ms = data.recur_interval_ms || null;
    this.last_run_at = data.last_run_at || null;

    // State
    this.state = data.state || TASK_STATES.PENDING;
    this.assigned_worker = data.assigned_worker || null;
    this.retry_count = data.retry_count || 0;

    // Results
    this.result = data.result || null;
    this.error = data.error || null;

    // Metadata
    this.created_at = data.created_at || Date.now();
    this.updated_at = data.updated_at || Date.now();
    this.effort_estimate_ms = data.effort_estimate_ms || 300000; // 5 min default
    this.expected_yield = data.expected_yield || 0;
  }
}

// =====================================================================
//  ScanScheduler
// =====================================================================

class ScanScheduler {
  /**
   * @param {object} options
   * @param {object} [options.optimizerEngine]     - OptimizerEngine instance
   * @param {object} [options.predictionEngine]    - PredictionEngine instance
   * @param {object} [options.yieldForecaster]     - YieldForecaster instance
   * @param {object} [options.riskForecaster]      - RiskForecaster instance
   * @param {object} [options.priorityShaper]       - PriorityShaper instance
   * @param {object} [options.resourceOptimizer]    - ResourceOptimizer instance
   * @param {object} [options.campaignEngine]       - CampaignEngine instance
   * @param {object} [options.knowledgeBase]        - KnowledgeBase instance
   * @param {object} [options.brainRegistry]        - BrainRegistry instance
   * @param {object} [options.config]               - Override default config
   */
  constructor(options = {}) {
    this.optimizerEngine = options.optimizerEngine || null;
    this.predictionEngine = options.predictionEngine || null;
    this.yieldForecaster = options.yieldForecaster || null;
    this.riskForecaster = options.riskForecaster || null;
    this.priorityShaper = options.priorityShaper || null;
    this.resourceOptimizer = options.resourceOptimizer || null;
    this.campaignEngine = options.campaignEngine || null;
    this.kb = options.knowledgeBase || null;
    this.brainRegistry = options.brainRegistry || null;

    this.config = { ...DEFAULT_SCHEDULER_CONFIG, ...(options.config || {}) };

    // ── Task management ──────────────────────────────────────
    /** @type {Map<string, ScanTask>} task_id → task */
    this.tasks = new Map();

    /** @type {string[]} ordered task queue (highest priority first) */
    this.queue = [];

    /** @type {Set<string>} currently running task IDs */
    this.running = new Set();

    /** @type {Map<string, ScanTask>} completed tasks (last 200) */
    this.completed = new Map();

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_scheduled: 0,
      total_completed: 0,
      total_failed: 0,
      total_retried: 0,
      total_cancelled: 0,
      avg_completion_time_ms: 0,
      avg_queue_time_ms: 0,
      throughput_per_hour: 0,
      concurrent_utilization: 0,
      queue_depth: 0,
      deferred_count: 0,
      recurring_count: 0,
    };

    // ── Completion time tracking ─────────────────────────────
    this._completionTimes = [];
    this._queueTimes = [];
    this._hourlyCompletions = new Array(24).fill(0);
    this._lastHourReset = Date.now();

    // ── Schedule tick ────────────────────────────────────────
    this._tickTimer = setInterval(() => {
      this._tick();
    }, this.config.schedule_tick_ms);

    this._deferredTimer = setInterval(() => {
      this._checkDeferred();
    }, this.config.deferred_check_ms);

    // Ensure directory exists
    fs.mkdirSync(SCHEDULER_DIR, { recursive: true });

    // Auto-load
    this.load();
  }

  // ─── Task Scheduling ─────────────────────────────────────────────

  /**
   * Schedule a new scan task.
   *
   * @param {object} taskData
   * @returns {ScanTask}
   */
  schedule(taskData) {
    const task = new ScanTask(taskData);

    // Compute priority
    this._computePriority(task);

    // Check dependencies
    this._checkDependencies(task);

    // Add to task map
    this.tasks.set(task.id, task);
    this.metrics.total_scheduled++;

    // Queue or defer
    if (task.scheduled_at && task.scheduled_at > Date.now()) {
      task.state = TASK_STATES.DEFERRED;
      this.metrics.deferred_count++;
    } else if (task.dependency_readiness >= 1.0) {
      this._enqueue(task);
    } else {
      task.state = TASK_STATES.PENDING;
    }

    // Track recurring
    if (task.recurring) {
      this.metrics.recurring_count++;
    }

    return task;
  }

  /**
   * Schedule a batch of tasks (e.g., from a campaign).
   *
   * @param {object[]} taskDataList
   * @returns {ScanTask[]}
   */
  scheduleBatch(taskDataList) {
    return taskDataList.map(td => this.schedule(td));
  }

  /**
   * Schedule automatic scanning based on predictions and risk.
   * Generates tasks for all known targets based on current
   * optimization strategy.
   *
   * @returns {ScanTask[]}
   */
  scheduleAutoScan() {
    const tasks = [];
    const targetIds = this._collectTargetIds();
    const strategy = this.optimizerEngine
      ? this.optimizerEngine.currentStrategy
      : 'balanced';

    for (const targetId of targetIds) {
      // Get predicted yield for this target
      const predictedYield = this._getPredictedYield(targetId);
      const riskScore = this._getRiskScore(targetId);

      // Only schedule if yield prediction or risk justifies it
      if (predictedYield > 0.3 || riskScore > 50) {
        // Determine task type based on strategy and conditions
        let taskType = TASK_TYPES.FULL_SCAN;
        if (riskScore > 70) taskType = TASK_TYPES.REGRESSION_CHECK;
        else if (predictedYield > 1.0) taskType = TASK_TYPES.DEEP_DIVE;
        else if (predictedYield > 0.5) taskType = TASK_TYPES.TARGET_EXPLORE;

        tasks.push({
          target_id: targetId,
          type: taskType,
          base_priority: Math.min(100, Math.round(predictedYield * 50 + riskScore * 0.5)),
          prediction_boost: Math.max(0.5, Math.min(2.0, predictedYield)),
          risk_multiplier: 1 + riskScore / 200,
          expected_yield: predictedYield,
        });
      }
    }

    return this.scheduleBatch(tasks);
  }

  // ─── Task Execution Simulation ───────────────────────────────────

  /**
   * Start the next task in the queue (simulated execution).
   * In production, this dispatches to a WorkerPool.
   *
   * @returns {ScanTask|null}
   */
  startNext() {
    if (this.running.size >= this.config.max_concurrent) return null;
    if (this.queue.length === 0) return null;

    // Find highest-priority ready task
    for (let i = 0; i < this.queue.length; i++) {
      const taskId = this.queue[i];
      const task = this.tasks.get(taskId);
      if (!task) continue;

      // Check dependencies
      if (task.dependency_readiness < 1.0) continue;

      // Remove from queue
      this.queue.splice(i, 1);

      // Start the task
      task.state = TASK_STATES.RUNNING;
      task.started_at = Date.now();
      task.updated_at = Date.now();
      this.running.add(taskId);

      return task;
    }

    return null;
  }

  /**
   * Complete a running task.
   *
   * @param {string} taskId
   * @param {object} [result]
   */
  completeTask(taskId, result = null) {
    const task = this.tasks.get(taskId);
    if (!task || task.state !== TASK_STATES.RUNNING) return;

    task.state = TASK_STATES.COMPLETED;
    task.completed_at = Date.now();
    task.updated_at = Date.now();
    task.result = result;

    this.running.delete(taskId);
    this.completed.set(taskId, task);

    // Cap completed map
    if (this.completed.size > 200) {
      const oldest = [...this.completed.entries()]
        .sort((a, b) => a[1].completed_at - b[1].completed_at)[0];
      if (oldest) this.completed.delete(oldest[0]);
    }

    // Update metrics
    this.metrics.total_completed++;
    const duration = task.completed_at - task.started_at;
    this._completionTimes.push(duration);
    if (this._completionTimes.length > 100) this._completionTimes = this._completionTimes.slice(-100);
    this.metrics.avg_completion_time_ms = this._completionTimes.length > 0
      ? Math.round(this._completionTimes.reduce((s, t) => s + t, 0) / this._completionTimes.length)
      : 0;

    if (task.started_at) {
      const queueTime = task.started_at - task.created_at;
      this._queueTimes.push(queueTime);
      if (this._queueTimes.length > 100) this._queueTimes = this._queueTimes.slice(-100);
      this.metrics.avg_queue_time_ms = this._queueTimes.length > 0
        ? Math.round(this._queueTimes.reduce((s, t) => s + t, 0) / this._queueTimes.length)
        : 0;
    }

    // Track hourly completions
    const hour = new Date().getHours();
    this._hourlyCompletions[hour]++;

    // Compute throughput
    this._computeThroughput();

    // Handle recurring tasks
    if (task.recurring && task.recur_interval_ms) {
      this.schedule({
        ...task,
        id: undefined,
        state: TASK_STATES.PENDING,
        scheduled_at: Date.now() + task.recur_interval_ms,
        started_at: null,
        completed_at: null,
        result: null,
        error: null,
        retry_count: 0,
        assigned_worker: null,
        last_run_at: Date.now(),
        created_at: Date.now(),
        updated_at: Date.now(),
      });
    }
  }

  /**
   * Fail a running task.
   *
   * @param {string} taskId
   * @param {string} [error]
   */
  failTask(taskId, error = 'unknown') {
    const task = this.tasks.get(taskId);
    if (!task || task.state !== TASK_STATES.RUNNING) return;

    task.error = error;
    task.updated_at = Date.now();
    this.running.delete(taskId);

    if (task.retry_count < this.config.retry_limit) {
      task.state = TASK_STATES.RETRYING;
      task.retry_count++;
      this.metrics.total_retried++;

      // Re-queue with backoff
      const backoff = this.config.retry_backoff_ms * Math.pow(2, task.retry_count - 1);
      task.scheduled_at = Date.now() + backoff;
      task.state = TASK_STATES.DEFERRED;
    } else {
      task.state = TASK_STATES.FAILED;
      this.metrics.total_failed++;
      this.completed.set(taskId, task);
    }
  }

  /**
   * Cancel a task.
   *
   * @param {string} taskId
   */
  cancelTask(taskId) {
    const task = this.tasks.get(taskId);
    if (!task) return;

    if (task.state === TASK_STATES.RUNNING) {
      this.running.delete(taskId);
    }

    // Remove from queue
    const idx = this.queue.indexOf(taskId);
    if (idx !== -1) this.queue.splice(idx, 1);

    task.state = TASK_STATES.CANCELLED;
    task.updated_at = Date.now();
    this.metrics.total_cancelled++;
  }

  // ─── Schedule Tick ────────────────────────────────────────────────

  _tick() {
    // Start tasks up to max concurrency
    while (this.running.size < this.config.max_concurrent && this.queue.length > 0) {
      const task = this.startNext();
      if (!task) break;

      // Simulate auto-completion for tasks (in real mode, WorkerPool handles this)
      // Here we just mark it as started; completion is event-driven
    }

    // Update utilization metric
    this.metrics.concurrent_utilization = this.config.max_concurrent > 0
      ? Math.round(this.running.size / this.config.max_concurrent * 100) / 100
      : 0;

    this.metrics.queue_depth = this.queue.length;

    // Reset hourly counts if needed
    if (Date.now() - this._lastHourReset > 3600000) {
      this._hourlyCompletions = new Array(24).fill(0);
      this._lastHourReset = Date.now();
    }
  }

  _checkDeferred() {
    const now = Date.now();

    for (const [taskId, task] of this.tasks) {
      if (task.state === TASK_STATES.DEFERRED && task.scheduled_at && task.scheduled_at <= now) {
        this._enqueue(task);
      }

      // Check for timed-out running tasks
      if (task.state === TASK_STATES.RUNNING && task.started_at) {
        if (now - task.started_at > this.config.max_task_duration_ms) {
          this.failTask(taskId, 'timeout');
        }
      }
    }
  }

  // ─── Priority Computation ─────────────────────────────────────────

  _computePriority(task) {
    // Base priority from shaper or raw
    let basePriority = task.base_priority;

    // Boost from yield predictions
    let predictionBoost = task.prediction_boost || 1.0;
    if (this.yieldForecaster && task.target_id) {
      const forecast = this.yieldForecaster.getTargetForecast(task.target_id);
      if (forecast) {
        predictionBoost = Math.max(0.5, Math.min(2.0, forecast.expected_bugs));
        task.prediction_boost = predictionBoost;
      }
    }

    // Risk multiplier
    let riskMultiplier = task.risk_multiplier || 1.0;
    if (this.riskForecaster && task.target_id) {
      const riskForecast = this.riskForecaster.getTargetForecast(task.target_id);
      if (riskForecast) {
        riskMultiplier = 1 + riskForecast.risk_score / 200;
        task.risk_multiplier = riskMultiplier;
      }
    }

    // Urgency factor (deadline proximity)
    let urgencyFactor = 1.0;
    if (task.deadline) {
      const timeRemaining = task.deadline - Date.now();
      if (timeRemaining < 3600000) urgencyFactor = 2.0; // < 1 hour
      else if (timeRemaining < 14400000) urgencyFactor = 1.5; // < 4 hours
      else if (timeRemaining < 86400000) urgencyFactor = 1.2; // < 24 hours
      task.urgency_factor = urgencyFactor;
    }

    // Dependency readiness
    this._checkDependencies(task);

    // Compute final priority
    const computedPriority = Math.round(
      Math.min(this.config.max_priority,
        basePriority * predictionBoost * riskMultiplier * urgencyFactor * task.dependency_readiness
      )
    );

    task.computed_priority = Math.max(this.config.min_priority, computedPriority);
    task.updated_at = Date.now();
  }

  _checkDependencies(task) {
    if (task.depends_on.length === 0) {
      task.dependency_readiness = 1.0;
      return;
    }

    let ready = 0;
    for (const depId of task.depends_on) {
      const dep = this.tasks.get(depId);
      if (dep && dep.state === TASK_STATES.COMPLETED) {
        ready++;
      }
    }

    task.dependency_readiness = task.depends_on.length > 0
      ? ready / task.depends_on.length
      : 1.0;
  }

  // ─── Queue Management ─────────────────────────────────────────────

  _enqueue(task) {
    if (this.queue.length >= this.config.max_queue_size) {
      // Drop lowest priority task
      const lastId = this.queue[this.queue.length - 1];
      const lastTask = this.tasks.get(lastId);
      if (lastTask && lastTask.computed_priority < task.computed_priority) {
        this.cancelTask(lastId);
      } else {
        return; // Can't enqueue
      }
    }

    task.state = TASK_STATES.QUEUED;
    task.updated_at = Date.now();
    this.queue.push(task.id);

    // Keep queue sorted by priority (highest first)
    this.queue.sort((a, b) => {
      const taskA = this.tasks.get(a);
      const taskB = this.tasks.get(b);
      return (taskB?.computed_priority || 0) - (taskA?.computed_priority || 0);
    });
  }

  // ─── Helper Methods ───────────────────────────────────────────────

  _getPredictedYield(targetId) {
    if (!this.predictionEngine) return 0.5;
    const prediction = this.predictionEngine.getTargetPrediction(targetId);
    return prediction ? prediction.predicted_yield : 0.5;
  }

  _getRiskScore(targetId) {
    if (!this.riskForecaster) return 30;
    const forecast = this.riskForecaster.getTargetForecast(targetId);
    return forecast ? forecast.risk_score : 30;
  }

  _collectTargetIds() {
    const ids = new Set();
    if (this.brainRegistry) {
      for (const [id] of this.brainRegistry.brains) ids.add(id);
    }
    if (this.kb) {
      for (const [id] of this.kb.assets) ids.add(id);
    }
    if (this.campaignEngine) {
      for (const [, c] of this.campaignEngine.campaigns) {
        for (const tid of c.target_ids) ids.add(tid);
      }
    }
    return [...ids];
  }

  _computeThroughput() {
    const now = Date.now();
    const recentCompleted = [...this.completed.values()].filter(
      t => t.completed_at && now - t.completed_at < 3600000
    );
    this.metrics.throughput_per_hour = recentCompleted.length;
  }

  // ─── Query Methods ──────────────────────────────────────────────

  getQueue() {
    return this.queue.map(id => this.tasks.get(id)).filter(Boolean);
  }

  getRunning() {
    return [...this.running].map(id => this.tasks.get(id)).filter(Boolean);
  }

  getTask(taskId) {
    return this.tasks.get(taskId) || null;
  }

  getSchedule() {
    return {
      queue: this.getQueue().map(t => ({
        id: t.id,
        type: t.type,
        target_id: t.target_id,
        priority: t.computed_priority,
        state: t.state,
        scheduled_at: t.scheduled_at,
      })),
      running: this.getRunning().map(t => ({
        id: t.id,
        type: t.type,
        target_id: t.target_id,
        started_at: t.started_at,
        effort_estimate_ms: t.effort_estimate_ms,
      })),
      pending: [...this.tasks.values()]
        .filter(t => t.state === TASK_STATES.PENDING || t.state === TASK_STATES.DEFERRED)
        .map(t => ({
          id: t.id,
          type: t.type,
          target_id: t.target_id,
          state: t.state,
          scheduled_at: t.scheduled_at,
          priority: t.computed_priority,
        })),
    };
  }

  getMetrics() {
    this._computeThroughput();
    return {
      ...this.metrics,
      concurrent_utilization: this.config.max_concurrent > 0
        ? Math.round(this.running.size / this.config.max_concurrent * 100) / 100
        : 0,
      queue_depth: this.queue.length,
      total_tasks: this.tasks.size,
      hourly_distribution: this._hourlyCompletions,
    };
  }

  // ─── Persistence ────────────────────────────────────────────────

  save() {
    const filePath = path.join(SCHEDULER_DIR, 'scheduler-state.json');
    const data = {
      version: '0.9',
      saved_at: Date.now(),
      tasks: [...this.tasks.entries()].slice(-200),
      queue: this.queue.slice(0, 100),
      completed: [...this.completed.entries()].slice(-100),
      metrics: this.metrics,
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(SCHEDULER_DIR, 'scheduler-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      this.tasks = new Map(
        (data.tasks || []).map(([k, v]) => [k, new ScanTask(v)])
      );
      this.queue = data.queue || [];
      this.completed = new Map(
        (data.completed || []).map(([k, v]) => [k, new ScanTask(v)])
      );
      this.metrics = { ...this.metrics, ...(data.metrics || {}) };
      return true;
    } catch (_) {
      return false;
    }
  }

  shutdown() {
    if (this._tickTimer) clearInterval(this._tickTimer);
    if (this._deferredTimer) clearInterval(this._deferredTimer);
    this.save();
  }
}

module.exports = {
  ScanScheduler,
  ScanTask,
  TASK_STATES,
  TASK_TYPES,
  DEFAULT_SCHEDULER_CONFIG,
  SCHEDULER_DIR,
};

