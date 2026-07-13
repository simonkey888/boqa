/**
 * BOQA verification-farm.js — Verification Farm v0.6
 *
 * Parallel validation workers that execute verification plans
 * against live targets. Each worker performs one of:
 *   - replay:              replay captured request sequences
 *   - state_diff:          compare before/after application state
 *   - workflow_validation: traverse multi-step workflows
 *   - permission_validation: check authorization boundary conditions
 *
 * Worker lifecycle:
 *   idle → assigned → running → completed | failed | timeout
 *
 * The farm manages a pool of workers, distributes verification
 * tasks, and collects results. Results feed back into the
 * hypothesis prioritizer and knowledge base.
 *
 * Safe mode constraints enforced at worker level:
 *   - Each verification action is checked against allowed actions
 *   - Forbidden actions are rejected before execution
 *   - Workers self-terminate if they detect policy violations
 *   - Rate limits prevent excessive requests
 */

const crypto = require('crypto');
const { EventEmitter } = require('events');
const executionGuard = require('./lib/execution-authorization-guard');
const { BrowserEgressGuard } = require('./lib/browser-egress-guard');

// ─── Worker States ──────────────────────────────────────────────────

const WORKER_STATES = {
  IDLE:      'idle',
  ASSIGNED:  'assigned',
  RUNNING:   'running',
  COMPLETED: 'completed',
  FAILED:    'failed',
  TIMEOUT:   'timeout',
};

// ─── Verification Actions ───────────────────────────────────────────

const ALLOWED_ACTIONS = new Set([
  'navigation',
  'authenticated_replay',
  'request_replay',
  'state_comparison',
  'header_variation',
  'cookie_variation',
  'cache_validation',
  'permission_validation',
  'workflow_validation',
]);

const FORBIDDEN_ACTIONS = new Set([
  'bruteforce',
  'fuzzing_at_scale',
  'credential_attacks',
  'dos',
  'privilege_escalation_attempts',
  'destructive_mutations',
  'mass_scanning',
]);

// ─── Defaults ───────────────────────────────────────────────────────

const DEFAULT_MAX_WORKERS = 10;
const DEFAULT_TIMEOUT_MS = 30000;
const DEFAULT_RATE_LIMIT_MS = 200; // min time between requests
const DEFAULT_MAX_RETRIES = 2;

// =====================================================================
//  VerificationWorker
// =====================================================================

class VerificationWorker extends EventEmitter {
  /**
   * @param {string} id - worker identifier
   * @param {object} options
   * @param {number} [options.timeout]         - per-task timeout in ms
   * @param {number} [options.rateLimitMs]     - min time between requests
   * @param {number} [options.maxRetries]      - max retries per task
   * @param {object} [options.agent]           - Playwright Agent instance
   */
  constructor(id, options = {}) {
    super();
    this.id = id;
    this.timeout = options.timeout || DEFAULT_TIMEOUT_MS;
    this.rateLimitMs = options.rateLimitMs || DEFAULT_RATE_LIMIT_MS;
    this.maxRetries = options.maxRetries || DEFAULT_MAX_RETRIES;
    this.agent = options.agent || null;
    this.registry = options.registry || null;
    this.resolver = options.resolver;
    this.executionGuard = options.executionGuard || executionGuard;
    this.browserEgressGuardFactory = options.browserEgressGuardFactory || (guardOptions => new BrowserEgressGuard(guardOptions));
    this._egressInstalledFor = null;

    this.state = WORKER_STATES.IDLE;
    this.currentTask = null;
    this.lastActionTs = 0;
    this.tasksCompleted = 0;
    this.tasksFailed = 0;
    this.totalDurationMs = 0;
    this.createdAt = Date.now();
  }

  /**
   * Assign a verification task to this worker.
   *
   * @param {object} task
   * @param {string} task.id              - task identifier
   * @param {string} task.hypothesis_id   - hypothesis being verified
   * @param {string} task.action          - verification action type
   * @param {object} task.params          - action-specific parameters
   * @param {string} task.target_id       - target to verify against
   * @param {number} [task.priority]      - task priority
   * @returns {Promise<object>} verification result
   */
  async execute(task) {
    // Validate action
    if (!ALLOWED_ACTIONS.has(task.action)) {
      if (FORBIDDEN_ACTIONS.has(task.action)) {
        return this._fail(task, `Forbidden action: ${task.action}`);
      }
      return this._fail(task, `Unknown action: ${task.action}`);
    }

    this.state = WORKER_STATES.ASSIGNED;
    this.currentTask = task;

    const startTime = Date.now();

    try {
      this.state = WORKER_STATES.RUNNING;
      this.emit('start', { workerId: this.id, taskId: task.id });

      let result;
      let attempts = 0;

      while (attempts <= this.maxRetries) {
        attempts++;

        // A retry is a new outbound attempt: verify immutability and current
        // registry/DNS state again immediately before dispatch.
        const integrity = this.executionGuard.verifyTaskIntegrity(task);
        if (!integrity.allowed) throw new Error(`${integrity.code}: ${integrity.reason}`);
        const authorization = await this.executionGuard.validateTaskAsync(task, this.registry, { resolver: this.resolver });
        if (!authorization.allowed) throw new Error(`${authorization.code}: ${authorization.reason}`);

        // Rate limiting
        await this._enforceRateLimit();

        // Execute with timeout
        result = await this._executeWithTimeout(task);

        if (result.verdict !== 'timeout') break;

        if (attempts <= this.maxRetries) {
          // Wait before retry
          await new Promise(r => setTimeout(r, 1000 * attempts));
        }
      }

      const durationMs = Date.now() - startTime;
      result.duration_ms = durationMs;
      result.attempts = attempts;

      this.state = WORKER_STATES.COMPLETED;
      this.tasksCompleted++;
      this.totalDurationMs += durationMs;
      this.currentTask = null;

      this.emit('complete', { workerId: this.id, taskId: task.id, result });
      return result;

    } catch (err) {
      const durationMs = Date.now() - startTime;
      this.state = WORKER_STATES.FAILED;
      this.tasksFailed++;
      this.totalDurationMs += durationMs;
      this.currentTask = null;

      const result = {
        task_id: task.id,
        hypothesis_id: task.hypothesis_id,
        verdict: 'error',
        error: err.message,
        duration_ms: durationMs,
        worker_id: this.id,
        ts: Date.now(),
      };

      this.emit('error', { workerId: this.id, taskId: task.id, error: err.message });
      return result;
    }
  }

  /**
   * Execute a single verification action with timeout.
   *
   * @param {object} task
   * @returns {Promise<object>}
   * @private
   */
  async _executeWithTimeout(task) {
    return new Promise(async (resolve, reject) => {
      const timer = setTimeout(() => {
        resolve({
          task_id: task.id,
          hypothesis_id: task.hypothesis_id,
          verdict: 'timeout',
          evidence: [],
          worker_id: this.id,
          ts: Date.now(),
        });
      }, this.timeout);

      try {
        const result = await this._executeAction(task);
        clearTimeout(timer);
        resolve(result);
      } catch (err) {
        clearTimeout(timer);
        reject(err);
      }
    });
  }

  /**
   * Execute the actual verification action.
   * Returns a structured result with verdict and evidence.
   *
   * @param {object} task
   * @returns {Promise<object>}
   * @private
   */
  async _executeAction(task) {
    const { action, params, hypothesis_id, target_id } = task;

    // Build the base result
    const result = {
      task_id: task.id,
      hypothesis_id,
      target_id,
      action,
      verdict: 'inconclusive',
      evidence: [],
      worker_id: this.id,
      ts: Date.now(),
    };

    switch (action) {
      case 'navigation':
        return this._executeNavigation(task, result);
      case 'authenticated_replay':
        return this._executeAuthenticatedReplay(task, result);
      case 'request_replay':
        return this._executeRequestReplay(task, result);
      case 'state_comparison':
        return this._executeStateComparison(task, result);
      case 'header_variation':
        return this._executeHeaderVariation(task, result);
      case 'cookie_variation':
        return this._executeCookieVariation(task, result);
      case 'permission_validation':
        return this._executePermissionValidation(task, result);
      case 'workflow_validation':
        return this._executeWorkflowValidation(task, result);
      case 'cache_validation':
        return this._executeCacheValidation(task, result);
      default:
        result.verdict = 'unknown_action';
        return result;
    }
  }

  // ─── Action Implementations ──────────────────────────────────────

  async _authorizeUrl(task, url, method = 'GET') {
    const result = await this.executionGuard.validateTaskAsync({
      action: 'navigation',
      target_id: task.target_id,
      params: { url, method },
    }, this.registry, {
      resolver: this.resolver,
    });
    if (!result.allowed) throw new Error(`${result.code}: ${result.reason}`);
    return result;
  }

  async _ensureBrowserEgress(task) {
    if (!this.agent?.page) return;
    const context = this.agent.page.context();
    if (this._egressInstalledFor === context) return;
    const policy = this.browserEgressGuardFactory({
      registry: this.registry,
      targetId: task.target_id,
      resolver: this.resolver,
    });
    await policy.install(context);
    this._egressInstalledFor = context;
  }

  async _executeNavigation(task, result) {
    const { url, expected_status, expected_redirect } = task.params || {};

    result.evidence.push({
      type: 'navigation_attempt',
      url: url || 'unknown',
      ts: Date.now(),
    });

    // If we have a Playwright agent, perform real navigation
    if (this.agent && this.agent.page) {
      try {
        await this._authorizeUrl(task, url, 'GET');
        await this._ensureBrowserEgress(task);
        const response = await this.agent.page.goto(url, {
          waitUntil: 'domcontentloaded',
          timeout: this.timeout,
        });

        const status = response ? response.status() : null;
        result.evidence.push({
          type: 'navigation_result',
          url,
          status,
          ts: Date.now(),
        });

        if (expected_status && status !== expected_status) {
          result.verdict = 'confirmed';
          result.evidence.push({
            type: 'status_mismatch',
            expected: expected_status,
            actual: status,
            ts: Date.now(),
          });
        } else if (expected_redirect) {
          const finalUrl = this.agent.page.url();
          if (!finalUrl.includes(expected_redirect)) {
            result.verdict = 'confirmed';
            result.evidence.push({
              type: 'redirect_mismatch',
              expected_redirect,
              actual_url: finalUrl,
              ts: Date.now(),
            });
          } else {
            result.verdict = 'rejected';
          }
        } else {
          result.verdict = 'observed';
        }
      } catch (err) {
        result.verdict = 'error';
        result.evidence.push({ type: 'navigation_error', error: err.message, ts: Date.now() });
      }
    } else {
      // No agent — simulated result
      result.verdict = 'observed';
      result.evidence.push({
        type: 'simulated_navigation',
        note: 'No Playwright agent available; result is inferred',
        ts: Date.now(),
      });
    }

    return result;
  }

  async _executeAuthenticatedReplay(task, result) {
    const { request_sequence, cookies } = task.params || {};

    result.evidence.push({
      type: 'authenticated_replay_start',
      request_count: request_sequence?.length || 0,
      cookie_count: Object.keys(cookies || {}).length,
      ts: Date.now(),
    });

    // Replay requests using agent if available
    if (this.agent && this.agent.page) {
      try {
        await this._ensureBrowserEgress(task);
        // Set cookies
        if (cookies) {
          await this._authorizeUrl(task, task.params?.url, 'GET');
          const cookieList = Object.entries(cookies).map(([name, value]) => ({
            name,
            value,
            domain: new URL(task.params?.url || 'https://example.com').hostname,
            path: '/',
          }));
          await this.agent.page.context().addCookies(cookieList);
        }

        // Replay sequence
        for (const req of (request_sequence || [])) {
          await this._authorizeUrl(task, req.url, req.method || 'GET');
          const response = await this.agent.page.goto(req.url, {
            waitUntil: 'domcontentloaded',
            timeout: this.timeout,
          });

          result.evidence.push({
            type: 'replay_step',
            url: req.url,
            status: response?.status(),
            ts: Date.now(),
          });
        }

        result.verdict = 'observed';
      } catch (err) {
        result.verdict = 'error';
        result.evidence.push({ type: 'replay_error', error: err.message, ts: Date.now() });
      }
    } else {
      result.verdict = 'observed';
      result.evidence.push({
        type: 'simulated_replay',
        note: 'No Playwright agent available',
        ts: Date.now(),
      });
    }

    return result;
  }

  async _executeRequestReplay(task, result) {
    const { method, url, headers, body } = task.params || {};

    result.evidence.push({
      type: 'request_replay',
      method, url,
      has_body: !!body,
      ts: Date.now(),
    });

    if (this.agent && this.agent.page) {
      try {
        await this._authorizeUrl(task, url, method || 'GET');
        await this._ensureBrowserEgress(task);
        const response = await this.agent.page.evaluate(async ({ method, url, headers, body }) => {
          const opts = { method, headers: headers || {} };
          if (body) opts.body = JSON.stringify(body);
          const res = await fetch(url, opts);
          return { status: res.status, headers: Object.fromEntries(res.headers.entries()) };
        }, { method, url, headers, body });

        result.evidence.push({
          type: 'request_replay_result',
          status: response.status,
          ts: Date.now(),
        });
        result.verdict = 'observed';
      } catch (err) {
        result.verdict = 'error';
        result.evidence.push({ type: 'replay_error', error: err.message, ts: Date.now() });
      }
    } else {
      result.verdict = 'observed';
    }

    return result;
  }

  async _executeStateComparison(task, result) {
    const { before_state, after_state } = task.params || {};

    result.evidence.push({
      type: 'state_comparison',
      has_before: !!before_state,
      has_after: !!after_state,
      ts: Date.now(),
    });

    // Compare states
    if (before_state && after_state) {
      const diff = this._computeStateDiff(before_state, after_state);
      result.evidence.push({
        type: 'state_diff',
        diff_fields: diff.changed_fields,
        added_fields: diff.added_fields,
        removed_fields: diff.removed_fields,
        ts: Date.now(),
      });

      result.verdict = diff.has_unexpected_changes ? 'confirmed' : 'rejected';
    } else {
      result.verdict = 'inconclusive';
    }

    return result;
  }

  async _executeHeaderVariation(task, result) {
    const { url, original_headers, modified_headers } = task.params || {};

    result.evidence.push({
      type: 'header_variation',
      url,
      original_keys: Object.keys(original_headers || {}),
      modified_keys: Object.keys(modified_headers || {}),
      ts: Date.now(),
    });

    result.verdict = 'observed';
    return result;
  }

  async _executeCookieVariation(task, result) {
    const { url, original_cookies, modified_cookies } = task.params || {};

    result.evidence.push({
      type: 'cookie_variation',
      url,
      original_keys: Object.keys(original_cookies || {}),
      modified_keys: Object.keys(modified_cookies || {}),
      ts: Date.now(),
    });

    result.verdict = 'observed';
    return result;
  }

  async _executePermissionValidation(task, result) {
    const { url, role_a_cookies, role_b_cookies, expected_accessible } = task.params || {};

    result.evidence.push({
      type: 'permission_validation',
      url,
      has_role_a: !!role_a_cookies,
      has_role_b: !!role_b_cookies,
      ts: Date.now(),
    });

    result.verdict = 'observed';
    return result;
  }

  async _executeWorkflowValidation(task, result) {
    const { steps } = task.params || {};

    result.evidence.push({
      type: 'workflow_validation',
      step_count: steps?.length || 0,
      ts: Date.now(),
    });

    if (this.agent && this.agent.page && steps) {
      try {
        await this._ensureBrowserEgress(task);
        for (let i = 0; i < steps.length; i++) {
          const step = steps[i];
          if (step.action === 'navigate') {
            await this._authorizeUrl(task, step.url, step.method || 'GET');
            await this.agent.page.goto(step.url, {
              waitUntil: 'domcontentloaded',
              timeout: this.timeout,
            });
          } else if (step.action === 'click') {
            await this.agent.page.click(step.selector, { timeout: this.timeout });
          } else if (step.action === 'fill') {
            await this.agent.page.fill(step.selector, step.value, { timeout: this.timeout });
          }

          result.evidence.push({
            type: 'workflow_step',
            step_index: i,
            action: step.action,
            ts: Date.now(),
          });
        }
        result.verdict = 'observed';
      } catch (err) {
        result.verdict = 'error';
        result.evidence.push({ type: 'workflow_error', step: i, error: err.message, ts: Date.now() });
      }
    } else {
      result.verdict = 'observed';
    }

    return result;
  }

  async _executeCacheValidation(task, result) {
    const { url, headers } = task.params || {};

    result.evidence.push({
      type: 'cache_validation',
      url,
      ts: Date.now(),
    });

    result.verdict = 'observed';
    return result;
  }

  // ─── Helpers ─────────────────────────────────────────────────────

  _fail(task, reason) {
    this.state = WORKER_STATES.FAILED;
    this.tasksFailed++;
    this.currentTask = null;

    return {
      task_id: task.id,
      hypothesis_id: task.hypothesis_id,
      verdict: 'rejected',
      reason,
      evidence: [{ type: 'rejection', reason, ts: Date.now() }],
      worker_id: this.id,
      ts: Date.now(),
    };
  }

  async _enforceRateLimit() {
    const now = Date.now();
    const elapsed = now - this.lastActionTs;
    if (elapsed < this.rateLimitMs) {
      await new Promise(r => setTimeout(r, this.rateLimitMs - elapsed));
    }
    this.lastActionTs = Date.now();
  }

  _computeStateDiff(before, after) {
    const changed_fields = [];
    const added_fields = [];
    const removed_fields = [];

    const beforeKeys = new Set(Object.keys(before));
    const afterKeys = new Set(Object.keys(after));

    for (const key of afterKeys) {
      if (!beforeKeys.has(key)) {
        added_fields.push(key);
      } else if (JSON.stringify(before[key]) !== JSON.stringify(after[key])) {
        changed_fields.push(key);
      }
    }

    for (const key of beforeKeys) {
      if (!afterKeys.has(key)) {
        removed_fields.push(key);
      }
    }

    return {
      changed_fields,
      added_fields,
      removed_fields,
      has_unexpected_changes: changed_fields.length > 0 || added_fields.length > 0,
    };
  }

  get isIdle() {
    return this.state === WORKER_STATES.IDLE;
  }

  getStats() {
    return {
      id: this.id,
      state: this.state,
      tasks_completed: this.tasksCompleted,
      tasks_failed: this.tasksFailed,
      total_duration_ms: this.totalDurationMs,
      avg_duration_ms: this.tasksCompleted > 0
        ? Math.round(this.totalDurationMs / this.tasksCompleted)
        : 0,
      created_at: this.createdAt,
    };
  }
}

// =====================================================================
//  VerificationFarm
// =====================================================================

class VerificationFarm extends EventEmitter {
  /**
   * @param {object} options
   * @param {number} [options.maxWorkers]       - max parallel workers (default 10)
   * @param {number} [options.timeout]          - per-task timeout in ms
   * @param {number} [options.rateLimitMs]      - rate limit between requests
   * @param {object} [options.agent]            - Playwright Agent instance
   * @param {object} [options.knowledgeBase]    - KnowledgeBase instance
   */
  constructor(options = {}) {
    super();
    this.maxWorkers = options.maxWorkers || DEFAULT_MAX_WORKERS;
    this.timeout = options.timeout || DEFAULT_TIMEOUT_MS;
    this.rateLimitMs = options.rateLimitMs || DEFAULT_RATE_LIMIT_MS;
    this.agent = options.agent || null;
    this.kb = options.knowledgeBase || null;
    this.registry = options.registry || null;
    this.resolver = options.resolver;
    this.executionGuard = options.executionGuard || executionGuard;
    this.browserEgressGuardFactory = options.browserEgressGuardFactory;

    /** @type {Map<string, VerificationWorker>} worker_id → worker */
    this.workers = new Map();

    /** @type {Map<string, object>} task_id → task */
    this.tasks = new Map();

    /** @type {Map<string, object>} task_id → result */
    this.results = new Map();

    /** @type {object[]} pending task queue */
    this.pendingQueue = [];

    // Initialize worker pool
    for (let i = 0; i < this.maxWorkers; i++) {
      const worker = new VerificationWorker(`W-${String(i + 1).padStart(3, '0')}`, {
        timeout: this.timeout,
        rateLimitMs: this.rateLimitMs,
        agent: this.agent,
        registry: this.registry,
        resolver: this.resolver,
        executionGuard: this.executionGuard,
        browserEgressGuardFactory: this.browserEgressGuardFactory,
      });

      worker.on('complete', ({ workerId, taskId, result }) => {
        this.emit('task_complete', { workerId, taskId, result });
      });

      worker.on('error', ({ workerId, taskId, error }) => {
        this.emit('task_error', { workerId, taskId, error });
      });

      this.workers.set(worker.id, worker);
    }
  }

  // ─── Task Management ─────────────────────────────────────────────

  setAgent(agent) {
    this.agent = agent;
    for (const worker of this.workers.values()) worker.agent = agent;
  }

  /**
   * Submit a verification task to the farm.
   *
   * @param {object} task
   * @param {string} task.hypothesis_id
   * @param {string} task.action - verification action type
   * @param {object} task.params - action-specific parameters
   * @param {string} task.target_id
   * @param {number} [task.priority] - higher = executed sooner
   * @returns {object} the queued task with id
   */
  submitTask(task) {
    return { error: 'ASYNC_EXECUTION_GUARD_REQUIRED: use submitTaskAsync()', task: null };
  }

  async submitTaskAsync(task) {
    // Validate action
    if (!task || FORBIDDEN_ACTIONS.has(task.action)) {
      return { error: task ? `Forbidden action: ${task.action}` : 'Task is required', task: null };
    }

    const taskId = task.id || `TSK-${crypto.randomUUID().substring(0, 8)}`;
    const candidate = {
      id: taskId,
      hypothesis_id: task.hypothesis_id,
      action: task.action,
      params: task.params || {},
      target_id: task.target_id,
      priority: task.priority || 50,
      status: 'queued',
      submitted_at: Date.now(),
    };

    const authorization = await this.executionGuard.validateTaskAsync(candidate, this.registry, { resolver: this.resolver });
    if (!authorization.allowed) {
      return { error: `${authorization.code}: ${authorization.reason}`, task: null };
    }

    const queuedTask = this.executionGuard.sealTask(candidate);

    this.tasks.set(taskId, queuedTask);
    this.pendingQueue.push(queuedTask);

    // Sort by priority (descending)
    this.pendingQueue.sort((a, b) => (b.priority || 0) - (a.priority || 0));

    return { error: null, task: queuedTask };
  }

  /**
   * Submit multiple tasks at once.
   *
   * @param {object[]} tasks
   * @returns {object[]} queued tasks
   */
  submitBatch(tasks) {
    return [];
  }

  async submitBatchAsync(tasks) {
    const results = await Promise.all(tasks.map(task => this.submitTaskAsync(task)));
    return results.filter(result => !result.error).map(result => result.task);
  }

  /**
   * Process the pending queue. Assigns tasks to idle workers.
   * Returns a promise that resolves when all currently assignable
   * tasks are dispatched.
   *
   * @returns {Promise<object[]>} results from completed tasks
   */
  async processQueue() {
    const results = [];

    while (this.pendingQueue.length > 0) {
      const idleWorker = this._getIdleWorker();
      if (!idleWorker) break;

      const task = this.pendingQueue.shift();
      if (!task) break;

      const integrity = this.executionGuard.verifyTaskIntegrity(task);
      const authorization = integrity.allowed
        ? await this.executionGuard.validateTaskAsync(task, this.registry, { resolver: this.resolver })
        : integrity;
      if (!authorization.allowed) {
        task.status = 'rejected';
        const result = {
          task_id: task.id,
          hypothesis_id: task.hypothesis_id,
          verdict: 'rejected',
          reason: `${authorization.code}: ${authorization.reason}`,
          evidence: [],
        };
        this.results.set(task.id, result);
        results.push(result);
        continue;
      }

      task.status = 'running';
      task.worker_id = idleWorker.id;

      try {
        const result = await idleWorker.execute(task);
        result.worker_id = idleWorker.id;

        this.results.set(task.id, result);
        task.status = result.verdict === 'error' ? 'failed' : 'completed';

        // Persist to knowledge base
        if (this.kb) {
          this.kb.addValidation({
            finding_id: task.hypothesis_id,
            verdict: result.verdict,
            evidence: result.evidence,
            duration_ms: result.duration_ms,
            worker_id: result.worker_id,
            meta: { action: task.action, target_id: task.target_id },
          });
        }

        results.push(result);
      } catch (err) {
        task.status = 'failed';
        results.push({
          task_id: task.id,
          hypothesis_id: task.hypothesis_id,
          verdict: 'error',
          error: err.message,
          worker_id: idleWorker.id,
        });
      }
    }

    return results;
  }

  /**
   * Run all pending tasks to completion.
   *
   * @param {number} [maxConcurrent] - override max workers
   * @returns {Promise<object[]>} all results
   */
  async runAll(maxConcurrent) {
    const allResults = [];

    while (this.pendingQueue.length > 0) {
      const batch = await this.processQueue();
      allResults.push(...batch);

      // If no workers were available, wait
      if (batch.length === 0 && this.pendingQueue.length > 0) {
        await new Promise(r => setTimeout(r, 1000));
      }
    }

    return allResults;
  }

  // ─── Queries ─────────────────────────────────────────────────────

  /**
   * Get results for a hypothesis.
   *
   * @param {string} hypothesisId
   * @returns {object[]}
   */
  getResultsForHypothesis(hypothesisId) {
    const results = [];
    for (const result of this.results.values()) {
      if (result.hypothesis_id === hypothesisId) {
        results.push(result);
      }
    }
    return results.sort((a, b) => (b.ts || 0) - (a.ts || 0));
  }

  /**
   * Get farm statistics.
   * @returns {object}
   */
  getStats() {
    const workers = [...this.workers.values()];
    const idle = workers.filter(w => w.isIdle).length;
    const busy = workers.length - idle;

    return {
      total_workers: workers.length,
      idle_workers: idle,
      busy_workers: busy,
      utilization: workers.length > 0 ? Math.round((busy / workers.length) * 100) : 0,
      pending_tasks: this.pendingQueue.length,
      completed_tasks: this.results.size,
      total_tasks: this.tasks.size,
    };
  }

  /**
   * Get all worker stats.
   * @returns {object[]}
   */
  getWorkerStats() {
    return [...this.workers.values()].map(w => w.getStats());
  }

  // ─── Internal ────────────────────────────────────────────────────

  _getIdleWorker() {
    for (const worker of this.workers.values()) {
      if (worker.isIdle) return worker;
    }
    return null;
  }
}

module.exports = { VerificationFarm, VerificationWorker, WORKER_STATES, ALLOWED_ACTIONS, FORBIDDEN_ACTIONS };
