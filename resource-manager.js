/**
 * BOQA resource-manager.js — ResourceManager v0.9
 *
 * Dynamically allocates workers based on target value and predicted
 * yield. Builds on top of the v0.7 ResourceOptimizer but adds v0.9
 * optimization layer capabilities:
 *
 *   - Prediction-driven allocation: use yield forecasts to allocate
 *     workers, not just observed EV
 *   - Dynamic scaling: scale worker count up/down based on demand
 *     and predicted yield
 *   - Worker health tracking: track worker health, capacity, and
 *     specialization
 *   - Elastic pool management: add/remove workers as demand changes
 *   - Allocation efficiency: measure and optimize allocation
 *     efficiency (target: >= 90% utilization)
 *   - Fair scheduling: prevent starvation of lower-priority targets
 *   - Cost tracking: track cost per worker, cost per bug found
 *
 * Allocation blending model:
 *   blended_value(target) =
 *     prediction_weight × predicted_yield +
 *     observed_weight × observed_ev +
 *     risk_weight × risk_forecast -
 *     cost_weight × normalized_cost
 *
 * Where:
 *   prediction_weight = 0.40  (yield forecast contribution)
 *   observed_weight   = 0.30  (observed EV from v0.7 optimizer)
 *   risk_weight       = 0.15  (risk forecast contribution)
 *   cost_weight       = 0.15  (cost penalty)
 *
 * Fair scheduling guarantee:
 *   Every target receives at least min_workers_per_target (1) worker
 *   regardless of blended value, preventing starvation of low-EV
 *   targets that may still produce high-severity findings.
 *
 * Safe mode: ResourceManager only suggests and tracks allocations;
 * execution is delegated to WorkerPool and VerificationFarm.
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const RESOURCE_DIR = path.join(__dirname, 'output', 'knowledge', 'resources');

// ─── Default Configuration ──────────────────────────────────────────

const DEFAULT_RM_CONFIG = {
  max_workers:              8,
  min_workers:              2,
  scale_up_threshold:       0.80,    // utilization above 80% → scale up
  scale_down_threshold:     0.40,    // utilization below 40% → scale down
  rebalance_interval_ms:    120000,  // 2 minutes
  cooling_period_ms:        300000,  // 5 minutes (drain → idle cooldown)
  health_check_interval_ms: 60000,   // 1 minute
  max_cost_per_bug:         100,     // cost ceiling per bug found
  target_utilization:       0.90,    // target 90% utilization

  // Blending weights
  prediction_weight:        0.40,
  observed_weight:          0.30,
  risk_weight:              0.15,
  cost_weight:              0.15,

  // Per-target limits
  min_workers_per_target:   1,
  max_workers_per_target:   4,

  // Fair scheduling
  fair_share_reserve_ratio: 0.10,    // 10% of pool reserved for fair share

  // Health thresholds
  health_drain_threshold:   0.30,    // health score below 30% → drain
  health_recover_threshold: 0.70,    // health score above 70% → recover

  // Cost defaults
  default_cost_per_worker_hour: 1.0,

  // History limits
  max_allocation_history:    500,
  max_worker_history:        1000,
};

// ─── Worker States ──────────────────────────────────────────────────

const WORKER_STATES = {
  IDLE:         'idle',
  WORKING:      'working',
  DRAINING:     'draining',
  COOLING_DOWN: 'cooling_down',
};

// =====================================================================
//  WorkerState
// =====================================================================

class WorkerState {
  /**
   * @param {object} data
   * @param {string} [data.id]
   * @param {string} [data.target_id]
   * @param {string} [data.state]
   * @param {number} [data.capacity]
   * @param {string} [data.specialization]
   * @param {object} [data.current_task]
   * @param {number} [data.health_score]
   * @param {number} [data.bugs_found]
   * @param {number} [data.cost_incurred]
   * @param {number} [data.last_active_at]
   */
  constructor(data = {}) {
    this.id             = data.id             || `W-${crypto.randomUUID().substring(0, 8)}`;
    this.target_id      = data.target_id      || null;
    this.state          = data.state          || WORKER_STATES.IDLE;
    this.capacity       = data.capacity       || 1.0;   // 0.0–1.0
    this.specialization = data.specialization || 'general';
    this.current_task   = data.current_task   || null;
    this.health_score   = data.health_score   || 1.0;   // 0.0–1.0
    this.bugs_found     = data.bugs_found     || 0;
    this.cost_incurred  = data.cost_incurred  || 0;
    this.last_active_at = data.last_active_at || Date.now();
  }

  /**
   * Whether the worker is available for assignment.
   * @returns {boolean}
   */
  isAvailable() {
    return this.state === WORKER_STATES.IDLE &&
           this.health_score >= 0.5 &&
           this.capacity > 0;
  }

  /**
   * Whether the worker should be drained due to poor health.
   * @param {number} threshold
   * @returns {boolean}
   */
  shouldDrain(threshold) {
    return this.health_score < threshold && this.state === WORKER_STATES.WORKING;
  }

  /**
   * Serialize to plain object.
   * @returns {object}
   */
  toJSON() {
    return {
      id:             this.id,
      target_id:      this.target_id,
      state:          this.state,
      capacity:       this.capacity,
      specialization: this.specialization,
      current_task:   this.current_task,
      health_score:   this.health_score,
      bugs_found:     this.bugs_found,
      cost_incurred:  this.cost_incurred,
      last_active_at: this.last_active_at,
    };
  }
}

// =====================================================================
//  AllocationDecision
// =====================================================================

class AllocationDecision {
  /**
   * @param {object} data
   * @param {string} [data.id]
   * @param {string} [data.target_id]
   * @param {number} [data.worker_count]
   * @param {boolean} [data.prediction_based]
   * @param {boolean} [data.observed_based]
   * @param {number} [data.expected_yield]
   * @param {number} [data.cost_estimate]
   * @param {number} [data.confidence]
   */
  constructor(data = {}) {
    this.id               = data.id               || `AD-${crypto.randomUUID().substring(0, 8)}`;
    this.target_id        = data.target_id        || null;
    this.worker_count     = data.worker_count     || 0;
    this.prediction_based = data.prediction_based || false;
    this.observed_based   = data.observed_based   || false;
    this.expected_yield   = data.expected_yield   || 0;
    this.cost_estimate    = data.cost_estimate    || 0;
    this.confidence       = data.confidence       || 0;     // 0.0–1.0
  }

  /**
   * Serialize to plain object.
   * @returns {object}
   */
  toJSON() {
    return {
      id:               this.id,
      target_id:        this.target_id,
      worker_count:     this.worker_count,
      prediction_based: this.prediction_based,
      observed_based:   this.observed_based,
      expected_yield:   this.expected_yield,
      cost_estimate:    this.cost_estimate,
      confidence:       this.confidence,
    };
  }
}

// =====================================================================
//  ResourceManager
// =====================================================================

class ResourceManager {
  /**
   * @param {object} options
   * @param {object} [options.predictionEngine]     - PredictionEngine instance
   * @param {object} [options.yieldForecaster]      - YieldForecaster instance
   * @param {object} [options.riskForecaster]       - RiskForecaster instance
   * @param {object} [options.resourceOptimizer]    - ResourceOptimizer v0.7 instance
   * @param {object} [options.optimizerEngine]       - OptimizerEngine v0.9 instance
   * @param {object} [options.efficiencyTracker]    - efficiency tracker instance
   * @param {object} [options.budgetOptimizer]      - budget optimizer instance
   * @param {object} [options.knowledgeBase]        - KnowledgeBase instance
   * @param {object} [options.brainRegistry]        - BrainRegistry instance
   * @param {object} [options.campaignEngine]       - CampaignEngine instance
   * @param {object} [options.learningEngine]       - LearningEngine instance
   * @param {object} [options.config]               - Override DEFAULT_RM_CONFIG
   */
  constructor(options = {}) {
    this.predictionEngine  = options.predictionEngine  || null;
    this.yieldForecaster   = options.yieldForecaster   || null;
    this.riskForecaster    = options.riskForecaster    || null;
    this.resourceOptimizer = options.resourceOptimizer || null;
    this.optimizerEngine   = options.optimizerEngine   || null;
    this.efficiencyTracker = options.efficiencyTracker || null;
    this.budgetOptimizer   = options.budgetOptimizer   || null;
    this.kb                = options.knowledgeBase     || null;
    this.brainRegistry     = options.brainRegistry     || null;
    this.campaignEngine    = options.campaignEngine    || null;
    this.learningEngine    = options.learningEngine    || null;
    this.config            = { ...DEFAULT_RM_CONFIG, ...(options.config || {}) };

    // ── Worker pool ──────────────────────────────────────────────
    /** @type {Map<string, WorkerState>} worker_id → WorkerState */
    this.workerPool = new Map();

    // ── Allocation state ─────────────────────────────────────────
    /** @type {Map<string, AllocationDecision>} target_id → current decision */
    this.currentAllocations = new Map();

    /** @type {object[]} allocation history for audit trail */
    this.allocationHistory = [];

    /** @type {Map<string, number>} target_id → blended value */
    this.targetBlendedValues = new Map();

    /** @type {Map<string, number>} target_id → observed EV (from v0.7) */
    this.targetObservedEVs = new Map();

    /** @type {Map<string, number>} target_id → predicted yield */
    this.targetPredictedYields = new Map();

    // ── Metrics ──────────────────────────────────────────────────
    this._metrics = {
      bugs_found:              0,
      total_cost:              0,
      total_worker_hours:      0,
      allocation_count:        0,
      rebalance_count:         0,
      scale_up_count:          0,
      scale_down_count:        0,
      health_drain_count:      0,
      avg_allocation_latency_ms: 0,
      _latency_sum:            0,
      _latency_count:          0,
    };

    /** @type {Date|null} last rebalance time */
    this.lastRebalanceAt = null;

    /** @type {Date|null} last health check time */
    this.lastHealthCheckAt = null;

    // ── Seed minimum workers ─────────────────────────────────────
    for (let i = 0; i < this.config.min_workers; i++) {
      this._createWorker();
    }

    // ── Ensure persistence directory ─────────────────────────────
    fs.mkdirSync(RESOURCE_DIR, { recursive: true });

    // ── Periodic timers ──────────────────────────────────────────
    this._rebalanceTimer = setInterval(() => {
      this.rebalance();
    }, this.config.rebalance_interval_ms);

    this._healthCheckTimer = setInterval(() => {
      this._runHealthChecks();
    }, this.config.health_check_interval_ms);

    // ── Auto-load persisted state ────────────────────────────────
    this.load();
  }

  // ─── Dynamic Allocation ────────────────────────────────────────

  /**
   * Compute the blended value for a target by combining predicted
   * yield, observed EV, risk forecast, and cost.
   *
   * blended_value = prediction_weight × predicted_yield +
   *                 observed_weight   × observed_ev +
   *                 risk_weight       × risk_forecast -
   *                 cost_weight       × normalized_cost
   *
   * @param {string} targetId
   * @returns {number} blended value 0–100
   */
  computeBlendedValue(targetId) {
    const cfg = this.config;

    // ── Predicted yield ───────────────────────────────────────
    let predictedYield = 0;
    if (this.yieldForecaster) {
      const forecast = this.yieldForecaster.getTargetForecast(targetId);
      predictedYield = forecast ? Math.min(forecast.expected_bugs * 10, 100) : 0;
    } else if (this.predictionEngine) {
      const pred = this.predictionEngine.predictTarget(targetId);
      predictedYield = pred ? Math.min(pred.predicted_yield * 10, 100) : 0;
    }
    this.targetPredictedYields.set(targetId, predictedYield);

    // ── Observed EV (from v0.7 ResourceOptimizer) ─────────────
    let observedEV = 0;
    if (this.resourceOptimizer) {
      observedEV = this.resourceOptimizer.computeTargetEV(targetId);
    } else {
      observedEV = this._fallbackObservedEV(targetId);
    }
    this.targetObservedEVs.set(targetId, observedEV);

    // ── Risk forecast ─────────────────────────────────────────
    let riskValue = 0;
    if (this.riskForecaster) {
      const risk = this.riskForecaster.getTargetRisk
        ? this.riskForecaster.getTargetRisk(targetId)
        : null;
      riskValue = risk ? risk.regression_likelihood * 100 : 0;
    }

    // ── Normalized cost ───────────────────────────────────────
    const normalizedCost = this._computeNormalizedCost(targetId);

    // ── Blend ─────────────────────────────────────────────────
    const blended = Math.round(
      (cfg.prediction_weight * predictedYield +
       cfg.observed_weight   * observedEV +
       cfg.risk_weight       * riskValue -
       cfg.cost_weight       * normalizedCost) * 100
    ) / 100;

    const clamped = Math.max(0, Math.min(blended, 100));
    this.targetBlendedValues.set(targetId, clamped);
    return clamped;
  }

  /**
   * Compute allocation decisions for all known targets.
   *
   * Strategy:
   *   1. Compute blended value for each target
   *   2. Reserve fair-share workers for low-value targets
   *   3. Distribute remaining workers proportionally to blended value
   *   4. Enforce per-target min/max limits
   *   5. Ensure total allocation does not exceed pool size
   *   6. Record allocation decisions with confidence scores
   *
   * @returns {object} allocation plan
   */
  computeAllocation() {
    const startTime = Date.now();
    const cfg = this.config;

    const targetIds = this._collectTargetIds();
    const blendedValues = [];
    for (const tid of targetIds) {
      const bv = this.computeBlendedValue(tid);
      blendedValues.push({ target_id: tid, blended_value: bv });
    }
    blendedValues.sort((a, b) => b.blended_value - a.blended_value);

    // ── Available workers ─────────────────────────────────────
    const totalWorkers = this.workerPool.size;
    const fairShareReserve = Math.max(1, Math.floor(totalWorkers * cfg.fair_share_reserve_ratio));
    const distributable = Math.max(0, totalWorkers - fairShareReserve);
    const totalBlendedValue = blendedValues.reduce((s, e) => s + e.blended_value, 0);

    // ── Distribute workers ────────────────────────────────────
    const decisions = [];
    for (const { target_id, blended_value } of blendedValues) {
      let workerCount;
      if (totalBlendedValue > 0) {
        workerCount = Math.max(
          cfg.min_workers_per_target,
          Math.min(
            cfg.max_workers_per_target,
            Math.round((blended_value / totalBlendedValue) * distributable)
          )
        );
      } else {
        workerCount = cfg.min_workers_per_target;
      }

      // Determine signal source
      const predictedYield = this.targetPredictedYields.get(target_id) || 0;
      const observedEV     = this.targetObservedEVs.get(target_id) || 0;
      const predictionBased = predictedYield >= observedEV;
      const observedBased   = observedEV > predictedYield;

      // Cost estimate
      const costEstimate = workerCount * cfg.default_cost_per_worker_hour;

      // Confidence from blended value magnitude
      const confidence = Math.min(1.0, blended_value / 50);

      const decision = new AllocationDecision({
        target_id,
        worker_count:     workerCount,
        prediction_based: predictionBased,
        observed_based:   observedBased,
        expected_yield:   blended_value,
        cost_estimate:    Math.round(costEstimate * 100) / 100,
        confidence:       Math.round(confidence * 100) / 100,
      });

      decisions.push(decision);
    }

    // ── Budget adjustment ─────────────────────────────────────
    let allocatedWorkers = decisions.reduce((s, d) => s + d.worker_count, 0);
    while (allocatedWorkers > totalWorkers && decisions.length > 0) {
      const lowest = decisions
        .filter(d => d.worker_count > cfg.min_workers_per_target)
        .sort((a, b) => a.expected_yield - b.expected_yield)[0];
      if (!lowest) break;
      lowest.worker_count--;
      lowest.cost_estimate = Math.round(lowest.worker_count * cfg.default_cost_per_worker_hour * 100) / 100;
      allocatedWorkers--;
    }

    // ── Fair share: give unallocated workers to lowest targets ──
    const unallocated = totalWorkers - allocatedWorkers;
    if (unallocated > 0) {
      const lowTargets = decisions
        .filter(d => d.worker_count < cfg.max_workers_per_target)
        .sort((a, b) => a.expected_yield - b.expected_yield);
      let remaining = unallocated;
      for (const target of lowTargets) {
        if (remaining <= 0) break;
        const add = Math.min(remaining, cfg.max_workers_per_target - target.worker_count);
        target.worker_count += add;
        target.cost_estimate = Math.round(target.worker_count * cfg.default_cost_per_worker_hour * 100) / 100;
        remaining -= add;
      }
    }

    // ── Build allocation plan ─────────────────────────────────
    const plan = {
      id:              `ALLOC-${crypto.randomUUID().substring(0, 8)}`,
      total_workers:   totalWorkers,
      distributable,
      fair_share_reserve: fairShareReserve,
      decisions,
      generated_at:    Date.now(),
    };

    // ── Track allocation latency ──────────────────────────────
    const latency = Date.now() - startTime;
    this._metrics._latency_sum += latency;
    this._metrics._latency_count += 1;
    this._metrics.avg_allocation_latency_ms = Math.round(
      this._metrics._latency_sum / this._metrics._latency_count
    );
    this._metrics.allocation_count++;

    return plan;
  }

  // ─── Scale Up / Down ───────────────────────────────────────────

  /**
   * Scale up the worker pool by adding workers.
   *
   * @param {number} count - number of workers to add
   * @returns {WorkerState[]} newly created workers
   */
  scaleUp(count) {
    const cfg = this.config;
    const currentSize = this.workerPool.size;
    const maxAdd = Math.max(0, cfg.max_workers - currentSize);
    const toAdd = Math.min(count, maxAdd);

    const added = [];
    for (let i = 0; i < toAdd; i++) {
      added.push(this._createWorker());
    }

    if (added.length > 0) {
      this._metrics.scale_up_count++;
    }

    return added;
  }

  /**
   * Scale down the worker pool by draining and removing workers.
   *
   * @param {number} count - number of workers to remove
   * @returns {string[]} IDs of removed workers
   */
  scaleDown(count) {
    const cfg = this.config;
    const currentSize = this.workerPool.size;
    const maxRemove = Math.max(0, currentSize - cfg.min_workers);
    const toRemove = Math.min(count, maxRemove);

    // Prefer idle workers first, then least healthy
    const candidates = [...this.workerPool.values()]
      .filter(w => w.state !== WORKER_STATES.DRAINING && w.state !== WORKER_STATES.COOLING_DOWN)
      .sort((a, b) => {
        // Idle workers first
        if (a.state === WORKER_STATES.IDLE && b.state !== WORKER_STATES.IDLE) return -1;
        if (b.state === WORKER_STATES.IDLE && a.state !== WORKER_STATES.IDLE) return 1;
        // Then by health (least healthy first)
        return a.health_score - b.health_score;
      });

    const removed = [];
    for (let i = 0; i < toRemove && i < candidates.length; i++) {
      const worker = candidates[i];
      if (worker.state === WORKER_STATES.WORKING) {
        worker.state = WORKER_STATES.DRAINING;
        // Will be fully removed after drain completes
        this._scheduleDrainComplete(worker);
      } else {
        this.workerPool.delete(worker.id);
      }
      removed.push(worker.id);
    }

    if (removed.length > 0) {
      this._metrics.scale_down_count++;
    }

    return removed;
  }

  // ─── Rebalance ─────────────────────────────────────────────────

  /**
   * Rebalance worker allocations based on current conditions.
   *
   * Steps:
   *   1. Compute new allocation plan
   *   2. Check utilization for scaling decisions
   *   3. Reassign workers to match new plan
   *   4. Record history
   *
   * @returns {object} the new allocation plan
   */
  rebalance() {
    const cfg = this.config;

    // ── Compute new allocation plan ───────────────────────────
    const plan = this.computeAllocation();

    // ── Update current allocations ────────────────────────────
    this.currentAllocations.clear();
    for (const decision of plan.decisions) {
      this.currentAllocations.set(decision.target_id, decision);
    }

    // ── Check utilization for scaling ─────────────────────────
    const utilization = this._computeUtilization();
    if (utilization > cfg.scale_up_threshold && this.workerPool.size < cfg.max_workers) {
      this.scaleUp(1);
    } else if (utilization < cfg.scale_down_threshold && this.workerPool.size > cfg.min_workers) {
      this.scaleDown(1);
    }

    // ── Reassign workers ──────────────────────────────────────
    this._reassignWorkers(plan.decisions);

    // ── Record history ────────────────────────────────────────
    this.allocationHistory.push({
      plan_id:       plan.id,
      target_count:  plan.decisions.length,
      total_workers: plan.total_workers,
      utilization:   Math.round(utilization * 100) / 100,
      decisions:     plan.decisions.map(d => d.toJSON()),
      ts:            Date.now(),
    });

    if (this.allocationHistory.length > cfg.max_allocation_history) {
      this.allocationHistory = this.allocationHistory.slice(-cfg.max_allocation_history);
    }

    this._metrics.rebalance_count++;
    this.lastRebalanceAt = Date.now();

    return plan;
  }

  // ─── Worker Tracking ───────────────────────────────────────────

  /**
   * Assign a worker to a target.
   *
   * @param {string} targetId
   * @param {WorkerState} worker
   * @returns {boolean} success
   */
  assignWorker(targetId, worker) {
    if (!worker || !worker.isAvailable()) return false;

    worker.target_id    = targetId;
    worker.state        = WORKER_STATES.WORKING;
    worker.last_active_at = Date.now();
    worker.current_task = {
      target_id: targetId,
      assigned_at: Date.now(),
    };

    return true;
  }

  /**
   * Release a worker back to the idle pool.
   *
   * @param {string} workerId
   * @returns {boolean} success
   */
  releaseWorker(workerId) {
    const worker = this.workerPool.get(workerId);
    if (!worker) return false;

    // Record cost for the work session
    if (worker.current_task) {
      const elapsed = Date.now() - worker.current_task.assigned_at;
      const hours = elapsed / 3600000;
      const cost = hours * this.config.default_cost_per_worker_hour;
      worker.cost_incurred = Math.round((worker.cost_incurred + cost) * 100) / 100;
      this._metrics.total_cost = Math.round((this._metrics.total_cost + cost) * 100) / 100;
      this._metrics.total_worker_hours = Math.round((this._metrics.total_worker_hours + hours) * 100) / 100;
    }

    // Transition to cooling down
    worker.target_id    = null;
    worker.state        = WORKER_STATES.COOLING_DOWN;
    worker.current_task = null;
    worker.last_active_at = Date.now();

    // Schedule return to idle after cooling period
    setTimeout(() => {
      if (worker.state === WORKER_STATES.COOLING_DOWN) {
        worker.state = WORKER_STATES.IDLE;
      }
    }, this.config.cooling_period_ms);

    return true;
  }

  /**
   * Record a bug found by a worker.
   *
   * @param {string} workerId
   * @param {object} [bugInfo]
   * @returns {boolean}
   */
  recordBugFound(workerId, bugInfo = {}) {
    const worker = this.workerPool.get(workerId);
    if (!worker) return false;

    worker.bugs_found++;
    this._metrics.bugs_found++;

    // Track cost per bug
    const costPerBug = this._metrics.bugs_found > 0
      ? this._metrics.total_cost / this._metrics.bugs_found
      : 0;

    return true;
  }

  // ─── Health Monitoring ─────────────────────────────────────────

  /**
   * Update a worker's health score.
   *
   * @param {string} workerId
   * @param {number} score - health score 0.0–1.0
   * @returns {boolean}
   */
  updateWorkerHealth(workerId, score) {
    const worker = this.workerPool.get(workerId);
    if (!worker) return false;

    const prevScore = worker.health_score;
    worker.health_score = Math.max(0, Math.min(1, score));

    // Auto-drain unhealthy workers
    if (worker.shouldDrain(this.config.health_drain_threshold)) {
      this._drainWorker(worker);
    }

    // Recover from drain if health improves
    if (worker.state === WORKER_STATES.DRAINING &&
        worker.health_score >= this.config.health_recover_threshold) {
      worker.state = worker.target_id ? WORKER_STATES.WORKING : WORKER_STATES.IDLE;
    }

    return true;
  }

  /**
   * Run health checks on all workers.
   * @private
   */
  _runHealthChecks() {
    for (const [id, worker] of this.workerPool) {
      // Simple health model: degrade health for idle workers over time
      if (worker.state === WORKER_STATES.WORKING) {
        // Working workers maintain health
        worker.health_score = Math.min(1.0, worker.health_score + 0.01);
      } else if (worker.state === WORKER_STATES.IDLE) {
        // Idle workers slowly degrade (stale knowledge)
        const idleTime = Date.now() - worker.last_active_at;
        if (idleTime > this.config.cooling_period_ms * 2) {
          worker.health_score = Math.max(0.2, worker.health_score - 0.005);
        }
      }

      // Auto-drain unhealthy workers
      if (worker.shouldDrain(this.config.health_drain_threshold)) {
        this._drainWorker(worker);
      }
    }

    this.lastHealthCheckAt = Date.now();
  }

  // ─── Cost Tracking ─────────────────────────────────────────────

  /**
   * Get cost per bug across the entire resource pool.
   * @returns {number}
   */
  get cost_per_bug() {
    return this._metrics.bugs_found > 0
      ? Math.round((this._metrics.total_cost / this._metrics.bugs_found) * 100) / 100
      : 0;
  }

  /**
   * Get the total cost incurred.
   * @returns {number}
   */
  get total_cost() {
    return this._metrics.total_cost;
  }

  /**
   * Get the current worker count.
   * @returns {number}
   */
  get worker_count() {
    return this.workerPool.size;
  }

  /**
   * Get the bugs-per-worker ratio.
   * @returns {number}
   */
  get bugs_per_worker() {
    return this.workerPool.size > 0
      ? Math.round((this._metrics.bugs_found / this.workerPool.size) * 100) / 100
      : 0;
  }

  /**
   * Get the current utilization rate.
   * @returns {number} 0.0–1.0
   */
  get utilization_rate() {
    return Math.round(this._computeUtilization() * 100) / 100;
  }

  // ─── Query Methods ─────────────────────────────────────────────

  /**
   * Get comprehensive metrics.
   * @returns {object}
   */
  getMetrics() {
    return {
      bugs_found:               this._metrics.bugs_found,
      bugs_per_worker:          this.bugs_per_worker,
      total_cost:               this.total_cost,
      cost_per_bug:             this.cost_per_bug,
      worker_count:             this.worker_count,
      utilization_rate:         this.utilization_rate,
      avg_allocation_latency_ms: this._metrics.avg_allocation_latency_ms,
      total_worker_hours:       this._metrics.total_worker_hours,
      allocation_count:         this._metrics.allocation_count,
      rebalance_count:          this._metrics.rebalance_count,
      scale_up_count:           this._metrics.scale_up_count,
      scale_down_count:         this._metrics.scale_down_count,
      health_drain_count:       this._metrics.health_drain_count,
      last_rebalance_at:        this.lastRebalanceAt,
      last_health_check_at:     this.lastHealthCheckAt,
    };
  }

  /**
   * Get the current worker pool.
   * @returns {WorkerState[]}
   */
  getWorkerPool() {
    return [...this.workerPool.values()];
  }

  /**
   * Get the allocation history.
   * @param {number} [limit] - max entries to return
   * @returns {object[]}
   */
  getAllocationHistory(limit) {
    const history = this.allocationHistory;
    return limit ? history.slice(-limit) : history;
  }

  /**
   * Get current allocations.
   * @returns {AllocationDecision[]}
   */
  getCurrentAllocations() {
    return [...this.currentAllocations.values()]
      .sort((a, b) => b.expected_yield - a.expected_yield);
  }

  /**
   * Get the blended value for a target.
   * @param {string} targetId
   * @returns {number}
   */
  getBlendedValue(targetId) {
    return this.targetBlendedValues.get(targetId) || 0;
  }

  /**
   * Get the observed EV for a target.
   * @param {string} targetId
   * @returns {number}
   */
  getObservedEV(targetId) {
    return this.targetObservedEVs.get(targetId) || 0;
  }

  /**
   * Get the predicted yield for a target.
   * @param {string} targetId
   * @returns {number}
   */
  getPredictedYield(targetId) {
    return this.targetPredictedYields.get(targetId) || 0;
  }

  // ─── Persistence ───────────────────────────────────────────────

  /**
   * Save resource manager state to disk.
   * @returns {string} file path written
   */
  save() {
    const data = {
      version:            '0.9',
      saved_at:           Date.now(),
      config:             this.config,
      workers:            [...this.workerPool.entries()].map(([id, w]) => [id, w.toJSON()]),
      current_allocations: [...this.currentAllocations.entries()].map(([id, d]) => [id, d.toJSON()]),
      allocation_history:  this.allocationHistory.slice(-this.config.max_allocation_history),
      metrics:            this._metrics,
      blended_values:     [...this.targetBlendedValues.entries()],
      observed_evs:       [...this.targetObservedEVs.entries()],
      predicted_yields:   [...this.targetPredictedYields.entries()],
    };

    const filePath = path.join(RESOURCE_DIR, 'resource-manager.json');
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  /**
   * Load resource manager state from disk.
   * @returns {boolean} success
   */
  load() {
    const filePath = path.join(RESOURCE_DIR, 'resource-manager.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      // Restore workers (merge with seeded minimum workers)
      if (data.workers && Array.isArray(data.workers)) {
        this.workerPool.clear();
        for (const [id, wData] of data.workers) {
          this.workerPool.set(id, new WorkerState(wData));
        }
      }

      // Restore allocations
      if (data.current_allocations && Array.isArray(data.current_allocations)) {
        this.currentAllocations.clear();
        for (const [id, dData] of data.current_allocations) {
          this.currentAllocations.set(id, new AllocationDecision(dData));
        }
      }

      // Restore history
      if (data.allocation_history) {
        this.allocationHistory = data.allocation_history;
      }

      // Restore metrics
      if (data.metrics) {
        Object.assign(this._metrics, data.metrics);
      }

      // Restore blended values, observed EVs, predicted yields
      if (data.blended_values) {
        this.targetBlendedValues = new Map(data.blended_values);
      }
      if (data.observed_evs) {
        this.targetObservedEVs = new Map(data.observed_evs);
      }
      if (data.predicted_yields) {
        this.targetPredictedYields = new Map(data.predicted_yields);
      }

      return true;
    } catch (_) {
      return false;
    }
  }

  // ─── Shutdown ──────────────────────────────────────────────────

  /**
   * Shut down the resource manager. Persist state and clear timers.
   */
  shutdown() {
    // Persist final state
    this.save();

    // Clear timers
    if (this._rebalanceTimer) {
      clearInterval(this._rebalanceTimer);
      this._rebalanceTimer = null;
    }
    if (this._healthCheckTimer) {
      clearInterval(this._healthCheckTimer);
      this._healthCheckTimer = null;
    }

    // Drain all workers gracefully
    for (const [id, worker] of this.workerPool) {
      if (worker.state === WORKER_STATES.WORKING) {
        worker.state = WORKER_STATES.DRAINING;
      }
    }
  }

  // ─── Internal Methods ─────────────────────────────────────────

  /**
   * Create a new worker and add it to the pool.
   * @private
   * @param {object} [overrides]
   * @returns {WorkerState}
   */
  _createWorker(overrides = {}) {
    const worker = new WorkerState(overrides);
    this.workerPool.set(worker.id, worker);
    return worker;
  }

  /**
   * Drain a worker, releasing its current assignment.
   * @private
   * @param {WorkerState} worker
   */
  _drainWorker(worker) {
    worker.state = WORKER_STATES.DRAINING;
    if (worker.current_task) {
      const elapsed = Date.now() - worker.current_task.assigned_at;
      const hours = elapsed / 3600000;
      const cost = hours * this.config.default_cost_per_worker_hour;
      worker.cost_incurred = Math.round((worker.cost_incurred + cost) * 100) / 100;
      this._metrics.total_cost = Math.round((this._metrics.total_cost + cost) * 100) / 100;
      this._metrics.total_worker_hours = Math.round((this._metrics.total_worker_hours + hours) * 100) / 100;
    }
    worker.current_task = null;
    this._metrics.health_drain_count++;
  }

  /**
   * Schedule a draining worker for removal after cooling period.
   * @private
   * @param {WorkerState} worker
   */
  _scheduleDrainComplete(worker) {
    setTimeout(() => {
      if (worker.state === WORKER_STATES.DRAINING) {
        // Move to cooling down if not already removed
        worker.state = WORKER_STATES.COOLING_DOWN;
        worker.target_id = null;

        // Remove after another cooling period
        setTimeout(() => {
          if (this.workerPool.size > this.config.min_workers) {
            this.workerPool.delete(worker.id);
          } else if (worker.state === WORKER_STATES.COOLING_DOWN) {
            worker.state = WORKER_STATES.IDLE;
          }
        }, this.config.cooling_period_ms);
      }
    }, this.config.cooling_period_ms / 2);
  }

  /**
   * Reassign workers to match allocation decisions.
   * @private
   * @param {AllocationDecision[]} decisions
   */
  _reassignWorkers(decisions) {
    // Build target → desired count map
    const desiredCounts = new Map();
    for (const decision of decisions) {
      desiredCounts.set(decision.target_id, decision.worker_count);
    }

    // Count current assignments per target
    const currentCounts = new Map();
    const workersByTarget = new Map();
    for (const [id, worker] of this.workerPool) {
      if (worker.target_id) {
        currentCounts.set(worker.target_id, (currentCounts.get(worker.target_id) || 0) + 1);
        if (!workersByTarget.has(worker.target_id)) {
          workersByTarget.set(worker.target_id, []);
        }
        workersByTarget.get(worker.target_id).push(worker);
      }
    }

    // Release excess workers from over-allocated targets
    for (const [targetId, workers] of workersByTarget) {
      const desired = desiredCounts.get(targetId) || 0;
      const current = currentCounts.get(targetId) || 0;
      if (current > desired) {
        const toRelease = current - desired;
        // Release least healthy workers first
        workers.sort((a, b) => a.health_score - b.health_score);
        for (let i = 0; i < toRelease && i < workers.length; i++) {
          this.releaseWorker(workers[i].id);
        }
      }
    }

    // Assign idle workers to under-allocated targets
    const idleWorkers = [...this.workerPool.values()]
      .filter(w => w.isAvailable())
      .sort((a, b) => b.health_score - a.health_score);

    for (const [targetId, desiredCount] of desiredCounts) {
      const current = currentCounts.get(targetId) || 0;
      const needed = desiredCount - current;
      for (let i = 0; i < needed && idleWorkers.length > 0; i++) {
        const worker = idleWorkers.shift();
        if (worker) {
          this.assignWorker(targetId, worker);
        }
      }
    }
  }

  /**
   * Compute the current utilization rate.
   * @private
   * @returns {number} 0.0–1.0
   */
  _computeUtilization() {
    const total = this.workerPool.size;
    if (total === 0) return 0;
    const working = [...this.workerPool.values()]
      .filter(w => w.state === WORKER_STATES.WORKING)
      .length;
    return working / total;
  }

  /**
   * Compute a normalized cost score for a target.
   * @private
   * @param {string} targetId
   * @returns {number} 0–100
   */
  _computeNormalizedCost(targetId) {
    // Compute cost already incurred on this target
    let costOnTarget = 0;
    for (const [, worker] of this.workerPool) {
      if (worker.target_id === targetId) {
        costOnTarget += worker.cost_incurred;
      }
    }

    // Normalize against max_cost_per_bug
    const maxCost = this.config.max_cost_per_bug;
    if (maxCost <= 0) return 0;
    return Math.min(100, (costOnTarget / maxCost) * 100);
  }

  /**
   * Fallback observed EV when ResourceOptimizer is not available.
   * @private
   * @param {string} targetId
   * @returns {number}
   */
  _fallbackObservedEV(targetId) {
    let bugYieldRate = 0.1;
    let avgSeverity  = 0.5;
    let coverageGap  = 0.5;
    let learnBoost   = 1.0;

    if (this.brainRegistry) {
      const brain = this.brainRegistry.getOrCreate(targetId);
      if (brain.total_sessions > 0) {
        bugYieldRate = brain.historicalFindings.filter(
          f => f.lifecycle_state === 'confirmed' || f.verdict === 'confirmed'
        ).length / brain.total_sessions;
      }
      const confirmed = brain.historicalFindings.filter(
        f => f.lifecycle_state === 'confirmed' || f.verdict === 'confirmed'
      );
      if (confirmed.length > 0) {
        const sevMap = { critical: 1.0, high: 0.8, medium: 0.5, low: 0.25, info: 0.1 };
        avgSeverity = confirmed.reduce((s, f) => s + (sevMap[f.severity] || 0.5), 0) / confirmed.length;
      }
      if (brain.coverageTrend.length > 0) {
        coverageGap = 1 - (brain.coverageTrend[brain.coverageTrend.length - 1].score / 100);
      }
    }

    if (this.learningEngine) {
      const tl = this.learningEngine.targetLearning.get(targetId);
      if (tl && tl.observations > 0) {
        const rate = tl.confirmed / tl.observations;
        if (rate > 0.1 && rate < 0.5) {
          learnBoost = 1.0 + (rate * 0.5);
        } else if (rate >= 0.5) {
          learnBoost = 0.8;
        }
      }
    }

    return Math.min(100, Math.round(bugYieldRate * 100 * avgSeverity * coverageGap * learnBoost * 100) / 100);
  }

  /**
   * Collect all known target IDs from connected subsystems.
   * @private
   * @returns {string[]}
   */
  _collectTargetIds() {
    const ids = new Set();

    if (this.brainRegistry) {
      for (const [id] of this.brainRegistry.brains) {
        ids.add(id);
      }
    }
    if (this.kb) {
      for (const [id] of this.kb.assets) {
        ids.add(id);
      }
    }
    if (this.campaignEngine) {
      for (const [, campaign] of this.campaignEngine.campaigns) {
        for (const tid of (campaign.target_ids || [])) {
          ids.add(tid);
        }
      }
    }
    if (this.yieldForecaster) {
      for (const [id] of this.yieldForecaster.forecasts) {
        ids.add(id);
      }
    }

    return [...ids];
  }
}

// ─── Module Exports ─────────────────────────────────────────────────

module.exports = {
  ResourceManager,
  WorkerState,
  AllocationDecision,
  DEFAULT_RM_CONFIG,
  WORKER_STATES,
};

