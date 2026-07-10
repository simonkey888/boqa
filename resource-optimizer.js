/**
 * BOQA resource-optimizer.js — Resource Optimizer v0.7
 *
 * Allocates workers to highest expected value targets and campaigns.
 * Balances exploration vs. exploitation based on:
 *
 *   - Expected bug value per target (from TargetBrain and LearningEngine)
 *   - Current campaign priorities and goals
 *   - Worker availability and capacity
 *   - Coverage gaps per target
 *   - Historical success rates
 *   - Time-of-day patterns (some targets more active at certain times)
 *
 * Optimization strategy:
 *   - Compute expected_value for each target
 *   - Rank targets by EV
 *   - Allocate workers proportionally to EV
 *   - Rebalance periodically as conditions change
 *   - Reserve workers for exploration (unexplored targets)
 *   - Reserve workers for verification (high-value hypotheses)
 *
 * Expected value computation:
 *   EV(target) = bug_yield_rate × avg_bug_severity × coverage_gap × learning_boost
 *
 * Safe mode: optimizer only suggests allocations; execution
 * is delegated to the WorkerPool and VerificationFarm.
 */

const crypto = require('crypto');

// ─── Default Configuration ─────────────────────────────────────────

const DEFAULT_CONFIG = {
  max_workers: 8,
  exploration_reserve_ratio: 0.15,  // 15% of workers for exploration
  verification_reserve_ratio: 0.20, // 20% of workers for verification
  rebalance_interval_ms: 120000,    // 2 minutes
  min_workers_per_target: 1,
  max_workers_per_target: 4,
  eviction_threshold: 0.05,         // EV below this → reduce allocation
  boost_threshold: 0.30,            // EV above this → increase allocation
};

// ─── Worker Allocation States ──────────────────────────────────────

const ALLOCATION_STATES = {
  EXPLORING:   'exploring',
  VERIFYING:   'verifying',
  CAMPAIGN:    'campaign',
  IDLE:        'idle',
  MAINTENANCE: 'maintenance',
};

// =====================================================================
//  ResourceOptimizer
// =====================================================================

class ResourceOptimizer {
  /**
   * @param {object} options
   * @param {object} [options.knowledgeBase]      - KnowledgeBase instance
   * @param {object} [options.brainRegistry]       - BrainRegistry instance
   * @param {object} [options.learningEngine]       - LearningEngine instance
   * @param {object} [options.campaignEngine]       - CampaignEngine instance
   * @param {object} [options.verificationFarm]     - VerificationFarm instance
   * @param {object} [options.workerPool]           - WorkerPool instance
   * @param {object} [options.coverageEngine]       - CoverageEngine instance
   * @param {object} [options.config]               - Override default config
   */
  constructor(options = {}) {
    this.kb = options.knowledgeBase || null;
    this.brainRegistry = options.brainRegistry || null;
    this.learningEngine = options.learningEngine || null;
    this.campaignEngine = options.campaignEngine || null;
    this.verificationFarm = options.verificationFarm || null;
    this.workerPool = options.workerPool || null;
    this.coverageEngine = options.coverageEngine || null;
    this.config = { ...DEFAULT_CONFIG, ...(options.config || {}) };

    // ── Allocation state ───────────────────────────────────────
    /** @type {Map<string, object>} target_id → allocation info */
    this.allocations = new Map();

    /** @type {object[]} allocation history for audit trail */
    this.allocationHistory = [];

    /** @type {Map<string, number>} target_id → last computed EV */
    this.targetEVs = new Map();

    /** @type {object} current worker distribution */
    this.currentDistribution = {
      total_workers: this.config.max_workers,
      exploring: 0,
      verifying: 0,
      campaign: 0,
      idle: this.config.max_workers,
    };

    /** @type {number} rebalance count */
    this.rebalanceCount = 0;

    /** @type {Date|null} last rebalance time */
    this.lastRebalanceAt = null;

    // Start rebalance timer
    this._rebalanceTimer = setInterval(() => {
      this.rebalance();
    }, this.config.rebalance_interval_ms);
  }

  // ─── Expected Value Computation ─────────────────────────────────

  /**
   * Compute the expected value of allocating resources to a target.
   *
   * EV = bug_yield_rate × avg_bug_severity × coverage_gap × learning_boost
   *
   * @param {string} targetId
   * @returns {number} expected value 0-100
   */
  computeTargetEV(targetId) {
    let bugYieldRate = 0.1; // default
    let avgBugSeverity = 0.5; // default
    let coverageGap = 0.5; // default
    let learningBoost = 1.0; // default (no boost)

    // Get target brain data
    if (this.brainRegistry) {
      const brain = this.brainRegistry.getOrCreate(targetId);

      // Bug yield rate: confirmed bugs / total sessions
      if (brain.total_sessions > 0) {
        bugYieldRate = brain.historicalFindings.filter(
          f => f.lifecycle_state === 'confirmed' || f.verdict === 'confirmed'
        ).length / brain.total_sessions;
      }

      // Average severity of confirmed findings
      const confirmed = brain.historicalFindings.filter(
        f => f.lifecycle_state === 'confirmed' || f.verdict === 'confirmed'
      );
      if (confirmed.length > 0) {
        const severityMap = { critical: 1.0, high: 0.8, medium: 0.5, low: 0.25, info: 0.1 };
        avgBugSeverity = confirmed.reduce((s, f) => s + (severityMap[f.severity] || 0.5), 0) / confirmed.length;
      }

      // Coverage gap: 1 - current_coverage
      if (brain.coverageTrend.length > 0) {
        coverageGap = 1 - (brain.coverageTrend[brain.coverageTrend.length - 1].score / 100);
      }
    }

    // Get learning boost
    if (this.learningEngine) {
      const targetLearning = this.learningEngine.targetLearning.get(targetId);
      if (targetLearning && targetLearning.observations > 0) {
        const successRate = targetLearning.confirmed / targetLearning.observations;
        // Targets with medium success rates get a boost (high yield potential)
        // Very low or very high rates get less boost
        if (successRate > 0.1 && successRate < 0.5) {
          learningBoost = 1.0 + (successRate * 0.5);
        } else if (successRate >= 0.5) {
          learningBoost = 0.8; // already well-mined
        }
      }
    }

    // Compute EV
    const ev = Math.round(
      bugYieldRate * 100 * avgBugSeverity * coverageGap * learningBoost * 100
    ) / 100;

    this.targetEVs.set(targetId, ev);
    return Math.min(ev, 100);
  }

  /**
   * Compute EVs for all known targets.
   * @returns {object[]} sorted by EV descending
   */
  computeAllEVs() {
    const targetIds = new Set();

    // Collect all known target IDs
    if (this.brainRegistry) {
      for (const [id] of this.brainRegistry.brains) {
        targetIds.add(id);
      }
    }
    if (this.kb) {
      for (const [id] of this.kb.assets) {
        targetIds.add(id);
      }
    }
    if (this.campaignEngine) {
      for (const [, campaign] of this.campaignEngine.campaigns) {
        for (const tid of campaign.target_ids) {
          targetIds.add(tid);
        }
      }
    }

    const evs = [];
    for (const targetId of targetIds) {
      const ev = this.computeTargetEV(targetId);
      evs.push({ target_id: targetId, ev });
    }

    evs.sort((a, b) => b.ev - a.ev);
    return evs;
  }

  // ─── Allocation ─────────────────────────────────────────────────

  /**
   * Compute the optimal worker allocation across targets.
   *
   * Strategy:
   *   1. Reserve workers for exploration (exploration_reserve_ratio)
   *   2. Reserve workers for verification (verification_reserve_ratio)
   *   3. Distribute remaining workers proportionally to EV
   *   4. Ensure minimum allocation per target
   *   5. Cap maximum allocation per target
   *
   * @returns {object} allocation plan
   */
  computeAllocation() {
    const totalWorkers = this.config.max_workers;
    const evs = this.computeAllEVs();

    // Reserve workers
    const explorationReserve = Math.max(1, Math.floor(totalWorkers * this.config.exploration_reserve_ratio));
    const verificationReserve = Math.max(1, Math.floor(totalWorkers * this.config.verification_reserve_ratio));
    const distributable = Math.max(0, totalWorkers - explorationReserve - verificationReserve);

    // Distribute workers proportionally to EV
    const totalEV = evs.reduce((s, e) => s + e.ev, 0);
    const allocations = [];

    for (const { target_id, ev } of evs) {
      let workers;
      if (totalEV > 0) {
        workers = Math.max(
          this.config.min_workers_per_target,
          Math.min(
            this.config.max_workers_per_target,
            Math.round((ev / totalEV) * distributable)
          )
        );
      } else {
        workers = this.config.min_workers_per_target;
      }

      allocations.push({
        target_id,
        ev,
        workers,
        state: this._determineAllocationState(ev),
        reason: this._allocationReason(ev, workers),
      });
    }

    // Adjust for total budget (may exceed due to minimum allocations)
    let allocatedWorkers = allocations.reduce((s, a) => s + a.workers, 0);
    while (allocatedWorkers > distributable && allocations.length > 0) {
      // Remove worker from lowest EV target
      const lowest = allocations.reduce((min, a) => a.workers > this.config.min_workers_per_target && a.ev < min.ev ? a : min, { ev: Infinity, workers: 0 });
      if (lowest.workers <= this.config.min_workers_per_target) break;
      lowest.workers--;
      allocatedWorkers--;
    }

    // Build allocation plan
    const plan = {
      id: `ALLOC-${crypto.randomUUID().substring(0, 8)}`,
      total_workers: totalWorkers,
      exploration_reserve: explorationReserve,
      verification_reserve: verificationReserve,
      distributable,
      target_allocations: allocations,
      campaign_allocations: this._campaignAllocations(explorationReserve + verificationReserve),
      generated_at: Date.now(),
    };

    return plan;
  }

  /**
   * Rebalance worker allocations based on current conditions.
   *
   * @returns {object} the new allocation plan
   */
  rebalance() {
    const plan = this.computeAllocation();

    // Update allocation state
    this.allocations.clear();
    for (const alloc of plan.target_allocations) {
      this.allocations.set(alloc.target_id, alloc);
    }

    // Update current distribution
    this.currentDistribution = {
      total_workers: plan.total_workers,
      exploring: plan.exploration_reserve,
      verifying: plan.verification_reserve,
      campaign: plan.campaign_allocations.reduce((s, a) => s + a.workers, 0),
      idle: plan.total_workers - plan.target_allocations.reduce((s, a) => s + a.workers, 0) -
            plan.exploration_reserve - plan.verification_reserve,
    };

    // Record history
    this.allocationHistory.push({
      plan_id: plan.id,
      target_count: plan.target_allocations.length,
      total_allocated: plan.target_allocations.reduce((s, a) => s + a.workers, 0),
      distribution: { ...this.currentDistribution },
      ts: Date.now(),
    });

    if (this.allocationHistory.length > 100) {
      this.allocationHistory = this.allocationHistory.slice(-100);
    }

    this.rebalanceCount++;
    this.lastRebalanceAt = Date.now();

    return plan;
  }

  // ─── Query Methods ──────────────────────────────────────────────

  /**
   * Get current allocation for a target.
   *
   * @param {string} targetId
   * @returns {object|null}
   */
  getAllocation(targetId) {
    return this.allocations.get(targetId) || null;
  }

  /**
   * Get all current allocations.
   * @returns {object[]}
   */
  getAllAllocations() {
    return [...this.allocations.values()].sort((a, b) => b.ev - a.ev);
  }

  /**
   * Get optimizer statistics.
   * @returns {object}
   */
  getStats() {
    return {
      total_targets: this.allocations.size,
      distribution: this.currentDistribution,
      target_evs: [...this.targetEVs.entries()].map(([id, ev]) => ({ target_id: id, ev })),
      rebalance_count: this.rebalanceCount,
      last_rebalance_at: this.lastRebalanceAt,
      config: this.config,
    };
  }

  // ─── Internal ───────────────────────────────────────────────────

  _determineAllocationState(ev) {
    if (ev >= this.config.boost_threshold) return ALLOCATION_STATES.EXPLORING;
    if (ev >= 0.15) return ALLOCATION_STATES.VERIFYING;
    if (ev < this.config.eviction_threshold) return ALLOCATION_STATES.IDLE;
    return ALLOCATION_STATES.CAMPAIGN;
  }

  _allocationReason(ev, workers) {
    if (ev >= this.config.boost_threshold) return 'high_ev_target';
    if (ev >= 0.15) return 'moderate_ev_target';
    if (workers <= this.config.min_workers_per_target) return 'minimum_allocation';
    return 'low_ev_reduce_allocation';
  }

  _campaignAllocations(availableWorkers) {
    if (!this.campaignEngine) return [];

    const activeCampaigns = this.campaignEngine.list({ state: 'running' });
    if (activeCampaigns.length === 0) return [];

    // Distribute available workers across active campaigns
    const allocations = [];
    const perCampaign = Math.max(1, Math.floor(availableWorkers / activeCampaigns.length));

    for (const campaign of activeCampaigns) {
      allocations.push({
        campaign_id: campaign.id,
        campaign_name: campaign.name,
        workers: Math.min(perCampaign, campaign.budget.max_workers || perCampaign),
      });
    }

    return allocations;
  }

  /**
   * Shut down the optimizer.
   */
  shutdown() {
    if (this._rebalanceTimer) {
      clearInterval(this._rebalanceTimer);
    }
  }
}

module.exports = { ResourceOptimizer, ALLOCATION_STATES, DEFAULT_CONFIG };

