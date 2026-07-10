/**
 * BOQA budget-optimizer.js — BudgetOptimizer v0.9
 *
 * Distributes scanning budget across targets and campaigns to maximize
 * return on investment. The BudgetOptimizer manages:
 *
 *   - Budget allocation: distribute total budget across targets
 *     proportional to expected yield
 *   - Campaign budgeting: allocate budget to campaigns based on
 *     predicted effectiveness
 *   - Cost tracking: track actual vs. planned spending per
 *     target/campaign
 *   - ROI computation: compute return (bugs found × severity) /
 *     investment (worker-hours)
 *   - Budget rebalancing: reallocate underspent budget to
 *     higher-yield targets
 *   - Reserve management: maintain exploration and verification
 *     reserves
 *   - Budget alerts: alert when approaching budget limits
 *
 * Budget distribution formula:
 *   target_budget_ratio = predicted_yield × (1 - risk_penalty) ×
 *                         coverage_gap_factor
 *   Normalized so all ratios sum to (1 - reserve_ratio)
 *
 * Safe mode: budget optimizer only recommends allocations; execution
 * is delegated to the WorkerPool and CampaignEngine.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const BUDGET_DIR = path.join(__dirname, 'output', 'knowledge', 'budget');

// ─── Default Budget Configuration ───────────────────────────────────

const DEFAULT_BUDGET_CONFIG = {
  rebalance_interval_ms:    300000,   // 5 minutes
  reserve_ratio:            0.10,     // 10% held in reserve
  min_allocation_per_target: 1,       // minimum workers per target
  max_allocation_per_target: 4,       // maximum workers per target
  roi_window_days:          30,       // rolling ROI window
  alert_threshold_pct:      0.80,     // alert at 80% budget usage
  underspent_threshold_pct: 0.30,     // flag if under 30% spent
};

// ─── Alert Types ────────────────────────────────────────────────────

const ALERT_TYPES = {
  APPROACHING_LIMIT: 'approaching_limit',
  EXCEEDED:          'exceeded',
  UNDERSPENT:        'underspent',
  OVERSPENT:         'overspent',
};

// ─── Severity Weight Map ────────────────────────────────────────────

const SEVERITY_WEIGHTS = {
  critical: 1.0,
  high:     0.8,
  medium:   0.5,
  low:      0.25,
  info:     0.1,
};

// =====================================================================
//  BudgetAllocation
// =====================================================================

class BudgetAllocation {
  /**
   * @param {object} data
   */
  constructor(data = {}) {
    this.id = data.id || `BA-${crypto.randomUUID().substring(0, 8)}`;
    this.target_id = data.target_id || 'portfolio';
    this.allocated_workers = data.allocated_workers || 0;
    this.allocated_hours = data.allocated_hours || 0;
    this.allocated_hypotheses = data.allocated_hypotheses || 0;
    this.expected_bugs = data.expected_bugs || 0;
    this.expected_roi = data.expected_roi || 0;
    this.actual_bugs = data.actual_bugs || 0;
    this.actual_cost = data.actual_cost || 0;
    this.variance = data.variance || 0;
    this.ts = data.ts || Date.now();
  }
}

// =====================================================================
//  BudgetAlert
// =====================================================================

class BudgetAlert {
  /**
   * @param {object} data
   */
  constructor(data = {}) {
    this.id = data.id || `BALT-${crypto.randomUUID().substring(0, 8)}`;
    this.type = data.type || ALERT_TYPES.APPROACHING_LIMIT;
    this.target_id = data.target_id || null;
    this.severity = data.severity || 'medium';
    this.message = data.message || '';
    this.ts = data.ts || Date.now();
  }
}

// =====================================================================
//  BudgetOptimizer
// =====================================================================

class BudgetOptimizer {
  /**
   * @param {object} options
   * @param {object} [options.optimizerEngine]      - OptimizerEngine instance
   * @param {object} [options.yieldForecaster]      - YieldForecaster instance
   * @param {object} [options.campaignForecaster]   - CampaignForecaster instance
   * @param {object} [options.predictionEngine]     - PredictionEngine instance
   * @param {object} [options.efficiencyTracker]    - EfficiencyTracker instance
   * @param {object} [options.knowledgeBase]        - KnowledgeBase instance
   * @param {object} [options.brainRegistry]        - BrainRegistry instance
   * @param {object} [options.campaignEngine]       - CampaignEngine instance
   * @param {object} [options.resourceOptimizer]    - ResourceOptimizer instance
   * @param {object} [options.config]               - Override default config
   */
  constructor(options = {}) {
    this.optimizerEngine = options.optimizerEngine || null;
    this.yieldForecaster = options.yieldForecaster || null;
    this.campaignForecaster = options.campaignForecaster || null;
    this.predictionEngine = options.predictionEngine || null;
    this.efficiencyTracker = options.efficiencyTracker || null;
    this.kb = options.knowledgeBase || null;
    this.brainRegistry = options.brainRegistry || null;
    this.campaignEngine = options.campaignEngine || null;
    this.resourceOptimizer = options.resourceOptimizer || null;
    this.config = { ...DEFAULT_BUDGET_CONFIG, ...(options.config || {}) };

    // ── Total budget ────────────────────────────────────────────
    /** @type {object|null} { max_workers, max_hours, max_hypotheses, max_cost } */
    this.totalBudget = null;

    // ── Allocations ─────────────────────────────────────────────
    /** @type {Map<string, BudgetAllocation>} target_id → allocation */
    this.allocations = new Map();

    /** @type {Map<string, BudgetAllocation>} campaign_id → allocation */
    this.campaignAllocations = new Map();

    // ── Spending tracking ───────────────────────────────────────
    /** @type {Map<string, object>} target_id → { workers_spent, hours_spent, hypotheses_spent, cost_spent } */
    this.spendRecords = new Map();

    // ── ROI tracking ────────────────────────────────────────────
    /** @type {Map<string, object[]>} target_id → roi history entries */
    this.roiHistory = new Map();

    // ── Alerts ──────────────────────────────────────────────────
    /** @type {BudgetAlert[]} */
    this.alerts = [];

    // ── Reserves ────────────────────────────────────────────────
    /** @type {object} exploration + verification reserves */
    this.reserves = {
      exploration: { workers: 0, hours: 0, hypotheses: 0 },
      verification: { workers: 0, hours: 0, hypotheses: 0 },
    };

    // ── Metrics ─────────────────────────────────────────────────
    this.metrics = {
      total_budget: 0,
      total_spent: 0,
      budget_utilization: 0,
      portfolio_roi: 0,
      avg_cost_per_bug: 0,
      allocation_count: 0,
      alert_count: 0,
      rebalance_count: 0,
      last_rebalance_at: null,
    };

    // ── Allocation history ──────────────────────────────────────
    /** @type {object[]} */
    this.allocationHistory = [];

    // ── Periodic rebalance timer ────────────────────────────────
    this._rebalanceTimer = setInterval(() => {
      this.rebalanceBudget();
    }, this.config.rebalance_interval_ms);

    // Ensure directory exists
    fs.mkdirSync(BUDGET_DIR, { recursive: true });

    // Auto-load
    this.load();
  }

  // ─── Budget Setup ────────────────────────────────────────────────

  /**
   * Set the total scanning budget.
   *
   * @param {object} budget - { max_workers, max_hours, max_hypotheses, max_cost }
   */
  setTotalBudget(budget) {
    this.totalBudget = {
      max_workers: budget.max_workers || 0,
      max_hours: budget.max_hours || 0,
      max_hypotheses: budget.max_hypotheses || 0,
      max_cost: budget.max_cost || 0,
    };

    this.metrics.total_budget = this.totalBudget.max_cost;

    // Set up reserves
    const reserveWorkers = Math.max(1, Math.floor(
      this.totalBudget.max_workers * this.config.reserve_ratio
    ));
    const reserveHours = Math.max(1, Math.floor(
      this.totalBudget.max_hours * this.config.reserve_ratio
    ));
    const reserveHypotheses = Math.max(1, Math.floor(
      this.totalBudget.max_hypotheses * this.config.reserve_ratio
    ));

    // Split reserves evenly between exploration and verification
    this.reserves.exploration = {
      workers: Math.max(1, Math.floor(reserveWorkers / 2)),
      hours: Math.max(1, Math.floor(reserveHours / 2)),
      hypotheses: Math.max(1, Math.floor(reserveHypotheses / 2)),
    };

    this.reserves.verification = {
      workers: Math.max(1, reserveWorkers - this.reserves.exploration.workers),
      hours: Math.max(1, reserveHours - this.reserves.exploration.hours),
      hypotheses: Math.max(1, reserveHypotheses - this.reserves.exploration.hypotheses),
    };
  }

  // ─── Budget Allocation ───────────────────────────────────────────

  /**
   * Distribute budget across targets using predicted yield.
   *
   * Formula:
   *   target_budget_ratio = predicted_yield × (1 - risk_penalty) ×
   *                         coverage_gap_factor
   *   Normalized so all ratios sum to (1 - reserve_ratio)
   *
   * @returns {BudgetAllocation[]}
   */
  allocateBudget() {
    if (!this.totalBudget) return [];

    const targetIds = this._collectTargetIds();
    if (targetIds.length === 0) return [];

    // Compute budget ratios for each target
    const ratios = [];
    for (const targetId of targetIds) {
      const predictedYield = this._getPredictedYield(targetId);
      const riskPenalty = this._getRiskPenalty(targetId);
      const coverageGapFactor = this._getCoverageGapFactor(targetId);

      const ratio = predictedYield * (1 - riskPenalty) * coverageGapFactor;
      ratios.push({ target_id: targetId, ratio, predictedYield, riskPenalty, coverageGapFactor });
    }

    // Normalize ratios to sum to (1 - reserve_ratio)
    const totalRatio = ratios.reduce((s, r) => s + r.ratio, 0);
    const distributableRatio = 1 - this.config.reserve_ratio;

    for (const r of ratios) {
      r.normalized_ratio = totalRatio > 0
        ? (r.ratio / totalRatio) * distributableRatio
        : distributableRatio / ratios.length;
    }

    // Compute distributable budget (total minus reserves)
    const totalReserveWorkers = this.reserves.exploration.workers + this.reserves.verification.workers;
    const totalReserveHours = this.reserves.exploration.hours + this.reserves.verification.hours;
    const totalReserveHypotheses = this.reserves.exploration.hypotheses + this.reserves.verification.hypotheses;

    const distributableWorkers = Math.max(0, this.totalBudget.max_workers - totalReserveWorkers);
    const distributableHours = Math.max(0, this.totalBudget.max_hours - totalReserveHours);
    const distributableHypotheses = Math.max(0, this.totalBudget.max_hypotheses - totalReserveHypotheses);

    // Create allocations
    this.allocations.clear();
    const newAllocations = [];

    for (const r of ratios) {
      let allocatedWorkers = Math.round(r.normalized_ratio * distributableWorkers);
      let allocatedHours = Math.round(r.normalized_ratio * distributableHours);
      let allocatedHypotheses = Math.round(r.normalized_ratio * distributableHypotheses);

      // Clamp to min/max per target
      allocatedWorkers = Math.max(
        this.config.min_allocation_per_target,
        Math.min(this.config.max_allocation_per_target, allocatedWorkers)
      );
      allocatedHours = Math.max(1, allocatedHours);
      allocatedHypotheses = Math.max(1, allocatedHypotheses);

      // Expected bugs from yield forecast
      const expectedBugs = r.predictedYield * allocatedWorkers;
      const expectedROI = allocatedHours > 0 ? expectedBugs / allocatedHours : 0;

      const allocation = new BudgetAllocation({
        target_id: r.target_id,
        allocated_workers: allocatedWorkers,
        allocated_hours: allocatedHours,
        allocated_hypotheses: allocatedHypotheses,
        expected_bugs: Math.round(expectedBugs * 100) / 100,
        expected_roi: Math.round(expectedROI * 1000) / 1000,
        actual_bugs: this._getActualBugs(r.target_id),
        actual_cost: this._getActualCost(r.target_id),
        variance: 0,
      });

      allocation.variance = Math.round(
        (allocation.actual_cost - allocation.allocated_hours) * 100
      ) / 100;

      this.allocations.set(r.target_id, allocation);
      newAllocations.push(allocation);
    }

    // Adjust for total budget constraints (may exceed due to min allocations)
    this._adjustAllocationsToFitBudget(newAllocations, distributableWorkers);

    // Record history
    this.allocationHistory.push({
      allocation_count: newAllocations.length,
      total_workers_allocated: newAllocations.reduce((s, a) => s + a.allocated_workers, 0),
      total_hours_allocated: newAllocations.reduce((s, a) => s + a.allocated_hours, 0),
      ts: Date.now(),
    });

    if (this.allocationHistory.length > 100) {
      this.allocationHistory = this.allocationHistory.slice(-100);
    }

    // Update metrics
    this.metrics.allocation_count = this.allocations.size;

    return newAllocations;
  }

  /**
   * Allocate budget for a specific campaign.
   *
   * @param {string} campaignId
   * @returns {BudgetAllocation|null}
   */
  allocateCampaignBudget(campaignId) {
    if (!this.totalBudget || !this.campaignEngine) return null;

    const campaign = this.campaignEngine.campaigns
      ? this.campaignEngine.campaigns.get(campaignId)
      : null;
    if (!campaign) return null;

    // Get predicted campaign effectiveness
    const effectiveness = this._getCampaignEffectiveness(campaignId);

    // Compute campaign budget share from remaining distributable budget
    const totalAllocatedWorkers = [...this.allocations.values()]
      .reduce((s, a) => s + a.allocated_workers, 0);
    const totalReserveWorkers = this.reserves.exploration.workers + this.reserves.verification.workers;

    const remainingWorkers = Math.max(0,
      this.totalBudget.max_workers - totalAllocatedWorkers - totalReserveWorkers
    );
    const remainingHours = Math.max(0,
      this.totalBudget.max_hours - [...this.allocations.values()].reduce((s, a) => s + a.allocated_hours, 0) -
      this.reserves.exploration.hours - this.reserves.verification.hours
    );
    const remainingHypotheses = Math.max(0,
      this.totalBudget.max_hypotheses - [...this.allocations.values()].reduce((s, a) => s + a.allocated_hypotheses, 0) -
      this.reserves.exploration.hypotheses - this.reserves.verification.hypotheses
    );

    // Campaign budget proportional to effectiveness
    const campaignWorkers = Math.max(
      this.config.min_allocation_per_target,
      Math.min(
        this.config.max_allocation_per_target,
        Math.round(remainingWorkers * effectiveness)
      )
    );
    const campaignHours = Math.max(1, Math.round(remainingHours * effectiveness));
    const campaignHypotheses = Math.max(1, Math.round(remainingHypotheses * effectiveness));

    const expectedBugs = effectiveness * campaignWorkers * 0.5;
    const expectedROI = campaignHours > 0 ? expectedBugs / campaignHours : 0;

    const allocation = new BudgetAllocation({
      target_id: campaignId,
      allocated_workers: campaignWorkers,
      allocated_hours: campaignHours,
      allocated_hypotheses: campaignHypotheses,
      expected_bugs: Math.round(expectedBugs * 100) / 100,
      expected_roi: Math.round(expectedROI * 1000) / 1000,
      actual_bugs: 0,
      actual_cost: 0,
      variance: 0,
    });

    this.campaignAllocations.set(campaignId, allocation);

    return allocation;
  }

  // ─── Cost Tracking ───────────────────────────────────────────────

  /**
   * Record actual spending against a target's allocation.
   *
   * @param {string} targetId
   * @param {object} amount - { workers, hours, hypotheses, cost }
   */
  recordSpend(targetId, amount) {
    const current = this.spendRecords.get(targetId) || {
      workers_spent: 0,
      hours_spent: 0,
      hypotheses_spent: 0,
      cost_spent: 0,
    };

    current.workers_spent += amount.workers || 0;
    current.hours_spent += amount.hours || 0;
    current.hypotheses_spent += amount.hypotheses || 0;
    current.cost_spent += amount.cost || 0;

    this.spendRecords.set(targetId, current);

    // Update allocation actuals if exists
    const allocation = this.allocations.get(targetId);
    if (allocation) {
      allocation.actual_cost = current.hours_spent;
      allocation.variance = Math.round(
        (allocation.actual_cost - allocation.allocated_hours) * 100
      ) / 100;
    }

    // Update total spent in metrics
    this.metrics.total_spent = [...this.spendRecords.values()]
      .reduce((s, r) => s + r.cost_spent, 0);

    if (this.metrics.total_budget > 0) {
      this.metrics.budget_utilization = Math.round(
        (this.metrics.total_spent / this.metrics.total_budget) * 1000
      ) / 1000;
    }

    // Check alerts on each spend
    this._checkTargetAlerts(targetId);
  }

  // ─── ROI Computation ─────────────────────────────────────────────

  /**
   * Compute return on investment for a target.
   *
   * ROI = (bugs_found × severity_weight) / investment_hours
   *
   * @param {string} targetId
   * @returns {object} { roi, bugs_found, severity_return, investment_hours }
   */
  computeROI(targetId) {
    const allocation = this.allocations.get(targetId);
    const spend = this.spendRecords.get(targetId);
    const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;

    // Count confirmed bugs and their severity-weighted return
    let bugsFound = 0;
    let severityReturn = 0;

    if (brain) {
      const confirmed = brain.historicalFindings.filter(
        f => f.lifecycle_state === 'confirmed' || f.verdict === 'confirmed'
      );

      // Filter to ROI window
      const windowMs = this.config.roi_window_days * 86400000;
      const recentConfirmed = confirmed.filter(f => {
        const ts = f.created_at || f.observed_at || 0;
        return Date.now() - ts < windowMs;
      });

      bugsFound = recentConfirmed.length;

      for (const f of recentConfirmed) {
        severityReturn += SEVERITY_WEIGHTS[f.severity] || 0.5;
      }
    }

    const investmentHours = spend ? spend.hours_spent : (allocation ? allocation.allocated_hours : 0);
    const roi = investmentHours > 0 ? severityReturn / investmentHours : 0;

    // Update allocation
    if (allocation) {
      allocation.actual_bugs = bugsFound;
    }

    // Record in ROI history
    if (!this.roiHistory.has(targetId)) {
      this.roiHistory.set(targetId, []);
    }

    const history = this.roiHistory.get(targetId);
    history.push({
      roi: Math.round(roi * 10000) / 10000,
      bugs_found: bugsFound,
      severity_return: Math.round(severityReturn * 100) / 100,
      investment_hours: investmentHours,
      ts: Date.now(),
    });

    if (history.length > 500) {
      this.roiHistory.set(targetId, history.slice(-500));
    }

    return {
      roi: Math.round(roi * 10000) / 10000,
      bugs_found: bugsFound,
      severity_return: Math.round(severityReturn * 100) / 100,
      investment_hours: investmentHours,
    };
  }

  /**
   * Compute portfolio-level ROI.
   *
   * @returns {object} { roi, total_bugs, total_severity_return, total_investment, per_target }
   */
  computePortfolioROI() {
    let totalBugs = 0;
    let totalSeverityReturn = 0;
    let totalInvestment = 0;
    const perTarget = [];

    for (const [targetId] of this.allocations) {
      const result = this.computeROI(targetId);
      totalBugs += result.bugs_found;
      totalSeverityReturn += result.severity_return;
      totalInvestment += result.investment_hours;
      perTarget.push({ target_id: targetId, ...result });
    }

    const portfolioROI = totalInvestment > 0 ? totalSeverityReturn / totalInvestment : 0;

    this.metrics.portfolio_roi = Math.round(portfolioROI * 10000) / 10000;

    // Avg cost per bug
    if (totalBugs > 0 && this.metrics.total_spent > 0) {
      this.metrics.avg_cost_per_bug = Math.round(
        (this.metrics.total_spent / totalBugs) * 100
      ) / 100;
    }

    return {
      roi: Math.round(portfolioROI * 10000) / 10000,
      total_bugs: totalBugs,
      total_severity_return: Math.round(totalSeverityReturn * 100) / 100,
      total_investment: totalInvestment,
      per_target: perTarget,
    };
  }

  // ─── Budget Rebalancing ──────────────────────────────────────────

  /**
   * Reallocate underspent/overspent budget to higher-yield targets.
   *
   * Strategy:
   *   1. Identify underspent targets (spent < underspent_threshold × allocation)
   *   2. Identify overspent targets (spent > allocation)
   *   3. Reclaim budget from underspent targets
   *   4. Redistribute reclaimed budget to highest-yield targets
   *   5. Re-run allocation with updated ratios
   *
   * @returns {object} { rebalanced, reclaimed, redistributed, allocations }
   */
  rebalanceBudget() {
    if (!this.totalBudget) return { rebalanced: false, reason: 'no_budget' };

    const underspentThreshold = this.config.underspent_threshold_pct;
    let reclaimedWorkers = 0;
    let reclaimedHours = 0;
    let reclaimedHypotheses = 0;
    const reclaimedFrom = [];

    // Identify underspent targets and reclaim excess
    for (const [targetId, allocation] of this.allocations) {
      const spend = this.spendRecords.get(targetId);
      const hoursSpent = spend ? spend.hours_spent : 0;
      const spendRatio = allocation.allocated_hours > 0
        ? hoursSpent / allocation.allocated_hours
        : 0;

      if (spendRatio < underspentThreshold && allocation.allocated_workers > this.config.min_allocation_per_target) {
        // Reclaim one worker from underspent targets
        const reclaimed = allocation.allocated_workers - this.config.min_allocation_per_target;
        const fractionReclaimed = reclaimed / allocation.allocated_workers;

        reclaimedWorkers += reclaimed;
        reclaimedHours += Math.round(allocation.allocated_hours * fractionReclaimed);
        reclaimedHypotheses += Math.round(allocation.allocated_hypotheses * fractionReclaimed);

        allocation.allocated_workers = this.config.min_allocation_per_target;
        allocation.allocated_hours = Math.max(1, allocation.allocated_hours - Math.round(allocation.allocated_hours * fractionReclaimed));
        allocation.allocated_hypotheses = Math.max(1, allocation.allocated_hypotheses - Math.round(allocation.allocated_hypotheses * fractionReclaimed));

        reclaimedFrom.push({
          target_id: targetId,
          workers_reclaimed: reclaimed,
          hours_reclaimed: Math.round(allocation.allocated_hours * fractionReclaimed),
          spend_ratio: Math.round(spendRatio * 100) / 100,
        });
      }
    }

    // Redistribute reclaimed budget to highest-yield targets
    const redistributed = [];
    if (reclaimedWorkers > 0 || reclaimedHours > 0) {
      // Sort allocations by expected ROI descending
      const sortedAllocations = [...this.allocations.values()]
        .sort((a, b) => b.expected_roi - a.expected_roi);

      let workersToDistribute = reclaimedWorkers;
      let hoursToDistribute = reclaimedHours;
      let hypothesesToDistribute = reclaimedHypotheses;

      for (const allocation of sortedAllocations) {
        if (workersToDistribute <= 0 && hoursToDistribute <= 0) break;
        if (allocation.allocated_workers >= this.config.max_allocation_per_target) continue;

        const additionalWorkers = Math.min(
          this.config.max_allocation_per_target - allocation.allocated_workers,
          workersToDistribute
        );

        if (additionalWorkers > 0) {
          const hoursPerWorker = allocation.allocated_hours / Math.max(allocation.allocated_workers, 1);
          const hypothesesPerWorker = allocation.allocated_hypotheses / Math.max(allocation.allocated_workers, 1);

          allocation.allocated_workers += additionalWorkers;
          allocation.allocated_hours += Math.round(additionalWorkers * hoursPerWorker);
          allocation.allocated_hypotheses += Math.round(additionalWorkers * hypothesesPerWorker);

          // Recalculate expected values
          allocation.expected_bugs = Math.round(
            this._getPredictedYield(allocation.target_id) * allocation.allocated_workers * 100
          ) / 100;
          allocation.expected_roi = allocation.allocated_hours > 0
            ? Math.round((allocation.expected_bugs / allocation.allocated_hours) * 1000) / 1000
            : 0;

          workersToDistribute -= additionalWorkers;
          hoursToDistribute -= Math.round(additionalWorkers * hoursPerWorker);
          hypothesesToDistribute -= Math.round(additionalWorkers * hypothesesPerWorker);

          redistributed.push({
            target_id: allocation.target_id,
            workers_added: additionalWorkers,
            new_expected_roi: allocation.expected_roi,
          });
        }
      }
    }

    // Update metrics
    this.metrics.rebalance_count++;
    this.metrics.last_rebalance_at = Date.now();

    return {
      rebalanced: true,
      reclaimed: {
        workers: reclaimedWorkers,
        hours: reclaimedHours,
        hypotheses: reclaimedHypotheses,
        from: reclaimedFrom,
      },
      redistributed,
      allocations: [...this.allocations.values()],
    };
  }

  // ─── Alert Checking ──────────────────────────────────────────────

  /**
   * Check for budget limit approaches and generate alerts.
   *
   * @returns {BudgetAlert[]}
   */
  checkAlerts() {
    const newAlerts = [];

    // Portfolio-level alerts
    if (this.totalBudget) {
      const totalHoursSpent = [...this.spendRecords.values()]
        .reduce((s, r) => s + r.hours_spent, 0);
      const totalCostSpent = [...this.spendRecords.values()]
        .reduce((s, r) => s + r.cost_spent, 0);

      const hourUtilization = this.totalBudget.max_hours > 0
        ? totalHoursSpent / this.totalBudget.max_hours
        : 0;
      const costUtilization = this.totalBudget.max_cost > 0
        ? totalCostSpent / this.totalBudget.max_cost
        : 0;

      // Approaching limit
      if (hourUtilization >= this.config.alert_threshold_pct && hourUtilization < 1.0) {
        newAlerts.push(new BudgetAlert({
          type: ALERT_TYPES.APPROACHING_LIMIT,
          target_id: 'portfolio',
          severity: 'high',
          message: `Portfolio hours at ${Math.round(hourUtilization * 100)}% of budget (${totalHoursSpent}/${this.totalBudget.max_hours})`,
        }));
      }

      if (costUtilization >= this.config.alert_threshold_pct && costUtilization < 1.0) {
        newAlerts.push(new BudgetAlert({
          type: ALERT_TYPES.APPROACHING_LIMIT,
          target_id: 'portfolio',
          severity: 'high',
          message: `Portfolio cost at ${Math.round(costUtilization * 100)}% of budget (${totalCostSpent}/${this.totalBudget.max_cost})`,
        }));
      }

      // Exceeded
      if (hourUtilization >= 1.0) {
        newAlerts.push(new BudgetAlert({
          type: ALERT_TYPES.EXCEEDED,
          target_id: 'portfolio',
          severity: 'critical',
          message: `Portfolio hours budget exceeded (${totalHoursSpent}/${this.totalBudget.max_hours})`,
        }));
      }

      if (costUtilization >= 1.0) {
        newAlerts.push(new BudgetAlert({
          type: ALERT_TYPES.EXCEEDED,
          target_id: 'portfolio',
          severity: 'critical',
          message: `Portfolio cost budget exceeded (${totalCostSpent}/${this.totalBudget.max_cost})`,
        }));
      }
    }

    // Per-target alerts
    for (const [targetId, allocation] of this.allocations) {
      const spend = this.spendRecords.get(targetId);
      if (!spend) continue;

      const hoursRatio = allocation.allocated_hours > 0
        ? spend.hours_spent / allocation.allocated_hours
        : 0;

      // Underspent
      if (hoursRatio < this.config.underspent_threshold_pct) {
        newAlerts.push(new BudgetAlert({
          type: ALERT_TYPES.UNDERSPENT,
          target_id: targetId,
          severity: 'low',
          message: `Target ${targetId} underspent: ${Math.round(hoursRatio * 100)}% of allocation used (${spend.hours_spent}/${allocation.allocated_hours} hours)`,
        }));
      }

      // Overspent
      if (hoursRatio > 1.0) {
        newAlerts.push(new BudgetAlert({
          type: ALERT_TYPES.OVERSPENT,
          target_id: targetId,
          severity: 'medium',
          message: `Target ${targetId} overspent: ${Math.round(hoursRatio * 100)}% of allocation used (${spend.hours_spent}/${allocation.allocated_hours} hours)`,
        }));
      }

      // Approaching limit per target
      if (hoursRatio >= this.config.alert_threshold_pct && hoursRatio <= 1.0) {
        newAlerts.push(new BudgetAlert({
          type: ALERT_TYPES.APPROACHING_LIMIT,
          target_id: targetId,
          severity: 'medium',
          message: `Target ${targetId} approaching budget limit: ${Math.round(hoursRatio * 100)}% used`,
        }));
      }
    }

    // Add new alerts
    this.alerts.push(...newAlerts);

    // Cap alerts
    if (this.alerts.length > 1000) {
      this.alerts = this.alerts.slice(-1000);
    }

    this.metrics.alert_count = this.alerts.length;

    return newAlerts;
  }

  // ─── Metrics ─────────────────────────────────────────────────────

  /**
   * Get current budget optimizer metrics.
   *
   * @returns {object}
   */
  getMetrics() {
    // Refresh computed metrics
    if (this.totalBudget) {
      const totalSpent = [...this.spendRecords.values()]
        .reduce((s, r) => s + r.cost_spent, 0);
      this.metrics.total_budget = this.totalBudget.max_cost;
      this.metrics.total_spent = totalSpent;
      this.metrics.budget_utilization = this.totalBudget.max_cost > 0
        ? Math.round((totalSpent / this.totalBudget.max_cost) * 1000) / 1000
        : 0;
    }

    this.metrics.allocation_count = this.allocations.size;
    this.metrics.alert_count = this.alerts.length;

    return { ...this.metrics };
  }

  // ─── Internal: Yield / Risk / Coverage Helpers ───────────────────

  /**
   * Get predicted yield for a target from yield forecaster or prediction engine.
   * @param {string} targetId
   * @returns {number} 0-100
   */
  _getPredictedYield(targetId) {
    // Try yield forecaster first
    if (this.yieldForecaster) {
      const forecast = this.yieldForecaster.getTargetForecast(targetId);
      if (forecast && forecast.expected_bugs > 0) {
        return Math.min(forecast.expected_bugs, 100);
      }
    }

    // Try prediction engine
    if (this.predictionEngine) {
      const prediction = this.predictionEngine.getTargetPrediction
        ? this.predictionEngine.getTargetPrediction(targetId)
        : null;
      if (prediction && prediction.predicted_yield) {
        return Math.min(prediction.predicted_yield, 100);
      }
    }

    // Fallback: estimate from brain
    if (this.brainRegistry) {
      const brain = this.brainRegistry.getOrCreate(targetId);
      if (brain && brain.total_sessions > 0) {
        const confirmed = brain.historicalFindings.filter(
          f => f.lifecycle_state === 'confirmed' || f.verdict === 'confirmed'
        ).length;
        return Math.min(confirmed / brain.total_sessions * 10, 100);
      }
    }

    return 1.0; // default: low but non-zero for new targets
  }

  /**
   * Get risk penalty for a target (0-1, higher = more risky = less budget).
   * @param {string} targetId
   * @returns {number}
   */
  _getRiskPenalty(targetId) {
    // High risk targets might waste budget on false positives
    if (this.optimizerEngine && this.optimizerEngine._computeRiskPenalty) {
      return this.optimizerEngine._computeRiskPenalty(targetId);
    }

    // Estimate from brain false positive rate
    if (this.brainRegistry) {
      const brain = this.brainRegistry.getOrCreate(targetId);
      if (brain && brain.historicalFindings.length > 0) {
        const falsePositives = brain.historicalFindings.filter(
          f => f.lifecycle_state === 'false_positive' || f.verdict === 'false_positive'
        ).length;
        const fpRate = falsePositives / brain.historicalFindings.length;
        return Math.min(fpRate * 0.5, 0.5); // cap at 50% penalty
      }
    }

    return 0.05; // default: small risk penalty
  }

  /**
   * Get coverage gap factor for a target (0-1, higher = more gap = more budget).
   * @param {string} targetId
   * @returns {number}
   */
  _getCoverageGapFactor(targetId) {
    if (this.brainRegistry) {
      const brain = this.brainRegistry.getOrCreate(targetId);
      if (brain && brain.coverageTrend.length > 0) {
        const latestCoverage = brain.coverageTrend[brain.coverageTrend.length - 1].score / 100;
        return 1 - latestCoverage; // gap = 1 - coverage
      }
    }

    return 0.7; // default: assume significant coverage gap
  }

  /**
   * Get campaign effectiveness score.
   * @param {string} campaignId
   * @returns {number} 0-1
   */
  _getCampaignEffectiveness(campaignId) {
    if (this.campaignForecaster) {
      const forecast = this.campaignForecaster.getLatestForecast
        ? this.campaignForecaster.getLatestForecast()
        : null;
      if (forecast && forecast.recommended_shapes) {
        const matchingShape = forecast.recommended_shapes.find(
          s => s.id === campaignId || s.type === campaignId
        );
        if (matchingShape) {
          return matchingShape.effectiveness_score / 100;
        }
      }
    }

    return 0.5; // default effectiveness
  }

  // ─── Internal: Budget Helpers ────────────────────────────────────

  _adjustAllocationsToFitBudget(allocations, distributableWorkers) {
    let totalAllocated = allocations.reduce((s, a) => s + a.allocated_workers, 0);
    let iterations = 0;

    while (totalAllocated > distributableWorkers && iterations < 50) {
      // Find allocation with most workers above minimum
      const target = allocations
        .filter(a => a.allocated_workers > this.config.min_allocation_per_target)
        .sort((a, b) => b.allocated_workers - a.allocated_workers)[0];

      if (!target) break;

      target.allocated_workers--;
      totalAllocated--;
      iterations++;

      // Adjust hours and hypotheses proportionally
      const ratio = target.allocated_workers / (target.allocated_workers + 1);
      target.allocated_hours = Math.max(1, Math.round(target.allocated_hours * ratio));
      target.allocated_hypotheses = Math.max(1, Math.round(target.allocated_hypotheses * ratio));
    }
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

  _getActualBugs(targetId) {
    if (this.brainRegistry) {
      const brain = this.brainRegistry.getOrCreate(targetId);
      if (brain) {
        return brain.historicalFindings.filter(
          f => f.lifecycle_state === 'confirmed' || f.verdict === 'confirmed'
        ).length;
      }
    }
    return 0;
  }

  _getActualCost(targetId) {
    const spend = this.spendRecords.get(targetId);
    return spend ? spend.hours_spent : 0;
  }

  _checkTargetAlerts(targetId) {
    if (!this.totalBudget) return;

    const allocation = this.allocations.get(targetId);
    const spend = this.spendRecords.get(targetId);
    if (!allocation || !spend) return;

    const hourRatio = allocation.allocated_hours > 0
      ? spend.hours_spent / allocation.allocated_hours
      : 0;

    // Check for approaching limit
    if (hourRatio >= this.config.alert_threshold_pct && hourRatio < 1.0) {
      this._addAlert(ALERT_TYPES.APPROACHING_LIMIT, targetId, 'medium',
        `Target ${targetId} approaching budget: ${Math.round(hourRatio * 100)}% used`);
    }

    // Check for exceeded
    if (hourRatio >= 1.0) {
      this._addAlert(ALERT_TYPES.EXCEEDED, targetId, 'critical',
        `Target ${targetId} exceeded budget: ${Math.round(hourRatio * 100)}% used`);
    }
  }

  _addAlert(type, targetId, severity, message) {
    // Deduplicate: don't add same type/target within 60 seconds
    const recent = this.alerts.find(a =>
      a.type === type &&
      a.target_id === targetId &&
      Date.now() - a.ts < 60000
    );
    if (recent) return;

    const alert = new BudgetAlert({
      type,
      target_id: targetId,
      severity,
      message,
    });

    this.alerts.push(alert);

    if (this.alerts.length > 1000) {
      this.alerts = this.alerts.slice(-1000);
    }

    this.metrics.alert_count = this.alerts.length;
  }

  // ─── Persistence ────────────────────────────────────────────────

  /**
   * Save budget optimizer state to disk.
   * @returns {string} file path
   */
  save() {
    const filePath = path.join(BUDGET_DIR, 'budget-optimizer.json');

    const data = {
      version: '0.9',
      saved_at: Date.now(),
      total_budget: this.totalBudget,
      allocations: [...this.allocations.entries()].map(([k, v]) => [k, { ...v }]),
      campaign_allocations: [...this.campaignAllocations.entries()].map(([k, v]) => [k, { ...v }]),
      spend_records: [...this.spendRecords.entries()],
      roi_history: [...this.roiHistory.entries()].map(([k, v]) => [k, v.slice(-100)]),
      alerts: this.alerts.slice(-200),
      reserves: this.reserves,
      metrics: this.metrics,
      allocation_history: this.allocationHistory.slice(-50),
      config: this.config,
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  /**
   * Load budget optimizer state from disk.
   * @returns {boolean}
   */
  load() {
    const filePath = path.join(BUDGET_DIR, 'budget-optimizer.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      this.totalBudget = data.total_budget || null;

      this.allocations = new Map(
        (data.allocations || []).map(([k, v]) => [k, new BudgetAllocation(v)])
      );

      this.campaignAllocations = new Map(
        (data.campaign_allocations || []).map(([k, v]) => [k, new BudgetAllocation(v)])
      );

      this.spendRecords = new Map(data.spend_records || []);

      this.roiHistory = new Map(
        (data.roi_history || []).map(([k, v]) => [k, Array.isArray(v) ? v : []])
      );

      this.alerts = (data.alerts || []).map(a => new BudgetAlert(a));

      this.reserves = data.reserves || {
        exploration: { workers: 0, hours: 0, hypotheses: 0 },
        verification: { workers: 0, hours: 0, hypotheses: 0 },
      };

      this.metrics = data.metrics || { ...this.metrics };
      this.allocationHistory = data.allocation_history || [];

      return true;
    } catch (_) {
      return false;
    }
  }

  // ─── Shutdown ────────────────────────────────────────────────────

  /**
   * Shut down the budget optimizer.
   */
  shutdown() {
    if (this._rebalanceTimer) {
      clearInterval(this._rebalanceTimer);
      this._rebalanceTimer = null;
    }

    // Final save
    try {
      this.save();
    } catch (_) {
      // ignore save errors during shutdown
    }
  }
}

module.exports = { BudgetOptimizer, BudgetAllocation, BudgetAlert, DEFAULT_BUDGET_CONFIG };

