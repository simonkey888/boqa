/**
 * BOQA campaign-engine.js — Campaign Engine v0.7
 *
 * Runs long-lived discovery campaigns that span multiple sessions
 * and targets. Campaign types:
 *
 *   - continuous_scan:  runs continuously with configurable intervals
 *   - scheduled_scan:   runs at specific times (cron-like)
 *   - goal_based_scan:  runs until a specific goal is met
 *   - coverage_campaign: runs until coverage target is achieved
 *
 * Campaign lifecycle:
 *   created → scheduled → running → paused → completed | failed | cancelled
 *
 * Each campaign tracks:
 *   - target(s) and scope
 *   - execution history (runs, results)
 *   - goal progress (if goal-based)
 *   - resource budget (max workers, max duration, max findings)
 *   - learning feedback (what worked, what didn't)
 *
 * The campaign engine integrates with:
 *   - CoveragePlanner for discovery planning
 *   - VerificationFarm for hypothesis validation
 *   - LearningEngine for campaign optimization
 *   - TargetBrain for target-specific intelligence
 *
 * Safe mode: campaigns respect authorization boundaries and
 * never exceed configured resource budgets.
 */

const crypto = require('crypto');
const { EventEmitter } = require('events');
const fs = require('fs');
const path = require('path');

// ─── Campaign Types ────────────────────────────────────────────────

const CAMPAIGN_TYPES = {
  CONTINUOUS_SCAN:   'continuous_scan',
  SCHEDULED_SCAN:    'scheduled_scan',
  GOAL_BASED_SCAN:   'goal_based_scan',
  COVERAGE_CAMPAIGN: 'coverage_campaign',
};

// ─── Campaign States ───────────────────────────────────────────────

const CAMPAIGN_STATES = {
  CREATED:   'created',
  SCHEDULED: 'scheduled',
  RUNNING:   'running',
  PAUSED:    'paused',
  COMPLETED: 'completed',
  FAILED:    'failed',
  CANCELLED: 'cancelled',
};

// ─── Default Config ────────────────────────────────────────────────

const DEFAULT_BUDGET = {
  max_workers: 4,
  max_duration_ms: 86400000,     // 24 hours
  max_findings: 1000,
  max_iterations: 100,
  max_hypotheses_per_run: 50,
};

const CAMPAIGNS_DIR = path.join(__dirname, 'output', 'campaigns');

// =====================================================================
//  Campaign
// =====================================================================

class Campaign {
  constructor(config = {}) {
    this.id = config.id || `CMP-${crypto.randomUUID().substring(0, 8)}`;
    this.name = config.name || `Campaign ${this.id}`;
    this.type = config.type || CAMPAIGN_TYPES.CONTINUOUS_SCAN;
    this.state = config.state || CAMPAIGN_STATES.CREATED;
    this.target_ids = config.target_ids || [];
    this.scope = config.scope || {}; // { domains, endpoints, categories }
    this.budget = { ...DEFAULT_BUDGET, ...(config.budget || {}) };

    // Scheduling
    this.schedule = config.schedule || {
      interval_ms: 300000, // 5 minutes default
      start_at: null,
      end_at: null,
      cron: null,
    };

    // Goals (for goal_based and coverage campaigns)
    this.goals = config.goals || {
      coverage_target: null,    // e.g., 90
      finding_target: null,     // e.g., 10 confirmed bugs
      categories: [],           // e.g., ['auth_bypass', 'csrf']
    };

    // Execution tracking
    this.runs = [];
    this.current_run = null;
    this.total_iterations = 0;
    this.total_hypotheses = 0;
    this.total_verifications = 0;
    this.total_bugs_confirmed = 0;
    this.total_events_processed = 0;

    // Learning
    this.effectiveness = {
      bugs_per_iteration: 0,
      avg_coverage_delta: 0,
      avg_verification_success_rate: 0,
      best_categories: [],
      worst_categories: [],
    };

    // Metadata
    this.created_at = Date.now();
    this.updated_at = Date.now();
    this.started_at = null;
    this.completed_at = null;
    this.last_run_at = null;

    // Tags for filtering
    this.tags = config.tags || [];
    this.metadata = config.metadata || {};
  }

  /**
   * Start a campaign run.
   * @returns {object} the run record
   */
  startRun() {
    const run = {
      id: `RUN-${crypto.randomUUID().substring(0, 8)}`,
      campaign_id: this.id,
      started_at: Date.now(),
      ended_at: null,
      status: 'running',
      iterations: 0,
      hypotheses_generated: 0,
      verifications_dispatched: 0,
      bugs_confirmed: 0,
      coverage_before: null,
      coverage_after: null,
      events_processed: 0,
    };

    this.current_run = run;
    this.state = CAMPAIGN_STATES.RUNNING;
    this.updated_at = Date.now();

    if (!this.started_at) {
      this.started_at = Date.now();
    }

    return run;
  }

  /**
   * End the current campaign run.
   *
   * @param {object} results - run results
   * @returns {object} the completed run
   */
  endRun(results = {}) {
    if (!this.current_run) return null;

    const run = this.current_run;
    run.ended_at = Date.now();
    run.status = results.status || 'completed';
    run.iterations = results.iterations || run.iterations;
    run.hypotheses_generated = results.hypotheses_generated || run.hypotheses_generated;
    run.verifications_dispatched = results.verifications_dispatched || run.verifications_dispatched;
    run.bugs_confirmed = results.bugs_confirmed || run.bugs_confirmed;
    run.coverage_after = results.coverage_after || run.coverage_after;
    run.events_processed = results.events_processed || run.events_processed;

    this.runs.push(run);
    this.current_run = null;

    // Update aggregate stats
    this.total_iterations += run.iterations;
    this.total_hypotheses += run.hypotheses_generated;
    this.total_verifications += run.verifications_dispatched;
    this.total_bugs_confirmed += run.bugs_confirmed;
    this.total_events_processed += run.events_processed;
    this.last_run_at = Date.now();
    this.updated_at = Date.now();

    // Update effectiveness
    this._computeEffectiveness();

    return run;
  }

  /**
   * Check if campaign goals are met.
   * @returns {boolean}
   */
  goalsMet() {
    if (this.type === CAMPAIGN_TYPES.COVERAGE_CAMPAIGN && this.goals.coverage_target) {
      // Check latest coverage from runs
      const latestRun = this.runs[this.runs.length - 1];
      if (latestRun?.coverage_after >= this.goals.coverage_target) {
        return true;
      }
    }

    if (this.type === CAMPAIGN_TYPES.GOAL_BASED_SCAN && this.goals.finding_target) {
      if (this.total_bugs_confirmed >= this.goals.finding_target) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if budget is exceeded.
   * @returns {boolean}
   */
  budgetExceeded() {
    if (this.budget.max_duration_ms && this.started_at) {
      if (Date.now() - this.started_at > this.budget.max_duration_ms) {
        return true;
      }
    }
    if (this.budget.max_findings && this.total_bugs_confirmed >= this.budget.max_findings) {
      return true;
    }
    if (this.budget.max_iterations && this.total_iterations >= this.budget.max_iterations) {
      return true;
    }
    return false;
  }

  /**
   * Get a summary of the campaign.
   * @returns {object}
   */
  getSummary() {
    return {
      id: this.id,
      name: this.name,
      type: this.type,
      state: this.state,
      target_ids: this.target_ids,
      total_runs: this.runs.length,
      total_iterations: this.total_iterations,
      total_hypotheses: this.total_hypotheses,
      total_verifications: this.total_verifications,
      total_bugs_confirmed: this.total_bugs_confirmed,
      total_events_processed: this.total_events_processed,
      effectiveness: this.effectiveness,
      goals_met: this.goalsMet(),
      budget_exceeded: this.budgetExceeded(),
      duration_ms: this.started_at ? Date.now() - this.started_at : 0,
      created_at: this.created_at,
      started_at: this.started_at,
      last_run_at: this.last_run_at,
      tags: this.tags,
    };
  }

  _computeEffectiveness() {
    if (this.total_iterations === 0) return;

    this.effectiveness.bugs_per_iteration =
      Math.round((this.total_bugs_confirmed / this.total_iterations) * 1000) / 1000;

    // Compute average coverage delta from runs
    const runsWithCoverage = this.runs.filter(r => r.coverage_before != null && r.coverage_after != null);
    if (runsWithCoverage.length > 0) {
      this.effectiveness.avg_coverage_delta = Math.round(
        runsWithCoverage.reduce((s, r) => s + (r.coverage_after - r.coverage_before), 0) /
        runsWithCoverage.length * 100
      ) / 100;
    }

    // Compute verification success rate
    if (this.total_verifications > 0) {
      this.effectiveness.avg_verification_success_rate =
        Math.round((this.total_bugs_confirmed / this.total_verifications) * 1000) / 1000;
    }
  }
}

// =====================================================================
//  CampaignEngine
// =====================================================================

class CampaignEngine extends EventEmitter {
  /**
   * @param {object} options
   * @param {object} [options.knowledgeBase]   - KnowledgeBase instance
   * @param {object} [options.coveragePlanner]  - CoveragePlanner instance
   * @param {object} [options.verificationFarm] - VerificationFarm instance
   * @param {object} [options.learningEngine]   - LearningEngine instance
   * @param {object} [options.brainRegistry]    - BrainRegistry instance
   */
  constructor(options = {}) {
    super();

    this.kb = options.knowledgeBase || null;
    this.coveragePlanner = options.coveragePlanner || null;
    this.verificationFarm = options.verificationFarm || null;
    this.learningEngine = options.learningEngine || null;
    this.brainRegistry = options.brainRegistry || null;

    /** @type {Map<string, Campaign>} campaign_id → campaign */
    this.campaigns = new Map();

    /** @type {Map<string, NodeJS.Timeout>} campaign_id → interval timer */
    this._timers = new Map();

    /** @type {boolean} engine running flag */
    this._running = false;

    // Ensure directory exists
    fs.mkdirSync(CAMPAIGNS_DIR, { recursive: true });

    // Auto-load
    this._loadAll();
  }

  // ─── Campaign CRUD ──────────────────────────────────────────────

  /**
   * Create a new campaign.
   *
   * @param {object} config - campaign configuration
   * @returns {Campaign}
   */
  create(config = {}) {
    const campaign = new Campaign(config);
    this.campaigns.set(campaign.id, campaign);
    this.emit('campaign_created', campaign);

    // If scheduled, set up timer
    if (campaign.type === CAMPAIGN_TYPES.SCHEDULED_SCAN && campaign.schedule.interval_ms) {
      this._scheduleCampaign(campaign);
    }

    return campaign;
  }

  /**
   * Get a campaign by ID.
   *
   * @param {string} campaignId
   * @returns {Campaign|null}
   */
  get(campaignId) {
    return this.campaigns.get(campaignId) || null;
  }

  /**
   * List campaigns, optionally filtered.
   *
   * @param {object} [filter] - { state, type, target_id, tag }
   * @returns {Campaign[]}
   */
  list(filter = {}) {
    let results = [...this.campaigns.values()];

    if (filter.state) {
      results = results.filter(c => c.state === filter.state);
    }
    if (filter.type) {
      results = results.filter(c => c.type === filter.type);
    }
    if (filter.target_id) {
      results = results.filter(c => c.target_ids.includes(filter.target_id));
    }
    if (filter.tag) {
      results = results.filter(c => c.tags.includes(filter.tag));
    }

    return results.sort((a, b) => b.updated_at - a.updated_at);
  }

  // ─── Campaign Control ───────────────────────────────────────────

  /**
   * Start a campaign.
   *
   * @param {string} campaignId
   * @returns {object} run record
   */
  start(campaignId) {
    const campaign = this.campaigns.get(campaignId);
    if (!campaign) throw new Error(`Campaign not found: ${campaignId}`);

    if (campaign.state === CAMPAIGN_STATES.RUNNING) {
      throw new Error(`Campaign already running: ${campaignId}`);
    }

    const run = campaign.startRun();
    this.emit('campaign_started', campaign);

    // For continuous scans, set up interval
    if (campaign.type === CAMPAIGN_TYPES.CONTINUOUS_SCAN) {
      this._scheduleCampaign(campaign);
    }

    return run;
  }

  /**
   * Pause a running campaign.
   *
   * @param {string} campaignId
   * @param {object} [results] - optional results snapshot
   */
  pause(campaignId, results = {}) {
    const campaign = this.campaigns.get(campaignId);
    if (!campaign) throw new Error(`Campaign not found: ${campaignId}`);

    if (campaign.current_run) {
      campaign.endRun({ ...results, status: 'paused' });
    }

    campaign.state = CAMPAIGN_STATES.PAUSED;
    campaign.updated_at = Date.now();

    // Clear timer
    this._clearTimer(campaignId);

    this.emit('campaign_paused', campaign);
  }

  /**
   * Resume a paused campaign.
   *
   * @param {string} campaignId
   * @returns {object} new run record
   */
  resume(campaignId) {
    const campaign = this.campaigns.get(campaignId);
    if (!campaign) throw new Error(`Campaign not found: ${campaignId}`);

    if (campaign.state !== CAMPAIGN_STATES.PAUSED) {
      throw new Error(`Campaign not paused: ${campaignId}`);
    }

    const run = campaign.startRun();
    this._scheduleCampaign(campaign);
    this.emit('campaign_resumed', campaign);
    return run;
  }

  /**
   * Cancel a campaign.
   *
   * @param {string} campaignId
   */
  cancel(campaignId) {
    const campaign = this.campaigns.get(campaignId);
    if (!campaign) throw new Error(`Campaign not found: ${campaignId}`);

    if (campaign.current_run) {
      campaign.endRun({ status: 'cancelled' });
    }

    campaign.state = CAMPAIGN_STATES.CANCELLED;
    campaign.completed_at = Date.now();
    campaign.updated_at = Date.now();

    this._clearTimer(campaignId);
    this.emit('campaign_cancelled', campaign);
  }

  /**
   * Complete a campaign (mark as done).
   *
   * @param {string} campaignId
   */
  complete(campaignId) {
    const campaign = this.campaigns.get(campaignId);
    if (!campaign) throw new Error(`Campaign not found: ${campaignId}`);

    if (campaign.current_run) {
      campaign.endRun({ status: 'completed' });
    }

    campaign.state = CAMPAIGN_STATES.COMPLETED;
    campaign.completed_at = Date.now();
    campaign.updated_at = Date.now();

    this._clearTimer(campaignId);
    this.emit('campaign_completed', campaign);
  }

  // ─── Campaign Execution ─────────────────────────────────────────

  /**
   * Execute a single iteration of a campaign.
   * This is the core loop step: discover → hypothesize → verify → learn.
   *
   * @param {string} campaignId
   * @returns {object} iteration results
   */
  async executeIteration(campaignId) {
    const campaign = this.campaigns.get(campaignId);
    if (!campaign) throw new Error(`Campaign not found: ${campaignId}`);

    const iterationStart = Date.now();
    const results = {
      campaign_id: campaignId,
      iteration: campaign.total_iterations + 1,
      started_at: iterationStart,
      hypotheses_generated: 0,
      verifications_dispatched: 0,
      bugs_confirmed: 0,
      coverage_before: 0,
      coverage_after: 0,
      events_processed: 0,
      learning_applied: false,
    };

    // For each target in the campaign
    for (const targetId of campaign.target_ids) {
      // Get target brain
      const brain = this.brainRegistry ? this.brainRegistry.getOrCreate(targetId) : null;

      // Step 1: Get current coverage
      if (this.coveragePlanner) {
        const coverageMap = this.coveragePlanner.coverageEngine?.getCoverageMap(targetId);
        results.coverage_before = coverageMap?.score || 0;
      }

      // Step 2: Generate exploration plan
      let hypotheses = [];
      if (this.coveragePlanner) {
        const plan = this.coveragePlanner.plan(targetId, {
          mode: 'continuous',
          max_steps: campaign.budget.max_hypotheses_per_run,
        });

        // Generate hypotheses from coverage gaps
        if (plan && plan.hypotheses) {
          hypotheses = plan.hypotheses;
        }
      }

      results.hypotheses_generated += hypotheses.length;

      // Step 3: Submit hypotheses for verification
      let verified = 0;
      let confirmed = 0;
      for (const hyp of hypotheses) {
        if (this.verificationFarm) {
          try {
            const { task } = await this.verificationFarm.submitTaskAsync({
              hypothesis_id: hyp.id,
              target_id: targetId,
              type: hyp.verification_cost === 'low' ? 'replay' : 'state_diff',
              priority: hyp.evv || 50,
            });
            if (task) verified++;
          } catch (_) {}
        }

        if (hyp.status === 'confirmed') confirmed++;
      }

      results.verifications_dispatched += verified;
      results.bugs_confirmed += confirmed;

      // Step 4: Record in target brain
      if (brain) {
        brain.recordCampaign();
        for (const hyp of hypotheses) {
          if (hyp.status === 'confirmed') {
            brain.recordFinding(hyp);
          }
        }

        // Record coverage snapshot
        const newCoverage = this.coveragePlanner?.coverageEngine?.getCoverageMap(targetId);
        results.coverage_after = newCoverage?.score || results.coverage_before;
        brain.recordCoverageSnapshot(results.coverage_after);
      }
    }

    // Step 5: Apply learning
    if (this.learningEngine) {
      this.learningEngine.learnFromIteration(results);
      results.learning_applied = true;
    }

    results.ended_at = Date.now();
    results.duration_ms = results.ended_at - iterationStart;

    this.emit('campaign_iteration', { campaignId, results });
    return results;
  }

  // ─── Auto-Run Management ────────────────────────────────────────

  /**
   * Start auto-running a campaign on an interval.
   *
   * @param {string} campaignId
   * @param {number} [intervalMs] - override campaign interval
   */
  startAutoRun(campaignId, intervalMs) {
    const campaign = this.campaigns.get(campaignId);
    if (!campaign) throw new Error(`Campaign not found: ${campaignId}`);

    const interval = intervalMs || campaign.schedule.interval_ms || 300000;

    this._clearTimer(campaignId);

    const timer = setInterval(async () => {
      try {
        // Check if campaign should still run
        if (campaign.budgetExceeded()) {
          this.complete(campaignId);
          return;
        }

        if (campaign.goalsMet()) {
          this.complete(campaignId);
          return;
        }

        // Execute iteration
        if (!campaign.current_run) {
          campaign.startRun();
        }

        await this.executeIteration(campaignId);

        if (campaign.current_run) {
          campaign.endRun({ status: 'running' });
        }
      } catch (err) {
        console.error(`[CampaignEngine] Error in auto-run for ${campaignId}: ${err.message}`);
      }
    }, interval);

    this._timers.set(campaignId, timer);
  }

  /**
   * Stop auto-running a campaign.
   *
   * @param {string} campaignId
   */
  stopAutoRun(campaignId) {
    this._clearTimer(campaignId);
  }

  // ─── Statistics ─────────────────────────────────────────────────

  /**
   * Get engine statistics.
   * @returns {object}
   */
  getStats() {
    const all = [...this.campaigns.values()];
    const byState = {};
    for (const c of all) {
      byState[c.state] = (byState[c.state] || 0) + 1;
    }

    const byType = {};
    for (const c of all) {
      byType[c.type] = (byType[c.type] || 0) + 1;
    }

    return {
      total_campaigns: all.length,
      by_state: byState,
      by_type: byType,
      total_bugs_confirmed: all.reduce((s, c) => s + c.total_bugs_confirmed, 0),
      total_iterations: all.reduce((s, c) => s + c.total_iterations, 0),
      active_timers: this._timers.size,
    };
  }

  // ─── Persistence ────────────────────────────────────────────────

  /**
   * Save all campaigns to disk.
   * @returns {number} number saved
   */
  saveAll() {
    let count = 0;
    for (const campaign of this.campaigns.values()) {
      const filePath = path.join(CAMPAIGNS_DIR, `${campaign.id}.json`);
      try {
        fs.writeFileSync(filePath, JSON.stringify(campaign, null, 2));
        count++;
      } catch (_) {}
    }
    return count;
  }

  /**
   * Load all campaigns from disk.
   * @private
   */
  _loadAll() {
    if (!fs.existsSync(CAMPAIGNS_DIR)) return;

    const files = fs.readdirSync(CAMPAIGNS_DIR).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const data = JSON.parse(fs.readFileSync(path.join(CAMPAIGNS_DIR, file), 'utf8'));
        const campaign = new Campaign(data);
        this.campaigns.set(campaign.id, campaign);
      } catch (_) {}
    }
  }

  _scheduleCampaign(campaign) {
    this._clearTimer(campaign.id);
    if (campaign.schedule.interval_ms) {
      this.startAutoRun(campaign.id, campaign.schedule.interval_ms);
    }
  }

  _clearTimer(campaignId) {
    const timer = this._timers.get(campaignId);
    if (timer) {
      clearInterval(timer);
      this._timers.delete(campaignId);
    }
  }

  /**
   * Shut down all campaigns and timers.
   */
  shutdown() {
    for (const campaignId of this._timers.keys()) {
      this._clearTimer(campaignId);
    }

    for (const campaign of this.campaigns.values()) {
      if (campaign.state === CAMPAIGN_STATES.RUNNING) {
        this.pause(campaign.id);
      }
    }

    this.saveAll();
  }
}

module.exports = { CampaignEngine, Campaign, CAMPAIGN_TYPES, CAMPAIGN_STATES, CAMPAIGNS_DIR };
