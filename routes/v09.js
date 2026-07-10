/**
 * BOQA routes/v09.js — v0.9 Optimization Layer API routes
 *
 * Extracted from server.js during modular refactor.
 * All engine/state references go through the `ctx` context object.
 * Middleware and pipeline functions are injected via parameters.
 */

/**
 * Register all v0.9 Optimization Layer routes on the Express app.
 *
 * @param {object} app            Express app instance
 * @param {object} ctx            Context object from lib/init.js (engines + state)
 * @param {object} middleware      { requireApiKey, rateLimiter }
 * @param {object} pipelines      { findCurrentTargetId }
 */
function registerRoutes(app, ctx, middleware, pipelines) {
  const { requireApiKey, rateLimiter } = middleware;
  const { findCurrentTargetId } = pipelines;

  // ═══════════════════════════════════════════════════════════════════════
  // v0.9 Optimization Layer Routes
  // ═══════════════════════════════════════════════════════════════════════

  // GET /api/optimize — Current optimization state, strategy, and objective score
  app.get('/api/optimize', (req, res) => {
    const result = ctx.optimizerEngine.optimize();
    ctx.lastOptimizeResult = {
      strategy: result.strategy,
      objective_score: result.snapshot.objective_score,
      bugs_per_worker: result.snapshot.bugs_per_worker,
      false_positive_rate: result.snapshot.false_positive_rate,
      scan_time_reduction: result.snapshot.scan_time_reduction,
      resource_utilization: result.snapshot.resource_utilization,
      applied_adjustment: result.applied_adjustment
        ? { param: result.applied_adjustment.param_name, old: result.applied_adjustment.old_value, new: result.applied_adjustment.new_value, reason: result.applied_adjustment.reason }
        : null,
      current_params: ctx.optimizerEngine.currentParams,
      strategy_ranking: ctx.optimizerEngine.getStrategyRanking(),
      success_criteria: ctx.optimizerEngine.getMetrics().success_criteria,
      latency_ms: result.latency_ms,
      generated_at: Date.now(),
    };
    res.json(ctx.lastOptimizeResult);
  });

  // GET /api/schedule — Scan task queue and schedule
  app.get('/api/schedule', (req, res) => {
    const schedule = ctx.scanScheduler.getSchedule();
    const metrics = ctx.scanScheduler.getMetrics();

    ctx.lastScheduleResult = {
      queue: schedule.queue,
      running: schedule.running,
      pending: schedule.pending,
      metrics,
      auto_scan_available: ctx.scanScheduler._collectTargetIds().length,
      generated_at: Date.now(),
    };

    res.json(ctx.lastScheduleResult);
  });

  // GET /api/resources — Resource allocation and worker pool state
  app.get('/api/resources', (req, res) => {
    const allocations = ctx.resourceManager.getCurrentAllocations();
    const workerPool = ctx.resourceManager.getWorkerPool();
    const metrics = ctx.resourceManager.getMetrics();

    ctx.lastResourceResult = {
      allocations,
      workers: workerPool,
      metrics,
      optimizer_state: ctx.optimizerEngine.getCurrentState(),
      generated_at: Date.now(),
    };

    res.json(ctx.lastResourceResult);
  });

  // GET /api/feedback — Feedback loop state and recent adjustments
  app.get('/api/feedback', (req, res) => {
    const metrics = ctx.feedbackLoop.getMetrics();
    const history = ctx.feedbackLoop.getFeedbackHistory(50);
    const convergence = ctx.feedbackLoop.detectConvergence();
    const oscillation = ctx.feedbackLoop.detectOscillation();

    ctx.lastFeedbackResult = {
      metrics,
      convergence,
      oscillation,
      recent_signals: history.signals.slice(-20),
      recent_adjustments: history.adjustments.slice(-20),
      generated_at: Date.now(),
    };

    res.json(ctx.lastFeedbackResult);
  });

  // GET /api/efficiency — Efficiency metrics and benchmarks
  app.get('/api/efficiency', (req, res) => {
    const snapshot = ctx.efficiencyTracker.computeSnapshot();
    const metrics = ctx.efficiencyTracker.getMetrics();
    const benchmarks = ctx.efficiencyTracker.getBenchmarks();

    ctx.lastEfficiencyResult = {
      snapshot,
      metrics,
      benchmarks,
      trends: {
        bugs_per_worker: ctx.efficiencyTracker.getTrend('bugs_per_worker'),
        false_positive_rate: ctx.efficiencyTracker.getTrend('false_positive_rate'),
        scan_time_reduction: ctx.efficiencyTracker.getTrend('scan_time_reduction'),
        resource_utilization: ctx.efficiencyTracker.getTrend('resource_utilization'),
      },
      budget: ctx.budgetOptimizer.getMetrics(),
      generated_at: Date.now(),
    };

    res.json(ctx.lastEfficiencyResult);
  });
}

module.exports = { registerRoutes };

