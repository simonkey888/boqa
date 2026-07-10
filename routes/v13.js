/**
 * BOQA routes/v13.js — v1.3 Decision Intelligence Hardening Layer API routes
 *
 * Extracted from server.js during modular refactor.
 * All engine/state references go through the `ctx` context object.
 * Middleware and pipeline functions are injected via parameters.
 */

/**
 * Register all v1.3 Decision Intelligence Hardening Layer routes on the Express app.
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
  // v1.3 Decision Intelligence Hardening Layer Routes
  // ═══════════════════════════════════════════════════════════════════════

  // GET /api/uncertainty — Uncertainty gating status
  app.get('/api/uncertainty', (req, res) => {
    const oppId = req.query.opportunity_id || undefined;

    ctx.lastUncertaintyResult = {
      global_decision_lock: ctx.uncertaintyGovernor.isDecisionLocked(),
      bands: oppId ? ctx.uncertaintyGovernor.getBand(oppId) : ctx.uncertaintyGovernor.getAllBands(),
      variance_assessment: ctx.uncertaintyGovernor.assessVariance(),
      metrics: ctx.uncertaintyGovernor.getMetrics(),
      generated_at: Date.now(),
    };

    res.json(ctx.lastUncertaintyResult);
  });

  // POST /api/uncertainty/gate — Gate an opportunity through uncertainty filter
  app.post('/api/uncertainty/gate', (req, res) => {
    const band = ctx.uncertaintyGovernor.gate(req.body);

    ctx.bus.emit({
      type: 'uncertainty_gated',
      ts: Date.now(),
      payload: { opportunity_id: req.body.opportunity_id, gate_state: band.gate_state },
      source: 'uncertainty_governor',
    });

    res.json({ band, filter: ctx.uncertaintyGovernor.filterPolicy(req.body.opportunity_id, req.body.proposed_policy || 'SIMULATE') });
  });

  // POST /api/uncertainty/lock — Activate/deactivate global decision lock
  app.post('/api/uncertainty/lock', (req, res) => {
    const { activate, reason } = req.body;
    if (activate) {
      ctx.uncertaintyGovernor.activateDecisionLock(reason || 'Manual activation');
      ctx.bus.emit({ type: 'decision_locked', ts: Date.now(), payload: { reason }, source: 'uncertainty_governor' });
    } else {
      ctx.uncertaintyGovernor.deactivateDecisionLock();
    }
    res.json({ locked: ctx.uncertaintyGovernor.isDecisionLocked(), reason: ctx.uncertaintyGovernor.globalLockReason });
  });

  // GET /api/counterfactual — Counterfactual validation status
  app.get('/api/counterfactual', (req, res) => {
    const oppId = req.query.opportunity_id || undefined;

    ctx.lastCounterfactualResult = {
      reports: oppId ? ctx.counterfactualValidator.getReport(oppId) : ctx.counterfactualValidator.getAllReports().slice(-20),
      failure_surface: ctx.counterfactualValidator.getFailureProbabilitySurface(),
      estimated_fp_rate: ctx.counterfactualValidator.getEstimatedFPRate(),
      metrics: ctx.counterfactualValidator.getMetrics(),
      generated_at: Date.now(),
    };

    res.json(ctx.lastCounterfactualResult);
  });

  // POST /api/counterfactual/validate — Validate an opportunity with counterfactual scenarios
  app.post('/api/counterfactual/validate', (req, res) => {
    const report = ctx.counterfactualValidator.validate(req.body);

    ctx.bus.emit({
      type: 'counterfactual_validated',
      ts: Date.now(),
      payload: { opportunity_id: req.body.opportunity_id, verdict: report.overall_verdict, avg_robustness: report.avg_robustness },
      source: 'counterfactual_validator',
    });

    res.json({ report });
  });

  // GET /api/stability — Decision stability status
  app.get('/api/stability', (req, res) => {
    ctx.lastStabilityResult = {
      stable_decisions: ctx.decisionStabilityEngine.getAllStableDecisions(),
      stability_index: ctx.decisionStabilityEngine.computeStabilityIndex(),
      cycle_count: ctx.decisionStabilityEngine.cycleCount,
      metrics: ctx.decisionStabilityEngine.getMetrics(),
      generated_at: Date.now(),
    };

    res.json(ctx.lastStabilityResult);
  });

  // POST /api/stability/stabilize — Stabilize a decision through temporal smoothing
  app.post('/api/stability/stabilize', (req, res) => {
    const stable = ctx.decisionStabilityEngine.stabilize(req.body);

    ctx.bus.emit({
      type: 'stability_filtered',
      ts: Date.now(),
      payload: { opportunity_id: req.body.opportunity_id, stable_policy: stable.stable_policy, is_oscillating: stable.is_oscillating },
      source: 'decision_stability_engine',
    });

    res.json({ stable });
  });

  // GET /api/alignment — Reality alignment status
  app.get('/api/alignment', (req, res) => {
    const oppId = req.query.opportunity_id || undefined;

    ctx.lastAlignmentResult = {
      alignments: oppId ? ctx.realityAlignmentLayer.getAlignment(oppId) : ctx.realityAlignmentLayer.getAllAlignments().slice(-20),
      benchmarks: Object.fromEntries(ctx.realityAlignmentLayer.customBenchmarks),
      calibration_error: ctx.realityAlignmentLayer.computeCalibrationError(),
      metrics: ctx.realityAlignmentLayer.getMetrics(),
      generated_at: Date.now(),
    };

    res.json(ctx.lastAlignmentResult);
  });

  // POST /api/alignment/align — Align an opportunity against benchmarks
  app.post('/api/alignment/align', (req, res) => {
    const result = ctx.realityAlignmentLayer.align(req.body);

    ctx.bus.emit({
      type: 'reality_aligned',
      ts: Date.now(),
      payload: { opportunity_id: req.body.opportunity_id, alignment_score: result.alignment_score, is_overfitted: result.is_overfitted },
      source: 'reality_alignment_layer',
    });

    res.json({ alignment: result });
  });

  // POST /api/alignment/benchmark — Set custom benchmarks
  app.post('/api/alignment/benchmark', (req, res) => {
    const { opportunity_class, benchmark } = req.body;
    if (!opportunity_class || !benchmark) return res.status(400).json({ error: 'opportunity_class and benchmark required' });

    ctx.realityAlignmentLayer.setBenchmark(opportunity_class, benchmark);
    res.json({ set: true, opportunity_class });
  });
}

module.exports = { registerRoutes };

