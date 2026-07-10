/**
 * BOQA routes/v14.js — v1.4 Autonomous Decision Kernel API routes
 *
 * Extracted from server.js during modular refactor.
 * All engine/state references go through the `ctx` context object.
 * Middleware and pipeline functions are injected via parameters.
 */

/**
 * Register all v1.4 Autonomous Decision Kernel routes on the Express app.
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
  // v1.4 Autonomous Decision Kernel Routes
  // ═══════════════════════════════════════════════════════════════════════

  // GET /api/autonomy — AutonomyGovernor status
  app.get('/api/autonomy', requireApiKey, rateLimiter, (req, res) => {
    ctx.lastAutonomyCheckResult = {
      autonomy_level: ctx.autonomyGovernor.getAutonomyLevel(),
      autonomy_level_name: ctx.autonomyGovernor.getAutonomyLevelName(),
      behavioral_mode: ctx.autonomyGovernor.getBehavioralMode(),
      subsystem_status: ctx.autonomyGovernor.getSubsystemStatus(),
      metrics: ctx.autonomyGovernor.getMetrics(),
      generated_at: Date.now(),
    };
    res.json(ctx.lastAutonomyCheckResult);
  });

  // POST /api/autonomy/check — Check autonomy permission for a decision
  app.post('/api/autonomy/check', requireApiKey, rateLimiter, (req, res) => {
    const result = ctx.autonomyGovernor.check(req.body);

    ctx.bus.emit({
      type: 'autonomy_checked',
      ts: Date.now(),
      payload: {
        opportunity_id: req.body.opportunity_id,
        decision_type: req.body.decision_type,
        final_action: result.final_action,
        final_score: result.final_score,
        autonomy_level: result.autonomy_level,
      },
      source: 'autonomy_governor',
    });

    ctx.lastAutonomyCheckResult = result;
    res.json({ autonomy_check: result });
  });

  // POST /api/autonomy/pipeline — Run full v1.4 decision pipeline
  app.post('/api/autonomy/pipeline', requireApiKey, rateLimiter, (req, res) => {
    const { opportunities, options } = req.body;
    if (!opportunities || !Array.isArray(opportunities)) {
      return res.status(400).json({ error: 'opportunities array required' });
    }

    const result = ctx.autonomyGovernor.runPipeline(opportunities, options || {});

    ctx.bus.emit({
      type: 'autonomy_pipeline_completed',
      ts: Date.now(),
      payload: {
        pipeline_id: result.pipeline_id,
        total_opportunities: result.total_opportunities,
        autonomy_level: result.autonomy_level,
        behavioral_mode: result.behavioral_mode,
        duration_ms: result.duration_ms,
      },
      source: 'autonomy_governor',
    });

    ctx.lastPipelineResult = result;
    res.json({ pipeline: result });
  });

  // POST /api/autonomy/mode — Set behavioral mode
  app.post('/api/autonomy/mode', requireApiKey, rateLimiter, (req, res) => {
    const { mode } = req.body;
    if (!mode) return res.status(400).json({ error: 'mode required' });

    try {
      ctx.autonomyGovernor.setBehavioralMode(mode);
      res.json({ set: true, mode: ctx.autonomyGovernor.getBehavioralMode() });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // POST /api/autonomy/level — Manually set autonomy level
  app.post('/api/autonomy/level', requireApiKey, rateLimiter, (req, res) => {
    const { level, reason } = req.body;
    if (level === undefined) return res.status(400).json({ error: 'level required' });

    ctx.autonomyGovernor.autonomyController.setLevel(level, reason || 'manual_api_override');
    res.json({
      set: true,
      current_level: ctx.autonomyGovernor.getAutonomyLevel(),
      effective_level: ctx.autonomyGovernor.autonomyController.getEffectiveLevel(),
    });
  });

  // POST /api/autonomy/outcome — Record a decision outcome for meta-learning
  app.post('/api/autonomy/outcome', requireApiKey, rateLimiter, (req, res) => {
    ctx.autonomyGovernor.recordOutcome(req.body);
    res.json({ recorded: true, performance: ctx.autonomyGovernor.selfCorrection.getPerformanceMetrics() });
  });

  // GET /api/autonomy/audit — Get audit log
  app.get('/api/autonomy/audit', requireApiKey, rateLimiter, (req, res) => {
    const limit = Math.min(parseInt(req.query.limit || '100', 10), 1000);
    res.json({ audit_log: ctx.autonomyGovernor.getAuditLog(limit) });
  });

  // GET /api/autonomy/permission-matrix — View current permission matrix
  app.get('/api/autonomy/permission-matrix', requireApiKey, rateLimiter, (req, res) => {
    res.json({
      matrix: ctx.autonomyGovernor.permissionMatrix.getMatrix(),
      autonomy_level: ctx.autonomyGovernor.getAutonomyLevel(),
    });
  });
}

module.exports = { registerRoutes };

