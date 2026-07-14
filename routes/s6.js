/**
 * BOQA routes/s6.js — S6 Autonomous Pipeline API routes (NUEVO)
 *
 * Provides API endpoints for the S6 autonomous bug detection pipeline:
 *   - POST /api/v2/pipeline/run  — Trigger autonomous target execution
 *   - GET  /api/v2/pipeline/stats — Metrics for all 7 S6 modules
 */

function registerRoutes(app, ctx, middleware, pipelines) {
  const { requireApiKey, rateLimiter } = middleware;

  // ─── POST /api/v2/pipeline/run ────────────────────────────────────
  // Trigger autonomous execution of the TargetRunner pipeline

  app.post('/api/v2/pipeline/run', requireApiKey, rateLimiter, async (req, res) => {
    try {
      const { targets, options } = req.body;

      if (!targets || !Array.isArray(targets) || targets.length === 0) {
        return res.status(400).json({
          error: 'targets array required',
          message: 'Provide a non-empty array of target objects: { url, name?, priority? }',
        });
      }

      // Submit all targets to the execution queue
      if (targets.some(target => !target?.id || target.url || target.base_url)) {
        return res.status(400).json({ error: 'canonical target ids required; inline target URLs are forbidden' });
      }
      const executions = await ctx.targetRunner.submitTargetsAsync(targets);

      // Run the scheduler to process the queue
      const scheduler = new (require('../target-runner').TargetScheduler)({
        targetRunner: ctx.targetRunner,
        executionQueue: ctx.executionQueue,
        maxWorkers: options?.maxWorkers || 3,
        pollInterval: options?.pollInterval || 1000,
      });

      // Execute all targets (non-blocking — returns summary)
      const summary = await scheduler.runAll(ctx);

      res.json({
        ok: true,
        submitted: executions.length,
        summary,
        stats: ctx.targetRunner.getStats(),
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ─── GET /api/v2/pipeline/stats ───────────────────────────────────
  // Metrics for all 7 S6 pipeline modules

  app.get('/api/v2/pipeline/stats', requireApiKey, rateLimiter, (req, res) => {
    const stats = {
      target_runner: ctx.targetRunner ? ctx.targetRunner.getStats() : null,
      real_bug_detector: ctx.realBugDetector ? ctx.realBugDetector.getStats() : null,
      false_positive_reducer: ctx.falsePositiveReducer ? ctx.falsePositiveReducer.getStats() : null,
      finding_confidence_engine: ctx.findingConfidenceEngine ? ctx.findingConfidenceEngine.getStats() : null,
      evidence_package_generator: ctx.evidencePackageGenerator ? ctx.evidencePackageGenerator.getStats() : null,
      automatic_replay_confirmation: ctx.automaticReplayConfirmation ? ctx.automaticReplayConfirmation.getStats() : null,
      knowledge_graph_integration: ctx.knowledgeGraphIntegration ? ctx.knowledgeGraphIntegration.getStats() : null,
      execution_queue: ctx.executionQueue ? ctx.executionQueue.getStats() : null,
    };

    res.json({
      ok: true,
      pipeline_version: 's6-1.0.0',
      modules: Object.keys(stats).filter(k => stats[k] !== null).length,
      stats,
      generated_at: Date.now(),
    });
  });
}

module.exports = { registerRoutes };
