/**
 * BOQA routes/v11.js — v1.1 Discovery Intelligence Layer API routes
 *
 * Extracted from server.js during modular refactor.
 * All engine/state references go through the `ctx` context object.
 * Middleware and pipeline functions are injected via parameters.
 */

/**
 * Register all v1.1 Discovery Intelligence Layer routes on the Express app.
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
  // v1.1 Discovery Intelligence Layer Routes
  // ═══════════════════════════════════════════════════════════════════════

  // GET /api/discovery/loop — Discovery loop state and ranked hypotheses (v1.1 namespaced)
  // NOTE: Was GET /api/discovery (collided with v01 discovery pipeline route).
  // Renamed to /api/discovery/loop to avoid route ambiguity.
  app.get('/api/discovery/loop', (req, res) => {
    const rankedHypotheses = ctx.discoveryLoopEngine.getRankedHypotheses({ limit: 20 });
    const loopState = ctx.discoveryLoopEngine.getState();
    const loopMetrics = ctx.discoveryLoopEngine.getMetrics();
    const lastCycle = ctx.discoveryLoopEngine.getLastCycle();

    ctx.lastDiscoveryResult = {
      loop_state: loopState,
      metrics: loopMetrics,
      ranked_hypotheses: rankedHypotheses,
      last_cycle: lastCycle,
      safe_mode: ctx.discoveryLoopEngine.safeMode,
      generated_at: Date.now(),
    };

    res.json(ctx.lastDiscoveryResult);
  });

  // POST /api/discovery/start — Start the discovery loop
  app.post('/api/discovery/start', (req, res) => {
    const started = ctx.discoveryLoopEngine.start();
    res.json({ started, state: ctx.discoveryLoopEngine.getState() });
  });

  // POST /api/discovery/pause — Pause the discovery loop
  app.post('/api/discovery/pause', (req, res) => {
    const paused = ctx.discoveryLoopEngine.pause();
    res.json({ paused, state: ctx.discoveryLoopEngine.getState() });
  });

  // POST /api/discovery/cycle — Run a single discovery cycle
  app.post('/api/discovery/cycle', async (req, res) => {
    try {
      const result = await ctx.discoveryLoopEngine.runOnce(req.body.signals || null);
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/discovery/validate — Record a validation result
  app.post('/api/discovery/validate', (req, res) => {
    const { hypothesis_id, valid, details } = req.body;
    if (!hypothesis_id || valid === undefined) {
      return res.status(400).json({ error: 'hypothesis_id and valid are required' });
    }
    ctx.discoveryLoopEngine.recordValidationResult(hypothesis_id, valid, details || {});
    res.json({ recorded: true, hypothesis_id, valid });
  });

  // GET /api/hypotheses-v2 — Ranked hypothesis set (v1.1 output)
  app.get('/api/hypotheses-v2', (req, res) => {
    const targetId = req.query.target_id || undefined;
    const bugClass = req.query.bug_class || undefined;
    const limit = parseInt(req.query.limit || '20', 10);

    const hypotheses = ctx.discoveryLoopEngine.getRankedHypotheses({
      target_id: targetId,
      bug_class: bugClass,
      limit,
    });

    ctx.lastHypothesesV2Result = {
      hypotheses,
      count: hypotheses.length,
      generated_at: Date.now(),
    };

    res.json(ctx.lastHypothesesV2Result);
  });

  // GET /api/surfaces — Attack surface model data
  app.get('/api/surfaces', (req, res) => {
    const targetId = req.query.target_id || undefined;
    const surfaceDetails = targetId
      ? ctx.attackSurfaceModeler.getSurfaceDetails(targetId)
      : [...ctx.attackSurfaceModeler.surfaces.keys()].map(tid => ctx.attackSurfaceModeler.getSurfaceDetails(tid));

    ctx.lastSurfaceResult = {
      surfaces: surfaceDetails,
      metrics: ctx.attackSurfaceModeler.getMetrics(),
      generated_at: Date.now(),
    };

    res.json(ctx.lastSurfaceResult);
  });

  // POST /api/surfaces/build — Build surface model for a target
  app.post('/api/surfaces/build', (req, res) => {
    const { target_id, asset_data } = req.body;
    if (!target_id) return res.status(400).json({ error: 'target_id is required' });

    const graph = ctx.attackSurfaceModeler.buildSurface(target_id, asset_data || null);
    res.json({
      target_id,
      node_count: graph.nodes.size,
      edge_count: graph.edges.size,
      coverage: graph.computeCoverage(),
      gaps: ctx.attackSurfaceModeler.getCoverageGaps(target_id).length,
    });
  });

  // GET /api/calibration — Confidence calibration state
  app.get('/api/calibration', (req, res) => {
    const targetId = req.query.target_id || undefined;
    const category = req.query.category || undefined;

    ctx.lastCalibrationResult = {
      metrics: ctx.confidenceCalibrator.getMetrics(),
      record: targetId ? ctx.confidenceCalibrator.getCalibrationRecord(targetId, category) : null,
      global_record: ctx.confidenceCalibrator.globalRecord,
      generated_at: Date.now(),
    };

    res.json(ctx.lastCalibrationResult);
  });

  // POST /api/calibration/observe — Record a calibration observation
  app.post('/api/calibration/observe', (req, res) => {
    const { target_id, category, predicted, actual } = req.body;
    if (predicted === undefined || actual === undefined) {
      return res.status(400).json({ error: 'predicted and actual are required' });
    }
    const record = ctx.confidenceCalibrator.recordObservation({
      target_id: target_id || '__global__',
      category: category || '__global__',
      predicted,
      actual,
    });
    res.json({ recorded: true, calibration_factor: record.calibration_factor, bias: record.bias });
  });

  // GET /api/memory — Memory graph state and stats
  app.get('/api/memory', (req, res) => {
    const nodeId = req.query.node_id || undefined;
    const depth = parseInt(req.query.depth || '1', 10);

    let subgraph = null;
    if (nodeId) {
      subgraph = ctx.memoryGraph.getSubgraph(nodeId, depth);
    }

    ctx.lastMemoryResult = {
      stats: ctx.memoryGraph.getStats(),
      failure_patterns: ctx.memoryGraph.detectRepeatedFailures(3),
      clusters: ctx.memoryGraph.clusterNodes({ minClusterSize: 3 }),
      subgraph,
      generated_at: Date.now(),
    };

    res.json(ctx.lastMemoryResult);
  });

  // POST /api/memory/node — Add a node to the memory graph
  app.post('/api/memory/node', (req, res) => {
    const node = ctx.memoryGraph.addNode(req.body);
    ctx.memoryGraph.autoLink(node);
    res.json({ node_id: node.id, type: node.type });
  });

  // GET /api/memory/similar — Find similar nodes by features
  app.get('/api/memory/similar', (req, res) => {
    try {
      const features = JSON.parse(req.query.features || '{}');
      const limit = parseInt(req.query.limit || '20', 10);
      const similar = ctx.memoryGraph.findSimilar(features, { limit });
      res.json({ similar, count: similar.length });
    } catch (err) {
      res.status(400).json({ error: 'Invalid features JSON' });
    }
  });
}

module.exports = { registerRoutes };

