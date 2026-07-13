/**
 * BOQA routes/v01.js — v0.1 through v0.6 (plus v0.7 discovery OS & health) API routes
 *
 * Extracted from server.js during modular refactor.
 * All engine/state references go through the `ctx` context object.
 * Middleware and pipeline functions are injected via parameters.
 */

const fs = require('fs');
const path = require('path');
const { createHealthHandler } = require('../lib/health');
const { SESSIONS_DIR } = require('../lib/config');

/**
 * Register all v0.1–v0.6 (plus v0.7 discovery OS & health) routes on the Express app.
 *
 * @param {object} app            Express app instance
 * @param {object} ctx            Context object from lib/init.js (engines + state)
 * @param {object} middleware      { requireAgent, requireApiKey, rateLimiter }
 * @param {object} pipelines      { runAnalysisPipeline, runVerificationPipeline,
 *                                   runOrchestrationPipeline, buildAuthGraph, findCurrentTargetId }
 */
function registerRoutes(app, ctx, middleware, pipelines) {
  const { requireAgent, requireApiKey, rateLimiter } = middleware;
  const {
    runAnalysisPipeline,
    runVerificationPipeline,
    runOrchestrationPipeline,
    buildAuthGraph,
    findCurrentTargetId,
  } = pipelines;

  // ═══════════════════════════════════════════════════════════════════════
  // v0.2 Core Routes
  // ═══════════════════════════════════════════════════════════════════════

  app.get('/api/stats', (req, res) => res.json(ctx.bus.getStats()));

  app.get('/api/events', (req, res) => {
    const limit = Math.min(parseInt(req.query.limit || '500', 10), 10000);
    const offset = parseInt(req.query.offset || '0', 10);
    const type = req.query.type;
    let events = ctx.bus.eventLog;
    if (type) events = events.filter(e => e.type === type);
    res.json({ total: events.length, offset, limit, events: events.slice(offset, offset + limit) });
  });

  app.get('/api/export', (req, res) => res.json(ctx.bus.exportSession()));

  app.get('/api/report', requireAgent, (req, res) => res.json(ctx.agent.getReport()));

  app.get('/api/baselines', (req, res) => res.json(ctx.baselineBuilder.list()));

  app.get('/api/anomalies', requireAgent, (req, res) => res.json({
    anomalies: ctx.agent.anomaly.getAnomalies(),
    summary: ctx.agent.anomaly.getSummary(),
  }));

  app.get('/api/diff', (req, res) => {
    if (ctx.lastDiff) res.json(ctx.lastDiff);
    else res.json({ error: 'No diff available — run in compare mode' });
  });

  app.get('/api/sessions', (req, res) => {
    const sessions = fs.readdirSync(SESSIONS_DIR)
      .filter(f => f.endsWith('.json'))
      .map(f => {
        try {
          const s = JSON.parse(fs.readFileSync(path.join(SESSIONS_DIR, f), 'utf8'));
          return { id: s.id, target: s.target, start: s.sessionStart, events: s.totalEvents, metrics: s.metrics };
        } catch (_) { return null; }
      })
      .filter(Boolean);
    res.json(sessions);
  });

  // ═══════════════════════════════════════════════════════════════════════
  // v0.3: Evidence-Based Bug Discovery Engine Routes
  // ═══════════════════════════════════════════════════════════════════════

  // GET /api/findings — all findings
  app.get('/api/findings', (req, res) => {
    const severity = req.query.severity;
    const category = req.query.category;
    let findings = ctx.lastFindings;

    if (findings instanceof Map) findings = [...findings.values()];

    if (severity) findings = findings.filter(f => f.severity === severity);
    if (category) findings = findings.filter(f => f.category === category);

    res.json({
      total: findings.length,
      findings,
      summary: ctx.riskEngine.getSummary(),
    });
  });

  // GET /api/finding/:id — single finding
  app.get('/api/finding/:id', (req, res) => {
    let findings = ctx.lastFindings;
    if (findings instanceof Map) findings = [...findings.values()];

    const finding = findings.find(f => f.id === req.params.id);
    if (!finding) return res.status(404).json({ error: 'Finding not found' });

    const evidence = ctx.evidenceEngine.getPackage(finding.id);
    res.json({ finding, evidence });
  });

  // GET /api/evidence — all evidence packages
  app.get('/api/evidence', (req, res) => {
    let evidence = ctx.lastEvidence;
    if (evidence instanceof Map) evidence = [...evidence.values()];

    res.json({
      total: evidence.length,
      packages: evidence,
    });
  });

  // GET /api/risk — risk summary
  app.get('/api/risk', (req, res) => {
    res.json(ctx.riskEngine.getSummary());
  });

  // GET /api/auth-graph — authentication flow graph
  app.get('/api/auth-graph', requireAgent, (req, res) => {
    const events = ctx.bus.eventLog;
    const report = ctx.agent.getReport();
    const graph = buildAuthGraph(events, report);
    res.json(graph);
  });

  // POST /api/analyze — trigger manual analysis pipeline
  app.post('/api/analyze', (req, res) => {
    try {
      const results = runAnalysisPipeline(ctx);
      if (results && results.skipped) {
        return res.status(503).json({
          error: 'agent_unavailable',
          message: 'Analysis pipeline skipped — browser agent is not initialized.',
          degraded_since: ctx.agentInitError || 'unknown',
        });
      }
      res.json({
        status: 'ok',
        hypotheses: ctx.hypothesisEngine.getHypotheses().length,
        validated: ctx.validatorEngine.getValidated().length,
        findings: ctx.lastFindings.length,
        summary: ctx.riskEngine.getSummary(),
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // v0.4: Verification Engine API Routes
  // ═══════════════════════════════════════════════════════════════════════

  // GET /api/bugs — confirmed bugs
  app.get('/api/bugs', (req, res) => {
    const severity = req.query.severity;
    const category = req.query.category;
    let bugs = ctx.lastConfirmedBugs;

    if (bugs instanceof Map) bugs = [...bugs.values()];

    if (severity) bugs = bugs.filter(b => b.severity === severity);
    if (category) bugs = bugs.filter(b => b.category === category);

    res.json({
      total: bugs.length,
      bugs,
      summary: ctx.verificationEngine.getSummary(),
    });
  });

  // GET /api/bug/:id — single confirmed bug
  app.get('/api/bug/:id', (req, res) => {
    let bugs = ctx.lastConfirmedBugs;
    if (bugs instanceof Map) bugs = [...bugs.values()];

    const bug = bugs.find(b => b.id === req.params.id);
    if (!bug) return res.status(404).json({ error: 'Bug not found' });

    const reproduction = ctx.reproductionEngine.getReproduction(bug.id);
    res.json({ bug, reproduction });
  });

  // GET /api/verification — verification plans and results
  app.get('/api/verification', (req, res) => {
    res.json({
      plans: ctx.verificationEngine.getPlans(),
      results: ctx.verificationEngine.getResults(),
      summary: ctx.verificationEngine.getSummary(),
    });
  });

  // POST /api/verify — run verification pipeline on current findings
  app.post('/api/verify', (req, res) => {
    try {
      const result = runVerificationPipeline(ctx);
      if (result && result.skipped) {
        return res.status(503).json({
          error: 'agent_unavailable',
          message: 'Verification pipeline skipped — browser agent is not initialized.',
          degraded_since: ctx.agentInitError || 'unknown',
        });
      }
      res.json({
        status: 'ok',
        plans_created: result.plans_created,
        plans_executed: result.plans_executed,
        bugs_confirmed: result.bugs_confirmed,
        summary: ctx.verificationEngine.getSummary(),
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/permission — permission analysis
  app.get('/api/permission', (req, res) => {
    res.json(ctx.lastPermissionAnalysis || { error: 'No permission analysis available — run POST /api/verify first' });
  });

  // GET /api/workflow — workflow analysis
  app.get('/api/workflow', (req, res) => {
    res.json(ctx.lastWorkflowAnalysis || { error: 'No workflow analysis available — run POST /api/verify first' });
  });

  // GET /api/state-diff — state diff snapshots and comparisons
  app.get('/api/state-diff', (req, res) => {
    res.json({
      snapshots: ctx.stateDiffEngine.getAllSnapshots().length,
      diffs: ctx.stateDiffEngine.getAllDiffs(),
      summary: ctx.stateDiffEngine.getSummary(),
    });
  });

  // GET /api/reproduction/:bugId — reproduction chain for a bug
  app.get('/api/reproduction/:bugId', (req, res) => {
    const repro = ctx.reproductionEngine.getReproduction(req.params.bugId);
    if (!repro) return res.status(404).json({ error: 'Reproduction not found' });
    res.json(repro);
  });

  // POST /api/disclosure — generate disclosure report
  app.post('/api/disclosure', (req, res) => {
    try {
      const session = ctx.bus.exportSession();
      const sessionMeta = {
        sessionId: session.id,
        target: session.target,
        sessionStart: session.sessionStart,
        sessionEnd: session.sessionEnd || Date.now(),
        duration: (session.sessionEnd || Date.now()) - session.sessionStart,
        totalEvents: session.totalEvents,
      };

      ctx.lastDisclosureReport = ctx.disclosureExporter.generateReport(ctx.lastFindings, ctx.lastEvidence, sessionMeta);

      // Save JSON report
      const jsonPath = ctx.disclosureExporter.saveReport(ctx.lastDisclosureReport);
      console.log(`[Server] Disclosure report → ${jsonPath}`);

      // Save Markdown report
      const md = ctx.disclosureExporter.generateMarkdown(ctx.lastDisclosureReport);
      const mdPath = ctx.disclosureExporter.saveMarkdown(md);
      console.log(`[Server] Markdown report → ${mdPath}`);

      res.json({
        status: 'ok',
        report_id: ctx.lastDisclosureReport.report_id,
        json_path: jsonPath,
        markdown_path: mdPath,
        total_findings: ctx.lastFindings.length,
        risk_level: ctx.lastDisclosureReport.executive_summary.risk_level,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // v0.5: Target Orchestration & Disclosure API Routes
  // ═══════════════════════════════════════════════════════════════════════

  // ─── Target Management ─────────────────────────────────────────────────

  // POST /api/targets — Register a new authorized target
  app.post('/api/targets', (req, res) => {
    try {
      const target = ctx.targetManager.addTarget(req.body);
      res.json({ status: 'ok', target });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // GET /api/targets — List all targets
  app.get('/api/targets', (req, res) => {
    const { environment, authorization_status, owner } = req.query;
    const targets = ctx.targetManager.listTargets({ environment, authorization_status, owner });
    res.json({
      total: targets.length,
      targets,
      stats: ctx.targetManager.getStats(),
    });
  });

  // GET /api/targets/:id — Single target
  app.get('/api/targets/:id', (req, res) => {
    const target = ctx.targetManager.getTarget(req.params.id);
    if (!target) return res.status(404).json({ error: 'Target not found' });
    res.json(target);
  });

  // PUT /api/targets/:id — Update target
  app.put('/api/targets/:id', (req, res) => {
    try {
      const target = ctx.targetManager.updateTarget(req.params.id, req.body);
      if (!target) return res.status(404).json({ error: 'Target not found' });
      res.json({ status: 'ok', target });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // DELETE /api/targets/:id — Remove target
  app.delete('/api/targets/:id', (req, res) => {
    const removed = ctx.targetManager.removeTarget(req.params.id);
    if (!removed) return res.status(404).json({ error: 'Target not found' });
    res.json({ status: 'ok', removed });
  });

  // ─── Scan Orchestration ────────────────────────────────────────────────

  // POST /api/scan — Queue a scan job
  app.post('/api/scan', (req, res) => {
    try {
      const { target_id, mode, type, priority, metadata } = req.body;
      const job = ctx.scheduler.enqueue({
        target_id: target_id || ctx.bus.target,
        mode: mode || ctx.CONFIG.mode,
        type: type || 'scan',
        priority: priority || 50,
        metadata: metadata || {},
      });
      res.json({ status: 'ok', job });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // ─── Queue Management ──────────────────────────────────────────────────

  // GET /api/queue — Get queue status
  app.get('/api/queue', (req, res) => {
    const { status, type, target_id } = req.query;
    const jobs = ctx.scheduler.listJobs({ status, type, target_id });
    res.json({
      total: jobs.length,
      jobs,
      stats: ctx.scheduler.getQueueStats(),
    });
  });

  // POST /api/queue/:id/cancel — Cancel a job
  app.post('/api/queue/:id/cancel', (req, res) => {
    const job = ctx.scheduler.cancel(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    res.json({ status: 'ok', job });
  });

  // POST /api/queue/:id/prioritize — Change job priority
  app.post('/api/queue/:id/prioritize', (req, res) => {
    const { priority } = req.body;
    const job = ctx.scheduler.prioritize(req.params.id, priority);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    res.json({ status: 'ok', job });
  });

  // ─── Worker Pool ───────────────────────────────────────────────────────

  // GET /api/workers — Get worker pool status
  app.get('/api/workers', (req, res) => {
    const { status } = req.query;
    const workers = ctx.workerPool.listWorkers({ status });
    res.json({
      total: workers.length,
      workers,
      stats: ctx.workerPool.getPoolStats(),
    });
  });

  // POST /api/workers/scale — Scale worker pool
  app.post('/api/workers/scale', (req, res) => {
    const { count } = req.body;
    if (typeof count !== 'number' || count < 1) {
      return res.status(400).json({ error: 'count must be a positive number' });
    }
    ctx.workerPool.scaleTo(count);
    res.json({ status: 'ok', target_count: count, stats: ctx.workerPool.getPoolStats() });
  });

  // ─── Asset Graph ───────────────────────────────────────────────────────

  // GET /api/assets — Get asset graphs
  app.get('/api/assets', (req, res) => {
    const { target_id } = req.query;
    if (target_id) {
      const graph = ctx.assetMapper.getGraph(target_id);
      if (!graph) return res.status(404).json({ error: 'No asset graph for target' });
      res.json(graph);
    } else {
      res.json({
        graphs: ctx.assetMapper.getAllGraphs(),
        total: Object.keys(ctx.assetMapper.getAllGraphs()).length,
      });
    }
  });

  // GET /api/assets/:targetId/export — Export asset graph for visualization
  app.get('/api/assets/:targetId/export', (req, res) => {
    const graph = ctx.assetMapper.exportGraph(req.params.targetId);
    if (!graph) return res.status(404).json({ error: 'No asset graph for target' });
    res.json(graph);
  });

  // ─── Leaderboard ───────────────────────────────────────────────────────

  // GET /api/leaderboard — Ranked findings leaderboard
  app.get('/api/leaderboard', (req, res) => {
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 500);
    ctx.lastLeaderboard = ctx.rankingEngine.getLeaderboard(limit);
    res.json({
      total: ctx.lastLeaderboard.length,
      leaderboard: ctx.lastLeaderboard,
      stats: ctx.rankingEngine.getStats(),
    });
  });

  // ─── Dedup Engine ──────────────────────────────────────────────────────

  // GET /api/dedup — Dedup statistics and canonical findings
  app.get('/api/dedup', (req, res) => {
    res.json({
      stats: ctx.dedupEngine.getStats(),
      canonical_findings: ctx.dedupEngine.getCanonicalFindings(),
      groups: ctx.dedupEngine.getDuplicateGroups(),
    });
  });

  // ─── Disclosure Pipeline ───────────────────────────────────────────────

  // GET /api/disclosures — List disclosure packages
  app.get('/api/disclosures', (req, res) => {
    const { status, severity, target_id, category } = req.query;
    const packages = ctx.disclosurePipeline.listPackages({ status, severity, target_id, category });
    res.json({
      total: packages.length,
      packages,
      stats: ctx.disclosurePipeline.getStats(),
    });
  });

  // POST /api/disclosures — Create a disclosure package
  app.post('/api/disclosures', (req, res) => {
    try {
      const { bug_id, context } = req.body;
      let bugs = ctx.lastConfirmedBugs;
      if (bugs instanceof Map) bugs = [...bugs.values()];

      const bug = bugs.find(b => b.id === bug_id);
      if (!bug) return res.status(404).json({ error: 'Bug not found' });
      const pkg = ctx.disclosurePipeline.createPackage(bug, context || {});
      res.json({ status: 'ok', package: pkg });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // POST /api/disclosures/:id/finalize — Finalize a disclosure package
  app.post('/api/disclosures/:id/finalize', (req, res) => {
    try {
      const pkg = ctx.disclosurePipeline.finalize(req.params.id);
      res.json({ status: 'ok', package: pkg });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // POST /api/disclosures/:id/submit — Submit a disclosure package
  app.post('/api/disclosures/:id/submit', (req, res) => {
    try {
      const { channel, reference } = req.body;
      const pkg = ctx.disclosurePipeline.submit(req.params.id, channel, reference);
      res.json({ status: 'ok', package: pkg });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // POST /api/disclosures/:id/acknowledge — Acknowledge disclosure
  app.post('/api/disclosures/:id/acknowledge', (req, res) => {
    try {
      const pkg = ctx.disclosurePipeline.acknowledge(req.params.id);
      res.json({ status: 'ok', package: pkg });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // POST /api/disclosures/:id/resolve — Resolve disclosure
  app.post('/api/disclosures/:id/resolve', (req, res) => {
    try {
      const pkg = ctx.disclosurePipeline.resolve(req.params.id, req.body);
      res.json({ status: 'ok', package: pkg });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // GET /api/disclosures/:id/report — Generate Markdown report for disclosure
  app.get('/api/disclosures/:id/report', (req, res) => {
    try {
      const markdown = ctx.disclosurePipeline.generateMarkdownReport(req.params.id);
      res.type('text/markdown').send(markdown);
    } catch (err) {
      res.status(404).json({ error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // v0.6: Autonomous Discovery Engine API Routes
  // ═══════════════════════════════════════════════════════════════════════

  // GET /api/coverage — Coverage map and score for current target
  app.get('/api/coverage', (req, res) => {
    const targetId = req.query.target_id || findCurrentTargetId(ctx) || ctx.CONFIG.target;
    const coverageMap = ctx.coverageEngine.getCoverageMap(targetId);
    const gaps = ctx.coverageEngine.getCoverageGaps(targetId);
    const unexplored = ctx.coverageEngine.getUnexploredEndpoints(targetId);

    ctx.lastCoverageMap = coverageMap;
    res.json({
      target_id: targetId,
      coverage: coverageMap,
      gaps,
      unexplored_endpoints: unexplored,
    });
  });

  // GET /api/discovery — Discovery pipeline state and exploration plan
  app.get('/api/discovery', (req, res) => {
    const targetId = req.query.target_id || findCurrentTargetId(ctx) || ctx.CONFIG.target;
    const mode = req.query.mode || ctx.coveragePlanner.getMode();
    const plan = ctx.coveragePlanner.plan(targetId, { mode });
    const explorationState = ctx.explorationEngine.getStateGraph(targetId);

    ctx.lastDiscoveryPlan = plan;
    res.json({
      mode,
      plan,
      exploration: explorationState,
      planner_state: ctx.coveragePlanner.getState(),
    });
  });

  // POST /api/discovery — Set execution mode or trigger discovery action
  app.post('/api/discovery', (req, res) => {
    try {
      const { action, mode, target_id } = req.body;
      const targetId = target_id || findCurrentTargetId(ctx) || ctx.CONFIG.target;

      if (mode) {
        ctx.coveragePlanner.setMode(mode);
        res.json({ status: 'ok', mode: ctx.coveragePlanner.getMode() });
        return;
      }

      if (action === 'start_continuous') {
        ctx.coveragePlanner.startContinuousLoop();
        res.json({ status: 'ok', message: 'Continuous loop started' });
        return;
      }

      if (action === 'stop_continuous') {
        ctx.coveragePlanner.stopContinuousLoop();
        res.json({ status: 'ok', message: 'Continuous loop stopped' });
        return;
      }

      if (action === 'run_loop') {
        const result = ctx.coveragePlanner.plan(targetId, { mode: 'continuous' });
        res.json({ status: 'ok', plan: result });
        return;
      }

      res.status(400).json({ error: 'Unknown action. Use: mode, start_continuous, stop_continuous, run_loop' });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // GET /api/hypotheses — Hypothesis queue with EVV scores
  app.get('/api/hypotheses', (req, res) => {
    const { status, category, target_id, min_evv, limit } = req.query;
    const hypotheses = ctx.hypothesisPrioritizer.query({
      status,
      category,
      target_id,
      min_evv: min_evv ? parseInt(min_evv, 10) : undefined,
      limit: limit ? parseInt(limit, 10) : 100,
    });

    const stats = ctx.hypothesisPrioritizer.getStats();
    const groups = ctx.hypothesisPrioritizer.getGroups();

    ctx.lastHypothesisQueue = hypotheses;
    res.json({
      total: hypotheses.length,
      hypotheses,
      stats,
      groups: groups.slice(0, 20),
    });
  });

  // POST /api/hypotheses — Submit a new hypothesis
  app.post('/api/hypotheses', (req, res) => {
    try {
      const hypothesis = ctx.hypothesisPrioritizer.submit(req.body);
      if (!hypothesis) {
        return res.status(403).json({ error: 'Hypothesis rejected (forbidden category)' });
      }

      // Broadcast hypothesis event
      ctx.bus._broadcast({
        type: 'hypothesis_new',
        ts: Date.now(),
        elapsed: Date.now() - ctx.bus.sessionStart,
        payload: {
          id: hypothesis.id,
          title: hypothesis.title,
          category: hypothesis.category,
          evv: hypothesis.evv,
          severity: hypothesis.severity,
        },
        source: 'hypothesis_prioritizer',
      });

      res.json({ status: 'ok', hypothesis });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // GET /api/verification-queue — Verification farm queue and results
  app.get('/api/verification-queue', (req, res) => {
    const farmStats = ctx.verificationFarm.getStats();
    const workerStats = ctx.verificationFarm.getWorkerStats();
    const hypothesis_id = req.query.hypothesis_id;

    let results = [];
    if (hypothesis_id) {
      results = ctx.verificationFarm.getResultsForHypothesis(hypothesis_id);
    }

    res.json({
      farm_stats: farmStats,
      workers: workerStats,
      results,
      pending_tasks: ctx.verificationFarm.pendingQueue?.length || 0,
    });
  });

  // POST /api/verification-queue — Submit a verification task
  app.post('/api/verification-queue', async (req, res) => {
    try {
      const { error, task } = await ctx.verificationFarm.submitTaskAsync(req.body);
      if (error) {
        return res.status(400).json({ error });
      }
      res.json({ status: 'ok', task });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // GET /api/knowledge — Knowledge base contents and metrics
  app.get('/api/knowledge', (req, res) => {
    const { domain, target_id, limit } = req.query;

    const summary = ctx.knowledgeBase.getSummary();
    const metrics = ctx.knowledgeBase.getMetrics();

    let data = {};
    if (domain === 'findings') {
      data = ctx.knowledgeBase.queryFindings({ target_id, limit: parseInt(limit || '50', 10) });
    } else if (domain === 'hypotheses') {
      data = ctx.knowledgeBase.queryHypotheses({ target_id, limit: parseInt(limit || '50', 10) });
    } else if (domain === 'observations') {
      data = ctx.knowledgeBase.getObservations(target_id || ctx.CONFIG.target, {
        limit: parseInt(limit || '100', 10),
      });
    } else if (domain === 'validations') {
      data = { total: ctx.knowledgeBase.validations.size };
    } else if (domain === 'coverage') {
      data = target_id ? ctx.knowledgeBase.getCoverage(target_id) : { total: ctx.knowledgeBase.coverage.size };
    } else if (domain === 'sessions') {
      data = ctx.knowledgeBase.getSessions(target_id);
    } else if (domain === 'assets') {
      data = target_id ? ctx.knowledgeBase.getAssets(target_id) : { total: ctx.knowledgeBase.assets.size };
    } else if (domain === 'correlations') {
      data = ctx.correlationEngine.query({ min_strength: 0.3 });
    }

    res.json({
      summary,
      metrics,
      domain: domain || 'all',
      data,
    });
  });

  // GET /api/planner — Coverage planner state and current plan
  app.get('/api/planner', (req, res) => {
    const targetId = req.query.target_id || findCurrentTargetId(ctx) || ctx.CONFIG.target;
    const state = ctx.coveragePlanner.getState();
    const metrics = ctx.coveragePlanner.getMetrics();
    const plan = ctx.coveragePlanner.plan(targetId, { mode: state.mode });

    res.json({
      state,
      metrics,
      current_plan: plan,
    });
  });

  // POST /api/planner — Control the planner
  app.post('/api/planner', (req, res) => {
    try {
      const { action, mode, target_id, interval_ms } = req.body;

      if (mode) {
        ctx.coveragePlanner.setMode(mode);
      }

      if (action === 'start') {
        ctx.coveragePlanner.startContinuousLoop();
      } else if (action === 'stop') {
        ctx.coveragePlanner.stopContinuousLoop();
      } else if (action === 'run_once') {
        const targetId = target_id || findCurrentTargetId(ctx) || ctx.CONFIG.target;
        const plan = ctx.coveragePlanner.plan(targetId, { mode: 'continuous' });
        res.json({ status: 'ok', plan });
        return;
      }

      if (interval_ms) {
        ctx.coveragePlanner.loopIntervalMs = interval_ms;
      }

      res.json({ status: 'ok', state: ctx.coveragePlanner.getState() });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // GET /api/metrics — North star metrics for the autonomous discovery engine
  app.get('/api/metrics', (req, res) => {
    const kbMetrics = ctx.knowledgeBase.getMetrics();
    const plannerMetrics = ctx.coveragePlanner.getMetrics();
    const farmStats = ctx.verificationFarm.getStats();
    const hypStats = ctx.hypothesisPrioritizer.getStats();
    const coverageScore = ctx.lastCoverageMap?.score || kbMetrics.coverage_score || 0;
    const learningMetrics = ctx.learningEngine.getMetrics();
    const evidenceStats = ctx.evidenceQualityEngine.getStats();
    const memoryStats = ctx.findingMemory.getStats();

    const targetId = findCurrentTargetId(ctx) || ctx.CONFIG.target;
    if (!ctx.lastCoverageMap && ctx.coverageEngine) {
      const map = ctx.coverageEngine.getCoverageMap(targetId);
      ctx.lastCoverageMap = map;
    }

    // v0.7 success criteria
    const validatedBugRatio = hypStats.total > 0
      ? hypStats.by_status.confirmed / hypStats.total
      : 0;

    res.json({
      north_star: {
        validated_bugs_per_hour: kbMetrics.validated_bugs_per_hour,
        false_positive_rate: kbMetrics.false_positive_rate,
        coverage_score: ctx.lastCoverageMap?.score || coverageScore,
        evidence_completeness: kbMetrics.evidence_completeness,
        mean_time_to_confirmation_s: Math.round((kbMetrics.mean_time_to_confirmation_ms || 0) / 1000),
        // v0.7 additions
        discovery_yield: ctx.lastDiscoveryYield?.discovery_yield || 0,
        coverage_growth_rate: ctx.lastDiscoveryYield?.coverage_growth_rate || 0,
        verification_success_rate: ctx.lastDiscoveryYield?.verification_success_rate || 0,
        learning_improvement_per_month: learningMetrics.improvement_per_month || 0,
      },
      success_criteria: {
        coverage_score: { value: ctx.lastCoverageMap?.score || coverageScore, target: '>=90' },
        validated_bug_ratio: { value: validatedBugRatio, target: '>=0.25' },
        false_positive_rate: { value: kbMetrics.false_positive_rate, target: '<=0.05' },
        evidence_readiness: { value: evidenceStats.readiness_rate || 0, target: '>=0.95' },
        learning_improvement: { value: learningMetrics.improvement_per_month || 0, target: 'positive' },
      },
      discovery: {
        mode: plannerMetrics.mode,
        running: plannerMetrics.running,
        iteration: plannerMetrics.iteration,
        total_iterations: plannerMetrics.total_iterations,
        hypotheses_generated: plannerMetrics.total_hypotheses_generated,
        verifications_dispatched: plannerMetrics.total_verifications_dispatched,
        bugs_confirmed: plannerMetrics.total_bugs_confirmed,
      },
      verification_farm: farmStats,
      hypothesis_queue: hypStats,
      knowledge_base: kbMetrics,
      // v0.7 sections
      campaigns: ctx.campaignEngine.getStats(),
      learning: learningMetrics,
      evidence_quality: evidenceStats,
      finding_memory: memoryStats,
      resource_optimizer: ctx.resourceOptimizer.getStats(),
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // v0.7: Discovery Operating System API Routes
  // ═══════════════════════════════════════════════════════════════════════

  // GET /api/campaigns — Campaign list and status
  app.get('/api/campaigns', (req, res) => {
    const { state, type, target_id } = req.query;
    const campaigns = ctx.campaignEngine.list({ state, type, target_id });
    const stats = ctx.campaignEngine.getStats();
    ctx.lastCampaignSummary = { campaigns, stats };
    res.json({
      total: campaigns.length,
      campaigns: campaigns.map(c => c.getSummary()),
      stats,
    });
  });

  // POST /api/campaigns — Create a new campaign
  app.post('/api/campaigns', (req, res) => {
    try {
      const campaign = ctx.campaignEngine.create(req.body);
      res.json({ status: 'ok', campaign: campaign.getSummary() });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // GET /api/campaigns/:id — Single campaign
  app.get('/api/campaigns/:id', (req, res) => {
    const campaign = ctx.campaignEngine.get(req.params.id);
    if (!campaign) return res.status(404).json({ error: 'Campaign not found' });
    res.json(campaign.getSummary());
  });

  // POST /api/campaigns/:id/start — Start a campaign
  app.post('/api/campaigns/:id/start', (req, res) => {
    try {
      const run = ctx.campaignEngine.start(req.params.id);
      ctx.bus._broadcast({
        type: 'campaign_started',
        ts: Date.now(),
        elapsed: Date.now() - ctx.bus.sessionStart,
        payload: { campaign_id: req.params.id },
        source: 'campaign_engine',
      });
      res.json({ status: 'ok', run });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // POST /api/campaigns/:id/pause — Pause a campaign
  app.post('/api/campaigns/:id/pause', (req, res) => {
    try {
      ctx.campaignEngine.pause(req.params.id);
      res.json({ status: 'ok' });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // POST /api/campaigns/:id/iterate — Execute one iteration
  app.post('/api/campaigns/:id/iterate', async (req, res) => {
    try {
      const results = await ctx.campaignEngine.executeIteration(req.params.id);
      ctx.bus._broadcast({
        type: 'campaign_iteration',
        ts: Date.now(),
        elapsed: Date.now() - ctx.bus.sessionStart,
        payload: results,
        source: 'campaign_engine',
      });
      res.json({ status: 'ok', results });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // GET /api/portfolio — Portfolio risk assessment
  app.get('/api/portfolio', (req, res) => {
    const targets = ctx.brainRegistry.list();
    const targetEvs = ctx.resourceOptimizer.computeAllEVs();

    const portfolio = targets.map(t => {
      const brain = ctx.brainRegistry.get(t.target_id);
      const ev = targetEvs.find(e => e.target_id === t.target_id);
      return {
        target_id: t.target_id,
        findings: t.findings,
        coverage: t.coverage,
        expected_value: ev?.ev || 0,
        sessions: t.sessions,
      };
    });

    ctx.lastPortfolioRisk = ctx.executiveReporting.generateRiskAssessment();
    res.json({
      total_targets: targets.length,
      portfolio,
      risk_assessment: ctx.lastPortfolioRisk,
    });
  });

  // GET /api/learning — Learning engine metrics and weights
  app.get('/api/learning', (req, res) => {
    const metrics = ctx.learningEngine.getMetrics();
    const categoryScores = ctx.learningEngine.getHypothesisSuccessScores();
    const verificationScores = ctx.learningEngine.getVerificationSuccessScores();

    ctx.lastLearningMetrics = metrics;
    res.json({
      metrics,
      hypothesis_success_scores: categoryScores,
      verification_success_scores: verificationScores,
      current_weights: ctx.learningEngine.currentWeights,
      weight_history: ctx.learningEngine.weightHistory.slice(-10),
    });
  });

  // POST /api/learning — Control the learning engine
  app.post('/api/learning', (req, res) => {
    try {
      const { action } = req.body;

      if (action === 'reweight') {
        const result = ctx.learningEngine.reweight();
        ctx.bus._broadcast({
          type: 'learning_reweight',
          ts: Date.now(),
          elapsed: Date.now() - ctx.bus.sessionStart,
          payload: result,
          source: 'learning_engine',
        });
        res.json({ status: 'ok', result });
        return;
      }

      if (action === 'record_outcome') {
        const outcome = req.body.outcome;
        ctx.learningEngine.recordOutcome(outcome);
        ctx.bus._broadcast({
          type: 'learning_outcome',
          ts: Date.now(),
          elapsed: Date.now() - ctx.bus.sessionStart,
          payload: outcome,
          source: 'learning_engine',
        });
        res.json({ status: 'ok' });
        return;
      }

      res.status(400).json({ error: 'Unknown action. Use: reweight, record_outcome' });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // GET /api/discovery-yield — Discovery yield metrics
  app.get('/api/discovery-yield', (req, res) => {
    const kbMetrics = ctx.knowledgeBase.getMetrics();
    const campaignStats = ctx.campaignEngine.getStats();
    const memoryStats = ctx.findingMemory.getStats();
    const learningMetrics = ctx.learningEngine.getMetrics();

    // Compute discovery yield: bugs per 1000 events
    const totalEvents = ctx.bus.eventIndex || 1;
    const confirmedBugs = [...ctx.knowledgeBase.findings.values()]
      .filter(f => f.lifecycle_state === 'confirmed' || f.lifecycle_state === 'ranked').length;
    const discoveryYield = Math.round((confirmedBugs / totalEvents) * 1000 * 100) / 100;

    // Compute coverage growth rate
    const targetId = req.query.target_id || findCurrentTargetId(ctx) || ctx.CONFIG.target;
    const brain = ctx.brainRegistry.getOrCreate(targetId);
    const coverageGrowthRate = brain.getCoverageGrowthRate();

    // Compute mean time to confirmed bug (minutes)
    const mtcb = kbMetrics.mean_time_to_confirmation_ms
      ? Math.round(kbMetrics.mean_time_to_confirmation_ms / 60000)
      : 0;

    // Verification success rate
    const totalVerifications = ctx.knowledgeBase.validations.size || 1;
    const confirmedVerifications = [...ctx.knowledgeBase.validations.values()]
      .filter(v => v.verdict === 'confirmed').length;
    const verificationSuccessRate = Math.round((confirmedVerifications / totalVerifications) * 10000) / 10000;

    ctx.lastDiscoveryYield = {
      discovery_yield: discoveryYield,
      coverage_growth_rate: coverageGrowthRate,
      mean_time_to_confirmed_bug_min: mtcb,
      verification_success_rate: verificationSuccessRate,
      total_events: totalEvents,
      confirmed_bugs: confirmedBugs,
      campaigns_total_bugs: campaignStats.total_bugs_confirmed,
      cross_target_patterns: memoryStats.cross_target_patterns,
      learning_improvement: learningMetrics.improvement_per_month,
    };

    res.json(ctx.lastDiscoveryYield);
  });

  // GET /api/optimizer — Resource optimizer allocation
  app.get('/api/optimizer', (req, res) => {
    const stats = ctx.resourceOptimizer.getStats();
    const allocations = ctx.resourceOptimizer.getAllAllocations();

    ctx.lastOptimizerAlloc = { stats, allocations };
    res.json({
      stats,
      allocations,
      target_evs: ctx.resourceOptimizer.computeAllEVs(),
    });
  });

  // POST /api/optimizer — Trigger rebalance
  app.post('/api/optimizer', (req, res) => {
    try {
      const { action } = req.body;
      if (action === 'rebalance') {
        const plan = ctx.resourceOptimizer.rebalance();
        ctx.bus._broadcast({
          type: 'optimizer_rebalance',
          ts: Date.now(),
          elapsed: Date.now() - ctx.bus.sessionStart,
          payload: { target_count: plan.target_allocations.length },
          source: 'resource_optimizer',
        });
        res.json({ status: 'ok', plan });
        return;
      }
      res.status(400).json({ error: 'Unknown action. Use: rebalance' });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // GET /api/intelligence — Target intelligence profiles
  app.get('/api/intelligence', (req, res) => {
    const { target_id } = req.query;

    if (target_id) {
      const brain = ctx.brainRegistry.getOrCreate(target_id);
      ctx.lastIntelligence = brain.getProfile();
      res.json(ctx.lastIntelligence);
    } else {
      const profiles = ctx.brainRegistry.list().map(t => {
        const brain = ctx.brainRegistry.get(t.target_id);
        return brain ? brain.getProfile() : { target_id: t.target_id };
      });
      res.json({
        total: profiles.length,
        profiles,
      });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Health & Readiness Routes
  // ═══════════════════════════════════════════════════════════════════════

  // GET /api/health — Server health + agent status (CF-004)
  app.get('/api/health', createHealthHandler(ctx));

  // GET /api/readiness — Disclosure readiness assessment
  app.get('/api/readiness', (req, res) => {
    const stats = ctx.evidenceQualityEngine.getStats();
    const ready = ctx.evidenceQualityEngine.getDisclosureReady();
    const certificates = ctx.evidenceQualityEngine.getCertificates();

    // Score all current findings
    let allFindings = ctx.lastFindings.length > 0
      ? ctx.lastFindings
      : ctx.knowledgeBase.queryFindings({ limit: 100 });

    if (allFindings instanceof Map) allFindings = [...allFindings.values()];

    const assessments = ctx.evidenceQualityEngine.scoreAll(allFindings);

    ctx.lastReadiness = {
      stats,
      disclosure_ready: ready.length,
      certificates_issued: certificates.length,
      recent_assessments: assessments.slice(0, 20),
    };

    res.json(ctx.lastReadiness);
  });
}

module.exports = { registerRoutes };
