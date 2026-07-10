/**
 * BOQA routes/v12.js — v1.2 Decision Evolution Layer API routes
 *
 * Extracted from server.js during modular refactor.
 * All engine/state references go through the `ctx` context object.
 * Middleware and pipeline functions are injected via parameters.
 */

/**
 * Register all v1.2 Decision Evolution Layer routes on the Express app.
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
  // v1.2 Decision Evolution Layer Routes
  // ═══════════════════════════════════════════════════════════════════════

  // GET /api/economic — Economic value scores and portfolio summary
  app.get('/api/economic', requireApiKey, rateLimiter, (req, res) => {
    const targetId = req.query.target_id || undefined;
    const oppClass = req.query.opportunity_class || undefined;

    ctx.lastEconomicResult = {
      scores: ctx.economicValueEngine.getRankedScores({
        target_id: targetId,
        opportunity_class: oppClass,
      }),
      portfolio_summary: ctx.economicValueEngine.getPortfolioSummary(),
      metrics: ctx.economicValueEngine.getMetrics(),
      generated_at: Date.now(),
    };

    res.json(ctx.lastEconomicResult);
  });

  // POST /api/economic/register — Register an opportunity for economic scoring
  app.post('/api/economic/register', requireApiKey, rateLimiter, (req, res) => {
    const opp = ctx.economicValueEngine.registerOpportunity(req.body);
    const score = ctx.economicValueEngine.score(opp.id);

    ctx.bus.emit({
      type: 'economic_scored',
      ts: Date.now(),
      payload: { opportunity_id: opp.id, normalized_score: score?.normalized_score },
      source: 'economic_value_engine',
    });

    res.json({ opportunity_id: opp.id, score });
  });

  // POST /api/economic/score-all — Score all registered opportunities
  app.post('/api/economic/score-all', requireApiKey, rateLimiter, (req, res) => {
    const scores = ctx.economicValueEngine.scoreAll();
    res.json({ scored: scores.length, top: scores[0] || null });
  });

  // GET /api/comparator — Cross-class opportunity comparison
  app.get('/api/comparator', (req, res) => {
    const profile = req.query.profile || undefined;

    ctx.lastComparatorResult = {
      active_profile: ctx.opportunityComparator.getActiveProfile(),
      profiles: ctx.opportunityComparator.listProfiles(),
      pareto_frontier: ctx.opportunityComparator.getParetoFrontier(),
      ranked: ctx.opportunityComparator.getRankedOpportunities(),
      metrics: ctx.opportunityComparator.getMetrics(),
      generated_at: Date.now(),
    };

    res.json(ctx.lastComparatorResult);
  });

  // POST /api/comparator/compare — Run comparison across all scored opportunities
  app.post('/api/comparator/compare', (req, res) => {
    const profile = req.body.profile || req.query.profile || undefined;

    try {
      const matrix = ctx.opportunityComparator.compareAll(profile);
      ctx.bus.emit({
        type: 'opportunity_compared',
        ts: Date.now(),
        payload: { pareto_count: matrix.pareto_frontier.length, total: matrix.opportunities.length },
        source: 'opportunity_comparator',
      });

      res.json({
        opportunity_count: matrix.opportunities.length,
        pareto_count: matrix.pareto_frontier.length,
        dominated_count: matrix.dominated_set.length,
        profile_used: matrix.profile_used,
        top: matrix.opportunities[0] || null,
      });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // POST /api/comparator/profile — Set the active decision profile
  app.post('/api/comparator/profile', (req, res) => {
    const { profile } = req.body;
    if (!profile) return res.status(400).json({ error: 'profile is required' });

    const changed = ctx.opportunityComparator.setProfile(profile);
    if (!changed) return res.status(400).json({ error: `Unknown profile: ${profile}` });

    res.json({ profile: ctx.opportunityComparator.getActiveProfile() });
  });

  // GET /api/policy — Policy decisions and action portfolio
  app.get('/api/policy', requireApiKey, rateLimiter, (req, res) => {
    const policyFilter = req.query.policy || undefined;

    ctx.lastPolicyResult = {
      policies: ctx.decisionPolicyEngine.getPolicies({ policy: policyFilter }),
      ranked_portfolio: ctx.decisionPolicyEngine.getRankedActionPortfolio(),
      audit_log: ctx.decisionPolicyEngine.getAuditLog(50),
      metrics: ctx.decisionPolicyEngine.getMetrics(),
      generated_at: Date.now(),
    };

    res.json(ctx.lastPolicyResult);
  });

  // POST /api/policy/decide — Decide policies for all scored opportunities
  app.post('/api/policy/decide', requireApiKey, rateLimiter, (req, res) => {
    try {
      const decisions = ctx.decisionPolicyEngine.decideAll();

      for (const d of decisions) {
        ctx.bus.emit({
          type: 'policy_decided',
          ts: Date.now(),
          payload: { opportunity_id: d.opportunity_id, policy: d.policy },
          source: 'decision_policy_engine',
        });
      }

      res.json({ decided: decisions.length, by_policy: ctx.decisionPolicyEngine.metrics.policy_distribution });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // POST /api/policy/approve — Grant human approval for DEPLOY
  app.post('/api/policy/approve', requireApiKey, rateLimiter, (req, res) => {
    const { opportunity_id, approver } = req.body;
    if (!opportunity_id) return res.status(400).json({ error: 'opportunity_id is required' });

    const decision = ctx.decisionPolicyEngine.grantApproval(opportunity_id, approver || 'human_operator');
    if (!decision) return res.status(404).json({ error: 'Opportunity not found' });

    res.json({ opportunity_id, policy: decision.policy, approved: decision.human_approval });
  });

  // GET /api/allocation — Capital allocation simulation results
  app.get('/api/allocation', requireApiKey, rateLimiter, (req, res) => {
    ctx.lastAllocationResult = {
      last_result: ctx.capitalAllocatorSim.getLastResult(),
      candidates: ctx.capitalAllocatorSim.candidates.size,
      metrics: ctx.capitalAllocatorSim.getMetrics(),
      generated_at: Date.now(),
    };

    res.json(ctx.lastAllocationResult);
  });

  // POST /api/allocation/simulate — Run allocation simulation
  app.post('/api/allocation/simulate', requireApiKey, rateLimiter, (req, res) => {
    const rounds = req.body.rounds || undefined;

    ctx.capitalAllocatorSim.loadFromEngine();
    const result = ctx.capitalAllocatorSim.simulate(null, rounds);

    ctx.bus.emit({
      type: 'portfolio_simulated',
      ts: Date.now(),
      payload: { expected_return: result.summary.expected_portfolio_return, var_95: result.summary.portfolio_var_95 },
      source: 'capital_allocator_sim',
    });

    res.json({
      expected_portfolio_return: result.summary.expected_portfolio_return,
      portfolio_var_95: result.summary.portfolio_var_95,
      portfolio_sharpe: result.summary.portfolio_sharpe,
      capital_utilized: result.summary.capital_utilized,
      opportunity_count: result.summary.opportunity_count,
      concentration_score: result.summary.concentration_score,
      simulation_rounds: result.summary.simulation_rounds,
    });
  });

  // POST /api/allocation/optimize — Optimize portfolio allocation
  app.post('/api/allocation/optimize', requireApiKey, rateLimiter, (req, res) => {
    const maxSteps = req.body.max_steps || undefined;

    ctx.capitalAllocatorSim.loadFromEngine();
    const result = ctx.capitalAllocatorSim.optimize(maxSteps);

    ctx.bus.emit({
      type: 'allocation_optimized',
      ts: Date.now(),
      payload: { expected_return: result.expected_portfolio_return, sharpe: result.portfolio_sharpe },
      source: 'capital_allocator_sim',
    });

    res.json({
      allocations: result.allocations,
      expected_portfolio_return: result.expected_portfolio_return,
      portfolio_var_95: result.portfolio_var_95,
      portfolio_sharpe: result.portfolio_sharpe,
      capital_utilized: result.capital_utilized,
      opportunity_count: result.opportunity_count,
      optimization_steps: result.optimization_steps,
    });
  });

  // POST /api/allocation/surface — Compute return surface
  app.post('/api/allocation/surface', requireApiKey, rateLimiter, (req, res) => {
    const points = req.body.points || 10;

    ctx.capitalAllocatorSim.loadFromEngine();
    const surface = ctx.capitalAllocatorSim.computeReturnSurface(points);

    res.json({ surface, points: surface.length });
  });

  // GET /api/decision-run — Decision run history
  app.get('/api/decision-run', requireApiKey, rateLimiter, (req, res) => {
    const limit = parseInt(req.query.limit || '20', 10);

    res.json({
      runs: ctx.liveDecisionRunner.getRunHistory(limit),
      latest: ctx.liveDecisionRunner.getLatestRun(),
      metrics: ctx.liveDecisionRunner.getMetrics(),
    });
  });

  // POST /api/decision-run — Execute a full decision run
  app.post('/api/decision-run', requireApiKey, rateLimiter, async (req, res) => {
    const opportunitySet = req.body.opportunities || req.body.opportunity_set || [];
    const runOptions = {
      profile: req.body.profile,
      capital_budget: req.body.capital_budget,
    };

    if (opportunitySet.length === 0) {
      return res.status(400).json({ error: 'opportunities array is required' });
    }

    ctx.bus.emit({
      type: 'decision_run_started',
      ts: Date.now(),
      payload: { opportunity_count: opportunitySet.length },
      source: 'live_decision_runner',
    });

    try {
      const result = await ctx.liveDecisionRunner.run(opportunitySet, runOptions);

      ctx.bus.emit({
        type: 'decision_run_completed',
        ts: Date.now(),
        payload: {
          run_id: result.run_id,
          opportunities: result.opportunities_scored,
          portfolio_size: result.ranked_portfolio.length,
          duration_ms: result.duration_ms,
        },
        source: 'live_decision_runner',
      });

      ctx.lastDecisionRunResult = result;

      res.json({
        run_id: result.run_id,
        state: result.state,
        mode: result.mode,
        opportunities_scored: result.opportunities_scored,
        opportunities_compared: result.opportunities_compared,
        policies_decided: result.policies_decided,
        allocation_simulated: result.allocation_simulated,
        portfolio: result.ranked_portfolio.slice(0, 20),
        portfolio_summary: result.portfolio_summary,
        duration_ms: result.duration_ms,
        trace_graph_nodes: result.trace_graph ? result.trace_graph.nodes.size : 0,
        trace_graph_edges: result.trace_graph ? result.trace_graph.edges.size : 0,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/decision-run/:id — Get a specific decision run
  app.get('/api/decision-run/:id', requireApiKey, rateLimiter, (req, res) => {
    const result = ctx.liveDecisionRunner.getRun(req.params.id);
    if (!result) return res.status(404).json({ error: 'Run not found' });
    res.json(result);
  });
}

module.exports = { registerRoutes };

