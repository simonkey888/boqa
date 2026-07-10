/**
 * BOQA routes/v08.js — v0.8 Predictive Discovery Layer API routes
 *
 * Extracted from server.js during modular refactor.
 * All engine/state references go through the `ctx` context object.
 * Middleware and pipeline functions are injected via parameters.
 */

/**
 * Register all v0.8 Predictive Discovery Layer routes on the Express app.
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
  // v0.8 Predictive Discovery Layer Routes
  // ═══════════════════════════════════════════════════════════════════════

  // GET /api/predictions — Target and category yield predictions
  app.get('/api/predictions', (req, res) => {
    const targetId = req.query.target_id;

    if (targetId) {
      const prediction = ctx.predictionEngine.predictTarget(targetId);
      const endpoints = ctx.predictionEngine.predictEndpoints(targetId);
      ctx.lastPredictions = {
        target: prediction,
        endpoints: endpoints.slice(0, 20),
        generated_at: Date.now(),
      };
    } else {
      const targets = ctx.predictionEngine.predictAllTargets();
      const categories = ctx.predictionEngine.predictCategories();
      ctx.lastPredictions = {
        targets: targets.slice(0, 30),
        categories: categories.slice(0, 20),
        accuracy: ctx.predictionEngine.getAccuracy(),
        stats: ctx.predictionEngine.getStats(),
        generated_at: Date.now(),
      };
    }

    res.json(ctx.lastPredictions);
  });

  // GET /api/yield-forecast — Expected bugs, severity distribution, verification rates
  app.get('/api/yield-forecast', (req, res) => {
    const targetId = req.query.target_id;

    if (targetId) {
      ctx.lastYieldForecast = ctx.yieldForecaster.forecastTarget(targetId);
    } else {
      ctx.lastYieldForecast = ctx.yieldForecaster.forecastPortfolio();
    }

    res.json(ctx.lastYieldForecast);
  });

  // GET /api/risk-forecast — Regression risk by target and campaign
  app.get('/api/risk-forecast', (req, res) => {
    const targetId = req.query.target_id;
    const campaignId = req.query.campaign_id;

    if (campaignId) {
      ctx.lastRiskForecast = ctx.riskForecaster.forecastCampaign(campaignId);
    } else if (targetId) {
      ctx.lastRiskForecast = ctx.riskForecaster.forecastTarget(targetId);
    } else {
      ctx.lastRiskForecast = ctx.riskForecaster.forecastPortfolio();
    }

    res.json(ctx.lastRiskForecast);
  });

  // GET /api/next-best-action — Prioritized action recommendations
  app.get('/api/next-best-action', (req, res) => {
    const maxActions = Math.min(parseInt(req.query.limit || '10', 10), 50);

    // Shape target priorities first
    const shapedPriorities = ctx.priorityShaper.shapeTargetPriorities();
    const actions = ctx.priorityShaper.getNextBestActions(maxActions);

    ctx.lastNextBestAction = {
      actions,
      shaped_priorities: shapedPriorities.slice(0, 10),
      shaper_stats: ctx.priorityShaper.getStats(),
      generated_at: Date.now(),
    };

    res.json(ctx.lastNextBestAction);
  });

  // GET /api/campaign-forecast — Recommended campaign shapes
  app.get('/api/campaign-forecast', (req, res) => {
    const forecast = ctx.campaignForecaster.forecast();

    ctx.lastCampaignForecast = {
      recommended_shapes: forecast.recommended_shapes.map(s => ({
        type: s.type,
        name: s.name,
        description: s.description,
        target_count: s.target_ids.length,
        max_workers: s.max_workers,
        duration_hours: Math.round(s.max_duration_ms / 3600000),
        expected_output: s.expected_output,
        effectiveness_score: s.effectiveness_score,
        confidence: s.confidence,
      })),
      current_vs_recommended: forecast.current_vs_recommended,
      optimal_budget: forecast.optimal_budget,
      best_time: forecast.best_time,
      expected_portfolio_yield: forecast.expected_portfolio_yield,
      shape_effectiveness: ctx.campaignForecaster.getStats().shape_effectiveness,
      generated_at: Date.now(),
    };

    res.json(ctx.lastCampaignForecast);
  });
}

module.exports = { registerRoutes };

