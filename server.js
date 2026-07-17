'use strict';

const express = require('express');
const http = require('http');
const path = require('path');
const { WebSocketServer } = require('ws');
const { createBillingAuth } = require('./lib/billing-auth');
const { DefensiveValidationService } = require('./lib/defensive-validation');
const { HunterRuntime } = require('./lib/hunter-runtime');
const { CONFIG, OUTPUT_DIR } = require('./lib/config');
const {
  createRequireAgent,
  errorHandler,
  requireApiKey,
  rateLimiter,
  verifyHmac,
  attachRawBodyCapture,
} = require('./lib/middleware');
const { initialize } = require('./lib/init');

const ctx = initialize(CONFIG, OUTPUT_DIR);
ctx.defensiveValidation = new DefensiveValidationService();

function provideHunterPolicy() {
  try {
    const assets = ctx.defensiveValidation.loadAssets();
    const authorizedAssets = assets.filter((asset) => ctx.defensiveValidation.authorize(asset).allowed);
    if (authorizedAssets.length === 0) {
      return { status: 'BLOCKED', reason: 'NO_AUTHORIZED_ASSETS', authorized_assets: [] };
    }
    return { status: 'READY', authorized_assets: authorizedAssets };
  } catch (error) {
    return { status: 'BLOCKED', reason: error.code || error.message || 'INVALID_POLICY', authorized_assets: [] };
  }
}

ctx.hunterRuntime = new HunterRuntime({
  cycleRunner: () => ctx.defensiveValidation.runCycle(),
  policyProvider: provideHunterPolicy,
  statePath: path.join(OUTPUT_DIR, 'hunter-state.json'),
  lockPath: path.join(OUTPUT_DIR, 'hunter-runtime.lock'),
});

const billingAuth = createBillingAuth();
const requireAgent = createRequireAgent(() => ctx.agent, () => ctx.agentInitError);
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json(attachRawBodyCapture({ limit: process.env.BOQA_JSON_LIMIT || '256kb' })));

const server = http.createServer(app);
app.get('/cobros', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.set('X-Robots-Tag', 'noindex, nofollow, noarchive');
  res.sendFile(path.join(__dirname, 'dashboard', 'cobros.html'));
});
app.use(express.static(path.join(__dirname, 'dashboard')));

app.get('/api/defensive/status', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json(ctx.hunterRuntime.publicStatus());
});
app.post('/api/private/billing/auth', billingAuth.authenticate);
app.get('/api/private/billing/session', billingAuth.requireSession, (req, res) => res.json({
  authenticated: true,
  csrf_token: req.billingSession.csrf,
  expires_at: new Date(req.billingSession.expiresAt).toISOString(),
}));
app.get('/api/private/billing/data', billingAuth.requireSession, (_req, res) => res.json({ movements: [], summary: null }));
app.post('/api/private/billing/logout', billingAuth.requireSession, billingAuth.requireCsrf, billingAuth.logout);

const pipelines = require('./lib/pipelines');
const wss = new WebSocketServer({ server, path: '/ws' });
ctx.bus.wsServer = wss;
ctx.wss = wss;
ctx.server = server;

const PUBLIC_READ_PATHS = new Set([
  '/health',
  '/replay/health',
  '/runtime/metrics',
  '/defensive/status',
  '/hunter/status',
]);

app.use('/api', (req, res, next) => {
  if (req.path.startsWith('/private/billing/')) return next();
  if (req.method === 'GET' && PUBLIC_READ_PATHS.has(req.path)) return next();
  verifyHmac(req, res, (hmacError) => {
    if (hmacError) return next(hmacError);
    rateLimiter(req, res, (rateError) => {
      if (rateError) return next(rateError);
      requireApiKey(req, res, next);
    });
  });
});

const middleware = { requireAgent, requireApiKey, rateLimiter };
require('./routes/hunter-v1').registerRoutes(app, ctx);
require('./routes/quality-v1').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v01').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v08').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v09').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v11').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v12').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v13').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v14').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v15').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/s6').registerRoutes(app, ctx, middleware, pipelines);

const { wireEventHandlers } = require('./lib/event-wiring');
wireEventHandlers(ctx, pipelines);

let lastCount = 0;
const statsTimer = setInterval(() => {
  const stats = ctx.bus.getStats();
  if (stats.totalEvents !== lastCount) {
    lastCount = stats.totalEvents;
    const top = Object.entries(stats.byType)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([type, count]) => `${type.split('_')[0]}=${count}`)
      .join(' ');
    const anomalyCount = ctx.agent ? ctx.agent.anomaly.getAnomalies().length : 0;
    console.log(`[Stats] ${stats.totalEvents} events | ${top} | anomalies=${anomalyCount} | findings=${ctx.lastFindings.length} | bugs=${ctx.lastConfirmedBugs.length} | ${stats.clients} dash`);
  }
}, 10_000);
statsTimer.unref?.();

if (CONFIG.autoAnalyze && CONFIG.analyzeInterval > 0) {
  const analysisTimer = setInterval(() => {
    if (ctx.bus.eventLog.length <= 10) return;
    try {
      pipelines.runAnalysisPipeline(ctx);
    } catch (error) {
      console.warn(`[Auto-Analyze] Error: ${error.message}`);
    }
  }, CONFIG.analyzeInterval * 1000);
  analysisTimer.unref?.();
}

const { createShutdown } = require('./lib/shutdown');
const legacyShutdown = createShutdown(ctx, pipelines);
let shutdownPromise = null;
function shutdown(signal) {
  if (shutdownPromise) return shutdownPromise;
  shutdownPromise = (async () => {
    if (ctx.hunterRuntime) await ctx.hunterRuntime.stop(signal);
    return legacyShutdown(signal);
  })();
  return shutdownPromise;
}

if (CONFIG.duration > 0) {
  const durationTimer = setTimeout(() => {
    console.log(`[Server] Duration limit reached (${CONFIG.duration}s) — shutting down`);
    void shutdown('DURATION_LIMIT');
  }, CONFIG.duration * 1000);
  durationTimer.unref?.();
}

process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGHUP', () => console.log('[Server] SIGHUP received — ignoring (background execution mode)'));
app.use(errorHandler);

async function main() {
  const modeLabel = { live: 'Live Observe', baseline: 'Baseline Build', compare: 'Compare' }[CONFIG.mode] || CONFIG.mode;
  console.log(`\n[BOQA] mode=${modeLabel} target=${CONFIG.target || 'none (fail-closed)'} session=${ctx.bus.sessionId.substring(0, 8)}`);

  server.listen(CONFIG.port, '0.0.0.0', () => {
    console.log(`[Server] Dashboard: http://localhost:${CONFIG.port}`);
  });

  const hunter = await ctx.hunterRuntime.start();
  console.log(`[Hunter] state=${hunter.state} reason=${hunter.reason || 'none'} last_cycle=${hunter.last_completed_at || 'none'}`);

  if (ctx.agent) {
    try {
      await ctx.agent.start();
      console.log(`[Server] Agent active — mode: ${CONFIG.mode}`);
    } catch (error) {
      ctx.agentStartError = error.message || String(error);
      console.error('[Server] Agent failed:', error.message);
      console.error('[Server] Server remains up in degraded browser-agent mode');
    }
  } else {
    console.warn(`[Server] Agent not initialized — degraded mode: ${ctx.agentInitError || 'unknown'}`);
  }

  if (ctx.runtimeMonitor) {
    ctx.runtimeMonitor.start();
    const agentRunning = ctx.agent ? (!('page' in ctx.agent) || Boolean(ctx.agent.page)) : false;
    ctx.runtimeMonitor.recordHealth(agentRunning ? 'ok' : 'degraded');
    console.log('[Server] Runtime monitor active');
  }
}

main().catch((error) => {
  console.error('[Server] Fatal bootstrap error:', error.message);
  void shutdown('BOOTSTRAP_ERROR');
});
