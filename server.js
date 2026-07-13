/**
 * BOQA server.js — Thin bootstrap (Phase 3 modular refactor)
 *
 * This file was refactored from a ~3700-line monolith into a thin
 * orchestrator that wires together modules from lib/ and routes/.
 *
 * Original behavior is 100% preserved — same routes, same shutdown,
 * same event wiring, same degraded-mode behavior.
 */

const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const path = require('path');

// ─── Config ─────────────────────────────────────────────────────────────

const { CONFIG, OUTPUT_DIR, SESSIONS_DIR, REPORTS_DIR } = require('./lib/config');

// ─── Middleware ──────────────────────────────────────────────────────────

const { createRequireAgent, errorHandler, requireApiKey, rateLimiter, verifyHmac, attachRawBodyCapture } = require('./lib/middleware');

// ─── Engine Initialization ──────────────────────────────────────────────

const { initialize } = require('./lib/init');
const ctx = initialize(CONFIG, OUTPUT_DIR);

// Create agent-aware middleware now that ctx exists
const requireAgent = createRequireAgent(() => ctx.agent, () => ctx.agentInitError);

// ─── Express + HTTP + WS ───────────────────────────────────────────────

const app = express();
// Capture raw body via express.json({ verify }) hook — this is the correct
// way to get the exact bytes received without breaking body parsing.
// attachRawBodyCapture() returns a config object with a verify callback that
// stashes the raw buffer on req._rawBody for HMAC verification later.
app.use(express.json(attachRawBodyCapture()));
const server = http.createServer(app);
app.use(express.static(path.join(__dirname, 'dashboard')));

// ─── Pipelines ──────────────────────────────────────────────────────────

const pipelines = require('./lib/pipelines');

// ─── WS Server (must create after bus for correct reference) ───────

const wss = new WebSocketServer({ server, path: '/ws' });
ctx.bus.wsServer = wss;

// Store references needed by shutdown
ctx.wss = wss;
ctx.server = server;

// ─── P0 SECURITY: Admin execution gate ──────────────────────────────────
// Block ALL POST/PUT/PATCH/DELETE on /api/* when BOQA_ADMIN_EXECUTION_ENABLED != 'true'
const { createAdminGate } = require('./lib/admin-gate');
const adminGate = createAdminGate();
app.use('/api', adminGate);

// ─── URGENT-5: Global API Auth Middleware ──────────────────────────────
// Apply verifyHmac + rateLimiter + requireApiKey to ALL /api routes.
// Whitelist: /health, /replay/health, /runtime/metrics (diagnostic endpoints)
//
// HMAC verification runs FIRST — if BOQA_HMAC_SECRET is set, requests
// without valid X-BOQA-Sig + X-BOQA-Ts headers are rejected before
// any other middleware runs. This protects even if rateLimiter/requireApiKey
// are disabled (defense in depth).
const AUTH_WHITELIST = new Set(['/health', '/replay/health', '/runtime/metrics']);

app.use('/api', (req, res, next) => {
  // Skip auth for whitelisted diagnostic paths (they have their own protection)
  const apiPath = req.path; // path relative to /api mount point
  if (AUTH_WHITELIST.has(apiPath)) {
    return next();
  }
  // HMAC first (no-op if BOQA_HMAC_SECRET unset), then rate limiter, then API key
  verifyHmac(req, res, (err) => {
    if (err) return next(err);
    rateLimiter(req, res, (err2) => {
      if (err2) return next(err2);
      requireApiKey(req, res, next);
    });
  });
});

// ─── Register API Routes ────────────────────────────────────────────────

const middleware = { requireAgent, requireApiKey, rateLimiter };

require('./routes/quality-v1').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v01').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v08').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v09').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v11').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v12').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v13').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v14').registerRoutes(app, ctx, middleware, pipelines);
require('./routes/v15').registerRoutes(app, ctx, middleware, pipelines);

// STRUCT-6: S6 Pipeline API routes
require('./routes/s6').registerRoutes(app, ctx, middleware, pipelines);

// ─── Event Wiring ──────────────────────────────────────────────────────

const { wireEventHandlers } = require('./lib/event-wiring');
wireEventHandlers(ctx, pipelines);

// ─── Stats Logging ─────────────────────────────────────────────────────

let lastCount = 0;
setInterval(() => {
  const stats = ctx.bus.getStats();
  if (stats.totalEvents !== lastCount) {
    lastCount = stats.totalEvents;
    const top = Object.entries(stats.byType).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([t, c]) => `${t.split('_')[0]}=${c}`).join(' ');
    const anomalyCount = ctx.agent ? ctx.agent.anomaly.getAnomalies().length : 0;
    const findingCount = ctx.lastFindings.length;
    const bugCount = ctx.lastConfirmedBugs.length;
    console.log(`[Stats] ${stats.totalEvents} events | ${top} | anomalies=${anomalyCount} | findings=${findingCount} | bugs=${bugCount} | ${stats.clients} dash`);
  }
}, 10000);

// ─── Auto-Analysis ─────────────────────────────────────────────────────

if (CONFIG.autoAnalyze && CONFIG.analyzeInterval > 0) {
  setInterval(() => {
    if (ctx.bus.eventLog.length > 10) {
      try {
        pipelines.runAnalysisPipeline(ctx);
      } catch (err) {
        console.warn(`[Auto-Analyze] Error: ${err.message}`);
      }
    }
  }, CONFIG.analyzeInterval * 1000);
}

// ─── Duration Timer ────────────────────────────────────────────────────

if (CONFIG.duration > 0) {
  setTimeout(() => {
    console.log(`[Server] Duration limit reached (${CONFIG.duration}s) — shutting down`);
    shutdown('DURATION_LIMIT');
  }, CONFIG.duration * 1000);
}

// ─── Shutdown Pipeline ─────────────────────────────────────────────────

const { createShutdown } = require('./lib/shutdown');
const shutdown = createShutdown(ctx, pipelines);

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// URGENT-1: SIGHUP handler — survive background execution (nohup, Docker, systemd)
process.on('SIGHUP', () => {
  console.log('[Server] SIGHUP received — ignoring (background execution mode)');
});

// P3: Global error handler — must be registered after all routes
app.use(errorHandler);

// ─── Boot ──────────────────────────────────────────────────────────────

async function main() {
  const modeLabel = {
    live: 'Live Observe',
    baseline: 'Baseline Build',
    compare: 'Compare',
  }[CONFIG.mode] || CONFIG.mode;

  console.log();
  console.log('  ╔═══════════════════════════════════════════════════════════════╗');
  console.log('  ║   BOQA — Browser Observability & QA Agent v1.4               ║');
  console.log('  ║   Autonomous Decision Kernel                                  ║');
  console.log('  ╠═══════════════════════════════════════════════════════════════╣');
  console.log(`  ║  Mode:      ${modeLabel.padEnd(49)}║`);
  console.log(`  ║  Target:    ${CONFIG.target.padEnd(49)}║`);
  console.log(`  ║  Session:   ${ctx.bus.sessionId.substring(0, 8).padEnd(49)}║`);
  console.log(`  ║  Dashboard: http://localhost:${String(CONFIG.port).padEnd(38)}║`);
  console.log(`  ║  Analyze:   every ${String(CONFIG.analyzeInterval + 's').padEnd(41)}║`);
  if (ctx.baselineObj) {
    console.log(`  ║  Baseline:  ${ctx.baselineObj.id.padEnd(49)}║`);
  }
  console.log('  ╚═══════════════════════════════════════════════════════════════╝');
  console.log();

  // Start HTTP
  server.listen(CONFIG.port, '0.0.0.0', () => {
    console.log(`[Server] Dashboard: http://localhost:${CONFIG.port}`);
  });

  // Start Agent (skip if init failed — degraded mode)
  if (ctx.agent) {
    try {
      await ctx.agent.start();
      console.log(`[Server] Agent active — mode: ${CONFIG.mode}`);
    } catch (e) {
      ctx.agentStartError = e.message || String(e);
      console.error('[Server] Agent failed:', e.message);
      console.error('[Server] Server remains up — v0.9 APIs and dashboard available');
    }
  } else {
    console.warn(`[Server] Agent not initialized — running in degraded mode. Error: ${ctx.agentInitError || 'unknown'}`);
    console.warn('[Server] Agent-dependent endpoints will return 503; other APIs remain functional.');
  }

  // P5: Start runtime monitor for production observability
  if (ctx.runtimeMonitor) {
    ctx.runtimeMonitor.start();
    const agentRunning = ctx.agent ? (!('page' in ctx.agent) || !!ctx.agent.page) : false;
    ctx.runtimeMonitor.recordHealth(agentRunning ? 'ok' : 'degraded');
    console.log('[Server] Runtime monitor active');
  }
}

main();

