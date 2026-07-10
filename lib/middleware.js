/**
 * BOQA lib/middleware.js — Express middleware layer
 *
 * Extracted from server.js during Phase 3 modular refactor.
 * Contains: requireAgent, requireApiKey, rateLimiter, errorHandler
 */

// ─── F2: Agent Guard Middleware ──────────────────────────────────────
// Rejects requests when agent is unavailable (degraded mode)

function createRequireAgent(getAgent, getInitError) {
  return function requireAgent(req, res, next) {
    const agent = getAgent();
    // P5-FIX: If agent has a .page property, it must be truthy (browser connected).
    // If agent has no .page property (e.g. test stub), just check agent is truthy.
    // This catches the case where Agent was constructed but browser launch failed.
    if (!agent) {
      return res.status(503).json({
        error: 'agent_unavailable',
        message: 'The browser agent is not initialized. Server is in degraded mode.',
        degraded_since: getInitError() || 'unknown',
      });
    }
    if ('page' in agent && !agent.page) {
      return res.status(503).json({
        error: 'agent_unavailable',
        message: 'The browser agent is not available. Browser session is not active.',
        degraded_since: getInitError() || 'unknown',
      });
    }
    next();
  };
}

// ─── P3: Standard Error Envelope ─────────────────────────────────────
// Prevents stack trace leaks in production

function errorHandler(err, req, res, _next) {
  const status = err.status || err.statusCode || 500;
  const isDev = process.env.NODE_ENV === 'development';
  res.status(status).json({
    error: err.code || 'internal_error',
    message: err.message || 'An unexpected error occurred',
    ...(isDev && { stack: err.stack }),
  });
}

// ─── P1: API Key Middleware ──────────────────────────────────────────
// Auth gate disabled per user request (temporary dev mode).
// To re-enable: set BOQA_API_KEY env var to a non-empty string.
// When env var is set, requests must include X-API-Key header matching it.
// When env var is unset (current state), all requests are accepted.

const API_KEY = process.env.BOQA_API_KEY || '';
let apiKeyWarningLogged = false;

function requireApiKey(req, res, next) {
  if (!API_KEY) {
    // Auth disabled — open access. Logged once on first request.
    if (!apiKeyWarningLogged) {
      console.warn('[Server] BOQA_API_KEY not set — protected routes are OPEN (auth disabled).');
      apiKeyWarningLogged = true;
    }
    return next();
  }
  const provided = req.headers['x-api-key'] || req.query.api_key || null;
  if (!provided || provided !== API_KEY) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Valid API key required. Set X-API-Key header or api_key query param.',
    });
  }
  next();
}

// ─── P2: Simple Rate Limiter ────────────────────────────────────────
// Token-bucket per-IP, no external deps. 60 requests per minute default.

const rateLimitBuckets = new Map(); // ip -> { tokens, lastRefill }
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_TOKENS = parseInt(process.env.BOQA_RATE_LIMIT || '60', 10);

function rateLimiter(req, res, next) {
  if (RATE_LIMIT_MAX_TOKENS <= 0) return next(); // disabled
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  let bucket = rateLimitBuckets.get(ip);
  if (!bucket) {
    bucket = { tokens: RATE_LIMIT_MAX_TOKENS, lastRefill: now };
    rateLimitBuckets.set(ip, bucket);
  }
  // Refill tokens based on elapsed time
  const elapsed = now - bucket.lastRefill;
  const refill = Math.floor((elapsed / RATE_LIMIT_WINDOW_MS) * RATE_LIMIT_MAX_TOKENS);
  if (refill > 0) {
    bucket.tokens = Math.min(RATE_LIMIT_MAX_TOKENS, bucket.tokens + refill);
    bucket.lastRefill = now;
  }
  if (bucket.tokens <= 0) {
    res.setHeader('Retry-After', Math.ceil(RATE_LIMIT_WINDOW_MS / 1000));
    return res.status(429).json({
      error: 'rate_limited',
      message: `Rate limit exceeded. Max ${RATE_LIMIT_MAX_TOKENS} requests per minute.`,
      retry_after_seconds: Math.ceil(RATE_LIMIT_WINDOW_MS / 1000),
    });
  }
  bucket.tokens--;
  next();
}

// Clean stale rate limit buckets every 5 minutes
setInterval(() => {
  const cutoff = Date.now() - (RATE_LIMIT_WINDOW_MS * 2);
  for (const [ip, bucket] of rateLimitBuckets.entries()) {
    if (bucket.lastRefill < cutoff) rateLimitBuckets.delete(ip);
  }
}, 300_000);

module.exports = {
  createRequireAgent,
  errorHandler,
  requireApiKey,
  rateLimiter,
};

