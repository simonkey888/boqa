'use strict';

const IDEMPOTENCY_TTL_MS = 15 * 60 * 1000;
const MANUAL_RATE_WINDOW_MS = 5 * 60 * 1000;
const MANUAL_RATE_LIMIT = 3;
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/;

function requestIp(req) {
  return String(req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || 'unknown');
}

function header(req, name) {
  if (typeof req.get === 'function') return req.get(name);
  return req.headers?.[name.toLowerCase()] || null;
}

function createManualCycleController(options = {}) {
  const now = options.now || Date.now;
  const idempotency = new Map();
  const rateBuckets = new Map();
  const rateLimit = Number(options.rateLimit || MANUAL_RATE_LIMIT);
  const rateWindowMs = Number(options.rateWindowMs || MANUAL_RATE_WINDOW_MS);
  const idempotencyTtlMs = Number(options.idempotencyTtlMs || IDEMPOTENCY_TTL_MS);

  function cleanup() {
    const current = now();
    for (const [key, entry] of idempotency) {
      if (entry.expiresAt <= current) idempotency.delete(key);
    }
    for (const [key, bucket] of rateBuckets) {
      if (current - bucket.windowStartedAt >= rateWindowMs) rateBuckets.delete(key);
    }
  }

  function strongAuth(req, res) {
    const configured = Boolean(process.env.BOQA_API_KEY && process.env.BOQA_HMAC_SECRET);
    const apiKeyHeaderPresent = Boolean(header(req, 'X-API-Key'));
    const authenticated = req.boqaAuth?.apiKey === true && req.boqaAuth?.hmac === true;
    if (!configured || !authenticated || !apiKeyHeaderPresent) {
      res.set('Cache-Control', 'no-store');
      res.status(401).json({ error: 'strong_auth_required' });
      return false;
    }
    return true;
  }

  function consumeRate(req, res) {
    cleanup();
    const key = requestIp(req);
    const current = now();
    let bucket = rateBuckets.get(key);
    if (!bucket || current - bucket.windowStartedAt >= rateWindowMs) {
      bucket = { count: 0, windowStartedAt: current };
      rateBuckets.set(key, bucket);
    }
    if (bucket.count >= rateLimit) {
      const retryAfterSeconds = Math.max(1, Math.ceil((rateWindowMs - (current - bucket.windowStartedAt)) / 1000));
      res.set('Retry-After', String(retryAfterSeconds));
      res.set('Cache-Control', 'no-store');
      res.status(429).json({ error: 'manual_cycle_rate_limited', retry_after_seconds: retryAfterSeconds });
      return false;
    }
    bucket.count += 1;
    return true;
  }

  async function handle(req, res, next, ctx) {
    if (!strongAuth(req, res)) return;
    const key = header(req, 'Idempotency-Key');
    if (!key || !IDEMPOTENCY_PATTERN.test(key)) {
      res.set('Cache-Control', 'no-store');
      return res.status(400).json({ error: 'valid_idempotency_key_required' });
    }

    cleanup();
    const existing = idempotency.get(key);
    if (existing) {
      res.set('Cache-Control', 'no-store');
      if (existing.status === 'in_progress') return res.status(409).json({ error: 'idempotent_request_in_progress' });
      return res.status(200).json({ ...existing.response, idempotent_replay: true });
    }
    if (!consumeRate(req, res)) return;
    if (!ctx.hunterRuntime) return res.status(503).json({ error: 'hunter_unavailable' });

    const preflight = ctx.hunterRuntime.preflightManual();
    if (!preflight.allowed) {
      res.set('Cache-Control', 'no-store');
      return res.status(409).json({ error: 'manual_cycle_blocked', reason: preflight.reason });
    }

    idempotency.set(key, { status: 'in_progress', expiresAt: now() + idempotencyTtlMs });
    try {
      const result = await ctx.hunterRuntime.runCycle('manual');
      const statusCode = result.accepted ? 202 : 409;
      const response = result.accepted
        ? { accepted: true, result: result.result, hunter: result.hunter }
        : { accepted: false, error: 'manual_cycle_blocked', reason: result.reason };
      if (result.accepted) {
        idempotency.set(key, { status: 'completed', response, expiresAt: now() + idempotencyTtlMs });
      } else {
        idempotency.delete(key);
      }
      res.set('Cache-Control', 'no-store');
      return res.status(statusCode).json(response);
    } catch (error) {
      idempotency.delete(key);
      return next(error);
    }
  }

  return { handle, cleanup, _idempotency: idempotency, _rateBuckets: rateBuckets };
}

function registerRoutes(app, ctx, options = {}) {
  const manual = createManualCycleController(options);

  app.get('/api/hunter/status', (_req, res) => {
    res.set('Cache-Control', 'no-store');
    if (!ctx.hunterRuntime) return res.status(503).json({ error: 'hunter_unavailable' });
    const status = ctx.hunterRuntime.publicStatus();
    return res.status(status.state === 'ERROR' ? 503 : 200).json(status);
  });

  app.post('/api/hunter/cycle', (req, res, next) => manual.handle(req, res, next, ctx));
  return manual;
}

module.exports = {
  IDEMPOTENCY_TTL_MS,
  MANUAL_RATE_LIMIT,
  MANUAL_RATE_WINDOW_MS,
  createManualCycleController,
  registerRoutes,
};
