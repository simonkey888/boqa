'use strict';

const crypto = require('crypto');

function createRequireAgent(getAgent, getInitError) {
  return function requireAgent(req, res, next) {
    const agent = getAgent();
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

function errorHandler(err, req, res, _next) {
  const status = err.status || err.statusCode || 500;
  const isDev = process.env.NODE_ENV === 'development';
  res.status(status).json({
    error: err.code || 'internal_error',
    message: err.message || 'An unexpected error occurred',
    ...(isDev && { stack: err.stack }),
  });
}

function safeEqualText(left, right) {
  const a = Buffer.from(String(left || ''), 'utf8');
  const b = Buffer.from(String(right || ''), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

let apiKeyWarningLogged = false;
function requireApiKey(req, res, next) {
  req.boqaAuth = req.boqaAuth || {};
  const expected = process.env.BOQA_API_KEY || '';
  if (!expected) {
    req.boqaAuth.apiKey = false;
    if (!apiKeyWarningLogged) {
      console.warn('[Server] BOQA_API_KEY not set — general protected routes are open for backward compatibility; strong-auth routes remain closed.');
      apiKeyWarningLogged = true;
    }
    return next();
  }
  const provided = req.headers['x-api-key'] || req.query?.api_key || null;
  if (!provided || !safeEqualText(provided, expected)) {
    req.boqaAuth.apiKey = false;
    return res.status(401).json({ error: 'unauthorized', message: 'Valid API key required.' });
  }
  req.boqaAuth.apiKey = true;
  next();
}

function _logHmacFailure(code, message, req) {
  if (process.env.BOQA_HMAC_LOG_FAILURES === 'false') return;
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const ua = req.headers['user-agent'] || 'unknown';
  const requestPath = req.originalUrl || req.url || '';
  console.warn(`[HMAC-FAIL] ${code} ip=${ip} path=${requestPath} ua=${ua.slice(0, 80)} msg=${message}`);
}

const rawBodyStore = new WeakMap();
function attachRawBodyCapture(expressJsonOptions = {}) {
  return {
    ...expressJsonOptions,
    verify: (req, _res, buf) => {
      const raw = buf.toString('utf8');
      rawBodyStore.set(req, raw);
      req._rawBody = raw;
      return true;
    },
  };
}

function captureRawBody(req, _res, next) {
  if (req._rawBody === undefined) req._rawBody = rawBodyStore.get(req) || '';
  next();
}

function verifyHmac(req, res, next) {
  req.boqaAuth = req.boqaAuth || {};
  const secret = process.env.BOQA_HMAC_SECRET || '';
  if (!secret) {
    req.boqaAuth.hmac = false;
    return next();
  }

  const providedSig = req.headers['x-boqa-sig'];
  const tsHeader = req.headers['x-boqa-ts'];
  if (!providedSig || !tsHeader) {
    req.boqaAuth.hmac = false;
    _logHmacFailure('hmac_missing', 'Missing X-BOQA-Sig or X-BOQA-Ts header', req);
    return res.status(401).json({ error: 'hmac_missing', message: 'X-BOQA-Sig and X-BOQA-Ts headers required.' });
  }

  const ts = Number(tsHeader);
  if (!Number.isInteger(ts) || String(ts) !== String(tsHeader).trim()) {
    req.boqaAuth.hmac = false;
    _logHmacFailure('hmac_invalid_ts', `Invalid ts: ${tsHeader}`, req);
    return res.status(401).json({ error: 'hmac_invalid_ts', message: 'X-BOQA-Ts must be a Unix timestamp in seconds.' });
  }

  const maxSkew = Number(process.env.BOQA_HMAC_SKEW_SECONDS || 300);
  const now = Math.floor(Date.now() / 1000);
  const skew = Math.abs(now - ts);
  if (skew > maxSkew) {
    req.boqaAuth.hmac = false;
    _logHmacFailure('hmac_stale_ts', `skew=${skew}s max=${maxSkew}s`, req);
    return res.status(401).json({ error: 'hmac_stale_ts', message: 'Timestamp outside the accepted anti-replay window.' });
  }

  const method = String(req.method || 'GET').toUpperCase();
  const requestPath = req.originalUrl || req.url || '';
  const body = req._rawBody !== undefined ? req._rawBody : rawBodyStore.get(req) || '';
  const expected = crypto.createHmac('sha256', secret).update(method + requestPath + String(ts) + body, 'utf8').digest('hex');
  if (!safeEqualText(providedSig, expected)) {
    req.boqaAuth.hmac = false;
    _logHmacFailure('hmac_invalid', 'Signature mismatch', req);
    return res.status(401).json({ error: 'hmac_invalid', message: 'Invalid HMAC signature.' });
  }

  req.boqaAuth.hmac = true;
  next();
}

const rateLimitBuckets = new Map();
const RATE_LIMIT_WINDOW_MS = 60_000;
function rateLimiter(req, res, next) {
  const maxTokens = Number(process.env.BOQA_RATE_LIMIT || 60);
  if (maxTokens <= 0) return next();
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const now = Date.now();
  let bucket = rateLimitBuckets.get(ip);
  if (!bucket) {
    bucket = { tokens: maxTokens, lastRefill: now };
    rateLimitBuckets.set(ip, bucket);
  }
  const elapsed = now - bucket.lastRefill;
  const refill = Math.floor((elapsed / RATE_LIMIT_WINDOW_MS) * maxTokens);
  if (refill > 0) {
    bucket.tokens = Math.min(maxTokens, bucket.tokens + refill);
    bucket.lastRefill = now;
  }
  if (bucket.tokens <= 0) {
    res.setHeader('Retry-After', String(Math.ceil(RATE_LIMIT_WINDOW_MS / 1000)));
    return res.status(429).json({
      error: 'rate_limited',
      message: `Rate limit exceeded. Max ${maxTokens} requests per minute.`,
      retry_after_seconds: Math.ceil(RATE_LIMIT_WINDOW_MS / 1000),
    });
  }
  bucket.tokens -= 1;
  next();
}

const cleanupTimer = setInterval(() => {
  const cutoff = Date.now() - RATE_LIMIT_WINDOW_MS * 2;
  for (const [ip, bucket] of rateLimitBuckets) {
    if (bucket.lastRefill < cutoff) rateLimitBuckets.delete(ip);
  }
}, 300_000);
cleanupTimer.unref?.();

module.exports = {
  createRequireAgent,
  errorHandler,
  requireApiKey,
  rateLimiter,
  verifyHmac,
  captureRawBody,
  attachRawBodyCapture,
};
