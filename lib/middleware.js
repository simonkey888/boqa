/**
 * BOQA lib/middleware.js — Express middleware layer
 *
 * Extracted from server.js during Phase 3 modular refactor.
 * Contains: requireAgent, requireApiKey, rateLimiter, errorHandler, verifyHmac
 */

const crypto = require('crypto');

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

// ─── P3: HMAC Signature Middleware ───────────────────────────────────
// Defense in depth: signs every /api/* request with HMAC-SHA256 using a
// shared secret between the Cloudflare Worker and the backend.
//
// If BOQA_HMAC_SECRET is NOT set → middleware is a no-op (backward compatible).
// If BOQA_HMAC_SECRET IS set → EVERY request must include valid X-BOQA-Sig
// and X-BOQA-Ts headers, or it's rejected with 401.
//
// Anti-replay: timestamp must be within MAX_SKEW_SECONDS (configurable via
// BOQA_HMAC_SKEW_SECONDS, default 300s = 5min) of server time.
//
// Anti-timing-attack: signatures are compared with crypto.timingSafeEqual
// after length verification (timingSafeEqual throws on different lengths).
//
// Raw body handling: express.json() parses the body into req.body, which
// loses the original byte sequence. To avoid signature mismatches from
// JSON re-serialization (key order, whitespace), we capture the raw body
// BEFORE express.json() runs and store it on req._rawBody. The middleware
// uses req._rawBody (exact bytes) for signature verification.
//
// Signature algorithm: HMAC-SHA256(secret, method + path + ts + rawBody)
//   - method: HTTP method uppercase (GET, POST, etc.)
//   - path: full path including query string (req.originalUrl)
//   - ts: X-BOQA-Ts header value (Unix seconds, string)
//   - rawBody: exact bytes received (empty string for GET/HEAD)

const HMAC_SECRET = process.env.BOQA_HMAC_SECRET || '';
const MAX_SKEW_SECONDS = parseInt(process.env.BOQA_HMAC_SKEW_SECONDS || '300', 10);
const HMAC_LOG_FAILURES = process.env.BOQA_HMAC_LOG_FAILURES !== 'false'; // default: log

function _logHmacFailure(code, message, req) {
  if (!HMAC_LOG_FAILURES) return;
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const ua = req.headers['user-agent'] || 'unknown';
  const path = req.originalUrl || req.url || '';
  console.warn(`[HMAC-FAIL] ${code} ip=${ip} path=${path} ua=${ua.slice(0, 80)} msg=${message}`);
}

// Raw body capture middleware — must run BEFORE express.json().
// Uses express.json({ verify }) hook to capture the raw body buffer
// WITHOUT consuming the stream (which would break express.json() itself).
// The verify callback receives the raw buffer before parsing; we stash it
// on req._rawBody for HMAC verification later.
//
// NOTE: This middleware is a no-op on its own. The actual capture happens
// in the verify hook that express.json() calls. We expose this as a
// separate exported function so server.js can mount it explicitly, but
// the real work is done by attachRawBodyCapture() which configures
// express.json() with the verify hook.

let _rawBodyStore = new WeakMap();

function attachRawBodyCapture(expressJsonOptions = {}) {
  // Returns an express.json() config object with the verify hook that
  // captures the raw body. Use as: app.use(express.json(attachRawBodyCapture()))
  return {
    ...expressJsonOptions,
    verify: (req, res, buf, encoding) => {
      // buf is the raw Buffer of the body. Store it for HMAC verification.
      // We use a WeakMap keyed by req so we don't pollute the req object
      // directly (some test environments don't allow it).
      _rawBodyStore.set(req, buf.toString('utf8'));
      // Also stash on req._rawBody for direct access in verifyHmac.
      req._rawBody = buf.toString('utf8');
      return true;  // tell express.json() to proceed with parsing
    },
  };
}

function captureRawBody(req, res, next) {
  // Legacy fallback: if attachRawBodyCapture wasn't used, capture raw body
  // via stream consumption. This is NOT recommended because it consumes
  // the stream and breaks express.json(). Prefer attachRawBodyCapture().
  // We keep this function for backward compat but make it a no-op —
  // the real capture happens in express.json({ verify }).
  if (req._rawBody === undefined) {
    req._rawBody = '';
  }
  next();
}

function verifyHmac(req, res, next) {
  // If no secret configured, middleware is a no-op (backward compat).
  // This is INTENTIONAL — it does NOT silently open the API. If you want
  // HMAC enforcement, set BOQA_HMAC_SECRET in the environment.
  if (!HMAC_SECRET) {
    return next();
  }

  const providedSig = req.headers['x-boqa-sig'];
  const tsHeader = req.headers['x-boqa-ts'];

  if (!providedSig || !tsHeader) {
    _logHmacFailure('hmac_missing', 'Missing X-BOQA-Sig or X-BOQA-Ts header', req);
    return res.status(401).json({
      error: 'hmac_missing',
      message: 'X-BOQA-Sig and X-BOQA-Ts headers required when HMAC is enabled.',
    });
  }

  // Parse and validate timestamp (must be integer seconds)
  const ts = parseInt(tsHeader, 10);
  if (!Number.isFinite(ts) || String(ts) !== String(tsHeader).trim()) {
    _logHmacFailure('hmac_invalid_ts', `Invalid ts: ${tsHeader}`, req);
    return res.status(401).json({
      error: 'hmac_invalid_ts',
      message: 'X-BOQA-Ts must be a Unix timestamp in seconds.',
    });
  }

  // Anti-replay: reject if timestamp is too far from server time
  const now = Math.floor(Date.now() / 1000);
  const skew = Math.abs(now - ts);
  if (skew > MAX_SKEW_SECONDS) {
    _logHmacFailure('hmac_stale_ts', `skew=${skew}s max=${MAX_SKEW_SECONDS}s`, req);
    return res.status(401).json({
      error: 'hmac_stale_ts',
      message: `Timestamp skew ${skew}s exceeds max ${MAX_SKEW_SECONDS}s. Possible replay attack.`,
      server_time: now,
      client_time: ts,
    });
  }

  // Use raw body (exact bytes) if available; fall back to JSON.stringify
  // for backward compat with older Worker versions that didn't capture raw.
  const bodyStr = req._rawBody !== undefined ? req._rawBody : '';

  const method = String(req.method || 'GET').toUpperCase();
  const path = req.originalUrl || req.url || '';
  const payload = method + path + String(ts) + bodyStr;

  const expectedSig = crypto
    .createHmac('sha256', HMAC_SECRET)
    .update(payload, 'utf8')
    .digest('hex');

  // timingSafeEqual requires same-length Buffers. Check length first.
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  const providedBuf = Buffer.from(providedSig, 'utf8');
  if (expectedBuf.length !== providedBuf.length) {
    _logHmacFailure('hmac_bad_length', `expected=${expectedBuf.length} got=${providedBuf.length}`, req);
    return res.status(401).json({
      error: 'hmac_bad_length',
      message: 'Signature length mismatch.',
    });
  }

  // Constant-time comparison to prevent timing attacks
  let valid = false;
  try {
    valid = crypto.timingSafeEqual(expectedBuf, providedBuf);
  } catch (_) {
    valid = false;
  }

  if (!valid) {
    _logHmacFailure('hmac_invalid', 'Signature mismatch', req);
    return res.status(401).json({
      error: 'hmac_invalid',
      message: 'Invalid HMAC signature.',
    });
  }

  // Signature valid — proceed to next middleware
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
  verifyHmac,
  captureRawBody,
  attachRawBodyCapture,
};

