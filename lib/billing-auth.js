'use strict';

const crypto = require('crypto');

const COOKIE_NAME = 'boqa_billing_session';
const SESSION_TTL_MS = 30 * 60 * 1000;
const FAILURE_WINDOW_MS = 15 * 60 * 1000;
const BLOCK_MS = 30 * 60 * 1000;
const MAX_FAILURES = 5;
const MAX_PIN_LENGTH = 128;
const MAX_SESSIONS = 256;
const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function fixedDigest(value) {
  return crypto.createHash('sha256').update(String(value ?? ''), 'utf8').digest();
}

function safeEqual(left, right) {
  return crypto.timingSafeEqual(fixedDigest(left), fixedDigest(right));
}

function setHeader(res, name, value) {
  if (typeof res.set === 'function') res.set(name, value);
  else if (typeof res.setHeader === 'function') res.setHeader(name, value);
  return res;
}

function setPrivateHeaders(res) {
  setHeader(res, 'Cache-Control', 'no-store, max-age=0');
  setHeader(res, 'Pragma', 'no-cache');
  setHeader(res, 'Expires', '0');
  setHeader(res, 'X-Content-Type-Options', 'nosniff');
  setHeader(res, 'X-Robots-Tag', 'noindex, nofollow, noarchive');
  setHeader(res, 'X-Frame-Options', 'DENY');
  return res;
}

function parseCookies(header = '') {
  const values = Object.create(null);
  const duplicates = new Set();
  let malformed = false;

  for (const rawPart of String(header || '').split(';')) {
    const part = rawPart.trim();
    if (!part) continue;
    const at = part.indexOf('=');
    if (at <= 0) {
      malformed = true;
      continue;
    }
    const name = part.slice(0, at).trim();
    const encoded = part.slice(at + 1);
    let value;
    try {
      value = decodeURIComponent(encoded);
    } catch (_) {
      malformed = true;
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(values, name)) duplicates.add(name);
    else values[name] = value;
  }

  return { values, duplicates, malformed };
}

function createBillingAuth(options = {}) {
  const now = options.now || Date.now;
  const sessions = new Map();
  const attempts = new Map();
  const secure = options.secure !== undefined ? Boolean(options.secure) : true;
  const maxSessions = Math.max(1, Number(options.maxSessions || MAX_SESSIONS));

  function clientKey(req) {
    const raw = String(req.ip || req.socket?.remoteAddress || 'unknown');
    return crypto.createHash('sha256').update(raw).digest('hex');
  }

  function cleanup() {
    const current = now();
    for (const [id, session] of sessions) {
      if (session.expiresAt <= current) sessions.delete(id);
    }
    for (const [key, entry] of attempts) {
      if (entry.blockedUntil <= current && current - entry.windowStartedAt > FAILURE_WINDOW_MS) attempts.delete(key);
    }
  }

  function cookie(value, maxAgeSeconds) {
    const maxAge = Math.max(0, Math.floor(Number(maxAgeSeconds) || 0));
    const expires = maxAge === 0 ? '; Expires=Thu, 01 Jan 1970 00:00:00 GMT' : '';
    return `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}; Priority=High${secure ? '; Secure' : ''}${expires}`;
  }

  function extractSessionId(req) {
    const parsed = parseCookies(req.headers?.cookie || '');
    if (parsed.malformed || parsed.duplicates.has(COOKIE_NAME)) return null;
    const id = parsed.values[COOKIE_NAME];
    return typeof id === 'string' && SESSION_ID_PATTERN.test(id) ? id : null;
  }

  function getSession(req) {
    cleanup();
    const id = extractSessionId(req);
    if (!id) return null;
    const session = sessions.get(id);
    if (!session || session.expiresAt <= now()) {
      sessions.delete(id);
      return null;
    }
    return session;
  }

  function clearSessionCookie(res) {
    setHeader(res, 'Set-Cookie', cookie('', 0));
  }

  function requireSession(req, res, next) {
    setPrivateHeaders(res);
    const session = getSession(req);
    if (!session) {
      clearSessionCookie(res);
      return res.status(401).json({ error: 'unauthorized' });
    }
    req.billingSession = session;
    next();
  }

  function requestAllowed(req) {
    const site = String(req.headers?.['sec-fetch-site'] || '').toLowerCase();
    if (site === 'cross-site') return false;
    const contentType = String(req.headers?.['content-type'] || '').toLowerCase();
    return !contentType || contentType.startsWith('application/json');
  }

  function evictOldestSession() {
    if (sessions.size < maxSessions) return;
    let oldestId = null;
    let oldestCreatedAt = Infinity;
    for (const [id, session] of sessions) {
      if (session.createdAt < oldestCreatedAt) {
        oldestId = id;
        oldestCreatedAt = session.createdAt;
      }
    }
    if (oldestId) sessions.delete(oldestId);
  }

  function authenticate(req, res) {
    setPrivateHeaders(res);
    cleanup();

    if (!requestAllowed(req)) return res.status(403).json({ error: 'access_denied' });

    const key = clientKey(req);
    const current = now();
    const entry = attempts.get(key) || { failures: 0, windowStartedAt: current, blockedUntil: 0 };
    if (entry.blockedUntil > current) {
      setHeader(res, 'Retry-After', Math.max(1, Math.ceil((entry.blockedUntil - current) / 1000)));
      return res.status(429).json({ error: 'access_denied' });
    }
    if (current - entry.windowStartedAt > FAILURE_WINDOW_MS) {
      entry.failures = 0;
      entry.windowStartedAt = current;
    }

    const expected = process.env.BOQA_BILLING_PIN;
    const provided = req.body?.pin;
    const validInput = typeof provided === 'string' && provided.length > 0 && provided.length <= MAX_PIN_LENGTH;
    if (!expected || !validInput || !safeEqual(provided, expected)) {
      entry.failures += 1;
      if (entry.failures >= MAX_FAILURES) entry.blockedUntil = current + BLOCK_MS;
      attempts.set(key, entry);
      if (entry.blockedUntil > current) {
        setHeader(res, 'Retry-After', Math.ceil(BLOCK_MS / 1000));
        return res.status(429).json({ error: 'access_denied' });
      }
      return res.status(401).json({ error: 'access_denied' });
    }

    attempts.delete(key);
    const previousId = extractSessionId(req);
    if (previousId) sessions.delete(previousId);
    evictOldestSession();

    const id = crypto.randomBytes(32).toString('base64url');
    const session = {
      id,
      csrf: crypto.randomBytes(24).toString('base64url'),
      createdAt: current,
      expiresAt: current + SESSION_TTL_MS,
    };
    sessions.set(id, session);
    setHeader(res, 'Set-Cookie', cookie(id, SESSION_TTL_MS / 1000));
    return res.json({
      authenticated: true,
      csrf_token: session.csrf,
      expires_at: new Date(session.expiresAt).toISOString(),
      expires_in_seconds: SESSION_TTL_MS / 1000,
    });
  }

  function csrfHeader(req) {
    if (typeof req.get === 'function') return req.get('X-CSRF-Token');
    return req.headers?.['x-csrf-token'] || null;
  }

  function requireCsrf(req, res, next) {
    setPrivateHeaders(res);
    if (!safeEqual(csrfHeader(req), req.billingSession?.csrf)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  }

  function logout(req, res) {
    setPrivateHeaders(res);
    const session = getSession(req);
    if (session && !safeEqual(csrfHeader(req), session.csrf)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    if (session) sessions.delete(session.id);
    clearSessionCookie(res);
    setHeader(res, 'Clear-Site-Data', '"cache", "cookies", "storage"');
    return res.json({ authenticated: false });
  }

  return {
    authenticate,
    requireSession,
    requireCsrf,
    logout,
    getSession,
    cleanup,
    setPrivateHeaders,
    _sessions: sessions,
    _attempts: attempts,
  };
}

module.exports = {
  createBillingAuth,
  COOKIE_NAME,
  SESSION_TTL_MS,
  MAX_FAILURES,
  MAX_PIN_LENGTH,
  parseCookies,
  safeEqual,
  setPrivateHeaders,
};
