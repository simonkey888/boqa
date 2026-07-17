'use strict';

const crypto = require('crypto');

const COOKIE_NAME = 'boqa_billing_session';
const SESSION_TTL_MS = 30 * 60 * 1000;
const FAILURE_WINDOW_MS = 15 * 60 * 1000;
const BLOCK_MS = 30 * 60 * 1000;
const MAX_FAILURES = 5;

function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map(v => v.trim()).filter(Boolean).map(v => {
    const at = v.indexOf('=');
    return at < 0 ? [v, ''] : [v.slice(0, at), decodeURIComponent(v.slice(at + 1))];
  }));
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function createBillingAuth(options = {}) {
  const now = options.now || Date.now;
  const sessions = new Map();
  const attempts = new Map();
  const secure = options.secure !== undefined ? options.secure : process.env.NODE_ENV === 'production';

  function clientKey(req) {
    return String(req.ip || req.socket?.remoteAddress || 'unknown');
  }

  function cleanup() {
    const current = now();
    for (const [id, session] of sessions) if (session.expiresAt <= current) sessions.delete(id);
    for (const [key, entry] of attempts) {
      if (entry.blockedUntil <= current && current - entry.windowStartedAt > FAILURE_WINDOW_MS) attempts.delete(key);
    }
  }

  function cookie(value, maxAgeSeconds) {
    return `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSeconds}${secure ? '; Secure' : ''}`;
  }

  function getSession(req) {
    cleanup();
    const id = parseCookies(req.headers.cookie)[COOKIE_NAME];
    const session = id && sessions.get(id);
    if (!session || session.expiresAt <= now()) return null;
    return session;
  }

  function requireSession(req, res, next) {
    res.set('Cache-Control', 'no-store');
    const session = getSession(req);
    if (!session) return res.status(401).json({ error: 'unauthorized' });
    req.billingSession = session;
    next();
  }

  function authenticate(req, res) {
    res.set('Cache-Control', 'no-store');
    cleanup();
    const key = clientKey(req);
    const current = now();
    const entry = attempts.get(key) || { failures: 0, windowStartedAt: current, blockedUntil: 0 };
    if (entry.blockedUntil > current) return res.status(429).json({ error: 'access_denied' });
    if (current - entry.windowStartedAt > FAILURE_WINDOW_MS) {
      entry.failures = 0;
      entry.windowStartedAt = current;
    }

    const expected = process.env.BOQA_BILLING_PIN;
    if (!expected || !safeEqual(req.body?.pin, expected)) {
      entry.failures += 1;
      if (entry.failures >= MAX_FAILURES) entry.blockedUntil = current + BLOCK_MS;
      attempts.set(key, entry);
      return res.status(entry.blockedUntil > current ? 429 : 401).json({ error: 'access_denied' });
    }

    attempts.delete(key);
    const id = crypto.randomBytes(32).toString('base64url');
    const session = { id, csrf: crypto.randomBytes(24).toString('base64url'), expiresAt: current + SESSION_TTL_MS };
    sessions.set(id, session);
    res.set('Set-Cookie', cookie(id, SESSION_TTL_MS / 1000));
    return res.json({ authenticated: true, csrf_token: session.csrf, expires_in_seconds: SESSION_TTL_MS / 1000 });
  }

  function requireCsrf(req, res, next) {
    if (!safeEqual(req.get('X-CSRF-Token'), req.billingSession?.csrf)) return res.status(403).json({ error: 'forbidden' });
    next();
  }

  function logout(req, res) {
    res.set('Cache-Control', 'no-store');
    const id = parseCookies(req.headers.cookie)[COOKIE_NAME];
    if (id) sessions.delete(id);
    res.set('Set-Cookie', cookie('', 0));
    return res.json({ authenticated: false });
  }

  return { authenticate, requireSession, requireCsrf, logout, getSession, cleanup, _sessions: sessions, _attempts: attempts };
}

module.exports = { createBillingAuth, COOKIE_NAME, SESSION_TTL_MS, MAX_FAILURES };
