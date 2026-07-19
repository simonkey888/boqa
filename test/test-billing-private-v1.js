'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {
  createBillingAuth,
  COOKIE_NAME,
  SESSION_TTL_MS,
  MAX_FAILURES,
} = require('../lib/billing-auth');
const { requireStrongProxyAuth } = require('../lib/middleware');

function response() {
  return {
    statusCode: 200,
    headers: {},
    body: null,
    set(name, value) { this.headers[name] = value; return this; },
    setHeader(name, value) { this.headers[name] = value; return this; },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; },
  };
}

function request(overrides = {}) {
  return {
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
    method: 'POST',
    originalUrl: '/api/private/billing/auth',
    url: '/api/private/billing/auth',
    headers: { 'content-type': 'application/json', cookie: '' },
    body: {},
    get(name) { return this.headers[String(name).toLowerCase()] || null; },
    ...overrides,
  };
}

function sign(secret, method, url, ts, body) {
  return crypto.createHmac('sha256', secret).update(method + url + String(ts) + body, 'utf8').digest('hex');
}

async function run() {
  const previous = {
    pin: process.env.BOQA_BILLING_PIN,
    key: process.env.BOQA_API_KEY,
    hmac: process.env.BOQA_HMAC_SECRET,
    skew: process.env.BOQA_HMAC_SKEW_SECONDS,
    hmacLogs: process.env.BOQA_HMAC_LOG_FAILURES,
  };

  let nowMs = Date.parse('2026-07-17T19:00:00.000Z');
  const testPin = crypto.randomBytes(18).toString('base64url');
  process.env.BOQA_BILLING_PIN = testPin;
  process.env.BOQA_HMAC_LOG_FAILURES = 'false';

  const blockedAuth = createBillingAuth({ now: () => nowMs, secure: true });
  const wrongReq = request({ body: { pin: 'wrong' } });
  for (let i = 0; i < MAX_FAILURES; i += 1) {
    const res = response();
    blockedAuth.authenticate(wrongReq, res);
    assert.ok([401, 429].includes(res.statusCode));
    assert.equal(res.headers['Cache-Control'], 'no-store, max-age=0');
  }
  const blocked = response();
  blockedAuth.authenticate(request({ body: { pin: testPin } }), blocked);
  assert.equal(blocked.statusCode, 429);
  assert.ok(Number(blocked.headers['Retry-After']) > 0);

  const crossSiteAuth = createBillingAuth({ now: () => nowMs, secure: true });
  const crossSite = response();
  crossSiteAuth.authenticate(request({
    headers: { 'content-type': 'application/json', 'sec-fetch-site': 'cross-site', cookie: '' },
    body: { pin: testPin },
  }), crossSite);
  assert.equal(crossSite.statusCode, 403);

  const auth = createBillingAuth({ now: () => nowMs, secure: true, maxSessions: 2 });
  const login = response();
  auth.authenticate(request({ body: { pin: testPin } }), login);
  assert.equal(login.statusCode, 200);
  assert.equal(login.body.authenticated, true);
  assert.match(login.headers['Set-Cookie'], new RegExp(`^${COOKIE_NAME}=`));
  assert.match(login.headers['Set-Cookie'], /HttpOnly/);
  assert.match(login.headers['Set-Cookie'], /SameSite=Strict/);
  assert.match(login.headers['Set-Cookie'], /Secure/);
  assert.match(login.headers['Set-Cookie'], /Priority=High/);
  assert.doesNotMatch(login.headers['Set-Cookie'], new RegExp(testPin));
  assert.doesNotMatch(JSON.stringify(login.body), new RegExp(testPin));

  const cookie = login.headers['Set-Cookie'].split(';')[0];
  const sessionReq = request({ method: 'GET', originalUrl: '/api/private/billing/session', headers: { cookie } });
  const session = auth.getSession(sessionReq);
  assert.ok(session);
  const fixedExpiry = session.expiresAt;
  nowMs += 10 * 60 * 1000;
  assert.equal(auth.getSession(sessionReq).expiresAt, fixedExpiry, 'session reads must not renew expiry');

  let passed = false;
  const sessionRes = response();
  auth.requireSession(sessionReq, sessionRes, () => { passed = true; });
  assert.equal(passed, true);
  assert.equal(sessionRes.headers['Cache-Control'], 'no-store, max-age=0');

  passed = false;
  const duplicateRes = response();
  auth.requireSession(request({ method: 'GET', headers: { cookie: `${cookie}; ${cookie}` } }), duplicateRes, () => { passed = true; });
  assert.equal(passed, false);
  assert.equal(duplicateRes.statusCode, 401);

  passed = false;
  const malformedRes = response();
  assert.doesNotThrow(() => auth.requireSession(request({ method: 'GET', headers: { cookie: `${COOKIE_NAME}=%E0%A4%A` } }), malformedRes, () => { passed = true; }));
  assert.equal(passed, false);
  assert.equal(malformedRes.statusCode, 401);

  const badLogout = response();
  auth.logout(request({
    originalUrl: '/api/private/billing/logout',
    headers: { cookie, 'x-csrf-token': 'wrong' },
  }), badLogout);
  assert.equal(badLogout.statusCode, 403);
  assert.ok(auth.getSession(sessionReq), 'invalid CSRF must not revoke session');

  const goodLogout = response();
  auth.logout(request({
    originalUrl: '/api/private/billing/logout',
    headers: { cookie, 'x-csrf-token': login.body.csrf_token },
  }), goodLogout);
  assert.equal(goodLogout.statusCode, 200);
  assert.match(goodLogout.headers['Set-Cookie'], /Max-Age=0/);
  assert.match(goodLogout.headers['Clear-Site-Data'], /cookies/);
  assert.equal(auth.getSession(sessionReq), null);

  const expiringAuth = createBillingAuth({ now: () => nowMs, secure: true });
  const expiringLogin = response();
  expiringAuth.authenticate(request({ body: { pin: testPin } }), expiringLogin);
  const expiringCookie = expiringLogin.headers['Set-Cookie'].split(';')[0];
  nowMs += SESSION_TTL_MS + 1;
  passed = false;
  const expiredRes = response();
  expiringAuth.requireSession(request({ method: 'GET', headers: { cookie: expiringCookie } }), expiredRes, () => { passed = true; });
  assert.equal(passed, false);
  assert.equal(expiredRes.statusCode, 401);
  assert.match(expiredRes.headers['Set-Cookie'], /Max-Age=0/);

  const recovery = response();
  expiringAuth.authenticate(request({ body: { pin: testPin } }), recovery);
  assert.equal(recovery.statusCode, 200, 'authentication must recover after expiry');

  const tooLong = response();
  expiringAuth.authenticate(request({ body: { pin: 'x'.repeat(129) } }), tooLong);
  assert.equal(tooLong.statusCode, 401);

  delete process.env.BOQA_API_KEY;
  delete process.env.BOQA_HMAC_SECRET;
  const unavailable = response();
  requireStrongProxyAuth(request(), unavailable, () => { throw new Error('unexpected next'); });
  assert.equal(unavailable.statusCode, 503);
  assert.equal(unavailable.body.error, 'private_proxy_auth_unavailable');

  process.env.BOQA_API_KEY = 'proxy-key';
  process.env.BOQA_HMAC_SECRET = 'proxy-hmac-secret';
  process.env.BOQA_HMAC_SKEW_SECONDS = '300';
  const ts = Math.floor(Date.now() / 1000);
  const body = JSON.stringify({ pin: 'opaque' });
  const url = '/api/private/billing/auth';
  const signature = sign(process.env.BOQA_HMAC_SECRET, 'POST', url, ts, body);

  const missingHeaderKey = response();
  requireStrongProxyAuth(request({
    _rawBody: body,
    headers: { 'x-boqa-sig': signature, 'x-boqa-ts': String(ts) },
    query: { api_key: 'proxy-key' },
  }), missingHeaderKey, () => { throw new Error('query key must not pass'); });
  assert.equal(missingHeaderKey.statusCode, 401);

  let strongPassed = false;
  const strongRes = response();
  requireStrongProxyAuth(request({
    _rawBody: body,
    headers: {
      'x-api-key': 'proxy-key',
      'x-boqa-sig': signature,
      'x-boqa-ts': String(ts),
      'content-type': 'application/json',
    },
  }), strongRes, () => { strongPassed = true; });
  assert.equal(strongPassed, true);

  const staleTs = ts - 1000;
  const staleRes = response();
  requireStrongProxyAuth(request({
    _rawBody: body,
    headers: {
      'x-api-key': 'proxy-key',
      'x-boqa-sig': sign(process.env.BOQA_HMAC_SECRET, 'POST', url, staleTs, body),
      'x-boqa-ts': String(staleTs),
    },
  }), staleRes, () => { throw new Error('stale signature must not pass'); });
  assert.equal(staleRes.statusCode, 401);

  const root = path.join(__dirname, '..');
  const html = fs.readFileSync(path.join(root, 'dashboard', 'cobros.html'), 'utf8');
  const js = fs.readFileSync(path.join(root, 'dashboard', 'cobros.js'), 'utf8');
  const server = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
  const billingSource = fs.readFileSync(path.join(root, 'lib', 'billing-auth.js'), 'utf8');
  const worker = fs.readFileSync(path.join(root, 'worker.js'), 'utf8');
  const publicBundle = `${html}\n${js}`;
  assert.doesNotMatch(publicBundle, /Centro de Cobros|Movimientos|movements|summary|portfolio|bount|finanz|pago|ingreso/i);
  assert.doesNotMatch(publicBundle, /BOQA_BILLING_PIN/);
  assert.doesNotMatch(publicBundle, /localStorage|sessionStorage|innerHTML/);
  assert.match(js, /textContent/);
  assert.match(js, /replaceChildren/);
  assert.match(js, /credentials:\s*'same-origin'/);
  assert.match(js, /cache:\s*'no-store'/);
  assert.match(server, /app\.use\('\/api\/private\/billing', requireStrongProxyAuth, rateLimiter\)/);
  assert.match(server, /Content-Security-Policy/);
  assert.match(server, /\['\/cobros', '\/cobros\.html'\]/);
  assert.match(server, /Permissions-Policy/);
  assert.match(server, /setPrivateHeaders\(res\)/);
  assert.match(billingSource, /X-Robots-Tag/);
  assert.match(billingSource, /no-store, max-age=0/);
  assert.match(billingSource, /Clear-Site-Data/);
  assert.match(server, /app\.post\('\/api\/private\/billing\/logout', billingAuth\.logout\)/);
  assert.match(worker, /function isPrivateSurface\(pathname\)/);
  assert.match(worker, /normalized\.endsWith\('\/cobros\.html'\)/);
  assert.match(worker, /if \(isPrivateSurface\(url\.pathname\)\)/);
  assert.match(worker, /Content-Security-Policy/);
  assert.match(worker, /X-Robots-Tag/);

  if (previous.pin === undefined) delete process.env.BOQA_BILLING_PIN; else process.env.BOQA_BILLING_PIN = previous.pin;
  if (previous.key === undefined) delete process.env.BOQA_API_KEY; else process.env.BOQA_API_KEY = previous.key;
  if (previous.hmac === undefined) delete process.env.BOQA_HMAC_SECRET; else process.env.BOQA_HMAC_SECRET = previous.hmac;
  if (previous.skew === undefined) delete process.env.BOQA_HMAC_SKEW_SECONDS; else process.env.BOQA_HMAC_SKEW_SECONDS = previous.skew;
  if (previous.hmacLogs === undefined) delete process.env.BOQA_HMAC_LOG_FAILURES; else process.env.BOQA_HMAC_LOG_FAILURES = previous.hmacLogs;

  console.log('billing/private hardening: PASS');
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
