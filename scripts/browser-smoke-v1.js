'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const vm = require('vm');
const { spawn } = require('child_process');
const { chromium } = require('playwright');

const ROOT = path.join(__dirname, '..');
const OUTPUT = path.join(ROOT, 'output', 'browser-smoke');
const BACKEND_PORT = 7070;
const EDGE_PORT = 8787;
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;
const EDGE_URL = `http://localhost:${EDGE_PORT}`;
const HEAD_SHA = process.env.BOQA_HEAD_SHA || process.env.GITHUB_SHA || 'local';
const startedAt = new Date().toISOString();

fs.rmSync(OUTPUT, { recursive: true, force: true });
fs.mkdirSync(OUTPUT, { recursive: true });

function secret() {
  return crypto.randomBytes(32).toString('base64url');
}

function appendLog(file, chunk) {
  fs.appendFileSync(path.join(OUTPUT, file), String(chunk));
}

function loadWorker() {
  const source = fs.readFileSync(path.join(ROOT, 'worker.js'), 'utf8');
  const transformed = source.replace(/export\s+default\s+\{/, 'globalThis.__boqaWorker = {');
  if (transformed === source) throw new Error('WORKER_EXPORT_NOT_FOUND');
  const context = vm.createContext({
    console,
    crypto: crypto.webcrypto,
    TextEncoder,
    TextDecoder,
    URL,
    Request,
    Response,
    Headers,
    fetch,
    setTimeout,
    clearTimeout,
  });
  vm.runInContext(transformed, context, { filename: 'worker.js' });
  if (!context.__boqaWorker || typeof context.__boqaWorker.fetch !== 'function') {
    throw new Error('WORKER_HANDLER_UNAVAILABLE');
  }
  return context.__boqaWorker;
}

function assetResponse(request) {
  const pathname = new URL(request.url).pathname;
  const files = new Map([
    ['/', 'dashboard/index.html'],
    ['/index.html', 'dashboard/index.html'],
    ['/style.css', 'dashboard/style.css'],
    ['/dashboard-state.js', 'dashboard/dashboard-state.js'],
    ['/app.js', 'dashboard/app.js'],
    ['/cobros', 'dashboard/cobros.html'],
    ['/cobros.html', 'dashboard/cobros.html'],
    ['/cobros.js', 'dashboard/cobros.js'],
    ['/private.css', 'dashboard/private.css'],
  ]);
  const relative = files.get(pathname);
  if (!relative) return new Response('not found', { status: 404 });
  const extension = path.extname(relative);
  const contentType = extension === '.html' ? 'text/html; charset=utf-8'
    : extension === '.css' ? 'text/css; charset=utf-8'
      : extension === '.js' ? 'application/javascript; charset=utf-8'
        : 'application/octet-stream';
  return new Response(fs.readFileSync(path.join(ROOT, relative)), {
    status: 200,
    headers: { 'Content-Type': contentType },
  });
}

async function createEdgeServer(env) {
  const worker = loadWorker();
  const server = http.createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const headers = new Headers();
      for (let index = 0; index < req.rawHeaders.length; index += 2) {
        headers.append(req.rawHeaders[index], req.rawHeaders[index + 1]);
      }
      const init = { method: req.method, headers };
      if (!['GET', 'HEAD'].includes(req.method) && body.length) init.body = body;
      const request = new Request(`${EDGE_URL}${req.url}`, init);
      const response = await worker.fetch(request, env);
      res.statusCode = response.status;
      res.statusMessage = response.statusText;
      const setCookies = typeof response.headers.getSetCookie === 'function'
        ? response.headers.getSetCookie()
        : response.headers.get('set-cookie') ? [response.headers.get('set-cookie')] : [];
      for (const [name, value] of response.headers.entries()) {
        if (name.toLowerCase() !== 'set-cookie') res.setHeader(name, value);
      }
      if (setCookies.length) res.setHeader('Set-Cookie', setCookies);
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      appendLog('edge.log', `${error.stack || error}\n`);
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'edge_harness_error' }));
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(EDGE_PORT, '127.0.0.1', resolve);
  });
  return server;
}

async function waitForHealthy(url, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  let last = 'not_started';
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { cache: 'no-store' });
      const payload = await response.json();
      last = `${response.status}:${JSON.stringify(payload)}`;
      if (response.ok && payload.status === 'ok' && payload.hunter?.state === 'ACTIVE') return payload;
    } catch (error) {
      last = error.message;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`BACKEND_NOT_HEALTHY:${last}`);
}

function isExpectedAuthConsoleError(text) {
  return /^Failed to load resource: the server responded with a status of (401 \(Unauthorized\)|403 \(Forbidden\))$/.test(text);
}

function wireDiagnostics(page, result, options = {}) {
  page.on('pageerror', (error) => result.page_errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() !== 'error') return;
    const text = message.text();
    if (options.allowExpectedAuthErrors && isExpectedAuthConsoleError(text)) {
      result.expected_auth_console_errors.push(text);
      return;
    }
    result.console_errors.push(text);
  });
}

async function publicSmoke(browser, viewport, label) {
  const context = await browser.newContext({ viewport, reducedMotion: 'reduce' });
  const page = await context.newPage();
  const result = { label, viewport, page_errors: [], console_errors: [] };
  wireDiagnostics(page, result);
  const response = await page.goto(EDGE_URL, { waitUntil: 'networkidle' });
  assert(response && response.ok(), `${label}:PUBLIC_NAVIGATION_FAILED`);
  await page.waitForFunction(() => document.getElementById('overall-state')?.textContent === 'FRESH', null, { timeout: 20_000 });
  assert.equal(await page.locator('#hunter-state').textContent(), 'ACTIVE');
  assert.equal(await page.locator('#health-status').textContent(), 'ok');
  assert.equal(await page.locator('#hunter-source').textContent(), '/api/hunter/status');
  assert.equal(await page.locator('#health-source').textContent(), '/api/health');
  assert.equal(await page.locator('#overall-state').getAttribute('data-state'), 'FRESH');
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true, `${label}:HORIZONTAL_OVERFLOW`);
  assert.equal(await page.locator('main').count(), 1);
  assert.equal(await page.locator('header').count() > 0, true);
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement?.classList.contains('skip-link')), true, `${label}:SKIP_LINK_NOT_FOCUSABLE`);
  assert.equal(result.page_errors.length, 0, `${label}:PAGEERROR:${result.page_errors.join('|')}`);
  assert.equal(result.console_errors.length, 0, `${label}:CONSOLE:${result.console_errors.join('|')}`);
  await page.screenshot({ path: path.join(OUTPUT, `${label}.png`), fullPage: true });
  result.overall_state = 'FRESH';
  result.hunter_state = 'ACTIVE';
  result.health_status = 'ok';
  result.horizontal_overflow = false;
  await context.close();
  return result;
}

async function privateSmoke(browser, billingPin) {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  const result = { page_errors: [], console_errors: [], expected_auth_console_errors: [] };
  wireDiagnostics(page, result, { allowExpectedAuthErrors: true });
  const response = await page.goto(`${EDGE_URL}/cobros`, { waitUntil: 'networkidle' });
  assert(response && response.ok(), 'PRIVATE_NAVIGATION_FAILED');
  const headers = response.headers();
  assert.match(headers['cache-control'] || '', /no-store/);
  assert.match(headers['x-robots-tag'] || '', /noindex/);
  assert.match(headers['content-security-policy'] || '', /frame-ancestors 'none'/);
  assert.equal(headers['referrer-policy'], 'no-referrer');
  const anonymousText = await page.locator('body').innerText();
  assert(!/Centro de Cobros|Movimientos|saldo|monto|ingreso/i.test(anonymousText), 'PRIVATE_LABEL_LEAKED_BEFORE_AUTH');
  assert.equal(await page.locator('#private-root').isHidden(), true);
  const anonymousDataStatus = await page.evaluate(() => fetch('/api/private/billing/data', {
    credentials: 'same-origin',
    cache: 'no-store',
  }).then((response) => response.status));
  assert.equal(anonymousDataStatus, 401);
  await page.screenshot({ path: path.join(OUTPUT, 'private-anonymous-mobile.png'), fullPage: true });

  await page.fill('#pin', 'invalid');
  await page.click('#access-form button[type="submit"]');
  await page.waitForFunction(() => document.getElementById('auth-error')?.textContent.length > 0);
  assert.match(await page.locator('#auth-error').textContent(), /No fue posible autorizar/);

  await page.fill('#pin', billingPin);
  await page.click('#access-form button[type="submit"]');
  await page.waitForFunction(() => !document.getElementById('private-root')?.hidden, null, { timeout: 15_000 });
  assert.equal(await page.locator('#gate').isHidden(), true);
  assert.equal(await page.locator('#private-view h1').textContent(), 'Centro de Cobros');
  const sessionCookie = (await context.cookies()).find((cookie) => cookie.name === 'boqa_billing_session');
  assert(sessionCookie, 'SESSION_COOKIE_MISSING');
  assert.equal(sessionCookie.httpOnly, true);
  assert.equal(sessionCookie.secure, true);
  assert.equal(sessionCookie.sameSite, 'Strict');

  const csrfRejected = await page.evaluate(() => fetch('/api/private/billing/logout', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
  }).then((response) => response.status));
  assert.equal(csrfRejected, 403);
  const sessionStillValid = await page.evaluate(() => fetch('/api/private/billing/session', {
    credentials: 'same-origin',
    cache: 'no-store',
  }).then((response) => response.status));
  assert.equal(sessionStillValid, 200);

  await page.click('#logout');
  await page.waitForFunction(() => !document.getElementById('gate')?.hidden);
  assert.equal(await page.locator('#private-root').isHidden(), true);
  assert.equal((await context.cookies()).some((cookie) => cookie.name === 'boqa_billing_session'), false);

  await context.addCookies([{
    name: 'boqa_billing_session',
    value: 'A'.repeat(43),
    domain: 'localhost',
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'Strict',
  }]);
  const tamperedStatus = await page.evaluate(() => fetch('/api/private/billing/session', {
    credentials: 'same-origin',
    cache: 'no-store',
  }).then((response) => response.status));
  assert.equal(tamperedStatus, 401);
  assert.equal(result.page_errors.length, 0, `PRIVATE_PAGEERROR:${result.page_errors.join('|')}`);
  assert.equal(result.console_errors.length, 0, `PRIVATE_CRITICAL_CONSOLE:${result.console_errors.join('|')}`);
  assert(result.expected_auth_console_errors.length >= 4, 'EXPECTED_AUTH_CONSOLE_EVENTS_MISSING');
  result.anonymous_data_status = anonymousDataStatus;
  result.authenticated = true;
  result.cookie = { http_only: true, secure: true, same_site: 'Strict' };
  result.csrf_rejected = true;
  result.logout_cleared = true;
  result.tampered_cookie_rejected = true;
  await context.close();
  return result;
}

async function main() {
  const apiKey = secret();
  const hmacSecret = secret();
  const billingPin = secret();
  const serverLog = fs.createWriteStream(path.join(OUTPUT, 'server.log'), { flags: 'wx' });
  const backend = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      CI: 'true',
      HEADLESS: 'true',
      BOQA_PORT: String(BACKEND_PORT),
      BOQA_API_KEY: apiKey,
      BOQA_HMAC_SECRET: hmacSecret,
      BOQA_BILLING_PIN: billingPin,
      BOQA_HMAC_LOG_FAILURES: 'false',
      BOQA_RELEASE_SHA: HEAD_SHA,
      BOQA_AUTO_ANALYZE: 'false',
      BOQA_HUNTER_INTERVAL_MS: '600000',
      BOQA_HUNTER_HEARTBEAT_MS: '1000',
      BOQA_HUNTER_HEARTBEAT_FRESHNESS_MS: '10000',
      BOQA_HUNTER_CYCLE_FRESHNESS_MS: '600000',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  backend.stdout.pipe(serverLog);
  backend.stderr.pipe(serverLog);

  let edge;
  let browser;
  const evidence = {
    schema_version: 1,
    head_sha: HEAD_SHA,
    started_at: startedAt,
    production_accessed: false,
    deploy_performed: false,
    secrets_written: false,
  };
  try {
    const health = await waitForHealthy(`${BACKEND_URL}/api/health`);
    evidence.backend = {
      status: health.status,
      hunter_state: health.hunter.state,
      release_sha: health.release_sha,
    };
    edge = await createEdgeServer({
      BOQA_BACKEND_URL: BACKEND_URL,
      BOQA_API_KEY: apiKey,
      BOQA_HMAC_SECRET: hmacSecret,
      ASSETS: { fetch: assetResponse },
    });
    browser = await chromium.launch({ headless: true });
    evidence.public = [];
    evidence.public.push(await publicSmoke(browser, { width: 1440, height: 900 }, 'desktop-1440'));
    evidence.public.push(await publicSmoke(browser, { width: 390, height: 844 }, 'mobile-390'));
    evidence.public.push(await publicSmoke(browser, { width: 360, height: 800 }, 'mobile-360'));
    evidence.private = await privateSmoke(browser, billingPin);
    evidence.page_errors = evidence.public.reduce((sum, item) => sum + item.page_errors.length, 0) + evidence.private.page_errors.length;
    evidence.console_errors = evidence.public.reduce((sum, item) => sum + item.console_errors.length, 0) + evidence.private.console_errors.length;
    evidence.expected_auth_console_errors = evidence.private.expected_auth_console_errors.length;
    evidence.status = 'PASS';
  } catch (error) {
    evidence.status = 'FAIL';
    evidence.error = error.message;
    throw error;
  } finally {
    evidence.completed_at = new Date().toISOString();
    fs.writeFileSync(path.join(OUTPUT, 'browser-smoke-evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`, { flag: 'wx' });
    if (browser) await browser.close().catch(() => {});
    if (edge) await new Promise((resolve) => edge.close(resolve));
    let backendExited = backend.exitCode !== null;
    if (!backendExited) {
      backend.kill('SIGTERM');
      backendExited = await Promise.race([
        new Promise((resolve) => backend.once('exit', () => resolve(true))),
        new Promise((resolve) => setTimeout(() => resolve(false), 5_000)),
      ]);
    }
    if (!backendExited) backend.kill('SIGKILL');
    serverLog.end();
  }
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
