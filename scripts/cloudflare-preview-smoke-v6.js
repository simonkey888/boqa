'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const ROOT = path.join(__dirname, '..');
const OUTPUT = path.join(ROOT, 'output', 'cloudflare-preview-v6', 'browser');
const PREVIEW_URL = String(process.env.BOQA_PREVIEW_URL || '').replace(/\/$/, '');
const HEAD_SHA = process.env.BOQA_HEAD_SHA || process.env.GITHUB_SHA || 'unknown';

if (!/^https:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)+\.workers\.dev$/i.test(PREVIEW_URL)) {
  throw new Error('INVALID_OR_MISSING_PREVIEW_URL');
}

fs.mkdirSync(OUTPUT, { recursive: true });

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseObject(body) {
  try {
    const value = JSON.parse(body);
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
  } catch (_) {
    return null;
  }
}

async function request(pathname) {
  const response = await fetch(`${PREVIEW_URL}${pathname}`, {
    cache: 'no-store',
    redirect: 'manual',
    headers: { Accept: 'application/json', 'Cache-Control': 'no-cache' },
  });
  const body = await response.text();
  return { response, body, json: parseObject(body) };
}

async function waitForPreview(evidence, timeoutMs = 180_000) {
  const deadline = Date.now() + timeoutMs;
  let attempt = 0;
  let last = null;
  while (Date.now() < deadline) {
    attempt += 1;
    try {
      const result = await request('/health');
      last = { status: result.response.status, error: null };
      if (result.response.status === 200 && result.json?.status === 'ok' && result.json?.worker === 'boqa') {
        evidence.preview_readiness = { ready: true, attempt_count: attempt, last_status: 200 };
        return;
      }
    } catch (error) {
      last = { status: null, error: error.cause?.code || error.code || error.message || 'fetch_failed' };
    }
    await sleep(3_000);
  }
  evidence.preview_readiness = {
    ready: false,
    attempt_count: attempt,
    last_status: last?.status ?? null,
    last_error: last?.error ?? null,
  };
  throw new Error(`PREVIEW_NOT_READY:${JSON.stringify(evidence.preview_readiness)}`);
}

async function verifyConcealment(evidence) {
  const paths = [
    '/cobros', '/COBROS', '/%2563obros', '/cobros.html', '/cobros.js', '/private.css',
    '/api/private/billing', '/api/private/billing/data', '/api/%255cprivate%255cbilling%255cdata',
    '/api/runtime/metrics', '/api/defensive/status', '/api/bugs', '/api/findings', '/api/metrics',
  ];
  evidence.concealed_paths = [];
  for (const pathname of paths) {
    const { response, body } = await request(pathname);
    assert.equal(response.status, 404, `${pathname}:NOT_CONCEALED`);
    assert.match(response.headers.get('cache-control') || '', /no-store/, `${pathname}:CACHE_POLICY`);
    assert.equal(response.headers.get('location'), null, `${pathname}:REDIRECT_LEAK`);
    assert(!/centro de cobros|movimientos|saldo|monto|ingreso|billing|payment|pago|finanz|finding|metric|defensive/i.test(body), `${pathname}:PURPOSE_LEAK`);
    evidence.concealed_paths.push({ pathname, status: 404, generic_body: true });
  }
}

async function classifyBackend(evidence) {
  const edge = await request('/health');
  assert.equal(edge.response.status, 200);
  assert.equal(edge.json?.status, 'ok');
  assert.equal(edge.json?.worker, 'boqa');
  assert.equal(edge.json?.backend_configured, true);
  evidence.worker_health = {
    status: edge.json.status,
    mode: edge.json.mode,
    backend_configured: edge.json.backend_configured,
  };

  const health = await request('/api/health');
  assert.equal(health.response.status, 200, `/api/health:${health.response.status}`);
  assert.equal(health.json?.status, 'ok');
  evidence.backend_health = {
    status: health.json.status,
    version: health.json.version || null,
    release_sha: health.json.release_sha || null,
  };

  const hunter = await request('/api/hunter/status');
  if (hunter.response.status === 200) {
    assert(hunter.json, 'HUNTER_JSON_REQUIRED');
    assert(['STOPPED', 'STARTING', 'ACTIVE', 'DEGRADED', 'BLOCKED', 'ERROR'].includes(hunter.json.state), 'HUNTER_STATE_INVALID');
    assert(Number.isFinite(Date.parse(hunter.json.timestamp)), 'HUNTER_TIMESTAMP_INVALID');
    evidence.classification = 'PROMOTION_READY';
    evidence.promotion_ready = true;
    evidence.hunter = {
      status: 200,
      state: hunter.json.state,
      timestamp_present: true,
    };
    return;
  }

  if (hunter.response.status === 404) {
    evidence.classification = 'BLOCKED_BACKEND_CONTRACT';
    evidence.promotion_ready = false;
    evidence.blocker = 'BACKEND_HUNTER_CONTRACT_MISSING';
    evidence.hunter = {
      status: 404,
      content_type: (hunter.response.headers.get('content-type') || '').split(';')[0] || null,
      body_recorded: false,
    };
    return;
  }

  throw new Error(`UNEXPECTED_HUNTER_STATUS:${hunter.response.status}`);
}

function wireDiagnostics(page, result, blockedMode) {
  page.on('pageerror', (error) => result.page_errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() !== 'error') return;
    const value = message.text();
    if (blockedMode && /Failed to load resource/.test(value) && /404/.test(value)) {
      result.expected_console_errors.push(value);
      return;
    }
    result.console_errors.push(value);
  });
  page.on('requestfailed', (request) => {
    result.failed_requests.push({ path: new URL(request.url()).pathname, error: request.failure()?.errorText || 'unknown' });
  });
}

async function smokeViewport(browser, viewport, label, classification) {
  const blockedMode = classification === 'BLOCKED_BACKEND_CONTRACT';
  const context = await browser.newContext({ viewport, reducedMotion: 'reduce' });
  const page = await context.newPage();
  const result = {
    label,
    viewport,
    page_errors: [],
    console_errors: [],
    expected_console_errors: [],
    failed_requests: [],
  };
  wireDiagnostics(page, result, blockedMode);

  const response = await page.goto(PREVIEW_URL, { waitUntil: 'networkidle', timeout: 60_000 });
  assert(response && response.ok(), `${label}:NAVIGATION_FAILED`);

  if (blockedMode) {
    await page.waitForFunction(() => document.getElementById('overall-state')?.textContent === 'DEGRADED', null, { timeout: 30_000 });
    assert.equal(await page.locator('#overall-reason').textContent(), 'Una fuente requerida no está disponible');
    assert.equal(await page.locator('#hunter-view-state').textContent(), 'UNAVAILABLE');
    assert.equal(await page.locator('#hunter-reason').textContent(), 'Respuesta HTTP 404');
    assert.equal(await page.locator('#health-view-state').textContent(), 'FRESH');
    assert.equal(await page.locator('#health-status').textContent(), 'ok');
  } else {
    await page.waitForFunction(() => document.getElementById('overall-state')?.textContent === 'FRESH', null, { timeout: 30_000 });
    assert.equal(await page.locator('#overall-reason').textContent(), 'Todas las fuentes están actualizadas');
    assert.equal(await page.locator('#hunter-view-state').textContent(), 'FRESH');
    assert.equal(await page.locator('#health-view-state').textContent(), 'FRESH');
    assert.equal(await page.locator('#hunter-state').textContent(), 'ACTIVE');
    assert.equal(await page.locator('#health-status').textContent(), 'ok');
  }

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  assert.equal(overflow, false, `${label}:HORIZONTAL_OVERFLOW`);

  if (viewport.width <= 520) {
    const sourceBoxes = await page.locator('.source-card').evaluateAll((nodes) => nodes.map((node) => node.getBoundingClientRect()));
    const secondaryBoxes = await page.locator('.unavailable-panel').evaluateAll((nodes) => nodes.map((node) => node.getBoundingClientRect()));
    assert.equal(sourceBoxes.length, 2);
    assert.equal(secondaryBoxes.length, 2);
    assert(Math.abs(sourceBoxes[0].top - sourceBoxes[1].top) < 2, `${label}:SOURCE_CARDS_NOT_COMPACT`);
    assert(Math.abs(secondaryBoxes[0].top - secondaryBoxes[1].top) < 2, `${label}:SECONDARY_PANELS_NOT_COMPACT`);
  }

  await page.waitForTimeout(200);
  assert.equal(result.page_errors.length, 0, `${label}:PAGE_ERRORS:${result.page_errors.join('|')}`);
  assert.equal(result.console_errors.length, 0, `${label}:CONSOLE_ERRORS:${result.console_errors.join('|')}`);
  assert.equal(result.failed_requests.length, 0, `${label}:FAILED_REQUESTS:${JSON.stringify(result.failed_requests)}`);
  if (blockedMode) assert(result.expected_console_errors.length >= 1, `${label}:EXPECTED_404_CONSOLE_MISSING`);

  await page.screenshot({ path: path.join(OUTPUT, `${label}.png`), fullPage: true });
  result.overall_state = blockedMode ? 'DEGRADED' : 'FRESH';
  result.horizontal_overflow = false;
  await context.close();
  return result;
}

async function main() {
  const evidence = {
    schema_version: 1,
    head_sha: HEAD_SHA,
    preview_url: PREVIEW_URL,
    production_accessed: false,
    production_changed: false,
    deploy_performed: false,
    rollback_executed: false,
    started_at: new Date().toISOString(),
  };

  let browser;
  try {
    await waitForPreview(evidence);
    await classifyBackend(evidence);
    await verifyConcealment(evidence);
    browser = await chromium.launch({ headless: true });
    evidence.viewports = [];
    evidence.viewports.push(await smokeViewport(browser, { width: 1440, height: 900 }, 'desktop-1440', evidence.classification));
    evidence.viewports.push(await smokeViewport(browser, { width: 390, height: 844 }, 'mobile-390', evidence.classification));
    evidence.viewports.push(await smokeViewport(browser, { width: 360, height: 800 }, 'mobile-360', evidence.classification));
    evidence.gate_status = 'PASS';
  } catch (error) {
    evidence.gate_status = 'FAIL';
    evidence.error = error.message || String(error);
    throw error;
  } finally {
    if (browser) await browser.close().catch(() => {});
    evidence.completed_at = new Date().toISOString();
    fs.writeFileSync(path.join(OUTPUT, 'preview-smoke-evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`);
  }
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
