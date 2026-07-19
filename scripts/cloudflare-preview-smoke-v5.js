'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const ROOT = path.join(__dirname, '..');
const OUTPUT = path.join(ROOT, 'output', 'cloudflare-preview-v5', 'browser');
const PREVIEW_URL = String(process.env.BOQA_PREVIEW_URL || '').replace(/\/$/, '');
const HEAD_SHA = process.env.BOQA_HEAD_SHA || process.env.GITHUB_SHA || 'unknown';

if (!/^https:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)+\.workers\.dev$/i.test(PREVIEW_URL)) {
  throw new Error('INVALID_OR_MISSING_PREVIEW_URL');
}

fs.mkdirSync(OUTPUT, { recursive: true });

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForPreview(evidence, timeoutMs = 180_000) {
  const deadline = Date.now() + timeoutMs;
  const attempts = [];
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${PREVIEW_URL}/health`, {
        cache: 'no-store',
        redirect: 'manual',
        headers: { 'Cache-Control': 'no-cache' },
      });
      const body = await response.text();
      let json = null;
      try { json = JSON.parse(body); } catch (_) {}
      attempts.push({ status: response.status, error: null });
      if (response.status === 200 && json?.status === 'ok' && json?.worker === 'boqa') {
        evidence.preview_readiness = { ready: true, attempt_count: attempts.length, last_status: response.status };
        return;
      }
    } catch (error) {
      attempts.push({ status: null, error: error.cause?.code || error.code || error.message || 'fetch_failed' });
    }
    await sleep(3_000);
  }
  const last = attempts.at(-1) || { status: null, error: 'no_attempt' };
  evidence.preview_readiness = { ready: false, attempt_count: attempts.length, last_status: last.status, last_error: last.error };
  throw new Error(`PREVIEW_NOT_READY:${JSON.stringify(evidence.preview_readiness)}`);
}

async function fetchJson(pathname, expectedStatus = 200) {
  const response = await fetch(`${PREVIEW_URL}${pathname}`, {
    cache: 'no-store',
    redirect: 'manual',
    headers: { 'Cache-Control': 'no-cache' },
  });
  const body = await response.text();
  assert.equal(response.status, expectedStatus, `${pathname}:STATUS_${response.status}:${body.slice(0, 200)}`);
  return { response, body, json: JSON.parse(body) };
}

async function verifyEdgeContracts(evidence) {
  const workerHealth = await fetchJson('/health');
  assert.equal(workerHealth.json.status, 'ok');
  assert.equal(workerHealth.json.worker, 'boqa');
  assert.equal(workerHealth.json.backend_configured, true);
  evidence.worker_health = {
    status: workerHealth.json.status,
    worker: workerHealth.json.worker,
    mode: workerHealth.json.mode,
    backend_configured: workerHealth.json.backend_configured,
  };

  const backendHealth = await fetchJson('/api/health');
  assert.equal(backendHealth.json.status, 'ok');
  evidence.backend_health = {
    status: backendHealth.json.status,
    release_sha: backendHealth.json.release_sha || null,
    version: backendHealth.json.version || null,
    hunter_state: backendHealth.json.hunter?.state || null,
  };

  const hunter = await fetchJson('/api/hunter/status');
  assert.equal(typeof hunter.json, 'object');
  evidence.hunter = {
    state: hunter.json.state || null,
    heartbeat_at: hunter.json.heartbeat_at || null,
    source_timestamp: hunter.json.source_timestamp || hunter.json.timestamp || null,
  };

  const concealedPaths = [
    '/cobros',
    '/COBROS',
    '/%2563obros',
    '/cobros.html',
    '/cobros.js',
    '/private.css',
    '/api/private/billing',
    '/api/private/billing/data',
    '/api/%255cprivate%255cbilling%255cdata',
    '/api/runtime/metrics',
    '/api/defensive/status',
    '/api/bugs',
    '/api/findings',
    '/api/metrics',
  ];

  evidence.concealed_paths = [];
  for (const pathname of concealedPaths) {
    const response = await fetch(`${PREVIEW_URL}${pathname}`, { cache: 'no-store', redirect: 'manual' });
    const body = await response.text();
    assert.equal(response.status, 404, `${pathname}:NOT_CONCEALED`);
    assert.match(response.headers.get('cache-control') || '', /no-store/);
    assert.equal(response.headers.get('location'), null);
    assert(!/centro de cobros|movimientos|saldo|monto|ingreso|billing|payment|pago|finanz|finding|metric|defensive/i.test(body), `${pathname}:PURPOSE_LEAK`);
    evidence.concealed_paths.push({ pathname, status: 404, generic_body: true });
  }
}

function wireDiagnostics(page, result) {
  page.on('pageerror', (error) => result.page_errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') result.console_errors.push(message.text());
  });
  page.on('requestfailed', (request) => {
    result.failed_requests.push({ url: request.url(), error: request.failure()?.errorText || 'unknown' });
  });
}

async function smokeViewport(browser, viewport, label) {
  const context = await browser.newContext({ viewport, reducedMotion: 'reduce' });
  const page = await context.newPage();
  const result = { label, viewport, page_errors: [], console_errors: [], failed_requests: [] };
  wireDiagnostics(page, result);

  const response = await page.goto(PREVIEW_URL, { waitUntil: 'networkidle', timeout: 60_000 });
  assert(response && response.ok(), `${label}:NAVIGATION_FAILED`);
  await page.waitForFunction(() => document.getElementById('overall-state')?.textContent === 'FRESH', null, { timeout: 30_000 });

  assert.equal(await page.locator('#overall-reason').textContent(), 'Todas las fuentes están actualizadas');
  assert.equal(await page.locator('#hunter-reason').textContent(), 'Contrato válido y actualizado');
  assert.equal(await page.locator('#health-reason').textContent(), 'Contrato válido y actualizado');
  assert.equal(await page.locator('#hunter-state').textContent(), 'ACTIVE');
  assert.equal(await page.locator('#health-status').textContent(), 'ok');

  const releaseText = await page.locator('#health-release').textContent();
  const releaseTitle = await page.locator('#health-release').getAttribute('title');
  if (/^[a-f0-9]{40}$/i.test(releaseTitle || '')) {
    assert.match(releaseText, /^[a-f0-9]{10}…[a-f0-9]{6}$/i, `${label}:RELEASE_NOT_ABBREVIATED`);
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

  assert.equal(result.page_errors.length, 0, `${label}:PAGE_ERRORS:${result.page_errors.join('|')}`);
  assert.equal(result.console_errors.length, 0, `${label}:CONSOLE_ERRORS:${result.console_errors.join('|')}`);
  assert.equal(result.failed_requests.length, 0, `${label}:FAILED_REQUESTS:${JSON.stringify(result.failed_requests)}`);

  await page.screenshot({ path: path.join(OUTPUT, `${label}.png`), fullPage: true });
  result.overall_state = 'FRESH';
  result.horizontal_overflow = false;
  result.release_visible = releaseText;
  result.release_full_available = Boolean(releaseTitle);
  await context.close();
  return result;
}

async function main() {
  const evidence = {
    schema_version: 1,
    head_sha: HEAD_SHA,
    preview_url: PREVIEW_URL,
    production_url_accessed: false,
    production_changed: false,
    deploy_performed: false,
    started_at: new Date().toISOString(),
  };

  let browser = null;
  try {
    await waitForPreview(evidence);
    await verifyEdgeContracts(evidence);
    browser = await chromium.launch({ headless: true });
    evidence.viewports = [];
    evidence.viewports.push(await smokeViewport(browser, { width: 1440, height: 900 }, 'desktop-1440'));
    evidence.viewports.push(await smokeViewport(browser, { width: 390, height: 844 }, 'mobile-390'));
    evidence.viewports.push(await smokeViewport(browser, { width: 360, height: 800 }, 'mobile-360'));
    evidence.status = 'PASS';
  } catch (error) {
    evidence.status = 'FAIL';
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
