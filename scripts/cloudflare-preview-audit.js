'use strict';

const fs = require('fs');
const { chromium } = require('playwright');

const base = process.env.PREVIEW_URL;
const out = process.env.OUT;
const sizes = [
  [1440, 900, 'desktop-1440'],
  [390, 844, 'mobile-390'],
  [360, 800, 'mobile-360'],
];
const expectedPrivateConsole = /Failed to load resource: the server responded with a status of (401|403)/;

async function auditPublic(browser, width, height, name) {
  const context = await browser.newContext({ viewport: { width, height } });
  const page = await context.newPage();
  const pageErrors = [];
  const consoleErrors = [];
  page.on('pageerror', (error) => pageErrors.push(String(error)));
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  const response = await page.goto(`${base}/`, { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForFunction(() => document.querySelector('#overall-state')?.textContent !== 'LOADING', null, { timeout: 20000 });
  const state = await page.evaluate(() => {
    const track = document.querySelector('.hunt-track');
    const trace = document.querySelector('#hunt-live');
    return {
      initialFocusClass: String(document.activeElement?.className || ''),
      heroVisible: Boolean(document.querySelector('#hero-title')),
      overallState: document.querySelector('#overall-state')?.textContent || null,
      hunterState: document.querySelector('#hunter-state')?.textContent || null,
      healthStatus: document.querySelector('#health-status')?.textContent || null,
      healthRelease: document.querySelector('#health-release')?.textContent || null,
      huntVisible: Boolean(trace),
      huntMode: trace?.dataset.mode || null,
      huntContainerType: track ? getComputedStyle(track).containerType : null,
      overflow: Math.max(0, document.documentElement.scrollWidth - document.documentElement.clientWidth),
    };
  });
  await page.screenshot({ path: `${out}/${name}-viewport.png` });
  await page.screenshot({ path: `${out}/${name}-full.png`, fullPage: true });
  await page.keyboard.press('Tab');
  const skipFocusable = await page.evaluate(() => document.activeElement?.classList.contains('skip-link') === true);
  await context.close();
  return { name, width, height, httpStatus: response?.status() || null, ...state, skipFocusable, pageErrors, consoleErrors };
}

async function auditPrivate(browser) {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  const pageErrors = [];
  const consoleErrors = [];
  page.on('pageerror', (error) => pageErrors.push(String(error)));
  page.on('console', (message) => {
    if (message.type() === 'error' && !expectedPrivateConsole.test(message.text())) consoleErrors.push(message.text());
  });
  const response = await page.goto(`${base}/cobros`, { waitUntil: 'networkidle', timeout: 30000 });
  const bodyText = await page.locator('body').innerText();
  const privateRootHidden = await page.locator('#private-root').isHidden();
  const sessionStatus = await page.evaluate(() => fetch('/api/private/billing/session', { credentials: 'same-origin', cache: 'no-store' }).then((r) => r.status));
  const dataStatus = await page.evaluate(() => fetch('/api/private/billing/data', { credentials: 'same-origin', cache: 'no-store' }).then((r) => r.status));
  await page.screenshot({ path: `${out}/cobros-anonymous-mobile.png`, fullPage: true });
  const privateLeak = /Centro de Cobros|Movimientos|saldo|monto|ingreso/i.test(bodyText);
  await context.close();
  return { httpStatus: response?.status() || null, privateRootHidden, sessionStatus, dataStatus, privateLeak, pageErrors, consoleErrors };
}

async function verifyHttp() {
  const expected = new Map([
    ['/', 200],
    ['/health', 200],
    ['/api/health', 200],
    ['/api/hunter/status', 200],
    ['/api/defensive/status', 200],
    ['/api/private/billing/session', 401],
    ['/api/private/billing/data', 401],
  ]);
  const rows = [];
  const failures = [];
  for (const [route, want] of expected) {
    const response = await fetch(base + route, { redirect: 'manual', cache: 'no-store' });
    rows.push({ route, status: response.status, expected: want, cacheControl: response.headers.get('cache-control'), contentType: response.headers.get('content-type') });
    if (response.status !== want) failures.push(`${route}:${response.status}`);
  }
  fs.writeFileSync(`${out}/http-contracts.json`, JSON.stringify(rows, null, 2));
  return failures;
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const results = [];
  const failures = [];
  try {
    for (const [width, height, name] of sizes) {
      const row = await auditPublic(browser, width, height, name);
      results.push(row);
      if (row.httpStatus !== 200 || !row.heroVisible || !row.huntVisible) failures.push(`${name}:content`);
      if (row.initialFocusClass.includes('skip-link') || !row.skipFocusable) failures.push(`${name}:focus`);
      if (row.huntContainerType !== 'inline-size' || !['ready', 'running', 'starting'].includes(row.huntMode)) failures.push(`${name}:trace`);
      if (row.overallState !== 'FRESH' || row.hunterState !== 'ACTIVE' || row.healthStatus !== 'ok') failures.push(`${name}:runtime`);
      if (row.overflow || row.pageErrors.length || row.consoleErrors.length) failures.push(`${name}:browser`);
    }
    const privateResult = await auditPrivate(browser);
    if (privateResult.httpStatus !== 200 || !privateResult.privateRootHidden || privateResult.sessionStatus !== 401 || privateResult.dataStatus !== 401 || privateResult.privateLeak || privateResult.pageErrors.length || privateResult.consoleErrors.length) failures.push('private_boundary');
    failures.push(...await verifyHttp());
    fs.writeFileSync(`${out}/browser-preview-evidence.json`, JSON.stringify({ sourceSha: process.env.SOURCE_SHA, previewUrl: base, results, private: privateResult, failures }, null, 2));
    if (failures.length) throw new Error(failures.join(','));
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error.stack || error);
  process.exit(1);
});
