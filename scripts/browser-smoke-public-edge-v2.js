'use strict';

const assert = require('assert');
const fs = require('fs');
const Module = require('module');
const path = require('path');

const originalPath = path.join(__dirname, 'browser-smoke-v1.js');
const originalSource = fs.readFileSync(originalPath, 'utf8');
const source = originalSource
  .replace(
    "['/style.css', 'dashboard/style.css'],",
    "['/style.css', 'dashboard/style.css'],\n    ['/mobile.css', 'dashboard/mobile.css'],",
  )
  .replace(
    "assert.equal(await page.locator('#overall-state').getAttribute('data-state'), 'FRESH');",
    `assert.equal(await page.locator('#overall-state').getAttribute('data-state'), 'FRESH');
  assert.equal(await page.locator('#overall-reason').textContent(), 'Todas las fuentes están actualizadas');
  assert.equal(await page.locator('#hunter-reason').textContent(), 'Contrato válido y actualizado');
  assert.equal(await page.locator('#health-reason').textContent(), 'Contrato válido y actualizado');
  const releaseText = await page.locator('#health-release').textContent();
  const releaseTitle = await page.locator('#health-release').getAttribute('title');
  assert.match(releaseText, /^[a-f0-9]{10}…[a-f0-9]{6}$/i, label + ':RELEASE_NOT_ABBREVIATED');
  assert.match(releaseTitle || '', /^[a-f0-9]{40}$/i, label + ':FULL_RELEASE_NOT_ACCESSIBLE');
  if (viewport.width <= 520) {
    const sourceBoxes = await page.locator('.source-card').evaluateAll((nodes) => nodes.map((node) => node.getBoundingClientRect()));
    const unavailableBoxes = await page.locator('.unavailable-panel').evaluateAll((nodes) => nodes.map((node) => node.getBoundingClientRect()));
    assert.equal(sourceBoxes.length, 2, label + ':SOURCE_CARD_COUNT');
    assert.equal(unavailableBoxes.length, 2, label + ':UNAVAILABLE_PANEL_COUNT');
    assert(Math.abs(sourceBoxes[0].top - sourceBoxes[1].top) < 2, label + ':SOURCE_CARDS_NOT_COMPACT');
    assert(Math.abs(unavailableBoxes[0].top - unavailableBoxes[1].top) < 2, label + ':SECONDARY_PANELS_NOT_COMPACT');
  }`,
  );

if (source === originalSource) {
  throw new Error('BROWSER_SMOKE_MOBILE_TRANSFORM_NOT_APPLIED');
}

const start = source.indexOf('async function privateSmoke(');
const end = source.indexOf('\nasync function main()', start);

if (start < 0 || end < 0 || end <= start) {
  throw new Error('PRIVATE_SMOKE_BOUNDARY_NOT_FOUND');
}

const replacement = String.raw`async function privateSmoke(browser) {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  const result = {
    page_errors: [],
    console_errors: [],
    expected_auth_console_errors: [],
    expected_concealment_console_errors: [],
    paths: [],
    hidden_operational_paths: [],
  };
  wireDiagnostics(page, result);

  const privatePaths = [
    '/cobros',
    '/cobros/',
    '/COBROS',
    '/%63obros',
    '/%2563obros',
    '/%252563obros',
    '/%252525252563obros',
    '//cobros',
    '/cobros.html',
    '/nested/cobros.html',
    '/%2563obros.html',
    '/cobros.js',
    '/private.css',
    '/api/private/billing',
    '/api/private/billing/',
    '/api/private/billing/data',
    '/API/PRIVATE/BILLING/DATA',
    '/%61pi/private/billing/data',
    '/%2561pi%252fprivate%252fbilling%252fdata',
    '/api//private//billing//data',
    '/api/%255cprivate%255cbilling%255cdata',
  ];

  for (const pathname of privatePaths) {
    const response = await fetch(
      EDGE_URL + pathname,
      { cache: 'no-store', redirect: 'manual' },
    );
    const body = await response.text();
    assert.equal(response.status, 404, pathname + ':PUBLIC_PRIVATE_STATUS');
    assert.match(response.headers.get('cache-control') || '', /no-store/, pathname + ':CACHE_POLICY');
    assert.match(response.headers.get('x-robots-tag') || '', /noindex/, pathname + ':ROBOTS_POLICY');
    assert.equal(response.headers.get('location'), null, pathname + ':REDIRECT_LEAK');
    assert(!/centro de cobros|movimientos|saldo|monto|ingreso|billing|payment|pago|finanz/i.test(body), pathname + ':PRIVATE_PURPOSE_LEAK');

    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      assert.deepEqual(JSON.parse(body), { error: 'not_found' }, pathname + ':GENERIC_API_BODY');
    } else {
      assert.equal(body, 'Not Found', pathname + ':GENERIC_ASSET_BODY');
    }

    result.paths.push({
      pathname,
      status: response.status,
      cache_control: response.headers.get('cache-control'),
      x_robots_tag: response.headers.get('x-robots-tag'),
      generic_body: true,
    });
  }

  const hiddenOperationalPaths = [
    '/api/runtime/metrics',
    '/api/defensive/status',
    '/api/bugs',
    '/api/findings',
    '/api/metrics',
  ];
  for (const pathname of hiddenOperationalPaths) {
    const response = await fetch(EDGE_URL + pathname, { cache: 'no-store', redirect: 'manual' });
    const body = await response.text();
    assert.equal(response.status, 404, pathname + ':OPERATIONAL_PATH_STATUS');
    assert.match(response.headers.get('cache-control') || '', /no-store/, pathname + ':OPERATIONAL_CACHE_POLICY');
    assert.deepEqual(JSON.parse(body), { error: 'not_found' }, pathname + ':OPERATIONAL_GENERIC_BODY');
    assert(!/bug|finding|metric|defensive|runtime|asset|target|evidence/i.test(body), pathname + ':OPERATIONAL_PURPOSE_LEAK');
    result.hidden_operational_paths.push({ pathname, status: response.status, generic_body: true });
  }

  const navigation = await page.goto(EDGE_URL + '/cobros', { waitUntil: 'networkidle' });
  assert(navigation, 'PRIVATE_CONCEALMENT_NAVIGATION_MISSING');
  assert.equal(navigation.status(), 404, 'PRIVATE_CONCEALMENT_NAVIGATION_STATUS');
  assert.match(navigation.headers()['cache-control'] || '', /no-store/);
  assert.match(navigation.headers()['x-robots-tag'] || '', /noindex/);
  const anonymousText = await page.locator('body').innerText();
  assert.equal(anonymousText.trim(), 'Not Found');
  assert(!/centro de cobros|movimientos|saldo|monto|ingreso|billing|payment|pago|finanz/i.test(anonymousText), 'PRIVATE_LABEL_LEAKED_AT_PUBLIC_EDGE');
  await page.screenshot({ path: path.join(OUTPUT, 'private-anonymous-mobile.png'), fullPage: true });

  await page.waitForTimeout(150);
  const isExpectedConcealment404 = (text) =>
    String(text).includes('Failed to load resource') &&
    String(text).includes('404') &&
    String(text).includes('Not Found');
  result.expected_concealment_console_errors = result.console_errors.filter(isExpectedConcealment404);
  result.console_errors = result.console_errors.filter((text) => !isExpectedConcealment404(text));

  assert.equal(result.page_errors.length, 0, 'PRIVATE_PAGEERROR:' + result.page_errors.join('|'));
  assert.equal(result.console_errors.length, 0, 'PRIVATE_CRITICAL_CONSOLE:' + result.console_errors.join('|'));
  assert(result.expected_concealment_console_errors.length >= 1, 'EXPECTED_CONCEALMENT_CONSOLE_EVENT_MISSING');
  result.public_edge_concealed = true;
  result.authenticated = false;
  result.backend_private_module_exercised_by_browser = false;
  result.backend_private_module_covered_by_suite = true;
  await context.close();
  return result;
}
`;

const transformed = source.slice(0, start) + replacement + source.slice(end);
const compiled = new Module(originalPath, module);
compiled.filename = originalPath;
compiled.paths = Module._nodeModulePaths(path.dirname(originalPath));
compiled._compile(transformed, originalPath);
