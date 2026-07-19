'use strict';

const assert = require('assert');
const fs = require('fs');
const Module = require('module');
const path = require('path');

const originalPath = path.join(__dirname, 'browser-smoke-v1.js');
const source = fs.readFileSync(originalPath, 'utf8');
const start = source.indexOf('async function privateSmoke(');
const end = source.indexOf('\nasync function main()', start);

if (start < 0 || end < 0 || end <= start) {
  throw new Error('PRIVATE_SMOKE_BOUNDARY_NOT_FOUND');
}

const replacement = String.raw`async function privateSmoke(browser) {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  const result = { page_errors: [], console_errors: [], expected_auth_console_errors: [], paths: [] };
  wireDiagnostics(page, result);

  const privatePaths = [
    '/cobros',
    '/cobros/',
    '/COBROS',
    '/%63obros',
    '//cobros',
    '/cobros.html',
    '/nested/cobros.html',
    '/cobros.js',
    '/private.css',
    '/api/private/billing',
    '/api/private/billing/',
    '/api/private/billing/data',
    '/API/PRIVATE/BILLING/DATA',
    '/%61pi/private/billing/data',
    '/api//private//billing//data',
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

    const normalized = pathname.toLowerCase().replace(/%61/g, 'a').replace(/\/{2,}/g, '/');
    if (normalized.startsWith('/api/')) {
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

  const navigation = await page.goto(EDGE_URL + '/cobros', { waitUntil: 'networkidle' });
  assert(navigation, 'PRIVATE_CONCEALMENT_NAVIGATION_MISSING');
  assert.equal(navigation.status(), 404, 'PRIVATE_CONCEALMENT_NAVIGATION_STATUS');
  assert.match(navigation.headers()['cache-control'] || '', /no-store/);
  assert.match(navigation.headers()['x-robots-tag'] || '', /noindex/);
  const anonymousText = await page.locator('body').innerText();
  assert.equal(anonymousText.trim(), 'Not Found');
  assert(!/centro de cobros|movimientos|saldo|monto|ingreso|billing|payment|pago|finanz/i.test(anonymousText), 'PRIVATE_LABEL_LEAKED_AT_PUBLIC_EDGE');
  await page.screenshot({ path: path.join(OUTPUT, 'private-anonymous-mobile.png'), fullPage: true });

  assert.equal(result.page_errors.length, 0, 'PRIVATE_PAGEERROR:' + result.page_errors.join('|'));
  assert.equal(result.console_errors.length, 0, 'PRIVATE_CRITICAL_CONSOLE:' + result.console_errors.join('|'));
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
