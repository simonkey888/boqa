'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

async function run() {
  const root = path.join(__dirname, '..');
  const html = fs.readFileSync(path.join(root, 'dashboard/index.html'), 'utf8');
  const app = fs.readFileSync(path.join(root, 'dashboard/app.js'), 'utf8');
  const worker = fs.readFileSync(path.join(root, 'worker.js'), 'utf8');
  const all = html + app;

  assert(!all.includes('Centro de Cobros'));
  assert(!all.includes('/cobros'));
  assert(!/portfolio|bount|finanz|pago|ingreso/i.test(all));
  assert(!app.includes('/api/private/'));
  assert(!html.includes('fonts.googleapis'));

  assert(worker.includes('function isPrivateSurface(pathname)'));
  assert(worker.includes('function hiddenPrivateResponse(pathname)'));
  assert(worker.includes("normalized.startsWith('/api/private/billing/')"));
  assert(worker.includes("normalized.endsWith('/cobros.html')"));
  assert(worker.includes("normalized.endsWith('/cobros.js')"));
  assert(worker.includes("normalized.endsWith('/private.css')"));
  assert(worker.includes('for (let pass = 0; pass < 8; pass += 1)'));
  assert(worker.includes('decodeURIComponent(decoded)'));
  assert(worker.includes(".replace(/\\\\/g, '/')"));
  assert(worker.includes('if (isPrivateSurface(url.pathname))'));
  assert(worker.includes('return hiddenPrivateResponse(url.pathname)'));
  assert(worker.includes("error: 'not_found'"));
  assert(worker.includes("'X-Robots-Tag': 'noindex, nofollow, noarchive'"));
  assert(worker.includes("'Cache-Control': 'no-store, max-age=0'"));
  assert(!worker.includes('isPrivateBilling'));
  assert(worker.indexOf('if (isPrivateSurface(url.pathname))') < worker.indexOf('if (env && env.ASSETS)'));

  const allowlistMatch = worker.match(/const publicReadPaths = new Set\(\[([\s\S]*?)\]\);/);
  assert(allowlistMatch, 'public API allowlist must remain explicit');
  const allowlistBody = allowlistMatch[1];
  assert(allowlistBody.includes("'/api/health'"));
  assert(allowlistBody.includes("'/api/hunter/status'"));
  assert(!allowlistBody.includes("'/api/runtime/metrics'"));
  assert(!allowlistBody.includes("'/api/defensive/status'"));
  assert(!allowlistBody.includes("'/api/bugs'"));
  assert(worker.includes("backendPath: '/api/defensive/status'"), 'legacy route may be used only as an internal compatibility source');
  assert(worker.includes('normalizeLegacyHunterPayload'));

  const moduleUrl = `data:text/javascript;base64,${Buffer.from(worker, 'utf8').toString('base64')}`;
  const workerModule = await import(moduleUrl);
  const publicWorker = workerModule.default;
  assert(publicWorker && typeof publicWorker.fetch === 'function');

  const privatePaths = [
    '/cobros', '/cobros/', '/COBROS', '/%63obros', '/%2563obros', '/%252563obros',
    '/%252525252563obros', '//cobros', '/cobros.html', '/nested/cobros.html', '/%2563obros.html',
    '/cobros.js', '/private.css', '/api/private/billing', '/api/private/billing/',
    '/api/private/billing/data', '/API/PRIVATE/BILLING/DATA', '/%61pi/private/billing/data',
    '/%2561pi%252fprivate%252fbilling%252fdata', '/api//private//billing//data',
    '/api/%255cprivate%255cbilling%255cdata',
  ];

  for (const pathname of privatePaths) {
    let assetsTouched = false;
    const env = {
      BOQA_BACKEND_URL: 'https://backend.invalid',
      ASSETS: { async fetch() { assetsTouched = true; throw new Error('private path reached public assets binding'); } },
    };
    const response = await publicWorker.fetch(new Request(`https://public.invalid${pathname}`), env);
    assert.equal(response.status, 404, `${pathname} must be concealed with 404`);
    assert.equal(response.headers.get('cache-control'), 'no-store, max-age=0');
    assert.match(response.headers.get('x-robots-tag') || '', /noindex/);
    assert.equal(response.headers.get('location'), null);
    assert.equal(assetsTouched, false, `${pathname} must not reach ASSETS`);
    const body = await response.text();
    assert(!/cobros|billing|payment|pago|finanz/i.test(body), `${pathname} response reveals private purpose`);
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) assert.deepEqual(JSON.parse(body), { error: 'not_found' });
    else assert.equal(body, 'Not Found');
  }

  const hiddenOperationalPaths = ['/api/runtime/metrics', '/api/defensive/status', '/api/bugs', '/api/findings', '/api/metrics'];
  for (const pathname of hiddenOperationalPaths) {
    const response = await publicWorker.fetch(new Request(`https://public.invalid${pathname}`), { BOQA_BACKEND_URL: 'https://backend.invalid' });
    assert.equal(response.status, 404, `${pathname} must not be public`);
    assert.equal(response.headers.get('cache-control'), 'no-store, max-age=0');
    assert.deepEqual(await response.json(), { error: 'not_found' });
  }

  assert(!/DEMO_BUGS|DEMO_COVERAGE|DEMO_FINDINGS|DEMO_HEALTH|demoJsonEvidence/.test(worker));
  assert(!fs.readFileSync(path.join(root, '.env.example'), 'utf8').includes('BOQA_BILLING_PIN'));
  console.log('public/private boundary: PASS');
}

run().catch((error) => { console.error(error); process.exit(1); });
