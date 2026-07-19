'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

async function loadWorker() {
  const workerSource = fs.readFileSync(path.join(__dirname, '..', 'worker.js'), 'utf8');
  const moduleUrl = `data:text/javascript;base64,${Buffer.from(workerSource, 'utf8').toString('base64')}`;
  return (await import(moduleUrl)).default;
}

async function run() {
  const worker = await loadWorker();
  const originalFetch = global.fetch;
  const env = {
    BOQA_BACKEND_URL: 'https://backend.invalid',
    BOQA_API_KEY: 'test-api-key',
    BOQA_HMAC_SECRET: 'test-hmac-secret',
  };

  try {
    const calls = [];
    global.fetch = async (request) => {
      const url = new URL(request.url);
      calls.push({
        pathname: url.pathname,
        apiKey: request.headers.get('x-api-key'),
        signature: request.headers.get('x-boqa-sig'),
        timestamp: request.headers.get('x-boqa-ts'),
      });
      if (url.pathname === '/api/hunter/status') {
        return new Response('<p>Cannot GET /api/hunter/status</p>', { status: 404, headers: { 'Content-Type': 'text/html' } });
      }
      if (url.pathname === '/api/defensive/status') {
        return Response.json({
          state: 'ACTIVE',
          freshness: {
            heartbeat_fresh: true,
            cycle_fresh: true,
            invariants_fresh: true,
            heartbeat_age_ms: 100,
            untrusted_extra: 'remove-me',
          },
          heartbeat_at: '2026-07-19T18:00:00.000Z',
          last_started_at: '2026-07-19T17:59:00.000Z',
          last_completed_at: '2026-07-19T17:59:10.000Z',
          next_scheduled_at: '2026-07-19T18:04:10.000Z',
          timestamp: '2026-07-19T18:00:01.000Z',
          authorized_assets: [{ id: 'must-not-leak' }],
          evidence: [{ detail: 'must-not-leak' }],
        });
      }
      throw new Error(`unexpected backend path ${url.pathname}`);
    };

    const response = await worker.fetch(new Request('https://public.invalid/api/hunter/status'), env);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('x-boqa-backend-contract'), 'defensive-status-v1');
    assert.equal(response.headers.get('cache-control'), 'no-store, max-age=0');
    const payload = await response.json();
    assert.deepEqual(payload, {
      state: 'ACTIVE',
      timestamp: '2026-07-19T18:00:01.000Z',
      freshness: {
        heartbeat_fresh: true,
        cycle_fresh: true,
        invariants_fresh: true,
        heartbeat_age_ms: 100,
      },
      heartbeat_at: '2026-07-19T18:00:00.000Z',
      last_started_at: '2026-07-19T17:59:00.000Z',
      last_completed_at: '2026-07-19T17:59:10.000Z',
      next_scheduled_at: '2026-07-19T18:04:10.000Z',
    });
    assert.equal('authorized_assets' in payload, false);
    assert.equal('evidence' in payload, false);
    assert.deepEqual(calls.map((entry) => entry.pathname), ['/api/hunter/status', '/api/defensive/status']);
    for (const call of calls) {
      assert.equal(call.apiKey, 'test-api-key');
      assert.match(call.signature || '', /^[a-f0-9]{64}$/);
      assert.match(call.timestamp || '', /^\d{10}$/);
    }

    let backendTouched = false;
    global.fetch = async () => { backendTouched = true; throw new Error('must not call backend'); };
    const hidden = await worker.fetch(new Request('https://public.invalid/api/defensive/status'), env);
    assert.equal(hidden.status, 404);
    assert.deepEqual(await hidden.json(), { error: 'not_found' });
    assert.equal(backendTouched, false);

    global.fetch = async (request) => {
      const pathname = new URL(request.url).pathname;
      if (pathname === '/api/hunter/status') return new Response('missing', { status: 404 });
      if (pathname === '/api/defensive/status') return Response.json({ state: 'ACTIVE', timestamp: 'invalid', evidence: ['no'] });
      throw new Error('unexpected path');
    };
    const invalid = await worker.fetch(new Request('https://public.invalid/api/hunter/status'), env);
    assert.equal(invalid.status, 502);
    assert.deepEqual(await invalid.json(), { error: 'legacy_hunter_contract_invalid' });

    console.log('worker legacy hunter compatibility: PASS');
  } finally {
    global.fetch = originalFetch;
  }
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
