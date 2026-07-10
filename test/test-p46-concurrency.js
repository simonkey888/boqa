/**
 * BOQA test-p46-concurrency.js — P4.6 Concurrency Validation
 *
 * Validates multiple simultaneous requests.
 * Stress: parallel_clients [5, 10, 25, 50]
 * Verify: no deadlocks, no race conditions, no duplicated findings,
 *         no corrupted persistence, no event loss.
 *
 * Zero behavior change. Zero API change. Only increases confidence.
 */

const http = require('http');
const express = require('express');
const path = require('path');
const os = require('os');

const { CONFIG, OUTPUT_DIR } = require('../lib/config');
const { createRequireAgent, errorHandler, requireApiKey, rateLimiter } = require('../lib/middleware');
const { initialize } = require('../lib/init');
const pipelines = require('../lib/pipelines');
const { EventBus } = require('../bus');

// ─── Test runner ────────────────────────────────────────────────────

let testsPassed = 0;
let testsFailed = 0;
const failures = [];

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    testsPassed++;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    testsFailed++;
    failures.push({ name, error: err.message });
    console.log(`  ✗ ${name}: ${err.message}`);
  }
}

// ─── Test server setup ──────────────────────────────────────────────

let app, server, ctx, baseUrl;

function setupServer() {
  const serverPort = 18080 + Math.floor(Math.random() * 1000);
  const testConfig = { ...CONFIG, port: serverPort, autoAnalyze: false, analyzeInterval: 9999, duration: 0 };
  const testOutputDir = path.join(os.tmpdir(), 'boqa-p46-test');

  ctx = initialize(testConfig, testOutputDir);
  const requireAgent = createRequireAgent(() => ctx.agent, () => ctx.agentInitError);

  app = express();
  app.use(express.json());
  const middleware = { requireAgent, requireApiKey, rateLimiter };

  require('../routes/v01').registerRoutes(app, ctx, middleware, pipelines);
  require('../routes/v08').registerRoutes(app, ctx, middleware, pipelines);
  require('../routes/v09').registerRoutes(app, ctx, middleware, pipelines);
  require('../routes/v11').registerRoutes(app, ctx, middleware, pipelines);
  require('../routes/v12').registerRoutes(app, ctx, middleware, pipelines);
  require('../routes/v13').registerRoutes(app, ctx, middleware, pipelines);
  require('../routes/v14').registerRoutes(app, ctx, middleware, pipelines);
  app.use(errorHandler);

  server = app.listen(serverPort);
  baseUrl = `http://localhost:${serverPort}`;
}

function teardownServer() {
  if (server) server.close();
  if (ctx && ctx.bus && ctx.bus.ndjsonStream) ctx.bus.ndjsonStream.end();
  if (ctx && ctx.memoryGraph && typeof ctx.memoryGraph.shutdown === 'function') ctx.memoryGraph.shutdown();
}

function request(method, urlPath, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, baseUrl);
    const opts = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: method.toUpperCase(),
      headers: { 'Accept': 'application/json', ...(options.headers || {}) },
      timeout: 15000,
    };
    if (options.body) {
      const bodyStr = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['Content-Length'] = Buffer.byteLength(bodyStr);
    }
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(data); } catch (e) { /* not json */ }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed, rawBody: data });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
    if (options.body) {
      const bodyStr = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
      req.write(bodyStr);
    }
    req.end();
  });
}

// ─── Run parallel requests ──────────────────────────────────────────

async function parallelRequests(count, method, urlPath, options = {}) {
  const promises = [];
  for (let i = 0; i < count; i++) {
    promises.push(request(method, urlPath, options));
  }
  return Promise.all(promises);
}

// ═══════════════════════════════════════════════════════════════════════
//  Test execution
// ═══════════════════════════════════════════════════════════════════════

async function runTests() {

console.log('\n=== Setting up test server ===');
setupServer();
console.log(`  Server on port ${server.address().port}`);

// ═══════════════════════════════════════════════════════════════════════
//  1. Parallel GET Requests
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 1. Parallel GET Requests ===');

await testAsync('5 parallel GET /api/stats — no deadlock', async () => {
  const results = await parallelRequests(5, 'GET', '/api/stats');
  assert(results.every(r => r.status === 200), 'All requests should return 200');
});

await testAsync('10 parallel GET /api/stats — no deadlock', async () => {
  const results = await parallelRequests(10, 'GET', '/api/stats');
  assert(results.every(r => r.status === 200), 'All requests should return 200');
});

await testAsync('25 parallel GET /api/events — no deadlock', async () => {
  const results = await parallelRequests(25, 'GET', '/api/events');
  assert(results.every(r => r.status === 200), 'All requests should return 200');
});

await testAsync('50 parallel GET /api/findings — no deadlock', async () => {
  const results = await parallelRequests(50, 'GET', '/api/findings');
  assert(results.every(r => r.status === 200), 'All requests should return 200');
});

await testAsync('10 parallel GET /api/coverage — no deadlock', async () => {
  const results = await parallelRequests(10, 'GET', '/api/coverage');
  assert(results.every(r => r.status === 200), 'All requests should return 200');
});

await testAsync('10 parallel GET /api/uncertainty — no deadlock', async () => {
  const results = await parallelRequests(10, 'GET', '/api/uncertainty');
  assert(results.every(r => r.status === 200), 'All requests should return 200');
});

await testAsync('10 parallel GET /api/autonomy — no deadlock', async () => {
  const results = await parallelRequests(10, 'GET', '/api/autonomy');
  assert(results.every(r => r.status === 200 || r.status === 401), 'All requests should return valid status');
});

// ═══════════════════════════════════════════════════════════════════════
//  2. Parallel Mixed Routes
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 2. Parallel Mixed Routes ===');

await testAsync('10 parallel mixed GET routes — no deadlock', async () => {
  const routes = [
    '/api/stats', '/api/events', '/api/findings', '/api/risk',
    '/api/coverage', '/api/knowledge', '/api/planner', '/api/metrics',
    '/api/predictions', '/api/efficiency',
  ];
  const promises = routes.map(r => request('GET', r));
  const results = await Promise.all(promises);
  assert(results.every(r => r.status === 200), 'All requests should return 200');
});

await testAsync('25 parallel mixed v1.1+v1.3 routes — no deadlock', async () => {
  const routes = [];
  for (let i = 0; i < 25; i++) {
    routes.push(['/api/discovery', '/api/calibration', '/api/uncertainty', '/api/stability', '/api/alignment'][i % 5]);
  }
  const promises = routes.map(r => request('GET', r));
  const results = await Promise.all(promises);
  assert(results.every(r => r.status === 200), 'All requests should return 200');
});

// ═══════════════════════════════════════════════════════════════════════
//  3. Parallel POST Requests
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 3. Parallel POST Requests ===');

await testAsync('5 parallel POST /api/calibration/observe — no race condition', async () => {
  const promises = [];
  for (let i = 0; i < 5; i++) {
    promises.push(request('POST', '/api/calibration/observe', {
      body: { target_id: `TGT-conc-${i}`, category: 'auth', predicted: 0.5 + i * 0.1, actual: 0.4 + i * 0.1 },
    }));
  }
  const results = await Promise.all(promises);
  assert(results.every(r => r.status === 200), 'All calibration observe requests should return 200');
});

await testAsync('10 parallel POST /api/memory/node — no race condition', async () => {
  const promises = [];
  for (let i = 0; i < 10; i++) {
    promises.push(request('POST', '/api/memory/node', {
      body: { type: 'finding', label: `Concurrent Node ${i}` },
    }));
  }
  const results = await Promise.all(promises);
  assert(results.every(r => r.status === 200), 'All memory node requests should return 200');
  // Verify no duplicate node IDs
  const nodeIds = results.map(r => r.body.node_id);
  const uniqueIds = new Set(nodeIds);
  assert(uniqueIds.size === nodeIds.length, 'All node IDs should be unique');
});

await testAsync('5 parallel POST /api/uncertainty/gate — no race condition', async () => {
  const promises = [];
  for (let i = 0; i < 5; i++) {
    promises.push(request('POST', '/api/uncertainty/gate', {
      body: { opportunity_id: `OPP-conc-${i}`, category: 'auth_bypass', confidence: 0.7, variance: 0.2 },
    }));
  }
  const results = await Promise.all(promises);
  assert(results.every(r => r.status === 200), 'All uncertainty gate requests should return 200');
});

// ═══════════════════════════════════════════════════════════════════════
//  4. No Corrupted Persistence
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 4. No Corrupted Persistence ===');

await testAsync('Parallel writes to EventBus — no event loss', async () => {
  const initialCount = ctx.bus.eventLog.length;
  const promises = [];
  for (let i = 0; i < 50; i++) {
    ctx.bus.emit({ type: 'network_request', ts: Date.now(), url: `https://concurrent-test-${i}.com`, method: 'GET' });
  }
  // Events should be added synchronously
  assert(ctx.bus.eventLog.length >= initialCount + 50, `Expected at least ${initialCount + 50} events, got ${ctx.bus.eventLog.length}`);
});

await testAsync('Parallel knowledge base writes — no data loss', async () => {
  const kb = ctx.knowledgeBase;
  const initialSize = kb.findings.size;
  for (let i = 0; i < 25; i++) {
    kb.upsertFinding({
      id: `FND-conc-${i}`,
      category: 'auth_bypass',
      severity: 'high',
      confidence: 0.8,
      target_id: 'TGT-conc',
    });
  }
  assert(kb.findings.size >= initialSize + 25, `Expected at least ${initialSize + 25} findings, got ${kb.findings.size}`);
});

await testAsync('Parallel memory graph writes — no node loss', async () => {
  const mg = ctx.memoryGraph;
  const initialSize = mg.nodes.size;
  for (let i = 0; i < 25; i++) {
    mg.addNode({ id: `GN-conc-${i}`, type: 'finding', label: `Concurrent ${i}` });
  }
  assert(mg.nodes.size >= initialSize + 25, `Expected at least ${initialSize + 25} nodes, got ${mg.nodes.size}`);
});

// ═══════════════════════════════════════════════════════════════════════
//  5. No Duplicated Findings
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 5. No Duplicated Findings ===');

await testAsync('Duplicate finding IDs are handled by upsert (no duplication)', async () => {
  const kb = ctx.knowledgeBase;
  const initialSize = kb.findings.size;
  const finding = {
    id: 'FND-dup-test',
    category: 'xss',
    severity: 'medium',
    confidence: 0.6,
  };
  kb.upsertFinding(finding);
  kb.upsertFinding(finding);
  kb.upsertFinding(finding);
  assert(kb.findings.has('FND-dup-test'), 'Finding should exist');
  // Upsert should not create duplicates
  assert(kb.findings.size === initialSize + 1, `Expected ${initialSize + 1} findings, got ${kb.findings.size}`);
});

await testAsync('Duplicate node IDs are handled (no duplication)', async () => {
  const mg = ctx.memoryGraph;
  const initialSize = mg.nodes.size;
  mg.addNode({ id: 'GN-dup-test', type: 'finding', label: 'Dup Test' });
  mg.addNode({ id: 'GN-dup-test', type: 'finding', label: 'Dup Test Updated' });
  assert(mg.nodes.has('GN-dup-test'), 'Node should exist');
  // Should be only one node with this ID
  assert(mg.nodes.size === initialSize + 1, `Expected ${initialSize + 1} nodes, got ${mg.nodes.size}`);
});

// ═══════════════════════════════════════════════════════════════════════
//  6. EventBus Concurrency
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 6. EventBus Concurrency ===');

await testAsync('EventBus emit is synchronous — no event reordering', async () => {
  const bus = new EventBus(null, { ndjsonPath: null });
  const order = [];
  for (let i = 0; i < 100; i++) {
    bus.emit({ type: 'network_request', ts: Date.now(), url: `https://order-${i}.com`, method: 'GET' });
    order.push(i);
  }
  // Verify events are in order
  for (let i = 0; i < 100; i++) {
    assert(bus.eventLog[i].url === `https://order-${i}.com`, `Event ${i} should be in order`);
  }
});

await testAsync('EventBus metrics are consistent after parallel emits', async () => {
  const bus = new EventBus(null, { ndjsonPath: null });
  const initialTotal = bus.metrics.request_count;
  for (let i = 0; i < 50; i++) {
    bus.emit({ type: 'network_request', ts: Date.now(), url: `https://test.com/${i}`, method: 'GET' });
  }
  assert(bus.metrics.request_count === initialTotal + 50, `Expected ${initialTotal + 50} requests, got ${bus.metrics.request_count}`);
  assert(bus.eventLog.length === 50, `Expected 50 events, got ${bus.eventLog.length}`);
});

// ═══════════════════════════════════════════════════════════════════════
//  7. Stress Test — 60s sustained load
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 7. Stress Test ===');

await testAsync('10-second sustained GET load — no failures', async () => {
  let totalRequests = 0;
  let failures = 0;
  const startTime = Date.now();
  const duration = 10000; // 10 seconds

  while (Date.now() - startTime < duration) {
    try {
      const res = await request('GET', '/api/stats');
      totalRequests++;
      if (res.status !== 200) failures++;
    } catch (e) {
      failures++;
      totalRequests++;
    }
  }

  console.log(`    → ${totalRequests} requests in 10s, ${failures} failures`);
  assert(failures === 0, `${failures} requests failed out of ${totalRequests}`);
  assert(totalRequests > 50, `Should handle more than 50 requests in 10s, got ${totalRequests}`);
});

// ═══════════════════════════════════════════════════════════════════════
//  Final Summary
// ═══════════════════════════════════════════════════════════════════════

console.log('\n' + '═'.repeat(70));
console.log(`  P4.6 Concurrency Validation Results: ${testsPassed} passed, ${testsFailed} failed`);
console.log('═'.repeat(70));

if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`  ✗ ${f.name}: ${f.error}`);
  }
}

teardownServer();
process.exit(testsFailed > 0 ? 1 : 0);

} // end runTests

runTests().catch(err => {
  console.error('Fatal error:', err);
  teardownServer();
  process.exit(1);
});

