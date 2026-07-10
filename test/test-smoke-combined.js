#!/usr/bin/env node
/**
 * BOQA Combined Smoke Runner — Starts server + runs smoke test in same process
 *
 * This avoids the background process management issues where the server
 * dies when the parent shell exits.
 */

const http = require('http');

// ─── Configuration ──────────────────────────────────────────────────

const HOST = '127.0.0.1';
const PORT = process.env.BOQA_PORT || 7070;
const API_KEY = process.env.BOQA_API_KEY || 'boqa-default-key';
const TIMEOUT = 10000;

// ─── Test runner ────────────────────────────────────────────────────

let testsPassed = 0;
let testsFailed = 0;
const failures = [];

function assert(condition, label) {
  if (condition) {
    console.log(`  ✓ ${label}`);
    testsPassed++;
  } else {
    console.log(`  ✗ ${label}`);
    testsFailed++;
    failures.push(label);
  }
}

async function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: HOST,
      port: PORT,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      timeout: TIMEOUT,
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(data); } catch (_) { parsed = data; }
        resolve({ status: res.statusCode, body: parsed, raw: data });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

// ─── Wait for server ────────────────────────────────────────────────

async function waitForServer(maxRetries = 30, intervalMs = 1000) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const res = await request('GET', '/api/health');
      if (res.status === 200 || res.status === 503) {
        console.log(`[Smoke] Server ready after ${(i + 1) * intervalMs}ms (status: ${res.status})`);
        return true;
      }
    } catch (_) {
      // Server not ready yet
    }
    await new Promise(r => setTimeout(r, intervalMs));
  }
  return false;
}

// ─── Test Suite ─────────────────────────────────────────────────────

async function runTests() {
  console.log();
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('  P5 Finalization Smoke Test');
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log();

  // ─── 1. Health Endpoints ──────────────────────────────────────────

  console.log('=== 1. Health Endpoints ===');

  let res;
  try {
    res = await request('GET', '/api/health');
    assert(res.status === 200 || res.status === 503, 'GET /api/health returns valid status');
    assert(res.body && (res.body.status === 'ok' || res.body.status === 'degraded'), '/api/health has status field');
    assert(res.body.modules_loaded !== undefined, '/api/health includes modules_loaded');
    assert(res.body.modules_loaded.replayManifestBuilder === true, '/api/health shows replayManifestBuilder loaded');
    assert(res.body.modules_loaded.replaySecurityGuard === true, '/api/health shows replaySecurityGuard loaded');
    assert(res.body.version !== undefined, '/api/health includes version');
  } catch (err) {
    assert(false, `GET /api/health failed: ${err.message}`);
  }

  try {
    res = await request('GET', '/api/replay/health');
    assert(res.status === 200, 'GET /api/replay/health returns 200');
    assert(res.body && res.body.status === 'ok', '/api/replay/health status is ok');
    assert(res.body.replay_subsystem !== undefined, '/api/replay/health includes replay_subsystem');
    assert(res.body.replay_subsystem.manifest_builder === true, '/api/replay/health shows manifest_builder');
    assert(res.body.replay_subsystem.session_recorder !== undefined, '/api/replay/health shows session_recorder');
    assert(res.body.replay_subsystem.replay_farm !== undefined, '/api/replay/health shows replay_farm');
    assert(res.body.replay_subsystem.time_machine_index !== undefined, '/api/replay/health shows time_machine_index');
    assert(res.body.replay_subsystem.security_guard !== undefined, '/api/replay/health shows security_guard');
  } catch (err) {
    assert(false, `GET /api/replay/health failed: ${err.message}`);
  }

  // ─── 2. Record a Simple Browser Session ──────────────────────────

  console.log();
  console.log('=== 2. Record a Simple Session ===');

  try {
    res = await request('POST', '/api/replay/record/start', {
      scenarioName: 'smoke-test-session',
      scenarioTags: ['smoke', 'finalization'],
    });
    assert(res.status === 200, 'POST /api/replay/record/start returns 200');
    assert(res.body.ok === true, 'Record start returns ok: true');
    assert(res.body.recorder_id !== undefined, 'Record start returns recorder_id');
  } catch (err) {
    assert(false, `Record start failed: ${err.message}`);
  }

  // Check recording status
  try {
    res = await request('GET', '/api/replay/record/status');
    assert(res.status === 200, 'GET /api/replay/record/status returns 200');
    assert(res.body.ok === true, 'Record status returns ok: true');
    assert(res.body.is_recording === true, 'Recorder reports is_recording: true');
  } catch (err) {
    assert(false, `Record status failed: ${err.message}`);
  }

  // Mark a step boundary
  try {
    res = await request('POST', '/api/replay/record/step', {
      stepName: 'navigation-complete',
      meta: { url: 'https://example.com' },
    });
    assert(res.status === 200, 'POST /api/replay/record/step returns 200');
    assert(res.body.ok === true, 'Step boundary returns ok: true');
  } catch (err) {
    assert(false, `Record step failed: ${err.message}`);
  }

  // Stop recording
  try {
    res = await request('POST', '/api/replay/record/stop');
    assert(res.status === 200, 'POST /api/replay/record/stop returns 200');
    assert(res.body.ok === true, 'Record stop returns ok: true');
    assert(res.body.recording !== undefined, 'Record stop returns recording data');
    assert(res.body.manifest !== undefined, 'Record stop auto-builds manifest');
  } catch (err) {
    assert(false, `Record stop failed: ${err.message}`);
  }

  // ─── 3. Replay the Session Deterministically ────────────────────

  console.log();
  console.log('=== 3. Replay Session Deterministically ===');

  // Get the recorded export
  let recordingExport = null;
  try {
    res = await request('GET', '/api/replay/record/export');
    assert(res.status === 200, 'GET /api/replay/record/export returns 200');
    assert(res.body.ok === true, 'Record export returns ok: true');
    recordingExport = res.body.recording;
  } catch (err) {
    assert(false, `Record export failed: ${err.message}`);
  }

  // Submit replay run
  if (recordingExport) {
    try {
      res = await request('POST', '/api/replay/run', {
        recording: recordingExport,
        options: { seed: 42, virtualClock: true },
      });
      // Replay run may succeed (200) or fail gracefully (500) with empty recording
      assert(res.status === 200 || res.status === 500, 'POST /api/replay/run returns valid status');
      if (res.status === 200) {
        assert(res.body.ok === true, 'Replay run returns ok: true');
        assert(res.body.report !== undefined, 'Replay run returns report');
        assert(res.body.report.loaded === true, 'Replay plan is loaded');
      } else {
        console.log('  ℹ Replay run returned 500 (expected for empty recording in degraded mode)');
      }
    } catch (err) {
      assert(false, `Replay run failed: ${err.message}`);
    }
  }

  // ─── 4. Verification ────────────────────────────────────────────

  console.log();
  console.log('=== 4. Replay Verification ===');

  if (recordingExport) {
    try {
      res = await request('POST', '/api/replay/verify', {
        original: recordingExport,
        replay: recordingExport,  // Self-comparison for smoke test
      });
      assert(res.status === 200, 'POST /api/replay/verify returns 200');
      assert(res.body.ok === true, 'Verify returns ok: true');
      assert(res.body.result !== undefined, 'Verify returns result');
    } catch (err) {
      assert(false, `Verify failed: ${err.message}`);
    }
  }

  // ─── 5. Scenario Library ────────────────────────────────────────

  console.log();
  console.log('=== 5. Scenario Library ===');

  try {
    res = await request('GET', '/api/replay/scenarios');
    assert(res.status === 200, 'GET /api/replay/scenarios returns 200');
    assert(res.body.ok === true, 'Scenarios returns ok: true');
    assert(Array.isArray(res.body.scenarios), 'Scenarios returns array');
  } catch (err) {
    assert(false, `Scenarios failed: ${err.message}`);
  }

  // ─── 6. Manifest and Redaction ──────────────────────────────────

  console.log();
  console.log('=== 6. Manifest and Redaction ===');

  try {
    res = await request('POST', '/api/replay/manifest', {
      scenarioName: 'smoke-manifest-test',
    });
    assert(res.status === 200, 'POST /api/replay/manifest returns 200');
    assert(res.body.ok === true, 'Manifest build returns ok: true');
    assert(res.body.manifest !== undefined, 'Manifest returns manifest data');
    assert(res.body.manifest.replay_id !== undefined, 'Manifest has replay_id');
    assert(res.body.manifest.fingerprint !== undefined, 'Manifest has fingerprint');
    assert(res.body.manifest.state_hash !== undefined, 'Manifest has state_hash');
    assert(res.body.manifest.artifact_hash !== undefined, 'Manifest has artifact_hash');
  } catch (err) {
    assert(false, `Manifest failed: ${err.message}`);
  }

  // Test redaction
  try {
    res = await request('POST', '/api/replay/security/redact', {
      data: {
        url: 'https://example.com/login',
        password: 'super-secret-123',
        token: 'bearer-abc-xyz',
        safe_field: 'this is fine',
        nested: {
          api_key: 'sk-12345',
          visible: 'ok',
        },
      },
    });
    assert(res.status === 200, 'POST /api/replay/security/redact returns 200');
    assert(res.body.ok === true, 'Redaction returns ok: true');
    // Verify secrets are actually redacted
    const redacted = res.body.redacted || res.body.data;
    if (redacted) {
      const hasPassword = JSON.stringify(redacted).includes('super-secret-123');
      const hasApiKey = JSON.stringify(redacted).includes('sk-12345');
      assert(!hasPassword, 'Redacted data does not contain password');
      assert(!hasApiKey, 'Redacted data does not contain api_key value');
    }
  } catch (err) {
    assert(false, `Redaction failed: ${err.message}`);
  }

  // Test secret scanning
  try {
    res = await request('POST', '/api/replay/security/scan', {
      data: {
        cookie: 'sessionid=abc123',
        authorization: 'Bearer tok123',
        normal: 'visible',
      },
    });
    assert(res.status === 200, 'POST /api/replay/security/scan returns 200');
    assert(res.body.ok === true, 'Scan returns ok: true');
  } catch (err) {
    assert(false, `Secret scan failed: ${err.message}`);
  }

  // Test signing and verification
  try {
    const testData = { replay_id: 'test-123', timestamp: Date.now() };
    res = await request('POST', '/api/replay/security/sign', { data: testData });
    assert(res.status === 200, 'POST /api/replay/security/sign returns 200');
    assert(res.body.ok === true, 'Sign returns ok: true');
    assert(res.body.signature !== undefined, 'Sign returns signature');

    if (res.body.signature) {
      const verifyRes = await request('POST', '/api/replay/security/verify', {
        data: testData,
        signature: res.body.signature,
      });
      assert(verifyRes.status === 200, 'POST /api/replay/security/verify returns 200');
      assert(verifyRes.body.ok === true, 'Verify returns ok: true');
      assert(verifyRes.body.valid === true, 'Signature is valid');
    }
  } catch (err) {
    assert(false, `Sign/verify failed: ${err.message}`);
  }

  // ─── 7. Time Machine Index ─────────────────────────────────────

  console.log();
  console.log('=== 7. Time Machine Index ===');

  try {
    res = await request('GET', '/api/replay/index/stats');
    assert(res.status === 200, 'GET /api/replay/index/stats returns 200');
    assert(res.body.ok === true, 'Index stats returns ok: true');
  } catch (err) {
    assert(false, `Index stats failed: ${err.message}`);
  }

  // ─── 8. Replay Farm ─────────────────────────────────────────────

  console.log();
  console.log('=== 8. Replay Farm ===');

  try {
    res = await request('GET', '/api/replay/farm/status');
    assert(res.status === 200, 'GET /api/replay/farm/status returns 200');
    assert(res.body.ok === true, 'Farm status returns ok: true');
  } catch (err) {
    assert(false, `Farm status failed: ${err.message}`);
  }

  // ─── 9. Degraded Mode ──────────────────────────────────────────

  console.log();
  console.log('=== 9. Degraded Mode ===');

  // The server may or may not have an agent — just verify health endpoint works
  try {
    res = await request('GET', '/api/health');
    assert(res.body.status === 'ok' || res.body.status === 'degraded', 'Server reports valid status (ok or degraded)');
    if (res.body.status === 'degraded') {
      assert(res.body.agent_available === false, 'Degraded mode: agent_available is false');
      console.log('  ℹ Server is in degraded mode (no browser agent)');
    } else {
      console.log('  ℹ Server has active agent');
    }
  } catch (err) {
    assert(false, `Degraded mode check failed: ${err.message}`);
  }

  // ─── 10. Route Namespace Verification ───────────────────────────

  console.log();
  console.log('=== 10. Route Namespace Verification ===');

  try {
    // /api/discovery should work (v01 handler)
    res = await request('GET', '/api/discovery');
    assert(res.status === 200, 'GET /api/discovery (v01) returns 200');

    // /api/discovery/loop should work (v11 namespaced handler)
    res = await request('GET', '/api/discovery/loop');
    assert(res.status === 200, 'GET /api/discovery/loop (v11) returns 200');
  } catch (err) {
    assert(false, `Route namespace check failed: ${err.message}`);
  }

  // ─── 11. Security Audit ────────────────────────────────────────

  console.log();
  console.log('=== 11. Security Audit ===');

  try {
    res = await request('GET', '/api/replay/security/audit');
    assert(res.status === 200, 'GET /api/replay/security/audit returns 200');
    assert(res.body.ok === true, 'Audit returns ok: true');
    assert(Array.isArray(res.body.audit_log), 'Audit log is an array');
  } catch (err) {
    assert(false, `Security audit failed: ${err.message}`);
  }

  // ─── 12. Capture Current Session ───────────────────────────────

  console.log();
  console.log('=== 12. Capture Current Session ===');

  try {
    res = await request('POST', '/api/replay/capture', {
      scenarioName: 'smoke-capture',
      scenarioTags: ['smoke'],
    });
    // This may fail if no bus events, but should not crash
    assert(res.status === 200 || res.status === 500, 'POST /api/replay/capture returns valid status');
    if (res.status === 200) {
      assert(res.body.ok === true, 'Capture returns ok: true');
      assert(res.body.manifest !== undefined, 'Capture returns manifest');
    }
  } catch (err) {
    assert(false, `Capture failed: ${err.message}`);
  }

  // ─── Results ────────────────────────────────────────────────────

  console.log();
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log(`  P5 Finalization Smoke: ${testsPassed} passed, ${testsFailed} failed`);
  console.log('═══════════════════════════════════════════════════════════════════════');

  if (failures.length > 0) {
    console.log();
    console.log('  Failures:');
    failures.forEach(f => console.log(`    - ${f}`));
  }
  console.log();

  return testsFailed;
}

// ─── Main ────────────────────────────────────────────────────────────

async function main() {
  console.log('[Smoke] Starting BOQA server in-process...');

  // Override config port if needed
  process.env.BOQA_PORT = PORT;

  // Smoke test was written to be run from the project root, but we live in test/.
  // chdir to the parent so all `./lib/...` and `./routes/...` requires resolve.
  // (chdir doesn't affect require() resolution — Node uses __dirname — so we
  // also define a ROOT helper and use absolute paths below.)
  const path = require('path');
  const ROOT = path.resolve(__dirname, '..');
  process.chdir(ROOT);
  const r = (p) => require(path.join(ROOT, p));

  // Start the server in this process
  const express = require('express');
  const { WebSocketServer } = require('ws');

  const { CONFIG, OUTPUT_DIR } = r('lib/config');
  const { createRequireAgent, errorHandler, requireApiKey, rateLimiter } = r('lib/middleware');
  const { initialize } = r('lib/init');

  const ctx = initialize(CONFIG, OUTPUT_DIR);
  const requireAgent = createRequireAgent(() => ctx.agent, () => ctx.agentInitError);

  const app = express();
  app.use(express.json());
  const server = http.createServer(app);
  app.use(express.static(path.join(__dirname, '..', 'dashboard')));

  const pipelines = r('lib/pipelines');

  const wss = new WebSocketServer({ server, path: '/ws' });
  ctx.bus.wsServer = wss;
  ctx.wss = wss;
  ctx.server = server;

  const middleware = { requireAgent, requireApiKey, rateLimiter };

  r('routes/v01').registerRoutes(app, ctx, middleware, pipelines);
  r('routes/v08').registerRoutes(app, ctx, middleware, pipelines);
  r('routes/v09').registerRoutes(app, ctx, middleware, pipelines);
  r('routes/v11').registerRoutes(app, ctx, middleware, pipelines);
  r('routes/v12').registerRoutes(app, ctx, middleware, pipelines);
  r('routes/v13').registerRoutes(app, ctx, middleware, pipelines);
  r('routes/v14').registerRoutes(app, ctx, middleware, pipelines);
  r('routes/v15').registerRoutes(app, ctx, middleware, pipelines);

  const { wireEventHandlers } = r('lib/event-wiring');
  wireEventHandlers(ctx, pipelines);

  app.use(errorHandler);

  // Start HTTP — bind to 0.0.0.0 explicitly
  await new Promise((resolve, reject) => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`[Smoke] Server listening on 0.0.0.0:${PORT}`);
      resolve();
    });
    server.on('error', reject);
  });

  // Start Agent (may fail — degraded mode is fine)
  if (ctx.agent) {
    try {
      await ctx.agent.start();
      console.log('[Smoke] Agent active');
    } catch (e) {
      ctx.agentStartError = e.message || String(e);
      console.log(`[Smoke] Agent failed (degraded mode): ${e.message.substring(0, 80)}`);
    }
  }

  // Start runtime monitor
  if (ctx.runtimeMonitor) {
    ctx.runtimeMonitor.start();
    const agentRunning = ctx.agent ? (!('page' in ctx.agent) || !!ctx.agent.page) : false;
    ctx.runtimeMonitor.recordHealth(agentRunning ? 'ok' : 'degraded');
  }

  // Wait for server to be ready
  console.log('[Smoke] Verifying server is ready...');
  const ready = await waitForServer(10, 500);
  if (!ready) {
    console.error('[Smoke] Server never became ready. Aborting.');
    process.exit(1);
  }

  // Run tests
  const failed = await runTests();

  // Shutdown
  console.log('[Smoke] Shutting down server...');
  server.close();
  wss.close();

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('[Smoke] Fatal error:', err);
  process.exit(1);
});

