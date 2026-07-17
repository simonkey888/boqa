'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'dashboard', 'index.html'), 'utf8');
const app = fs.readFileSync(path.join(root, 'dashboard', 'app.js'), 'utf8');
const state = fs.readFileSync(path.join(root, 'dashboard', 'dashboard-state.js'), 'utf8');
const worker = fs.readFileSync(path.join(root, 'worker.js'), 'utf8');

assert.match(html, /<script\s+src=["']\/dashboard-state\.js["']\s+defer><\/script>/, 'dashboard must load the state contract');
assert.match(html, /<script\s+src=["']\/app\.js["']\s+defer><\/script>/, 'dashboard must load /app.js');
assert.match(app, /poll\(\)/, 'dashboard must initialize');
assert.doesNotMatch(app, /['"]X-API-Key['"]\s*:/, 'browser must not send backend API key');
assert.doesNotMatch(app + html, /localStorage|auth-gate|modal de clave/i, 'dashboard must not contain a browser credential gate');
assert.doesNotMatch(app, /uptimeStart\s*:\s*Date\.now/, 'browser must not invent server uptime');
assert.match(app, /\/api\/hunter\/status/, 'dashboard must consume the public hunter contract');
assert.match(app, /\/api\/health/, 'dashboard must consume health');
assert.doesNotMatch(app, /defensive\/status|\/api\/bugs|\/api\/findings/, 'dashboard must not consume legacy synthetic sources');
assert.match(app, /document\.hidden/, 'polling must pause while hidden');
assert.match(state, /LOADING/);
assert.match(state, /FRESH/);
assert.match(state, /STALE/);
assert.match(state, /UNAVAILABLE/);
assert.match(worker, /proxyHeaders\.set\('X-API-Key', workerApiKey\)/, 'Worker must overwrite upstream API key');
assert.match(worker, /'\/api\/hunter\/status'/, 'Worker must proxy hunter status');
assert.doesNotMatch(worker, /default_api_key|DEMO_BUGS|DEMO_HEALTH|demoJsonEvidence|example\.com|mock data/i, 'Worker must not expose keys or demo state');
assert.match(worker, /pathname\.startsWith\('\/api\/private\/billing\/'\)/, 'private billing proxy must remain explicit');
assert.match(worker, /X-BOQA-Sig/);
assert.match(worker, /X-BOQA-Ts/);
assert.match(worker, /no-store, max-age=0/);
assert.doesNotMatch(worker, /cacheTtl|caches\.default|s-maxage/i, 'runtime state must not be edge-cached');
assert.doesNotMatch(worker, /Could not reach BOQA backend at/, 'Worker errors must not disclose backend URL');

console.log('Dashboard smoke test: PASS');
