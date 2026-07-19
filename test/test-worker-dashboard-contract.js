'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const worker = fs.readFileSync(path.join(root, 'worker.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'dashboard', 'index.html'), 'utf8');
const app = fs.readFileSync(path.join(root, 'dashboard', 'app.js'), 'utf8');
const state = fs.readFileSync(path.join(root, 'dashboard', 'dashboard-state.js'), 'utf8');

assert.match(worker, /'\/api\/hunter\/status'/, 'hunter status must be an explicit public read path');
assert.match(worker, /'\/api\/health'/, 'health must be an explicit public read path');
assert.match(worker, /request\.method === 'GET'/, 'public state access must remain read-only');
assert.match(worker, /function isPrivateSurface\(pathname\)/, 'private surface classifier must remain explicit');
assert.match(worker, /normalized\.startsWith\('\/api\/private\/billing\/'\)/, 'private billing API must be concealed explicitly');
assert.match(worker, /if \(isPrivateSurface\(url\.pathname\)\)/, 'private surface must be intercepted before API and asset routing');
assert.doesNotMatch(worker, /isPrivateBilling/, 'private billing must not remain in the public proxy allowlist');
assert.match(worker, /worker_auth_not_configured/, 'Worker must fail closed when auth bindings are absent');
assert.match(worker, /backend_unavailable|backend_unreachable/, 'Worker must expose bounded backend failure states');
assert.match(worker, /proxyHeaders\.set\('X-API-Key', workerApiKey\)/, 'Worker must overwrite upstream API key');
assert.match(worker, /X-BOQA-Sig/);
assert.match(worker, /X-BOQA-Ts/);
assert.match(worker, /redirect:\s*'manual'/, 'Worker must not follow backend redirects');
assert.match(worker, /Cache-Control': 'no-store, max-age=0'/, 'JSON responses must be no-store');
assert.match(worker, /headers\.set\('Cache-Control', 'no-store, max-age=0'\)/, 'proxied state must be no-store');

const allowlistMatch = worker.match(/const publicReadPaths = new Set\(\[([\s\S]*?)\]\);/);
assert(allowlistMatch, 'public API allowlist must be explicit');
assert.doesNotMatch(allowlistMatch[1], /\/api\/runtime\/metrics|\/api\/defensive\/status|\/api\/bugs/, 'unused operational APIs must not be public');
assert.match(worker, /backendPath:\s*'\/api\/defensive\/status'/, 'legacy fallback must remain internal');
assert.match(worker, /normalizeLegacyHunterPayload/, 'legacy payload must be normalized before exposure');
assert.match(worker, /legacy_hunter_contract_invalid/, 'invalid legacy payload must fail closed');
assert.doesNotMatch(worker, /DEMO_|demoJsonEvidence|mock data|caches\.default|cacheTtl|s-maxage/i, 'demo and edge caching must be absent');
assert.doesNotMatch(app + html, /\/api\/defensive\/status|\/api\/bugs|\/api\/findings/, 'dashboard must not consume legacy synthetic sources');
assert.match(state, /cache:\s*'no-store'/, 'browser fetch must explicitly bypass caches');

console.log('Worker/dashboard contract: PASS');
