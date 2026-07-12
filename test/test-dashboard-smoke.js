'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'dashboard', 'index.html'), 'utf8');
const app = fs.readFileSync(path.join(root, 'dashboard', 'app.js'), 'utf8');
const worker = fs.readFileSync(path.join(root, 'worker.js'), 'utf8');

assert.match(html, /<script\s+src=["']\/app\.js["']><\/script>/, 'dashboard must load /app.js');
assert.match(app, /verifyAccess\(\)/, 'dashboard must initialize');
assert.doesNotMatch(app, /['"]X-API-Key['"]\s*:/, 'browser must not send backend API key');
assert.doesNotMatch(app + html, /localStorage|auth-gate|modal de clave/i, 'dashboard must not contain a browser credential gate');
assert.doesNotMatch(app, /uptimeStart\s*:\s*Date\.now/, 'browser must not invent server uptime');
assert.match(app, /server_uptime_ms/, 'dashboard must consume server uptime');
assert.match(worker, /proxyHeaders\.set\('X-API-Key', workerApiKey\)/, 'Worker must overwrite upstream API key');
assert.doesNotMatch(worker, /default_api_key/, 'health must not expose a key');

console.log('Dashboard smoke test: PASS');
