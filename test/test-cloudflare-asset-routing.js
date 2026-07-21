'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const wrangler = fs.readFileSync(path.join(root, 'wrangler.toml'), 'utf8');
const worker = fs.readFileSync(path.join(root, 'worker.js'), 'utf8');

assert.match(wrangler, /\[assets\][\s\S]*run_worker_first\s*=\s*true/, 'Cloudflare must invoke the Worker before serving any static asset');
assert.match(wrangler, /binding\s*=\s*"ASSETS"/, 'Worker must retain the explicit assets binding');
assert.match(worker, /if \(isPrivateSurface\(url\.pathname\)\)/, 'Worker must intercept private paths');
assert(worker.indexOf('if (isPrivateSurface(url.pathname))') < worker.indexOf('env.ASSETS.fetch(request)'), 'private interception must run before asset lookup');

console.log('Cloudflare asset routing: PASS');
