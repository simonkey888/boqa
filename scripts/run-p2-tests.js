#!/usr/bin/env node
'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const files = fs.readdirSync(path.join(root, 'test')).filter(file => /^test-p2.*\.js$/.test(file)).sort();
let failed = 0;
for (const file of files) {
  const result = spawnSync(process.execPath, [path.join(root, 'test', file)], {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, BOQA_OTEL_ENABLED: 'false', BOQA_AUTO_ANALYZE: 'false', BOQA_ADMIN_EXECUTION_ENABLED: 'false', PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1' },
  });
  if (result.status !== 0) failed++;
}
console.log(`P2 focused files: ${files.length}; failed: ${failed}`);
process.exit(failed ? 1 : 0);
