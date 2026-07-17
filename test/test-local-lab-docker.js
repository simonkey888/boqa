'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { assertComposePolicy } = require('../lib/soak-qualification-helpers');

const root = path.resolve(__dirname, '..');
const probe = spawnSync('docker', ['compose', 'version'], { encoding: 'utf8' });
if (probe.status !== 0) {
  console.log('Docker unavailable: SKIP (real Docker remains mandatory in qualification workflow)');
  process.exit(0);
}

const evidenceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-compose-config-'));
const configured = spawnSync('docker', [
  'compose',
  '-f',
  path.join(root, 'compose.lab.yaml'),
  'config',
  '--format',
  'json',
], {
  cwd: root,
  encoding: 'utf8',
  env: {
    ...process.env,
    BOQA_REPO_ROOT: root,
    BOQA_EVIDENCE_DIR: evidenceDir,
    BOQA_ROUND_ID: 'config-validation',
  },
});

try {
  assert.equal(configured.status, 0, configured.stderr || configured.stdout);
  const model = JSON.parse(configured.stdout);
  assertComposePolicy(model);
  assert.deepEqual(
    model.services.candidate.healthcheck?.test?.slice(0, 2),
    ['CMD', '/nodejs/bin/node'],
    'Juice Shop uses a distroless Node image; healthcheck must invoke its absolute runtime path',
  );
  console.log('local lab docker config: PASS');
} finally {
  fs.rmSync(evidenceDir, { recursive: true, force: true });
}
