'use strict';

const fs = require('fs');
const path = require('path');
const { validateText } = require('../scripts/validate-workflow-policy');
const { scanFiles } = require('../scripts/scan-changed-secrets');

let passed = 0;
let failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`PASS ${name}`); }
  catch (error) { failed++; console.error(`FAIL ${name}: ${error.message}`); }
}
function assert(value, message) { if (!value) throw new Error(message); }

test('workflow policy rejects every forbidden capability', () => {
  const fixtures = [
    'on:\n  pull_request_target:', 'permissions: write-all',
    'BOQA_ADMIN_EXECUTION_ENABLED: true', 'BOQA_AUTO_ANALYZE: true', 'BOQA_OTEL_ENABLED: true',
    'run: curl https://boqa.simondalmasso44.workers.dev/health', 'run: ssh host',
    'run: cloudflared tunnel', 'run: wrangler deploy', 'run: oci compute instance list',
  ];
  for (const fixture of fixtures) assert(validateText(fixture).length === 1, `unsafe fixture accepted: ${fixture}`);
});

test('fail-closed workflow fixture passes policy', () => {
  const fixture = `permissions:\n  contents: read\nenv:\n  BOQA_ADMIN_EXECUTION_ENABLED: "false"\n  BOQA_AUTO_ANALYZE: "false"\n  BOQA_OTEL_ENABLED: "false"`;
  assert(validateText(fixture).length === 0, 'safe fixture rejected');
});

test('repository workflow is pull_request based, bounded and read-only', () => {
  const text = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'boqa-validation.yml'), 'utf8');
  assert(/pull_request\s*:/.test(text), 'pull_request trigger missing');
  assert(/workflow_dispatch\s*:/.test(text), 'workflow_dispatch missing');
  assert(/timeout-minutes\s*:/.test(text), 'timeout missing');
  assert(/contents\s*:\s*read/.test(text), 'read-only permission missing');
  assert(validateText(text).length === 0, 'workflow violates policy');
});

test('secret scanner reports only pattern category and filename', () => {
  const tmp = path.join(__dirname, '.secret-scan-fixture');
  const syntheticToken = ['github', 'pat', 'abcdefghijklmnopqrstuvwxyz123456'].join('_');
  fs.writeFileSync(tmp, syntheticToken);
  try {
    const findings = scanFiles([tmp]);
    assert(findings.length === 1 && findings[0].pattern === 'github_token', 'secret fixture not detected');
    assert(!JSON.stringify(findings).includes('abcdefghijklmnopqrstuvwxyz'), 'secret value returned');
  } finally { fs.unlinkSync(tmp); }
});

console.log(`\n${passed}/${passed + failed} tests passed`);
process.exit(failed ? 1 : 0);
