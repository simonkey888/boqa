'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { validateText } = require('../scripts/validate-workflow-policy');

const root = path.resolve(__dirname, '..');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/boqa-p21-external-labs.yml'), 'utf8');
const plane = fs.readFileSync(path.join(root, 'qualification/p21/runners/docker-plane.sh'), 'utf8');
const probe = fs.readFileSync(path.join(root, 'qualification/p21/fixtures/smoke-lab/isolation-probe.js'), 'utf8');

for (const required of [
  'permissions:\n  contents: read',
  'pull_request:',
  'workflow_dispatch:',
  "if: github.event_name == 'workflow_dispatch'",
  'timeout-minutes:',
  'BOQA_ADMIN_EXECUTION_ENABLED: "false"',
  'BOQA_AUTO_ANALYZE: "false"',
  'BOQA_OTEL_ENABLED: "false"',
]) assert(workflow.includes(required), `workflow missing ${required}`);

assert.strictEqual(validateText(workflow).length, 0, JSON.stringify(validateText(workflow)));
for (const forbidden of ['pull_request_target', 'write-all', '--privileged', '--network host', '/var/run/docker.sock', ':latest']) {
  assert(!workflow.includes(forbidden), `workflow contains ${forbidden}`);
  assert(!plane.includes(forbidden), `plane contains ${forbidden}`);
}

for (const required of [
  'docker network create --internal', '--read-only', '--cap-drop ALL',
  '--security-opt no-new-privileges', '--memory 128m', '--cpus 0.50',
  '--pids-limit 64', '--tmpfs', '--dns 127.0.0.1', 'trap cleanup',
  'docker volume ls', 'docker network ls', 'docker ps -aq',
]) assert(plane.includes(required), `plane missing ${required}`);

for (const required of ['external.invalid.', '1.1.1.1', '169.254.169.254', 'foreign_scenario_connected', 'host_gateway_connected']) {
  assert(probe.includes(required), `probe missing ${required}`);
}

console.log('P2.1 Docker execution-plane policy: PASS');
