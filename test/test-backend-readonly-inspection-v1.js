'use strict';

const assert = require('assert');
const fs = require('fs');
const { spawnSync } = require('child_process');

const workflowPath = '.github/workflows/boqa-backend-readonly-inspection-v1.yml';
const scriptPath = '.github/scripts/boqa-backend-readonly-inspection-v1.sh';
const workflow = fs.readFileSync(workflowPath, 'utf8');
const script = fs.readFileSync(scriptPath, 'utf8');

assert.match(workflow, /^on:\n  pull_request:\n    branches:\n      - deploy\/boqa-backend-preflight-v2\n    types:\n      - labeled/m);
assert.doesNotMatch(workflow, /^\s+(pull_request_target|push|schedule|workflow_dispatch):/m);
assert.match(workflow, /permissions:\n  contents: read/);
assert.match(workflow, /cancel-in-progress: false/);
assert.match(workflow, /authorized-backend-readonly-inspection/);
assert.match(workflow, /BOQA_BACKEND_INSPECTION_AUTHORIZED_SHA/);
assert.match(workflow, /STACK_BASE_SHA: 335a76afc303b7411737a729bdff2a761ce67d39/);
assert.match(workflow, /--no-retry[\s\S]*--query data\.id/);
assert.match(workflow, /--timeout-in-seconds 120/);
assert.doesNotMatch(workflow, /pull_request_target/);
assert.doesNotMatch(workflow, /permissions:\s*write|contents:\s*write|actions:\s*write/);
assert.doesNotMatch(workflow, /OBJECT_STORAGE/i);

assert.ok(Buffer.byteLength(script, 'utf8') <= 4000, 'inline OCI script exceeds 4000 bytes');
assert.strictEqual(spawnSync('bash', ['-n', scriptPath]).status, 0, 'inspection script syntax failed');
assert.match(script, /^#!/);
assert.match(script, /"mutated":false/);
assert.match(script, /127\.0\.0\.1\/api\/health/);
assert.match(script, /127\.0\.0\.1\/api\/hunter\/status/);
assert.doesNotMatch(script, /https?:\/\/(?!127\.0\.0\.1)/);
assert.doesNotMatch(
  script,
  /(^|[;&|\s])(rm|mv|cp|install|chmod|chown|mkdir|touch|truncate|tee|dd|kill|pkill|reboot|shutdown|systemctl|service|apt|yum|dnf)([;&|\s]|$)/im,
);
assert.doesNotMatch(
  script,
  /docker\s+(start|stop|restart|rm|rmi|pull|push|build|run|exec|update|rename|tag|network|volume|compose)/i,
);
assert.doesNotMatch(script, /curl.*(--request|-X).*(POST|PUT|PATCH|DELETE)/i);
assert.doesNotMatch(script, />\s*\/(etc|var|opt|srv|home|root)\//);
assert.match(script, /--tail 200/);
assert.match(script, /grep -Fxv \"\$IID\"/);
assert.match(script, /BLOCKED_DOCKER_ACCESS/);
assert.match(script, /BLOCKED_CONTAINER_AMBIGUITY/);
assert.match(script, /CLASS=INSPECTED/);

console.log('backend read-only inspection workflow policy: PASS');
