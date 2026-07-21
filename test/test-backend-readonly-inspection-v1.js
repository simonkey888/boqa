'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const workflowPath = '.github/workflows/boqa-backend-readonly-inspection-v1.yml';
const scriptPath = '.github/scripts/boqa-backend-readonly-inspection-v1.sh';
const workflow = fs.readFileSync(workflowPath, 'utf8');
const script = fs.readFileSync(scriptPath, 'utf8');
const exactBase = '335a76afc303b7411737a729bdff2a761ce67d39';
const exactBranch = 'deploy/boqa-backend-readonly-inspection-v1';

assert.match(workflow, /^on:\n  pull_request:\n    branches:\n      - deploy\/boqa-backend-preflight-v2\n    types:\n      - labeled/m);
assert.doesNotMatch(workflow, /^\s+(pull_request_target|push|schedule|workflow_dispatch):/m);
assert.match(workflow, /permissions:\n  contents: read/);
assert.doesNotMatch(workflow, /permissions:\s*write|contents:\s*write|actions:\s*write/);
assert.match(workflow, /github\.event\.pull_request\.number == 28/);
assert.match(workflow, /github\.event\.pull_request\.draft == true/);
assert.match(workflow, new RegExp(`github\\.event\\.pull_request\\.base\\.sha == '${exactBase}'`));
assert.match(workflow, new RegExp(`github\\.event\\.pull_request\\.head\\.ref == '${exactBranch}'`));
assert.match(workflow, /github\.event\.pull_request\.head\.repo\.full_name == github\.repository/);
assert.match(workflow, /github\.actor == github\.repository_owner/);
assert.match(workflow, /github\.run_attempt == 1/);
assert.match(workflow, /BOQA_BACKEND_INSPECTION_AUTHORIZED_SHA/);
assert.match(workflow, /test "\$EVENT_BASE_SHA" = "\$STACK_BASE_SHA"/);
assert.match(workflow, /test "\$returned_id" = "\$instance_id"/);
assert.match(workflow, /test "\$returned_compartment" = "\$compartment_id"/);
assert.match(workflow, /oci instance-agent command list[\s\S]*COMMAND_ALREADY_EXISTS_FOR_SOURCE_SHA/);
assert.match(workflow, /boqa-readonly-inspection-v1-\$\{SOURCE_SHA\}/);
assert.match(workflow, /textSha256:\$sha/);
assert.match(workflow, /--no-retry[\s\S]*--query data\.id/);
assert.match(workflow, /--timeout-in-seconds 120/);
assert.match(workflow, /\[\[ "\$service_sha" =~ \^\[0-9a-f\]\{64\}\$ \]\]/);
assert.match(workflow, /test "\$service_sha" = "\$local_sha"/);
assert.match(workflow, /BACKEND_READONLY_INSPECTION=COMPLETE/);
assert.match(workflow, /BACKEND_DEPLOYABILITY=NOT_EVALUATED/);
assert.match(workflow, /SCRIPT_POLICY=FORBIDDEN_HOST_MUTATION/);
assert.match(workflow, /SCRIPT_POLICY=FORBIDDEN_DOCKER_MUTATION/);
assert.doesNotMatch(workflow, /BACKEND_READONLY_INSPECTION=PASS/);
assert.doesNotMatch(workflow, /OBJECT_STORAGE/i);

const beforeSteps = workflow.slice(0, workflow.indexOf('\n    steps:'));
assert.doesNotMatch(beforeSteps, /secrets\./, 'OCI secrets must not be job-wide');
const configureStep = workflow.match(/- name: Configure isolated OCI profile and exact target[\s\S]*?\n      - name:/)?.[0] || '';
for (const name of [
  'OCI_TENANCY_OCID', 'OCI_USER_OCID', 'OCI_FINGERPRINT', 'OCI_PRIVATE_KEY',
  'OCI_REGION', 'OCI_COMPARTMENT_OCID', 'OCI_INSTANCE_OCID',
]) assert.match(configureStep, new RegExp(`secrets\\.${name}`));

assert.ok(Buffer.byteLength(script, 'utf8') <= 4000, 'inline OCI script exceeds 4000 bytes');
assert.strictEqual(spawnSync('bash', ['-n', scriptPath]).status, 0, 'inspection script syntax failed');
assert.match(script, /^#!/);
assert.match(script, /"state_mutation_command_attempted":false/);
assert.doesNotMatch(script, /"mutated":false|"mutation_attempted":false/);
assert.strictEqual((script.match(/http:\/\/127\.0\.0\.1\/api\/health/g) || []).length, 1);
assert.strictEqual((script.match(/http:\/\/127\.0\.0\.1\/api\/hunter\/status/g) || []).length, 1);
assert.doesNotMatch(script, /https?:\/\/(?!127\.0\.0\.1)/);
assert.match(script, /--no-trunc/);
assert.match(script, /BLOCKED_INSPECT_INCOMPLETE/);
assert.match(script, /\.Source=="\/var\/lib\/boqa\/output" and \.Destination=="\/app\/output" and \.RW==true/);
assert.doesNotMatch(script, /curl.*(--request|-X)/i);
assert.match(script, /--tail 200/);

const dockerCalls = [...script.matchAll(/"\$\{D\[@\]\}"\s+(ps|inspect|image\s+ls|logs)\b/g)].map((m) => m[1]);
assert.deepStrictEqual(dockerCalls.sort(), ['image ls', 'inspect', 'logs', 'ps']);

const mockDir = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-readonly-test-'));
const writeExe = (name, content) => {
  const file = path.join(mockDir, name);
  fs.writeFileSync(file, content, { mode: 0o755 });
  return file;
};

writeExe('docker', `#!/usr/bin/env bash
set -e
case "\${1:-}" in
  version) [ "\${MOCK_DOCKER_ACCESS:-1}" = 1 ] ;;
  ps)
    case "\${MOCK_CONTAINER_COUNT:-1}" in
      0) exit 0 ;;
      2) printf 'abc123\ndef456\n' ;;
      *) printf 'abc123\n' ;;
    esac ;;
  inspect)
    if [ "\${MOCK_INCOMPLETE:-0}" = 1 ]; then
      printf '%s\n' '[{"Config":{"Image":"","Env":[]},"Image":"","HostConfig":{"RestartPolicy":{"Name":"always"}},"Mounts":[],"NetworkSettings":{"Ports":{}}}]'
    else
      printf '%s\n' '[{"Config":{"Image":"registry.local:5000/team/boqa:current","Env":["BOQA_RELEASE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},"Image":"sha256:1111111111111111111111111111111111111111111111111111111111111111","HostConfig":{"RestartPolicy":{"Name":"always"}},"Mounts":[{"Source":"/var/lib/boqa/output","Destination":"/app/output","RW":true}],"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"80"}]}}}]'
    fi ;;
  image)
    [ "\${2:-}" = ls ]
    [ "\${3:-}" = 'registry.local:5000/team/boqa' ]
    printf '%s\n' "$*" | grep -q -- '--no-trunc'
    printf '%s\n' 'sha256:1111111111111111111111111111111111111111111111111111111111111111'
    [ "\${MOCK_NO_ROLLBACK:-0}" = 1 ] || printf '%s\n' 'sha256:2222222222222222222222222222222222222222222222222222222222222222' ;;
  logs) [ "\${MOCK_EMPTY_LOGS:-0}" = 1 ] || printf 'service started\nerror synthetic\n' ;;
  *) exit 2 ;;
esac
`);
writeExe('curl', `#!/usr/bin/env bash
set -e
url="\${!#}"
case "$url" in
  http://127.0.0.1/api/health)
    printf '{"status":"ok","release_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}\n200' ;;
  http://127.0.0.1/api/hunter/status)
    if [ "\${MOCK_HUNTER_INVALID:-0}" = 1 ]; then printf '<html>missing</html>\n404';
    else printf '{"state":"FRESH","heartbeat":"synthetic"}\n200'; fi ;;
  *) exit 3 ;;
esac
`);
writeExe('sudo', '#!/usr/bin/env bash\nexit 1\n');

function runFixture(extraEnv = {}) {
  const result = spawnSync('bash', [scriptPath], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: { ...process.env, PATH: `${mockDir}:${process.env.PATH}`, ...extraEnv },
  });
  assert.strictEqual(result.status, 0, result.stderr || result.stdout);
  assert.ok(Buffer.byteLength(result.stdout, 'utf8') <= 1024, 'sanitized output exceeds OCI 1KB limit');
  return JSON.parse(result.stdout);
}

const good = runFixture();
assert.strictEqual(good.class, 'INSPECTED');
assert.strictEqual(good.containers, 1);
assert.strictEqual(good.output_mount, true);
assert.strictEqual(good.rollback_count, 1);
assert.match(good.rollback_set_sha, /^[0-9a-f]{64}$/);
assert.strictEqual(good.health_json, true);
assert.strictEqual(good.hunter_json, true);
assert.match(good.hunter_keys_sha, /^[0-9a-f]{64}$/);
assert.strictEqual(good.state_mutation_command_attempted, false);

const emptyLogs = runFixture({ MOCK_EMPTY_LOGS: '1' });
assert.strictEqual(emptyLogs.log_lines, 0);
assert.strictEqual(emptyLogs.log_critical, 0);
assert.strictEqual(emptyLogs.log_secret_terms, 0);

const noRollback = runFixture({ MOCK_NO_ROLLBACK: '1' });
assert.strictEqual(noRollback.rollback_count, 0);
assert.strictEqual(noRollback.rollback_set_sha, '');

const incomplete = runFixture({ MOCK_INCOMPLETE: '1' });
assert.strictEqual(incomplete.class, 'BLOCKED_INSPECT_INCOMPLETE');
assert.strictEqual(incomplete.image_ref_sha, '');
assert.strictEqual(incomplete.image_id_sha, '');

const invalidHunter = runFixture({ MOCK_HUNTER_INVALID: '1' });
assert.strictEqual(invalidHunter.class, 'INSPECTED');
assert.strictEqual(invalidHunter.hunter_http, '404');
assert.strictEqual(invalidHunter.hunter_json, false);
assert.strictEqual(invalidHunter.hunter_keys_sha, '');

for (const count of ['0', '2']) {
  const ambiguous = runFixture({ MOCK_CONTAINER_COUNT: count });
  assert.strictEqual(ambiguous.class, 'BLOCKED_CONTAINER_AMBIGUITY');
  assert.strictEqual(ambiguous.containers, Number(count));
}
const noDocker = runFixture({ MOCK_DOCKER_ACCESS: '0' });
assert.strictEqual(noDocker.class, 'BLOCKED_DOCKER_ACCESS');
assert.strictEqual(noDocker.docker, 'NO');

fs.rmSync(mockDir, { recursive: true, force: true });
console.log('backend read-only inspection workflow policy and synthetic fixtures: PASS');
