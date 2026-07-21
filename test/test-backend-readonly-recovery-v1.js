'use strict';

const assert = require('assert');
const fs = require('fs');

const workflowPath = '.github/workflows/boqa-backend-readonly-recovery-v1.yml';
const workflow = fs.readFileSync(workflowPath, 'utf8');
const exactBase = 'fb1cc8bcfbf0f3d76d5f8860619e953266a388b6';
const exactBranch = 'deploy/boqa-backend-readonly-recovery-v1';
const originalCommand = 'boqa-readonly-inspection-v1-fb1cc8bcfbf0f3d76d5f8860619e953266a388b6';
const originalScriptSha = 'bf01b6b9988ac7d902ddd4cfd59a1ccb1b3bcef2168880a9b106e56b3e47fc41';

assert.match(workflow, /^on:\n  pull_request:\n    branches:\n      - deploy\/boqa-backend-readonly-inspection-v1\n    types:\n      - labeled/m);
assert.doesNotMatch(workflow, /^\s+(pull_request_target|push|schedule|workflow_dispatch):/m);
assert.match(workflow, /permissions:\n  contents: read/);
assert.doesNotMatch(workflow, /permissions:\s*write|contents:\s*write|actions:\s*write/);
assert.match(workflow, /github\.event\.pull_request\.number == 29/);
assert.match(workflow, /github\.event\.pull_request\.draft == true/);
assert.match(workflow, new RegExp(`github\\.event\\.pull_request\\.base\\.sha == '${exactBase}'`));
assert.match(workflow, new RegExp(`github\\.event\\.pull_request\\.head\\.ref == '${exactBranch}'`));
assert.match(workflow, /github\.event\.pull_request\.head\.repo\.full_name == github\.repository/);
assert.match(workflow, /github\.actor == github\.repository_owner/);
assert.match(workflow, /github\.run_attempt == 1/);
assert.match(workflow, /BOQA_BACKEND_RECOVERY_AUTHORIZED_SHA/);
assert.match(workflow, new RegExp(originalCommand));
assert.match(workflow, new RegExp(originalScriptSha));
assert.match(workflow, /test "\$EVENT_BASE_SHA" = "\$RECOVERY_BASE_SHA"/);
assert.match(workflow, /test "\$source_service_sha" = "\$EXPECTED_SCRIPT_SHA256"/);
assert.match(workflow, /test "\$source_local_sha" = "\$EXPECTED_SCRIPT_SHA256"/);
assert.match(workflow, /EXISTING_COMMAND_MATCH_COUNT/);
assert.match(workflow, /EXISTING_COMMAND_RECOVERY=COMPLETE/);
assert.match(workflow, /BACKEND_DEPLOYABILITY=NOT_EVALUATED/);
assert.match(workflow, /\' \/tmp\/recovered-output\.txt >\/dev\/null\n          cp \/tmp\/recovered-output\.txt "\$EVIDENCE_DIR\/inspection\.json"/);

for (const operation of ['cr' + 'eate', 'can' + 'cel', 'de' + 'lete']) {
  assert.doesNotMatch(workflow, new RegExp(`oci\\s+instance-agent\\s+command\\s+${operation}\\b`));
  assert.doesNotMatch(workflow, new RegExp(`oci\\s+instance-agent\\s+command-execution\\s+${operation}\\b`));
}
assert.strictEqual((workflow.match(/oci\s+instance-agent\s+command\s+list\b/g) || []).length, 1);
assert.strictEqual((workflow.match(/oci\s+instance-agent\s+command\s+get\b/g) || []).length, 1);
assert.strictEqual((workflow.match(/oci\s+instance-agent\s+command-execution\s+get\b/g) || []).length, 1);
assert.doesNotMatch(workflow, /oci\s+instance-agent\s+command-execution\s+list\b/);
assert.doesNotMatch(workflow, /docker\s+(start|stop|restart|rm|rmi|pull|push|build|run|exec|update|rename|tag|network|volume|compose)\b/);
assert.doesNotMatch(workflow, /BACKEND_INSPECTION=PASS|BACKEND_DEPLOYABILITY=PASS/);

const beforeSteps = workflow.slice(0, workflow.indexOf('\n    steps:'));
assert.doesNotMatch(beforeSteps, /secrets\./, 'OCI secrets must not be job-wide');
const configureStep = workflow.match(/- name: Configure isolated OCI profile and exact target[\s\S]*?\n      - name:/)?.[0] || '';
for (const name of [
  'OCI_TENANCY_OCID', 'OCI_USER_OCID', 'OCI_FINGERPRINT', 'OCI_PRIVATE_KEY',
  'OCI_REGION', 'OCI_COMPARTMENT_OCID', 'OCI_INSTANCE_OCID',
]) assert.match(configureStep, new RegExp(`secrets\\.${name}`));

const resolveIndex = workflow.indexOf('- name: Resolve and authenticate exactly one existing command');
const recoverIndex = workflow.indexOf('- name: Recover terminal state and sanitized output from existing command');
const cleanupIndex = workflow.indexOf('- name: Remove temporary credentials, payload and identifiers before artifact handling');
const checksumIndex = workflow.indexOf('- name: Verify sanitized recovery evidence checksums');
const uploadIndex = workflow.indexOf('- name: Upload sanitized recovery evidence');
assert.ok(resolveIndex > 0 && recoverIndex > resolveIndex);
assert.ok(cleanupIndex > recoverIndex);
assert.ok(checksumIndex > cleanupIndex);
assert.ok(uploadIndex > cleanupIndex);

assert.match(workflow, /new_command_created:false/);
assert.match(workflow, /command_canceled:false/);
assert.match(workflow, /production_changed:false/);
assert.match(workflow, /raw_output_recorded:false/);
assert.match(workflow, /rm -f \/tmp\/instance\.json \/tmp\/commands\.json \/tmp\/command\.json \/tmp\/command-id \/tmp\/original-script\.b64 \/tmp\/original-script\.txt/);
assert.doesNotMatch(workflow, /path:\s*\/tmp|path:\s*\$HOME/);

console.log('backend read-only recovery workflow policy: PASS');

const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

function extractRunStep(name) {
  const marker = `      - name: ${name}\n        run: |\n`;
  const start = workflow.indexOf(marker);
  assert.ok(start >= 0, `missing workflow step: ${name}`);
  const bodyStart = start + marker.length;
  const next = workflow.indexOf('\n      - name:', bodyStart);
  const block = workflow.slice(bodyStart, next < 0 ? workflow.length : next);
  return block.split('\n').map((line) => line.startsWith('          ') ? line.slice(10) : line).join('\n');
}

const resolveScript = extractRunStep('Resolve and authenticate exactly one existing command');
const recoverScript = extractRunStep('Recover terminal state and sanitized output from existing command');
const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-recovery-fixture-'));
const mockBin = path.join(fixtureRoot, 'bin');
const evidenceDir = path.join(fixtureRoot, 'evidence');
fs.mkdirSync(mockBin);
fs.mkdirSync(evidenceDir);

const synthetic = {
  compartment: 'compartment-synthetic',
  instance: 'instance-synthetic',
  command: 'command-synthetic',
};
const payload = 'synthetic fixed payload\n';
const payloadSha = crypto.createHash('sha256').update(payload).digest('hex');
const inspection = {
  v: 1,
  class: 'INSPECTED',
  docker: 'DIRECT',
  containers: 1,
  image_ref_sha: 'a'.repeat(64),
  image_id_sha: 'b'.repeat(64),
  restart: 'always',
  mounts: 1,
  rw_mounts: 1,
  output_mount: true,
  port_bindings: 1,
  rollback_count: 0,
  rollback_set_sha: '',
  health_http: '200',
  health_status: 'ok',
  health_json: true,
  release_sha: 'c'.repeat(40),
  hunter_http: '404',
  hunter_state: 'missing',
  hunter_json: false,
  hunter_keys_sha: '',
  log_lines: 0,
  log_critical: 0,
  log_secret_terms: 0,
  state_mutation_command_attempted: false,
};
const recoveredText = `${JSON.stringify(inspection)}\n`;
const recoveredSha = crypto.createHash('sha256').update(recoveredText).digest('hex');
const commandName = originalCommand;
const shellQuote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
const mockOci = `#!/usr/bin/env bash
set -e
case "$*" in
  "compute instance get --instance-id ${synthetic.instance} --no-retry")
    printf '%s\\n' ${shellQuote(JSON.stringify({ data: { id: synthetic.instance, 'compartment-id': synthetic.compartment, 'lifecycle-state': 'RUNNING' } }))} ;;
  "instance-agent command list --compartment-id ${synthetic.compartment} --all --no-retry")
    printf '%s\\n' ${shellQuote(JSON.stringify({ data: [{ id: synthetic.command, 'display-name': commandName }] }))} ;;
  "instance-agent command get --command-id ${synthetic.command} --no-retry")
    printf '%s\\n' ${shellQuote(JSON.stringify({ data: {
      id: synthetic.command,
      'display-name': commandName,
      'compartment-id': synthetic.compartment,
      target: { 'instance-id': synthetic.instance },
      'timeout-in-seconds': 120,
      content: { source: { 'source-type': 'TEXT', 'text-sha256': payloadSha, text: payload }, output: { 'output-type': 'TEXT' } },
    } }))} ;;
  "instance-agent command-execution get --command-id ${synthetic.command} --instance-id ${synthetic.instance} --no-retry")
    printf '%s\\n' ${shellQuote(JSON.stringify({ data: { 'lifecycle-state': 'SUCCEEDED', content: { 'exit-code': 0, 'text-sha256': recoveredSha, text: recoveredText } } }))} ;;
  *) printf 'unexpected OCI fixture call: %s\\n' "$*" >&2; exit 90 ;;
esac
`;
const mockOciPath = path.join(mockBin, 'oci');
fs.writeFileSync(mockOciPath, mockOci, { mode: 0o755 });
fs.writeFileSync('/tmp/oci-compartment-id', synthetic.compartment, { mode: 0o600 });
fs.writeFileSync('/tmp/oci-instance-id', synthetic.instance, { mode: 0o600 });
fs.writeFileSync(path.join(evidenceDir, 'manifest.json'), JSON.stringify({
  existing_command_resolved: false,
  new_command_created: false,
  command_canceled: false,
  terminal_state_observed: false,
  sanitized_output_recorded: false,
  production_changed: false,
  deploy_performed: false,
  restart_performed: false,
  rollback_executed: false,
}));
const fixtureEnv = {
  ...process.env,
  PATH: `${mockBin}:${process.env.PATH}`,
  EVIDENCE_DIR: evidenceDir,
  EXPECTED_COMMAND_NAME: commandName,
  EXPECTED_SCRIPT_SHA256: payloadSha,
};
for (const [name, script] of [['resolve', resolveScript], ['recover', recoverScript]]) {
  const result = spawnSync('bash', ['-c', script], { cwd: process.cwd(), env: fixtureEnv, encoding: 'utf8' });
  assert.strictEqual(result.status, 0, `${name} fixture failed:\n${result.stdout}\n${result.stderr}`);
}
const recoveredEvidence = JSON.parse(fs.readFileSync(path.join(evidenceDir, 'inspection.json'), 'utf8'));
assert.deepStrictEqual(recoveredEvidence, inspection);
const recoveredManifest = JSON.parse(fs.readFileSync(path.join(evidenceDir, 'manifest.json'), 'utf8'));
assert.strictEqual(recoveredManifest.existing_command_resolved, true);
assert.strictEqual(recoveredManifest.terminal_state_observed, true);
assert.strictEqual(recoveredManifest.sanitized_output_recorded, true);
assert.strictEqual(recoveredManifest.new_command_created, false);
assert.strictEqual(recoveredManifest.command_canceled, false);
assert.match(fs.readFileSync(path.join(evidenceDir, 'result.txt'), 'utf8'), /EXISTING_COMMAND_RECOVERY=COMPLETE/);

for (const tempFile of [
  '/tmp/oci-compartment-id', '/tmp/oci-instance-id', '/tmp/command-id', '/tmp/instance.json',
  '/tmp/commands.json', '/tmp/command.json', '/tmp/original-script.b64', '/tmp/original-script.txt',
  '/tmp/execution.json', '/tmp/recovered-output.b64', '/tmp/recovered-output.txt', '/tmp/manifest.json',
  '/tmp/execution-evidence.json',
]) fs.rmSync(tempFile, { force: true });
fs.rmSync(fixtureRoot, { recursive: true, force: true });
console.log('backend read-only recovery synthetic existing-command fixture: PASS');
