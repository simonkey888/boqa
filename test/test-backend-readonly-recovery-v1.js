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
assert.match(workflow, /github\.event\.pull_request\.number == 0/);
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
