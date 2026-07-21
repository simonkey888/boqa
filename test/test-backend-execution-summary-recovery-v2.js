'use strict';

const assert = require('assert');
const fs = require('fs');

const path = '.github/workflows/boqa-backend-execution-summary-recovery-v2.yml';
const workflow = fs.readFileSync(path, 'utf8');
const base = 'fb1cc8bcfbf0f3d76d5f8860619e953266a388b6';
const branch = 'deploy/boqa-backend-readonly-recovery-v1';

assert.match(workflow, /^on:\n  pull_request:\n    branches:\n      - deploy\/boqa-backend-readonly-inspection-v1\n    types:\n      - labeled/m);
assert.doesNotMatch(workflow, /^\s+(pull_request_target|push|schedule|workflow_dispatch):/m);
assert.match(workflow, /permissions:\n  contents: read/);
assert.match(workflow, /github\.event\.pull_request\.number == 29/);
assert.match(workflow, /github\.event\.pull_request\.draft == true/);
assert.match(workflow, new RegExp(`github\\.event\\.pull_request\\.base\\.sha == '${base}'`));
assert.match(workflow, new RegExp(`github\\.event\\.pull_request\\.head\\.ref == '${branch}'`));
assert.match(workflow, /github\.event\.pull_request\.head\.repo\.full_name == github\.repository/);
assert.match(workflow, /github\.actor == github\.repository_owner/);
assert.match(workflow, /BOQA_AUTONOMOUS_READONLY=AUTHORIZED/);
assert.match(workflow, /github\.run_attempt == 1/);
assert.match(workflow, /github\.run_number == 1/);
assert.match(workflow, /EXPECTED_COMMAND_ID_SHA256: 30e89c9566194a082bbca401abc73f6d79bf011696fa14171df34827a6df636b/);
assert.match(workflow, /COMMAND_ID_HASH_MISMATCH/);
assert.match(workflow, /EXECUTION_SUMMARY_MATCH_COUNT/);
assert.match(workflow, /EXECUTION_SUMMARY_RECOVERY=COMPLETE/);
assert.match(workflow, /BACKEND_DEPLOYABILITY=NOT_EVALUATED/);

const forbidden = ['cre' + 'ate', 'can' + 'cel', 'del' + 'ete'];
for (const verb of forbidden) {
  assert.doesNotMatch(workflow, new RegExp(`oci\\s+instance-agent\\s+command\\s+${verb}\\b`));
  assert.doesNotMatch(workflow, new RegExp(`oci\\s+instance-agent\\s+command-execution\\s+${verb}\\b`));
}
assert.strictEqual((workflow.match(/oci\s+instance-agent\s+command\s+list\b/g) || []).length, 1);
assert.strictEqual((workflow.match(/oci\s+instance-agent\s+command-execution\s+list\b/g) || []).length, 1);
assert.doesNotMatch(workflow, /oci\s+instance-agent\s+command\s+get\b/);
assert.doesNotMatch(workflow, /oci\s+instance-agent\s+command-execution\s+get\b/);
assert.doesNotMatch(workflow, /BACKEND_DEPLOYABILITY=PASS/);

const collect = workflow.indexOf('- name: Recover exact execution summary without command get');
const cleanup = workflow.indexOf('- name: Remove temporary credentials and raw responses');
const checksums = workflow.indexOf('- name: Verify sanitized evidence checksums');
const upload = workflow.indexOf('- name: Upload sanitized recovery evidence');
assert.ok(collect > 0);
assert.ok(cleanup > collect);
assert.ok(checksums > cleanup);
assert.ok(upload > cleanup);
assert.match(workflow, /new_command_created:false/);
assert.match(workflow, /command_canceled:false/);
assert.match(workflow, /production_changed:false/);
assert.match(workflow, /raw_output_recorded:false/);
assert.doesNotMatch(workflow, /path:\s*\/tmp|path:\s*\$HOME/);

console.log('backend execution-summary recovery v2 policy: PASS');
