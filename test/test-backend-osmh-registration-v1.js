'use strict';

const assert = require('assert');
const fs = require('fs');

const workflow = fs.readFileSync('.github/workflows/boqa-backend-osmh-registration-v1.yml', 'utf8');
const base = '7cffe43e457b91ade200268cf43c782d127ecb1b';
const branch = 'deploy/boqa-backend-osmh-agent-inventory-v1';

assert.match(workflow, /^on:\n  pull_request:\n    branches:\n      - deploy\/boqa-backend-agent-compatibility-diagnostic-v1\n    types:\n      - labeled/m);
assert.doesNotMatch(workflow, /^\s+(pull_request_target|push|schedule|workflow_dispatch):/m);
assert.match(workflow, /permissions:\n  contents: read/);
assert.match(workflow, /github\.event\.pull_request\.number == 0/);
assert.match(workflow, /github\.event\.pull_request\.draft == true/);
assert.match(workflow, new RegExp(`github\\.event\\.pull_request\\.base\\.sha == '${base}'`));
assert.match(workflow, new RegExp(`github\\.event\\.pull_request\\.head\\.ref == '${branch}'`));
assert.match(workflow, /github\.actor == github\.repository_owner/);
assert.match(workflow, /BOQA_AUTONOMOUS_READONLY=AUTHORIZED/);
assert.match(workflow, /github\.run_attempt == 1/);
assert.match(workflow, /github\.run_number == 1/);
assert.match(workflow, /EXPECTED_PR_NUMBER: '0'/);

assert.strictEqual((workflow.match(/oci\s+compute\s+instance\s+get\b/g) || []).length, 1);
assert.strictEqual((workflow.match(/oci\s+os-management-hub\s+managed-instance\s+list\b/g) || []).length, 1);
assert.doesNotMatch(workflow, /oci\s+os-management-hub\s+managed-instance\s+(install|remove|update|reboot|delete|attach|detach|enable|disable|refresh|switch)\b/);
assert.doesNotMatch(workflow, /oci\s+instance-agent\s+command(?:-execution)?\b/);
assert.doesNotMatch(workflow, /oci\s+compute\s+instance\s+(update|action|terminate|launch)\b/);
assert.doesNotMatch(workflow, /systemctl|service\s+oracle|yum\s|apt(?:-get)?\s|dnf\s|snap\s+(install|remove|refresh)|docker\s/);

for (const classification of [
  'OSMH_ACCESS_BLOCKED',
  'OSMH_NOT_REGISTERED',
  'OSMH_INSTANCE_AMBIGUOUS',
  'OSMH_REGISTERED',
]) assert.match(workflow, new RegExp(classification));

assert.match(workflow, /OSMH_REGISTRATION_DIAGNOSTIC=COMPLETE/);
assert.match(workflow, /BACKEND_INSPECTED=false/);
assert.match(workflow, /PRODUCTION_CHANGED=false/);
assert.match(workflow, /identifiers_recorded:false/);
assert.match(workflow, /raw_managed_instances_recorded:false/);
assert.match(workflow, /raw_error_recorded:false/);
assert.doesNotMatch(workflow, /path:\s*\/tmp|path:\s*\$HOME/);

const diagnose = workflow.indexOf('- name: Diagnose OSMH registration');
const cleanup = workflow.indexOf('- name: Remove temporary credentials and raw responses');
const checksums = workflow.indexOf('- name: Verify sanitized evidence checksums');
const upload = workflow.indexOf('- name: Upload sanitized diagnostic evidence');
assert.ok(diagnose > 0 && cleanup > diagnose && checksums > cleanup && upload > cleanup);

console.log('backend OSMH registration v1 policy: PASS');
