'use strict';

const assert = require('assert');
const fs = require('fs');

const workflow = fs.readFileSync('.github/workflows/boqa-backend-instance-agent-diagnostic-v1.yml', 'utf8');
const base = 'a2a866d3d1d34bde20ab9e869c2aa380058cebab';
const branch = 'deploy/boqa-backend-instance-agent-diagnostic-v1';

assert.match(workflow, /^on:\n  pull_request:\n    branches:\n      - deploy\/boqa-backend-readonly-recovery-v1\n    types:\n      - labeled/m);
assert.doesNotMatch(workflow, /^\s+(pull_request_target|push|schedule|workflow_dispatch):/m);
assert.match(workflow, /permissions:\n  contents: read/);
assert.doesNotMatch(workflow, /permissions:\s*write|contents:\s*write|actions:\s*write/);
assert.match(workflow, /github\.event\.pull_request\.number == 30/);
assert.match(workflow, /github\.event\.pull_request\.draft == true/);
assert.match(workflow, new RegExp(`github\\.event\\.pull_request\\.base\\.sha == '${base}'`));
assert.match(workflow, new RegExp(`github\\.event\\.pull_request\\.head\\.ref == '${branch}'`));
assert.match(workflow, /github\.event\.pull_request\.head\.repo\.full_name == github\.repository/);
assert.match(workflow, /github\.actor == github\.repository_owner/);
assert.match(workflow, /BOQA_AUTONOMOUS_READONLY=AUTHORIZED/);
assert.match(workflow, /github\.run_attempt == 1/);
assert.match(workflow, /github\.run_number == 1/);
assert.match(workflow, /EXPECTED_PR_NUMBER: '30'/);
assert.match(workflow, /INSTANCE_AGENT_DIAGNOSTIC=COMPLETE/);
assert.match(workflow, /BACKEND_INSPECTED=false/);
assert.match(workflow, /PRODUCTION_CHANGED=false/);

assert.strictEqual((workflow.match(/oci\s+compute\s+instance\s+get\b/g) || []).length, 1);
assert.strictEqual((workflow.match(/oci\s+instance-agent\s+plugin\s+list\b/g) || []).length, 1);
assert.doesNotMatch(workflow, /oci\s+instance-agent\s+command(?:-execution)?\b/);
assert.doesNotMatch(workflow, /oci\s+compute\s+instance\s+(update|action|terminate|launch)\b/);
assert.doesNotMatch(workflow, /oci\s+instance-agent\s+plugin\s+(update|create|delete)\b/);
assert.doesNotMatch(workflow, /docker\s+(start|stop|restart|rm|rmi|pull|push|build|run|exec|update|rename|tag|network|volume|compose)\b/);
assert.doesNotMatch(workflow, /systemctl|service\s+oracle|yum\s|apt(?:-get)?\s|dnf\s/);

for (const classification of [
  'PLUGIN_RUNNING',
  'BLOCKED_ALL_PLUGINS_DISABLED',
  'BLOCKED_MANAGEMENT_DISABLED',
  'BLOCKED_PLUGIN_DESIRED_DISABLED',
  'BLOCKED_PLUGIN_STOPPED',
  'BLOCKED_PLUGIN_NOT_SUPPORTED',
  'BLOCKED_PLUGIN_INVALID',
  'BLOCKED_PLUGIN_MISSING',
  'BLOCKED_PLUGIN_AMBIGUOUS',
  'BLOCKED_AGENT_CONFIG_UNKNOWN',
]) assert.match(workflow, new RegExp(classification));

assert.match(workflow, /raw_plugin_message_recorded:false/);
assert.match(workflow, /raw_plugin_list_recorded:false/);
assert.match(workflow, /identifiers_recorded:false/);
assert.doesNotMatch(workflow, /path:\s*\/tmp|path:\s*\$HOME/);

const diagnose = workflow.indexOf('- name: Diagnose desired and observed Run Command plugin state');
const cleanup = workflow.indexOf('- name: Remove temporary credentials and raw responses');
const checksums = workflow.indexOf('- name: Verify sanitized evidence checksums');
const upload = workflow.indexOf('- name: Upload sanitized diagnostic evidence');
assert.ok(diagnose > 0 && cleanup > diagnose && checksums > cleanup && upload > cleanup);

console.log('backend instance agent diagnostic v1 policy: PASS');
