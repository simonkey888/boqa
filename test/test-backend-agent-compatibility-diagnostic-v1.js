'use strict';

const assert = require('assert');
const fs = require('fs');

const workflow = fs.readFileSync('.github/workflows/boqa-backend-agent-compatibility-diagnostic-v1.yml', 'utf8');
const base = '38f47c3dae02393db3e79ed90cefe01b84c5e2d3';
const branch = 'deploy/boqa-backend-agent-compatibility-diagnostic-v1';

assert.match(workflow, /^on:\n  pull_request:\n    branches:\n      - deploy\/boqa-backend-instance-agent-diagnostic-v1\n    types:\n      - labeled/m);
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
assert.strictEqual((workflow.match(/oci\s+compute\s+image\s+get\b/g) || []).length, 1);
assert.strictEqual((workflow.match(/oci\s+instance-agent\s+available-plugins\s+get\b/g) || []).length, 1);
assert.strictEqual((workflow.match(/oci\s+instance-agent\s+plugin\s+list\b/g) || []).length, 1);
assert.doesNotMatch(workflow, /oci\s+instance-agent\s+command(?:-execution)?\b/);
assert.doesNotMatch(workflow, /oci\s+compute\s+(instance|image)\s+(update|action|terminate|launch|delete|import)\b/);
assert.doesNotMatch(workflow, /oci\s+instance-agent\s+plugin\s+(update|create|delete)\b/);
assert.doesNotMatch(workflow, /systemctl|service\s+oracle|yum\s|apt(?:-get)?\s|dnf\s|docker\s/);

for (const classification of [
  'BLOCKED_COMPATIBILITY_UNKNOWN',
  'BLOCKED_PLATFORM_PLUGIN_NOT_LISTED',
  'BLOCKED_AVAILABLE_PLUGIN_AMBIGUOUS',
  'BLOCKED_PLATFORM_NOT_SUPPORTED',
  'PLUGIN_PRESENT_NOW',
  'LIKELY_AGENT_UPDATE_REQUIRED_LEGACY_IMAGE',
  'LIKELY_AGENT_INSTALLATION_OR_VERSION_GAP',
]) assert.match(workflow, new RegExp(classification));

assert.match(workflow, /AGENT_COMPATIBILITY_DIAGNOSTIC=COMPLETE/);
assert.match(workflow, /BACKEND_INSPECTED=false/);
assert.match(workflow, /PRODUCTION_CHANGED=false/);
assert.match(workflow, /identifiers_recorded:false/);
assert.match(workflow, /raw_image_recorded:false/);
assert.match(workflow, /raw_available_plugins_recorded:false/);
assert.match(workflow, /raw_observed_plugins_recorded:false/);
assert.doesNotMatch(workflow, /path:\s*\/tmp|path:\s*\$HOME/);

const diagnose = workflow.indexOf('- name: Diagnose image compatibility and observed plugin gap');
const cleanup = workflow.indexOf('- name: Remove temporary credentials and raw responses');
const checksums = workflow.indexOf('- name: Verify sanitized evidence checksums');
const upload = workflow.indexOf('- name: Upload sanitized diagnostic evidence');
assert.ok(diagnose > 0 && cleanup > diagnose && checksums > cleanup && upload > cleanup);

console.log('backend agent compatibility diagnostic v1 policy: PASS');
