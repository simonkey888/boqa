'use strict';

const assert = require('assert');
const {
  assertComposePolicy,
  assertEgressEvidence,
  assertRoundEvidence,
  safeProjectName,
  summarizeRounds,
} = require('../lib/soak-qualification-helpers');
const manifest = require('../qualification/labs/juice-shop-v1/manifest.json');

const hardened = {
  services: Object.fromEntries(['candidate', 'control', 'driver'].map((name) => [name, {
    read_only: true,
    cap_drop: ['ALL'],
    security_opt: ['no-new-privileges:true'],
    networks: { boqa_lab_internal: null },
    volumes: [],
  }])),
  networks: { boqa_lab_internal: { internal: true } },
};
assert.equal(assertComposePolicy(hardened), true);
assert.throws(() => assertComposePolicy({ ...hardened, networks: { boqa_lab_internal: { internal: false } } }), /NETWORK_NOT_INTERNAL/);
const bad = JSON.parse(JSON.stringify(hardened));
bad.services.driver.ports = ['8080:80'];
assert.throws(() => assertComposePolicy(bad), /PUBLISHED_PORT/);

const egress = {
  dns: { classification: 'BLOCKED_DNS' },
  metadata: { classification: 'BLOCKED_CONNECT' },
  documentation_ip: { classification: 'BLOCKED_TIMEOUT' },
};
assert.equal(assertEgressEvidence(egress), true);
assert.throws(() => assertEgressEvidence({ ...egress, dns: { classification: 'UNEXPECTED_CONNECTION' } }), /EGRESS_NOT_BLOCKED/);

const evidence = {
  result: { vulnerable: 'LAB_FINDING_CONFIRMED', control: 'LAB_CONTROL_CLEAN' },
  policy_status: 'AUTHORIZED',
  environment: 'controlled_lab',
  external_target: false,
  reportability: 'not_reportable',
  request_budget_verified: true,
  request_count: 4,
  evidence_sha256: 'a'.repeat(64),
  egress,
};
assert.equal(assertRoundEvidence(evidence, manifest), true);
assert.match(safeProjectName('BOQA PR#9 / ABC'), /^boqa-pr-9-abc$/);
assert.deepEqual(summarizeRounds([{ ...evidence, cleanup_verified: true }]), {
  rounds_requested: 1,
  rounds_completed: 1,
  vulnerable_confirmed: 1,
  controls_clean: 1,
  false_positives: 0,
  false_negatives: 0,
  cleanup_failures: 0,
});
console.log('soak qualification helpers: PASS');
