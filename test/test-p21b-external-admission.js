'use strict';

const assert = require('assert');
const { records, validateRecord, materializeRuntimeAdmission, verifyRepositoryFiles } = require('../qualification/p21/admission');

const all = records();
assert.strictEqual(all.length, 5, 'all five adapters must be evaluated');
assert.strictEqual(all.filter(record => record.admitted).length, 3, 'exactly three frameworks admitted initially');

for (const record of all.filter(item => item.admitted)) {
  const result = validateRecord(record);
  assert(result.valid, `${record.framework}: ${result.errors.join(',')}`);
  assert(!record.container_image.includes(':latest'), `${record.framework}: floating image`);
  assert.strictEqual(record.privileged, false);
  assert.strictEqual(record.host_network, false);
  assert.strictEqual(record.docker_socket, false);
  assert.deepStrictEqual(record.destructive_capabilities, []);
}

const verified = verifyRepositoryFiles();
assert(verified.every(result => result.validation.valid || !all.find(record => record.framework === result.framework).admitted), JSON.stringify(verified));

const vulfocus = all.find(record => record.framework === 'vulfocus');
assert.strictEqual(vulfocus.admitted, false);
assert.strictEqual(vulfocus.reason, 'BLOCKED_UNSAFE_DOCKER_CONTROL');
assert.strictEqual(vulfocus.docker_socket, true);

const sourceBuild = all.find(record => record.framework === 'owasp-nodegoat');
assert.strictEqual(materializeRuntimeAdmission(sourceBuild, null).runtime_ready, false);
assert.strictEqual(materializeRuntimeAdmission(sourceBuild, `sha256:${'a'.repeat(64)}`).runtime_ready, true);

const pinned = all.find(record => record.framework === 'owasp-juice-shop');
assert.strictEqual(materializeRuntimeAdmission(pinned, `sha256:${'b'.repeat(64)}`).runtime_ready, false);
assert.strictEqual(materializeRuntimeAdmission(pinned, pinned.container_digest).runtime_ready, true);

for (const record of all) {
  const publicFields = JSON.stringify(record).toLowerCase();
  for (const forbidden of ['password=', 'authorization:', 'cookie:', 'flag{', 'solution_url']) {
    assert(!publicFields.includes(forbidden), `${record.framework}: private value in admission record`);
  }
}

console.log('P2.1 external-lab admission and provenance: PASS');
