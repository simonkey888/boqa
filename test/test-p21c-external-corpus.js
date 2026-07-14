'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { BENCHMARK_PAIRS, privateOracleRows } = require('../qualification/p21/corpus/private-oracle');
const { publicDescriptor, publicCorpus, publicAgentInput, createRunHandle } = require('../qualification/p21/corpus/public-corpus');
const { routeForRun, scoreableOracleRows } = require('../qualification/p21/corpus/oracle-controller');
const { parseExpectedResults } = require('../qualification/p21/corpus/verify-upstream-corpus');
const { scoreReport, classifyPairedResult } = require('../qualification/p21/corpus/scoring-policy');
const { execFileSync } = require('child_process');

const privateRows = privateOracleRows();
const publicRows = publicCorpus();
const paired = privateRows.filter(row => row.corpus === 'paired_classification');
const detection = privateRows.filter(row => row.corpus === 'detection_only');
const stateful = privateRows.filter(row => row.corpus === 'stateful_coverage');

assert.strictEqual(privateRows.length, 32, 'external instance count');
assert.strictEqual(paired.length, 24, 'paired instance count');
assert.strictEqual(paired.filter(row => row.vulnerable === true).length, 12, 'vulnerable count');
assert.strictEqual(paired.filter(row => row.vulnerable === false).length, 12, 'safe count');
assert.strictEqual(detection.length, 4, 'detection-only count');
assert.strictEqual(stateful.length, 4, 'stateful count');
assert(new Set(privateRows.map(row => row.framework)).size >= 3, 'framework count');
assert(new Set(privateRows.map(row => row.family)).size >= 6, 'family count');
assert.strictEqual(BENCHMARK_PAIRS.length, 12, 'frozen pair count');

for (const scenarioId of new Set(paired.map(row => row.scenario_id))) {
  const pair = paired.filter(row => row.scenario_id === scenarioId);
  assert.strictEqual(pair.length, 2, `${scenarioId} missing pair`);
  const descriptors = pair.map(publicDescriptor);
  assert.deepStrictEqual(descriptors[0], descriptors[1], `${scenarioId} leaks variant through public descriptor`);
  assert.notStrictEqual(pair[0].source_case, pair[1].source_case, `${scenarioId} reuses one upstream case`);
}

const serializedPublic = JSON.stringify(publicRows).toLowerCase();
for (const forbidden of [
  'benchmarktest', 'nodegoat', 'juice-shop', 'vulnerable', 'safe', 'expected_cwe',
  'ground_truth', 'source_case', 'upstream_path', 'solution', 'writeup', 'flag', 'cve-',
  'scenario_id', 'seed', 'corpus', 'framework', 'family', 'variant', 'track',
]) assert(!serializedPublic.includes(forbidden), `public corpus leaks ${forbidden}`);

for (const row of publicRows) {
  assert.deepStrictEqual(publicAgentInput(row), row, `${row.scenario_id} agent-input drift`);
  assert(row.authorized_url.startsWith('http://target-') && row.authorized_url.includes('.p21.invalid/v/'), 'non-opaque URL');
  assert(row.scope.length === 1 && row.scope[0] === row.authorized_url, 'scope mismatch');
  assert.strictEqual(row.credentials, null, 'unexpected credentials');
}

const handles = [
  createRunHandle(() => Buffer.alloc(24, 0x11)),
  createRunHandle(() => Buffer.alloc(24, 0xa7)),
];
assert.notStrictEqual(handles[0], handles[1]);
for (const handle of handles) {
  assert(!/paired|state|detect|safe|vulner|benchmark|node|juice|seed/i.test(handle));
  assert(!/\d{3,}/.test(handle), 'run handle exposes a numeric range');
}
const handledInput = publicAgentInput(publicRows[0], handles[0]);
assert.deepStrictEqual(Object.keys(handledInput).sort(), ['authorized_url', 'budget', 'canonical_target_id', 'credentials', 'run_handle', 'scope']);

const oracleRows = scoreableOracleRows();
assert.strictEqual(oracleRows.length, 24);
assert(oracleRows.every(row => !Object.prototype.hasOwnProperty.call(row, 'upstream_path')), 'route leaked to scorer');

const selected = privateRows[0];
const route = routeForRun(selected.scenario_id, selected.variant);
assert.strictEqual(route.upstream_path, selected.upstream_path);
assert.throws(() => routeForRun(selected.scenario_id), /VARIANT_REQUIRED/);

const parsed = parseExpectedResults('# header\nBenchmarkTest00001,pathtraver,true,22\nBenchmarkTest00063,pathtraver,false,22\n');
assert.deepStrictEqual(parsed.get('BenchmarkTest00001'), { category: 'pathtraver', vulnerable: true, cwe: 'CWE-22' });
assert.deepStrictEqual(parsed.get('BenchmarkTest00063'), { category: 'pathtraver', vulnerable: false, cwe: 'CWE-22' });

const ready = Object.fromEntries(['clarity', 'reproducibility', 'evidence', 'impact', 'classification', 'scope_compliance'].map(key => [key, 2]));
assert.strictEqual(scoreReport(ready).total, 12);
assert.strictEqual(classifyPairedResult({ reported: true, reproduced_from_clean_state: true, evidence_verified: true }, { vulnerable: true }, ready).outcome, 'TP');
assert.strictEqual(classifyPairedResult({ reported: true, reproduced_from_clean_state: true, evidence_verified: true }, { vulnerable: false }, ready).outcome, 'FP');
assert.strictEqual(classifyPairedResult({ reported: false }, { vulnerable: true }, ready).outcome, 'FN');
assert.strictEqual(classifyPairedResult({ reported: false }, { vulnerable: false }, ready).outcome, 'TN');
assert.strictEqual(classifyPairedResult({ reported: true, reproduced_from_clean_state: true, evidence_verified: true, lab_fingerprint_only: true }, { vulnerable: true }, ready).outcome, 'FN');

const root = path.resolve(__dirname, '..');
const freeze = JSON.parse(fs.readFileSync(path.join(root, 'qualification/p21/corpus/corpus-freeze.json'), 'utf8'));
const digest = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const temp = path.join(os.tmpdir(), `p21-public-${process.pid}.json`);
execFileSync(process.execPath, [path.join(root, 'qualification/p21/corpus/generate-public-corpus.js'), temp]);
assert.strictEqual(digest(temp), freeze.digests.public_corpus_json_sha256);
fs.unlinkSync(temp);
assert.strictEqual(digest(path.join(root, 'qualification/p21/corpus/private-oracle.js')), freeze.digests.private_oracle_source_sha256);
assert.strictEqual(digest(path.join(root, 'qualification/p21/corpus/scoring-policy.js')), freeze.digests.scoring_policy_sha256);
assert.strictEqual(digest(path.join(root, 'qualification/p21/admission/records.json')), freeze.digests.admission_records_sha256);
assert.strictEqual(freeze.runtime_provenance.baseline_blocked_until_all_runtime_ready, true);
assert.strictEqual(freeze.runtime_provenance.owasp_juice_shop, 'VERIFIED_OCI_PRIMARY_METADATA');
assert.strictEqual(freeze.schema, 'boqa.p21.external-corpus-freeze.v1.1');
assert.strictEqual(freeze.amended_before_any_execution, true);
assert.strictEqual(freeze.instances_executed_at_amendment, 0);
assert.strictEqual(freeze.oracle_labels_changed, false);
assert.strictEqual(freeze.upstream_case_selection_changed, false);
assert.deepStrictEqual(freeze.normalization.agent_visible_fields, ['canonical_target_id', 'authorized_url', 'scope', 'credentials', 'budget', 'run_handle']);

console.log('P2.1 pinned external blind corpus: PASS');
