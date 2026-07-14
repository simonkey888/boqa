'use strict';

const assert = require('assert');
const { BENCHMARK_PAIRS, privateOracleRows } = require('../qualification/p21/corpus/private-oracle');
const { publicCorpus, publicAgentInput } = require('../qualification/p21/corpus/public-corpus');
const { routeForRun, scoreableOracleRows } = require('../qualification/p21/corpus/oracle-controller');
const { parseExpectedResults } = require('../qualification/p21/corpus/verify-upstream-corpus');

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
  const descriptors = pair.map(row => publicRows.find(item => item.scenario_id === row.scenario_id && item.seed === row.seed));
  assert.deepStrictEqual(descriptors[0], descriptors[1], `${scenarioId} leaks variant through public descriptor`);
  assert.notStrictEqual(pair[0].source_case, pair[1].source_case, `${scenarioId} reuses one upstream case`);
}

const serializedPublic = JSON.stringify(publicRows).toLowerCase();
for (const forbidden of [
  'benchmarktest', 'nodegoat', 'juice-shop', 'vulnerable', 'safe', 'expected_cwe',
  'ground_truth', 'source_case', 'upstream_path', 'solution', 'writeup', 'flag', 'cve-',
]) assert(!serializedPublic.includes(forbidden), `public corpus leaks ${forbidden}`);

for (const row of publicRows) {
  assert.deepStrictEqual(publicAgentInput(row), row, `${row.scenario_id} agent-input drift`);
  assert(row.authorized_url.startsWith('http://target-') && row.authorized_url.includes('.p21.invalid/v/'), 'non-opaque URL');
  assert(row.scope.length === 1 && row.scope[0] === row.authorized_url, 'scope mismatch');
  assert.strictEqual(row.credentials, null, 'unexpected credentials');
}

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

console.log('P2.1 pinned external blind corpus: PASS');
