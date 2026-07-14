'use strict';

const { compareResults } = require('../qualification/adapters/reference-comparator');

let passed = 0;
let failed = 0;
function test(name, fn) { try { fn(); passed++; console.log(`PASS ${name}`); } catch (error) { failed++; console.error(`FAIL ${name}: ${error.message}`); } }
function assert(value, message) { if (!value) throw new Error(message); }

test('comparator measures overlap and exclusive findings against independent oracle', () => {
  const result = compareResults({
    allowedCaseIds: ['a', 'b', 'c', 'd'],
    oracleRows: [{ case_id: 'a', vulnerable: true }, { case_id: 'b', vulnerable: true }, { case_id: 'c', vulnerable: false }, { case_id: 'd', vulnerable: false }],
    boqaResult: { findings: [{ case_id: 'a', reported: true }, { case_id: 'b', reported: true }], time_ms: 10, requests: 4 },
    referenceResult: { findings: [{ case_id: 'b', reported: true }, { case_id: 'c', reported: true }], time_ms: 20, requests: 8 },
  });
  assert(result.overlap.join(',') === 'b', JSON.stringify(result));
  assert(result.boqa_only.join(',') === 'a' && result.reference_only.join(',') === 'c', 'exclusive sets wrong');
  assert(result.boqa.metrics.precision === 1 && result.boqa.metrics.recall === 1, 'BOQA metrics wrong');
  assert(result.reference.metrics.precision === 0.5 && result.reference.metrics.recall === 0.5, 'reference metrics wrong');
});

test('reference tool cannot expand scope or inject into BOQA', () => {
  const boqaResult = { findings: [{ case_id: 'a', reported: true }], requests: 1 };
  const referenceResult = { findings: [{ case_id: 'outside', reported: true }], requests: 1 };
  const before = JSON.stringify(boqaResult);
  const result = compareResults({ allowedCaseIds: ['a'], oracleRows: [{ case_id: 'a', vulnerable: true }], boqaResult, referenceResult });
  assert(result.reference.scope_violations === 1 && result.reference_only.length === 0, 'out-of-scope reference finding accepted');
  assert(JSON.stringify(boqaResult) === before && result.boqa.metrics.TP === 1, 'reference changed BOQA result');
});

test('reference findings are not treated as ground truth', () => {
  const result = compareResults({
    allowedCaseIds: ['patched'], oracleRows: [{ case_id: 'patched', vulnerable: false }],
    boqaResult: { findings: [] }, referenceResult: { findings: [{ case_id: 'patched', reported: true }] },
  });
  assert(result.boqa.metrics.TN === 1, 'BOQA score was influenced');
  assert(result.reference.metrics.FP === 1, 'reference false positive was promoted to truth');
});

console.log(`\n${passed}/${passed + failed} tests passed`);
process.exit(failed ? 1 : 0);
