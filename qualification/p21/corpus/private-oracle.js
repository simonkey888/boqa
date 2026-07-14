'use strict';

const crypto = require('crypto');

const BENCHMARK_PAIRS = Object.freeze([
  ['path_handling', 'CWE-22', 'BenchmarkTest00001', 'BenchmarkTest00063', '/pathtraver-00/'],
  ['path_handling', 'CWE-22', 'BenchmarkTest00002', 'BenchmarkTest00064', '/pathtraver-00/'],
  ['reflected_xss', 'CWE-79', 'BenchmarkTest00013', 'BenchmarkTest00147', '/xss-00/'],
  ['reflected_xss', 'CWE-79', 'BenchmarkTest00014', 'BenchmarkTest00151', '/xss-00/'],
  ['session_boundary', 'CWE-614', 'BenchmarkTest00087', 'BenchmarkTest00016', '/securecookie-00/'],
  ['session_boundary', 'CWE-614', 'BenchmarkTest00169', 'BenchmarkTest00088', '/securecookie-00/'],
  ['query_authorization', 'CWE-89', 'BenchmarkTest00008', 'BenchmarkTest00052', '/sqli-00/'],
  ['query_authorization', 'CWE-89', 'BenchmarkTest00018', 'BenchmarkTest00104', '/sqli-00/'],
  ['trust_boundary', 'CWE-501', 'BenchmarkTest00004', 'BenchmarkTest00097', '/trustbound-00/'],
  ['trust_boundary', 'CWE-501', 'BenchmarkTest00031', 'BenchmarkTest00099', '/trustbound-00/'],
  ['structured_query', 'CWE-643', 'BenchmarkTest00207', 'BenchmarkTest00116', '/xpathi-00/'],
  ['structured_query', 'CWE-643', 'BenchmarkTest00442', 'BenchmarkTest00117', '/xpathi-00/'],
]);

const DETECTION_ONLY = Object.freeze([
  ['owasp-nodegoat', 'authentication_session', '/login'],
  ['owasp-nodegoat', 'horizontal_access_control', '/allocations/1'],
  ['owasp-nodegoat', 'stored_xss', '/memos'],
  ['owasp-nodegoat', 'vertical_access_control', '/benefits'],
]);

const STATEFUL = Object.freeze([
  ['owasp-juice-shop', 'authentication_session', '/rest/user/login'],
  ['owasp-juice-shop', 'api_authorization', '/api/Products'],
  ['owasp-juice-shop', 'horizontal_access_control', '/rest/basket/1'],
  ['owasp-juice-shop', 'reflected_xss', '/rest/products/search?q=p21-marker'],
]);

function opaque(value, length = 16) {
  return crypto.createHash('sha256').update(`boqa-p21:${value}`).digest('hex').slice(0, length);
}

function pairIdentity(family, pairIndex) {
  const opaqueId = opaque(`benchmark:${family}:${pairIndex}`);
  return Object.freeze({
    scenario_id: `P21-${opaqueId}`,
    target_id: `target-${opaqueId}`,
    hostname: `target-${opaqueId}.p21.invalid`,
    path: `/v/${opaque(`path:${family}:${pairIndex}`, 20)}`,
    seed: 1100 + pairIndex,
  });
}

function privateOracleRows() {
  const rows = [];
  BENCHMARK_PAIRS.forEach(([family, cwe, vulnerableCase, safeCase, prefix], pairIndex) => {
    const identity = pairIdentity(family, pairIndex);
    for (const [variant, upstreamCase, vulnerable] of [
      ['vulnerable', vulnerableCase, true],
      ['safe', safeCase, false],
    ]) {
      rows.push(Object.freeze({
        ...identity,
        corpus: 'paired_classification',
        framework: 'owasp-benchmark',
        variant,
        vulnerable,
        family,
        expected_cwe: cwe,
        upstream_method: 'GET',
        upstream_path: `${prefix}${upstreamCase}`,
        source_case: upstreamCase,
      }));
    }
  });

  DETECTION_ONLY.forEach(([framework, family, upstreamPath], index) => {
    const key = opaque(`${framework}:detection:${index}`);
    rows.push(Object.freeze({
      scenario_id: `P21-${key}`, target_id: `target-${key}`, hostname: `target-${key}.p21.invalid`,
      path: `/v/${opaque(`detection-path:${index}`, 20)}`, seed: 2100 + index,
      corpus: 'detection_only', framework, variant: 'upstream_vulnerable_app', vulnerable: null,
      family, expected_cwe: null, upstream_method: 'GET', upstream_path: upstreamPath,
    }));
  });

  STATEFUL.forEach(([framework, family, upstreamPath], index) => {
    const key = opaque(`${framework}:stateful:${index}`);
    rows.push(Object.freeze({
      scenario_id: `P21-${key}`, target_id: `target-${key}`, hostname: `target-${key}.p21.invalid`,
      path: `/v/${opaque(`stateful-path:${index}`, 20)}`, seed: 3100 + index,
      corpus: 'stateful_coverage', framework, variant: 'fresh_state', vulnerable: null,
      family, expected_cwe: null, upstream_method: 'GET', upstream_path: upstreamPath,
    }));
  });
  return Object.freeze(rows);
}

module.exports = { BENCHMARK_PAIRS, DETECTION_ONLY, STATEFUL, privateOracleRows };
