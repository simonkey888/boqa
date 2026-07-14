#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { privateOracleRows } = require('./private-oracle');

function parseExpectedResults(text) {
  const rows = new Map();
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const [testName, category, vulnerable, cwe] = line.split(',');
    rows.set(testName, { category, vulnerable: vulnerable === 'true', cwe: `CWE-${cwe}` });
  }
  return rows;
}

function verifyBenchmark(root) {
  const expectedFile = path.join(root, 'expectedresults-1.2.csv');
  const expected = parseExpectedResults(fs.readFileSync(expectedFile, 'utf8'));
  const categoryMap = {
    path_handling: 'pathtraver', reflected_xss: 'xss', session_boundary: 'securecookie',
    query_authorization: 'sqli', trust_boundary: 'trustbound', structured_query: 'xpathi',
  };
  const selected = privateOracleRows().filter(row => row.framework === 'owasp-benchmark');
  for (const row of selected) {
    const upstream = expected.get(row.source_case);
    if (!upstream) throw new Error(`UPSTREAM_CASE_MISSING:${row.source_case}`);
    if (upstream.vulnerable !== row.vulnerable) throw new Error(`UPSTREAM_LABEL_MISMATCH:${row.source_case}`);
    if (upstream.cwe !== row.expected_cwe) throw new Error(`UPSTREAM_CWE_MISMATCH:${row.source_case}`);
    if (upstream.category !== categoryMap[row.family]) throw new Error(`UPSTREAM_FAMILY_MISMATCH:${row.source_case}`);
  }
  return selected.length;
}

function verifyRouteStrings(root, framework) {
  const rows = privateOracleRows().filter(row => row.framework === framework);
  const files = [];
  function visit(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(full);
      else if (/\.(?:js|ts|html|json)$/.test(entry.name)) files.push(full);
    }
  }
  visit(root);
  const source = files.map(file => fs.readFileSync(file, 'utf8')).join('\n');
  for (const row of rows) {
    const route = row.upstream_path.split('?')[0].replace(/\/\d+$/, '');
    if (!source.includes(route)) throw new Error(`UPSTREAM_ROUTE_MISSING:${framework}:${route}`);
  }
  return rows.length;
}

function main() {
  const [benchmarkRoot, nodegoatRoot, juiceRoot, evidenceFile] = process.argv.slice(2);
  if (!benchmarkRoot || !nodegoatRoot || !juiceRoot || !evidenceFile) throw new Error('SOURCE_ROOTS_AND_EVIDENCE_REQUIRED');
  const counts = {
    benchmark: verifyBenchmark(benchmarkRoot),
    nodegoat: verifyRouteStrings(nodegoatRoot, 'owasp-nodegoat'),
    juice_shop: verifyRouteStrings(juiceRoot, 'owasp-juice-shop'),
  };
  const digest = crypto.createHash('sha256').update(JSON.stringify(counts)).digest('hex');
  fs.writeFileSync(evidenceFile, `${JSON.stringify({ verified: true, counts, aggregate_digest: digest }, null, 2)}\n`);
}

if (require.main === module) main();
module.exports = { parseExpectedResults, verifyBenchmark, verifyRouteStrings };
