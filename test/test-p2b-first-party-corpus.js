'use strict';

const { FAMILIES, buildFirstPartyManifests, scenarioPaths } = require('../qualification/manifests/first-party');
const { createFirstPartyRuntime, descriptor } = require('../qualification/fixtures/first-party-app');
const { BoqaFirstPartyAgent } = require('../qualification/adapters/boqa-first-party-agent');
const { runQualification } = require('../qualification/runners/harness');
const { calculateMetrics } = require('../qualification/reports/metrics');
const { scoreReport } = require('../qualification/reports/report-rubric');
const { buildAgentInput } = require('../qualification/adapters/agent-input');

let passed = 0;
let failed = 0;
async function test(name, fn) { try { await fn(); passed++; console.log(`PASS ${name}`); } catch (error) { failed++; console.error(`FAIL ${name}: ${error.stack || error.message}`); } }
function assert(value, message) { if (!value) throw new Error(message); }

(async () => {
  const manifests = buildFirstPartyManifests();

  await test('corpus contains 12 families, 24 logical variants and 72 instances', () => {
    assert(FAMILIES.length === 12, `families=${FAMILIES.length}`);
    assert(manifests.length === 72, `instances=${manifests.length}`);
    for (const [family] of FAMILIES) {
      const subset = manifests.filter(item => item.family === family);
      assert(subset.length === 6, `${family} instances=${subset.length}`);
      assert(new Set(subset.map(item => item.seed)).size === 3, `${family} seeds missing`);
      assert(new Set(subset.map(item => item.variant)).size === 2, `${family} variant missing`);
    }
  });

  await test('paired variants expose equivalent names, paths, ports and URL shape', () => {
    for (let familyIndex = 0; familyIndex < FAMILIES.length; familyIndex++) {
      for (const seed of [1, 2, 3]) {
        const pair = manifests.filter(item => item.private_fixture.family_index === familyIndex && item.seed === seed);
        assert(pair.length === 2, 'pair missing');
        assert(JSON.stringify(pair[0].limits.allowed_paths) === JSON.stringify(pair[1].limits.allowed_paths), 'paths leak variant');
        const inputs = pair.map(item => buildAgentInput(item, createFirstPartyRuntime(item)));
        assert(inputs.every(input => input.authorized_url === 'http://lab.internal'), 'URL shape differs');
        assert(inputs.every(input => !JSON.stringify(input).match(/vulnerable|patched|CWE-/)), 'agent input leaks oracle');
      }
    }
  });

  await test('seed randomization changes paths while preserving semantic interface', () => {
    for (let index = 0; index < FAMILIES.length; index++) {
      const paths = [1, 2, 3].map(seed => scenarioPaths(index, seed).join('|'));
      assert(new Set(paths).size === 3, `family ${index} paths not randomized`);
      const kinds = manifests.filter(item => item.private_fixture.family_index === index && item.variant === 'vulnerable').map(descriptor).map(item => item.interface);
      assert(new Set(kinds).size === 1, `family ${index} semantics changed`);
    }
  });

  await test('blind development corpus executes with perfect oracle separation', async () => {
    const agent = new BoqaFirstPartyAgent();
    const records = [];
    for (const manifest of manifests) {
      records.push(await runQualification({ manifest, runtime: createFirstPartyRuntime(manifest), agent, runId: `DEV-${manifest.scenario_id}` }));
    }
    const metrics = calculateMetrics(records);
    assert(metrics.TP === 36 && metrics.TN === 36 && metrics.FP === 0 && metrics.FN === 0, JSON.stringify(metrics));
    assert(metrics.precision === 1 && metrics.recall === 1 && metrics.F1 === 1, JSON.stringify(metrics));
    assert(records.every(record => record.scope_violations === 0 && record.destructive_actions === 0 && record.external_network_attempts === 0), 'safety violation');
  });

  await test('every synthetic TP contains a complete human-readable report', async () => {
    const agent = new BoqaFirstPartyAgent();
    for (const manifest of manifests.filter(item => item.variant === 'vulnerable')) {
      const record = await runQualification({ manifest, runtime: createFirstPartyRuntime(manifest), agent });
      const report = record.agent_result.reports[0];
      for (const field of ['title', 'affected_asset', 'preconditions', 'reproduction_steps', 'observed_result', 'expected_result', 'impact', 'evidence', 'tentative_cwe', 'tentative_severity', 'limitations']) assert(report?.[field], `${manifest.family}:${field}`);
      assert(scoreReport(report, record).ready_for_triage, `${manifest.family} report score`);
    }
  });

  console.log(`\n${passed}/${passed + failed} tests passed`);
  process.exit(failed ? 1 : 0);
})();
