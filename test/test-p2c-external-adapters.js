'use strict';

const { externalAdapters, OwaspBenchmarkAdapter, VulhubAdapter, VulfocusAdapter } = require('../qualification/adapters/external');
const { sha256, validateScenarioDefinition } = require('../qualification/adapters/external/base-adapter');

let passed = 0;
let failed = 0;
function test(name, fn) { try { fn(); passed++; console.log(`PASS ${name}`); } catch (error) { failed++; console.error(`FAIL ${name}: ${error.message}`); } }
function assert(value, message) { if (!value) throw new Error(message); }
const digest = `sha256:${'a'.repeat(64)}`;
const commit = 'b'.repeat(40);

test('all five public benchmark adapters exist and never auto-execute', () => {
  const adapters = externalAdapters();
  assert(adapters.length === 5, `adapters=${adapters.length}`);
  for (const adapter of adapters) {
    assert(adapter.status() === 'EXTERNAL_LABS_NOT_RUN', adapter.name);
    let blocked = false;
    try { adapter.execute(); } catch (error) { blocked = error.message.startsWith('EXTERNAL_LABS_NOT_RUN'); }
    assert(blocked, `${adapter.name} auto-executed`);
  }
});

test('unsafe or unpinned external scenarios fail closed', () => {
  const result = validateScenarioDefinition({ family: 'access_control', url: 'https://public.example', source_commit: 'main', image_digests: [], privileged: true });
  assert(!result.valid && result.errors.includes('NON_LOCAL_LAB_URL') && result.errors.includes('UNSAFE_CONTAINER_CONTROL'), JSON.stringify(result));
});

test('Vulfocus blocks Docker socket, privileged and host networking', () => {
  const adapter = new VulfocusAdapter();
  for (const controller of [{ mounts_docker_socket: true }, { privileged: true }, { host_network: true }]) {
    assert(adapter.evaluateController(controller).status === 'BLOCKED_UNSAFE_DOCKER_CONTROL', 'unsafe controller accepted');
  }
  const safe = adapter.evaluateController({ external_control_plane: true, internal_network: true, flag_withheld_from_agent: true });
  assert(safe.status === 'ADAPTER_READY_NOT_EXECUTED', JSON.stringify(safe));
  assert(!Object.prototype.hasOwnProperty.call(adapter.agentInput({ target: 'lab', flag: 'synthetic', ground_truth: true }), 'flag'), 'flag leaked');
});

test('Vulhub requires source, images and all configuration checksums', () => {
  const files = { compose: 'compose', manifest: 'manifest', oracle: 'oracle', fixture: 'fixture' };
  const definition = {
    family: 'isolated_ssrf', url: 'http://lab.internal/', source_commit: commit,
    image_digests: [digest], scenario_path: 'safe/http',
    checksums: Object.fromEntries(Object.entries(files).map(([name, value]) => [name, sha256(value)])),
  };
  assert(new VulhubAdapter().validatePinnedScenario(definition, files).valid, 'pinned scenario rejected');
  definition.checksums.oracle = 'bad';
  assert(!new VulhubAdapter().validatePinnedScenario(definition, files).valid, 'checksum mismatch accepted');
});

test('OWASP expected results are applied only after agent results', () => {
  const adapter = new OwaspBenchmarkAdapter();
  const result = adapter.scoreAfterAgent(
    [{ test_name: 'a', reported: true }, { test_name: 'b', reported: false }],
    [{ test_name: 'a', vulnerable: true }, { test_name: 'b', vulnerable: false }],
  );
  assert(result.TP === 1 && result.TN === 1 && result.FP === 0 && result.FN === 0, JSON.stringify(result));
});

console.log(`\n${passed}/${passed + failed} tests passed`);
process.exit(failed ? 1 : 0);
