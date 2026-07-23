'use strict';
const assert = require('assert');
const cryptoModule = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { canonicalJson, validateClosedContract } = require('../lib/safe-lab-hunter-contract-v1');
const { buildSafeLabPreviewBundle, replaceBuildBlock } = require('../scripts/build-safe-lab-preview-bundle');
if (!globalThis.crypto) globalThis.crypto = cryptoModule.webcrypto;

const ROOT = path.join(__dirname, '..');
const SHA = 'a'.repeat(40);
let passed = 0;
const digest = (value) => cryptoModule.createHash('sha256').update(value).digest('hex');

function contract() {
  const value = {
    schema_version: 1, environment: 'controlled_lab', status: 'FRESH', hunter_state: 'LAB_COMPLETE', reportable: false,
    authorized_scope: 'synthetic_fixture', target_kind: 'owasp_juice_shop_pinned', policy_id: 'safe-lab-readonly-v1',
    source_sha: SHA, run_id: 'sha256:0123456789abcdef', cycle_started_at: '2026-07-23T03:00:00.000Z',
    cycle_finished_at: '2026-07-23T03:00:01.000Z', observed_at: '2026-07-23T03:00:02.000Z',
    fresh_until: '2026-07-23T03:01:32.000Z', unavailable_after: '2026-07-24T03:00:02.000Z', finding_count: 1, control_finding_count: 0,
    false_positive_count: 0, false_negative_count: 0, unauthorized_connection_count: 0,
    cleanup_verified: true, egress_blocked: true, request_budget_verified: true,
    evidence_checksum: `sha256:${'b'.repeat(64)}`, message: 'Validación completada en laboratorio controlado',
  };
  validateClosedContract(value);
  return value;
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-lab-preview-'));
  const contractPath = path.join(root, 'hunter-status-public.json');
  const checksumPath = `${contractPath}.sha256`;
  const raw = `${canonicalJson(contract())}\n`;
  fs.writeFileSync(contractPath, raw);
  fs.writeFileSync(checksumPath, `${digest(raw)}  ${path.basename(contractPath)}\n`);
  return { root, contractPath, checksumPath };
}

const build = (value) => ({
  enabled: true, source_sha: value.source_sha, contract_checksum: `sha256:${digest(`${canonicalJson(value)}\n`)}`,
  promotion_ready: false, promotion_blocker: 'CONTROLLED_LAB_PREVIEW', contract: value,
});
const importWorker = async (source) => (await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}#${cryptoModule.randomUUID()}`)).default;
const source = () => fs.readFileSync(path.join(ROOT, 'worker.js'), 'utf8');
async function test(name, fn) { await fn(); passed += 1; console.log(`ok ${passed} - ${name}`); }

async function main() {
  await test('build requires explicit preview mode', async () => {
    const f = fixture();
    assert.throws(() => buildSafeLabPreviewBundle({ root: ROOT, contractPath: f.contractPath, checksumPath: f.checksumPath, expectedSourceSha: SHA, outputDir: path.join(f.root, 'out') }), (e) => e.code === 'SAFE_LAB_PREVIEW_BUILD_NOT_EXPLICIT');
  });
  await test('bundle embeds public contract and permanent blocker', async () => {
    const f = fixture();
    const out = path.join(f.root, 'out');
    const result = buildSafeLabPreviewBundle({ root: ROOT, contractPath: f.contractPath, checksumPath: f.checksumPath, expectedSourceSha: SHA, outputDir: out, mode: 'true' });
    assert.deepEqual([result.policy.promotion_ready, result.policy.promotion_blocker, result.policy.production_changed, result.policy.deploy_performed], [false, 'CONTROLLED_LAB_PREVIEW', false, false]);
    const built = fs.readFileSync(path.join(out, 'worker.js'), 'utf8');
    assert.match(built, /["']?enabled["']?\s*:\s*true/);
    assert.doesNotMatch(built, /container_identities|runtime_identity|private-container|OCID|Authorization:/i);
    assert.ok(fs.existsSync(path.join(out, 'dashboard', 'index.html')) && fs.existsSync(path.join(out, 'wrangler.toml')));
    assert.equal(fs.existsSync(path.join(out, 'dashboard', 'cobros.html')), false);
    assert.equal(fs.existsSync(path.join(out, 'dashboard', 'cobros.js')), false);
    assert.equal(fs.existsSync(path.join(out, 'dashboard', 'private.css')), false);
  });
  await test('disabled build preserves production backend proxy', async () => {
    const worker = await importWorker(source());
    const original = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async () => { calls += 1; return new Response('{"state":"IDLE"}', { headers: { 'content-type': 'application/json' } }); };
    try {
      const response = await worker.fetch(new Request('https://public.invalid/api/hunter/status'), { BOQA_BACKEND_URL: 'https://backend.invalid', BOQA_API_KEY: 'key', BOQA_HMAC_SECRET: 'secret' });
      assert.equal(response.status, 200); assert.equal(calls, 1); assert.deepEqual(await response.json(), { state: 'IDLE' });
      assert.equal((await (await worker.fetch(new Request('https://public.invalid/health'), { BOQA_BACKEND_URL: 'https://backend.invalid' })).json()).mode, 'production');
    } finally { globalThis.fetch = original; }
  });
  await test('enabled build serves contract without fetch', async () => {
    const value = contract();
    const worker = await importWorker(replaceBuildBlock(source(), build(value)));
    const original = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async () => { calls += 1; throw new Error('unexpected fetch'); };
    try {
      const response = await worker.fetch(new Request('https://preview.invalid/api/hunter/status'), {});
      assert.equal(response.status, 200); assert.match(response.headers.get('content-type') || '', /^application\/json/);
      assert.equal(response.headers.get('cache-control'), 'no-store, max-age=0'); assert.deepEqual(await response.json(), value); assert.equal(calls, 0);
    } finally { globalThis.fetch = original; }
  });
  await test('non-GET method is rejected', async () => {
    const worker = await importWorker(replaceBuildBlock(source(), build(contract())));
    const response = await worker.fetch(new Request('https://preview.invalid/api/hunter/status', { method: 'POST' }), {});
    assert.equal(response.status, 404); assert.deepEqual(await response.json(), { error: 'not_found' });
  });
  await test('private route remains concealed', async () => {
    const worker = await importWorker(replaceBuildBlock(source(), build(contract())));
    let touched = false;
    const response = await worker.fetch(new Request('https://preview.invalid/api/private/billing/data'), { ASSETS: { async fetch() { touched = true; } } });
    assert.equal(response.status, 404); assert.equal(touched, false); assert.deepEqual(await response.json(), { error: 'not_found' });
  });
  await test('mutated embedded contract without checksum update fails closed', async () => {
    const built = replaceBuildBlock(source(), build(contract())).replace('\"finding_count\": 1', '\"finding_count\": 2');
    const worker = await importWorker(built);
    const response = await worker.fetch(new Request('https://preview.invalid/api/hunter/status'), { BOQA_BACKEND_URL: 'https://backend.invalid' });
    assert.equal(response.status, 503); assert.equal((await response.json()).status, 'UNAVAILABLE');
  });
  await test('lab health is explicit and non-promotable', async () => {
    const worker = await importWorker(replaceBuildBlock(source(), build(contract())));
    const health = await (await worker.fetch(new Request('https://preview.invalid/health'), {})).json();
    assert.deepEqual([health.mode, health.promotion_ready, health.promotion_blocker, health.source_sha], ['controlled_lab_preview', false, 'CONTROLLED_LAB_PREVIEW', SHA]);
  });
  await test('promotion policy verifier accepts deliberate blocker', async () => {
    const f = fixture(); const out = path.join(f.root, 'out');
    buildSafeLabPreviewBundle({ root: ROOT, contractPath: f.contractPath, checksumPath: f.checksumPath, expectedSourceSha: SHA, outputDir: out, mode: 'true' });
    const result = spawnSync('node', ['scripts/verify-safe-lab-promotion-policy.js', path.join(out, 'promotion-policy.json')], { cwd: ROOT, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr); assert.match(result.stdout, /PROMOTION_READY=false/); assert.match(result.stdout, /CONTROLLED_LAB_PREVIEW/);
  });
  await test('worker has no dynamic artifact or contract fetch', async () => {
    const value = source();
    assert.doesNotMatch(value, /actions\/artifacts|archive_download_url|raw\.githubusercontent|artifact.*fetch|fetch\([^)]*contract/i);
    assert.match(value, /BOQA_SAFE_LAB_PREVIEW_BUILD_START/); assert.match(value, /enabled:\s*false/);
  });
  assert.equal(passed, 10); console.log(`1..${passed}`);
}
main().catch((error) => { console.error(error.stack || error); process.exit(1); });
