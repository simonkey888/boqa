'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { LocalLabRuntime } = require('../lib/local-lab-runtime');
const manifest = require('../qualification/labs/juice-shop-v1/manifest.json');

async function run() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-runtime-test-'));
  const calls = [];
  const runtime = new LocalLabRuntime({
    imageDigest: manifest.image_manifest_digest,
    lockPath: path.join(tmp, 'lock'),
    fetcher: async (url) => {
      calls.push(url);
      if (url.endsWith('/health')) return { status: 200, body: '{"status":"ok"}' };
      if (url.endsWith('/')) return { status: 200, body: '<html>Juice Shop</html>' };
      return url.includes('juice-shop')
        ? { status: 200, body: JSON.stringify({ data: [{ name: 'Apple Juice (1000ml)' }] }) }
        : { status: 200, body: JSON.stringify({ status: 'ok', data: [] }) };
    },
  });

  assert.equal(runtime.validateUrl('http://boqa-lab-juice-shop:3000/', manifest).allowed, true);
  assert.equal(runtime.validateUrl('https://example.com/', manifest).allowed, false);
  assert.equal(runtime.validateUrl('http://boqa-lab-juice-shop:3000/admin', manifest).allowed, false);
  const result = await runtime.runOnce({ runId: 'round-test-0001' });
  assert.equal(result.result.vulnerable, 'LAB_FINDING_CONFIRMED');
  assert.equal(result.result.control, 'LAB_CONTROL_CLEAN');
  assert.equal(result.request_count, 4);
  assert.equal(result.request_budget_verified, true);
  assert.equal(result.external_target, false);
  assert.match(result.evidence_sha256, /^[a-f0-9]{64}$/);
  assert.equal(calls.length, 4);

  fs.mkdirSync(path.join(tmp, 'locked'));
  const locked = new LocalLabRuntime({
    imageDigest: manifest.image_manifest_digest,
    lockPath: path.join(tmp, 'locked'),
    fetcher: async () => ({ status: 200, body: 'ok' }),
  });
  assert.equal((await locked.runOnce()).reason, 'LAB_LOCKED');

  const wrong = new LocalLabRuntime({ imageDigest: 'sha256:wrong', lockPath: path.join(tmp, 'wrong') });
  assert.equal(wrong.validateConfig().reason, 'IMAGE_DIGEST_MISMATCH');
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log('local lab runtime: PASS');
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
