'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');
const { LocalLabRuntime } = require('../lib/local-lab-runtime');
const { assertRoundEvidence, sha256 } = require('../lib/soak-qualification-helpers');

const manifest = require('../qualification/labs/juice-shop-v1/manifest.json');
const evidenceDir = process.env.BOQA_EVIDENCE_DIR || '/evidence';
const runId = process.env.BOQA_ROUND_ID;

function probeHttp(host, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const req = http.get({ host, port: 80, path: '/', timeout: timeoutMs }, (res) => {
      res.resume();
      resolve({ classification: 'UNEXPECTED_CONNECTION', status: res.statusCode || 0 });
    });
    req.on('timeout', () => {
      req.destroy();
      resolve({ classification: 'BLOCKED_TIMEOUT' });
    });
    req.on('error', (error) => {
      const classification = error.code === 'ENOTFOUND' ? 'BLOCKED_DNS' : 'BLOCKED_CONNECT';
      resolve({ classification, code: error.code || 'ERROR' });
    });
  });
}

async function main() {
  if (!runId || !/^[a-z0-9-]{8,80}$/.test(runId)) throw new Error('ROUND_ID_INVALID');
  fs.mkdirSync(evidenceDir, { recursive: true });
  const runtime = new LocalLabRuntime({ imageDigest: manifest.image_manifest_digest });
  const evidence = await runtime.runOnce({ runId });
  evidence.runtime_evidence_sha256 = evidence.evidence_sha256;
  delete evidence.evidence_sha256;
  evidence.egress = {
    dns: await probeHttp('example.invalid'),
    metadata: await probeHttp('169.254.169.254'),
    documentation_ip: await probeHttp('192.0.2.1'),
  };
  evidence.evidence_sha256 = sha256(JSON.stringify(evidence));
  assertRoundEvidence(evidence, manifest);
  const output = path.join(evidenceDir, `round-${runId}.json`);
  fs.writeFileSync(output, `${JSON.stringify(evidence, null, 2)}\n`, { flag: 'wx' });
  process.stdout.write(`${JSON.stringify({ status: 'PASS', output, evidence_sha256: evidence.evidence_sha256 })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exit(1);
});
