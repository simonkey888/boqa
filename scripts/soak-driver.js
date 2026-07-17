'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');
const { LocalLabRuntime } = require('../lib/local-lab-runtime');
const { assertRoundEvidence, computeEvidenceSha256 } = require('../lib/soak-qualification-helpers');

const manifest = require('../qualification/labs/juice-shop-v1/manifest.json');
const evidenceDir = process.env.BOQA_EVIDENCE_DIR || '/evidence';
const runId = process.env.BOQA_ROUND_ID;
const DNS_BLOCK_CODES = new Set(['ENOTFOUND', 'EAI_AGAIN', 'EAI_FAIL', 'EAI_NODATA']);
const CONNECT_BLOCK_CODES = new Set(['ENETUNREACH', 'EHOSTUNREACH', 'ECONNREFUSED', 'ECONNRESET']);

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
      const code = error.code || 'ERROR';
      let classification = 'ERROR';
      if (DNS_BLOCK_CODES.has(code)) classification = 'BLOCKED_DNS';
      else if (CONNECT_BLOCK_CODES.has(code)) classification = 'BLOCKED_CONNECT';
      resolve({ classification, code });
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
  evidence.evidence_sha256 = computeEvidenceSha256(evidence);
  assertRoundEvidence(evidence, manifest);
  const output = path.join(evidenceDir, `driver-round-${runId}.json`);
  fs.writeFileSync(output, `${JSON.stringify(evidence, null, 2)}\n`, { flag: 'wx', mode: 0o644 });
  process.stdout.write(`${JSON.stringify({ status: 'PASS', output, evidence_sha256: evidence.evidence_sha256 })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exit(1);
});
