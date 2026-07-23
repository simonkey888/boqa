#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {
  canonicalJson,
  validateClosedContract,
} = require('../lib/safe-lab-hunter-contract-v1');

const START = '// BOQA_SAFE_LAB_PREVIEW_BUILD_START';
const END = '// BOQA_SAFE_LAB_PREVIEW_BUILD_END';
const SHA_PATTERN = /^[a-f0-9]{40}$/;
const CHECKSUM_PATTERN = /^([a-f0-9]{64})  ([A-Za-z0-9._-]+)$/;

function fail(code, detail) {
  const error = new Error(detail ? `${code}:${detail}` : code);
  error.code = code;
  throw error;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function readContract(contractPath, checksumPath, expectedSourceSha) {
  if (!SHA_PATTERN.test(expectedSourceSha || '')) fail('SOURCE_SHA_INVALID');
  const raw = fs.readFileSync(contractPath, 'utf8');
  if (!raw.endsWith('\n')) fail('CONTRACT_NOT_CANONICAL');
  let contract;
  try {
    contract = JSON.parse(raw);
  } catch (_) {
    fail('CONTRACT_JSON_INVALID');
  }
  validateClosedContract(contract);
  if (`${canonicalJson(contract)}\n` !== raw) fail('CONTRACT_NOT_CANONICAL');
  if (contract.source_sha !== expectedSourceSha) fail('SOURCE_SHA_MISMATCH');
  const checksumLine = fs.readFileSync(checksumPath, 'utf8').trim();
  const match = CHECKSUM_PATTERN.exec(checksumLine);
  if (!match || match[2] !== path.basename(contractPath)) fail('CONTRACT_CHECKSUM_FORMAT_INVALID');
  const actual = sha256(raw);
  if (match[1] !== actual) fail('CONTRACT_CHECKSUM_MISMATCH');
  return { contract, raw, checksum: `sha256:${actual}` };
}

function replaceBuildBlock(workerSource, build) {
  const startIndex = workerSource.indexOf(START);
  const endIndex = workerSource.indexOf(END);
  if (startIndex < 0 || endIndex < 0 || endIndex <= startIndex) fail('WORKER_BUILD_MARKER_MISSING');
  if (workerSource.indexOf(START, startIndex + START.length) >= 0 || workerSource.indexOf(END, endIndex + END.length) >= 0) {
    fail('WORKER_BUILD_MARKER_DUPLICATE');
  }
  const replacement = `${START}\nconst SAFE_LAB_PREVIEW_BUILD = Object.freeze(${JSON.stringify(build, null, 2)});\n${END}`;
  return workerSource.slice(0, startIndex) + replacement + workerSource.slice(endIndex + END.length);
}

const PUBLIC_DASHBOARD_ASSETS = Object.freeze([
  'index.html',
  'app.js',
  'dashboard-state.js',
  'style.css',
  'mobile.css',
]);

function copyPublicDashboard(source, destination) {
  fs.mkdirSync(destination, { recursive: false });
  for (const filename of PUBLIC_DASHBOARD_ASSETS) {
    fs.copyFileSync(path.join(source, filename), path.join(destination, filename), fs.constants.COPYFILE_EXCL);
  }
}

function buildSafeLabPreviewBundle(options) {
  if (options.mode !== 'true') fail('SAFE_LAB_PREVIEW_BUILD_NOT_EXPLICIT');
  const root = path.resolve(options.root || path.join(__dirname, '..'));
  const outputDir = path.resolve(options.outputDir);
  if (fs.existsSync(outputDir)) fail('OUTPUT_ALREADY_EXISTS');
  const contractPath = path.resolve(options.contractPath);
  const checksumPath = path.resolve(options.checksumPath);
  const expectedSourceSha = String(options.expectedSourceSha || '').trim();
  const verified = readContract(contractPath, checksumPath, expectedSourceSha);
  const build = {
    enabled: true,
    source_sha: expectedSourceSha,
    contract_checksum: verified.checksum,
    promotion_ready: false,
    promotion_blocker: 'CONTROLLED_LAB_PREVIEW',
    contract: verified.contract,
  };

  fs.mkdirSync(outputDir, { recursive: false });
  const workerSource = fs.readFileSync(path.join(root, 'worker.js'), 'utf8');
  fs.writeFileSync(path.join(outputDir, 'worker.js'), replaceBuildBlock(workerSource, build), { flag: 'wx' });
  fs.copyFileSync(path.join(root, 'wrangler.toml'), path.join(outputDir, 'wrangler.toml'), fs.constants.COPYFILE_EXCL);
  copyPublicDashboard(path.join(root, 'dashboard'), path.join(outputDir, 'dashboard'));
  const dashboardPath = path.join(outputDir, 'dashboard', 'index.html');
  const dashboardHtml = fs.readFileSync(dashboardPath, 'utf8');
  const compiledDashboard = dashboardHtml
    .replace('data-environment="unknown"', 'data-environment="controlled_lab"')
    .replace('id="lab-banner" class="lab-banner" aria-label="Entorno de laboratorio controlado" hidden', 'id="lab-banner" class="lab-banner" aria-label="Entorno de laboratorio controlado"');
  if (compiledDashboard === dashboardHtml || !compiledDashboard.includes('data-environment="controlled_lab"')) {
    fail('DASHBOARD_LAB_MARKER_MISSING');
  }
  fs.writeFileSync(dashboardPath, compiledDashboard);
  const policy = {
    schema_version: 1,
    environment: 'controlled_lab',
    source_sha: expectedSourceSha,
    contract_checksum: verified.checksum,
    promotion_ready: false,
    promotion_blocker: 'CONTROLLED_LAB_PREVIEW',
    production_changed: false,
    deploy_performed: false,
  };
  fs.writeFileSync(path.join(outputDir, 'promotion-policy.json'), `${canonicalJson(policy)}\n`, { flag: 'wx' });
  return { outputDir, policy, build };
}

function main() {
  const [contractPath, checksumPath, expectedSourceSha, outputDir] = process.argv.slice(2);
  if (!contractPath || !checksumPath || !expectedSourceSha || !outputDir) {
    console.error('Usage: BOQA_SAFE_LAB_PREVIEW=true node scripts/build-safe-lab-preview-bundle.js <contract-json> <contract-sha256> <source-sha> <output-dir>');
    process.exit(2);
  }
  try {
    const result = buildSafeLabPreviewBundle({
      root: path.join(__dirname, '..'),
      contractPath,
      checksumPath,
      expectedSourceSha,
      outputDir,
      mode: process.env.BOQA_SAFE_LAB_PREVIEW,
    });
    process.stdout.write(`${canonicalJson(result.policy)}\n`);
  } catch (error) {
    console.error(error.code || error.message);
    process.exit(1);
  }
}

if (require.main === module) main();

module.exports = {
  buildSafeLabPreviewBundle,
  readContract,
  replaceBuildBlock,
};
