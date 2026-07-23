#!/usr/bin/env node
'use strict';

const fs = require('fs');

function fail(code) {
  console.error(code);
  process.exit(1);
}

const policyPath = process.argv[2];
if (!policyPath) {
  console.error('Usage: node scripts/verify-safe-lab-promotion-policy.js <promotion-policy.json>');
  process.exit(2);
}

let policy;
try {
  policy = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
} catch (_) {
  fail('PROMOTION_POLICY_INVALID_JSON');
}

if (policy.environment !== 'controlled_lab') fail('PROMOTION_POLICY_ENVIRONMENT_INVALID');
if (policy.promotion_ready !== false) fail('LAB_PREVIEW_MUST_NOT_BE_PROMOTABLE');
if (policy.promotion_blocker !== 'CONTROLLED_LAB_PREVIEW') fail('PROMOTION_BLOCKER_INVALID');
if (policy.production_changed !== false || policy.deploy_performed !== false) fail('PRODUCTION_MUTATION_DETECTED');
process.stdout.write('PROMOTION_POLICY=PASS\nPROMOTION_READY=false\nPROMOTION_BLOCKER=CONTROLLED_LAB_PREVIEW\n');
