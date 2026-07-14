'use strict';

const crypto = require('crypto');
const { privateOracleRows } = require('./private-oracle');

function publicDescriptor(row) {
  const authorizedUrl = `http://${row.hostname}${row.path}`;
  return Object.freeze({
    canonical_target_id: row.target_id,
    authorized_url: authorizedUrl,
    scope: Object.freeze([authorizedUrl]),
    credentials: null,
    budget: Object.freeze({ max_requests: 12, max_navigation: 3, timeout_ms: 45000 }),
  });
}

function publicCorpus() {
  return Object.freeze(privateOracleRows().map(publicDescriptor));
}

function createRunHandle(randomBytes = crypto.randomBytes) {
  const value = randomBytes(24);
  if (!Buffer.isBuffer(value) || value.length < 16) throw new Error('RUN_HANDLE_ENTROPY_REQUIRED');
  return `run_${value.toString('base64url')}`;
}

function publicAgentInput(row, runHandle = null) {
  const allowed = new Set(['canonical_target_id', 'authorized_url', 'scope', 'credentials', 'budget']);
  const input = {};
  for (const [key, value] of Object.entries(row)) if (allowed.has(key)) input[key] = value;
  if (runHandle !== null) {
    if (!/^run_[A-Za-z0-9_-]{22,}$/.test(runHandle)) throw new Error('INVALID_RUN_HANDLE');
    input.run_handle = runHandle;
  }
  return Object.freeze(input);
}

module.exports = { publicDescriptor, publicCorpus, publicAgentInput, createRunHandle };
