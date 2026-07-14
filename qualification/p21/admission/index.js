'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const RECORDS_FILE = path.join(__dirname, 'records.json');

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function records() {
  return JSON.parse(fs.readFileSync(RECORDS_FILE, 'utf8'));
}

function validateRecord(record) {
  const errors = [];
  const required = [
    'source_repository', 'source_commit', 'license', 'source_archive_sha256',
    'container_image', 'container_digest', 'build_context_sha256',
    'compose_sha256', 'runtime_user', 'reason',
  ];
  if (record.admitted) {
    for (const key of required) if (!record[key]) errors.push(`MISSING_${key.toUpperCase()}`);
  }
  if (!/^[a-f0-9]{40}$/.test(record.source_commit || '')) errors.push('INVALID_SOURCE_COMMIT');
  if (!/^[a-f0-9]{64}$/.test(record.source_archive_sha256 || '')) errors.push('INVALID_ARCHIVE_DIGEST');
  if (record.privileged) errors.push('PRIVILEGED_REQUIRED');
  if (record.host_network) errors.push('HOST_NETWORK_REQUIRED');
  if (record.docker_socket) errors.push('DOCKER_SOCKET_REQUIRED');
  if (record.admitted && /:latest(?:$|@)/.test(record.container_image)) errors.push('FLOATING_IMAGE');
  if (record.admitted && (record.destructive_capabilities || []).length) errors.push('DESTRUCTIVE_CAPABILITY');
  if (record.admitted && !String(record.deterministic_reset).includes('fresh')) errors.push('RESET_NOT_DETERMINISTIC');
  return { valid: errors.length === 0, errors };
}

function materializeRuntimeAdmission(record, localImageDigest) {
  const staticValidation = validateRecord(record);
  if (!staticValidation.valid || !record.admitted) return { runtime_ready: false, errors: staticValidation.errors };
  if (!/^sha256:[a-f0-9]{64}$/.test(localImageDigest || '')) return { runtime_ready: false, errors: ['IMAGE_DIGEST_REQUIRED'] };
  if (record.container_digest.startsWith('sha256:') && record.container_digest !== localImageDigest) {
    return { runtime_ready: false, errors: ['IMAGE_DIGEST_MISMATCH'] };
  }
  return { runtime_ready: true, errors: [], container_digest: localImageDigest };
}

function verifyRepositoryFiles(input = records()) {
  return input.map(record => {
    const slug = record.framework;
    const planPath = path.join(ROOT, 'qualification', 'p21', 'admission', 'plans', `${slug}.json`);
    const composePath = path.join(ROOT, 'qualification', 'p21', 'admission', 'compose', `${slug}.yaml`);
    const result = { framework: slug, validation: validateRecord(record) };
    if (record.admitted) {
      result.build_context_sha256 = sha256(fs.readFileSync(planPath));
      result.compose_sha256 = sha256(fs.readFileSync(composePath));
      if (result.build_context_sha256 !== record.build_context_sha256) result.validation.errors.push('BUILD_CONTEXT_DIGEST_MISMATCH');
      if (result.compose_sha256 !== record.compose_sha256) result.validation.errors.push('COMPOSE_DIGEST_MISMATCH');
      result.validation.valid = result.validation.errors.length === 0;
    }
    return result;
  });
}

module.exports = { sha256, records, validateRecord, materializeRuntimeAdmission, verifyRepositoryFiles };
