#!/usr/bin/env node
'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');

const PATTERNS = [
  ['private_key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
  ['github_token', /\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}\b/],
  ['aws_access_key', /\bAKIA[0-9A-Z]{16}\b/],
  ['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
  ['hardcoded_boqa_secret', /\b(?:BOQA_API_KEY|BOQA_HMAC_SECRET)\s*[=:]\s*['"](?!\$\{|process\.env|test-|placeholder)[^'"\s]{8,}/],
];

function changedFiles(base, head = 'HEAD') {
  const output = execFileSync('git', ['diff', '--name-only', '--diff-filter=ACMR', '-z', base, head]);
  return output.toString().split('\0').filter(Boolean);
}

function scanFiles(files) {
  const findings = [];
  for (const file of files) {
    if (!fs.existsSync(file)) continue;
    const data = fs.readFileSync(file);
    if (data.includes(0)) continue;
    const text = data.toString('utf8');
    for (const [pattern] of PATTERNS) {
      const regex = PATTERNS.find(([name]) => name === pattern)[1];
      if (regex.test(text)) findings.push({ file, pattern });
    }
  }
  return findings;
}

function main() {
  const base = process.argv[2] || 'HEAD^';
  const head = process.argv[3] || 'HEAD';
  const files = changedFiles(base, head);
  const findings = scanFiles(files);
  console.log(JSON.stringify({ scanned_files: files.length, findings }, null, 2));
  if (findings.length) process.exit(1);
}

if (require.main === module) main();
module.exports = { PATTERNS, changedFiles, scanFiles };
