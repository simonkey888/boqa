#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const RULES = [
  ['pull_request_target', /\bpull_request_target\s*:/i],
  ['write_all_permissions', /permissions\s*:\s*write-all/i],
  ['admin_execution_enabled', /BOQA_ADMIN_EXECUTION_ENABLED\s*:\s*['"]?true/i],
  ['auto_analysis_enabled', /BOQA_AUTO_ANALYZE\s*:\s*['"]?true/i],
  ['otel_enabled', /BOQA_OTEL_ENABLED\s*:\s*['"]?true/i],
  ['production_url', /boqa\.simondalmasso44\.workers\.dev|136\.248\.117\.15|nip\.io/i],
  ['ssh_command', /(?:^|\s|[-])ssh(?:\s|$)/im],
  ['cloudflare_cli', /\b(?:cloudflared|wrangler\s+deploy)\b/i],
  ['oci_cli', /\boci\s+(?:compute|bastion|network|iam)\b/i],
];

function validateText(text, filename = 'workflow') {
  return RULES.filter(([, regex]) => regex.test(text)).map(([rule]) => ({ file: filename, rule }));
}

function workflowFiles(root = path.resolve('.github', 'workflows')) {
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root)
    .filter(file => /\.ya?ml$/i.test(file))
    .map(file => path.join(root, file));
}

function main() {
  const files = workflowFiles();
  const findings = files.flatMap(file => validateText(fs.readFileSync(file, 'utf8'), file));
  console.log(JSON.stringify({ workflow_files: files.length, findings }, null, 2));
  if (findings.length) process.exit(1);
}

if (require.main === module) main();
module.exports = { RULES, validateText, workflowFiles };
