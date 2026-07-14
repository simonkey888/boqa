'use strict';

const fs = require('fs');
const path = require('path');
const { validateText } = require('../scripts/validate-workflow-policy');

const text = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'boqa-p2-qualification.yml'), 'utf8');
const required = ['permissions:\n  contents: read', 'pull_request:', 'workflow_dispatch:', 'timeout-minutes:', 'PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: "1"', 'npm run test:p2'];
for (const fragment of required) { if (!text.includes(fragment)) throw new Error(`P2 workflow missing ${fragment}`); }
if (validateText(text).length) throw new Error(`P2 workflow violates policy: ${JSON.stringify(validateText(text))}`);
for (const forbidden of ['pull_request_target', 'write-all', 'docker.sock', 'privileged: true', 'curl http', 'ssh ', 'wrangler deploy']) {
  if (text.includes(forbidden)) throw new Error(`P2 workflow contains ${forbidden}`);
}
console.log('P2 CI policy: PASS');
