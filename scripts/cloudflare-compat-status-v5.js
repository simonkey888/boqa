'use strict';

const fs = require('fs');
const path = require('path');

const previewUrl = String(process.env.BOQA_PREVIEW_URL || '').replace(/\/$/, '');
const outputDir = path.join(__dirname, '..', 'output', 'cloudflare-preview-v5', 'browser');

async function main() {
  if (!previewUrl) throw new Error('MISSING_PREVIEW_URL');
  fs.mkdirSync(outputDir, { recursive: true });
  const response = await fetch(`${previewUrl}/api/hunter/status`, {
    cache: 'no-store',
    redirect: 'manual',
    headers: { 'Cache-Control': 'no-cache' },
  });
  let error = null;
  try {
    const payload = await response.json();
    error = typeof payload?.error === 'string' ? payload.error : null;
  } catch (_) {}
  const evidence = {
    public_status: response.status,
    public_error: error,
    legacy_upstream_status: response.headers.get('x-boqa-compat-upstream-status'),
    legacy_upstream_type: response.headers.get('x-boqa-compat-upstream-type'),
    backend_contract: response.headers.get('x-boqa-backend-contract'),
    url_recorded: false,
    body_recorded: false,
  };
  fs.writeFileSync(
    path.join(outputDir, 'compat-status.json'),
    `${JSON.stringify(evidence, null, 2)}\n`,
  );
  console.log(JSON.stringify(evidence));
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
