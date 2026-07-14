#!/usr/bin/env bash
set -euo pipefail

RUNTIME_DIGESTS="${P21_RUNTIME_DIGESTS:-p21-runtime-digests.json}"
node - "$RUNTIME_DIGESTS" <<'NODE'
const fs = require('fs');
const file = process.argv[2];
if (!fs.existsSync(file)) throw new Error('RUNTIME_DIGESTS_NOT_FROZEN');
const evidence = JSON.parse(fs.readFileSync(file, 'utf8'));
if (evidence.frozen_before_baseline !== true || !Array.isArray(evidence.images) || evidence.images.length < 3) {
  throw new Error('RUNTIME_DIGESTS_INCOMPLETE');
}
if (!evidence.images.every(image => image.runtime_ready === true && /^sha256:[a-f0-9]{64}$/.test(image.local_image_id))) {
  throw new Error('RUNTIME_IMAGE_NOT_READY');
}
NODE

echo "P21_BASELINE_RUNNER_NOT_IMPLEMENTED" >&2
exit 2
