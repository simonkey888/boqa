#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SOURCES="${1:?verified source directory required}"
OUTPUT="${2:?runtime digest output required}"
BENCHMARK_ROOT="$SOURCES/owasp-benchmark/BenchmarkJava-79b9bd6177e07991a9c11dc19e457c840e229931"
NODEGOAT_ROOT="$SOURCES/owasp-nodegoat/NodeGoat-c5cb68a7084e4ae7dcc60e6a98768720a81841e8"

docker pull maven@sha256:e4a7ace3dc0d645ed97f8d9ad0b0d3f0b14fa8d150138f27f116d7105a639b82 >/dev/null
docker pull tomcat@sha256:fcf35a12fc228567f91484b076f40d3d6528c15beb7e24f13ade176bf4b6b2ca >/dev/null
docker pull node@sha256:4517380049fc3c9aacceae7764fcf3500354b0ac8a47e4afb35b5bbeb75b9498 >/dev/null
docker pull bkimminich/juice-shop@sha256:67b87bff95f5719f9a31ab2bcf48cacc30fcc30d4662c2047ca0c0b8b4b7ebae >/dev/null

docker build --network default --file "$ROOT/qualification/p21/images/owasp-benchmark.Dockerfile" \
  --tag boqa-p21/owasp-benchmark:79b9bd6177e0 "$BENCHMARK_ROOT"
docker build --network default --file "$ROOT/qualification/p21/images/owasp-nodegoat.Dockerfile" \
  --tag boqa-p21/nodegoat:c5cb68a7084e "$NODEGOAT_ROOT"

mkdir -p "$(dirname "$OUTPUT")"
node - "$OUTPUT" <<'NODE'
const { execFileSync } = require('child_process');
const fs = require('fs');
const output = process.argv[2];
const images = [
  { framework: 'owasp-benchmark', reference: 'boqa-p21/owasp-benchmark:79b9bd6177e0', source_commit: '79b9bd6177e07991a9c11dc19e457c840e229931' },
  { framework: 'owasp-nodegoat', reference: 'boqa-p21/nodegoat:c5cb68a7084e', source_commit: 'c5cb68a7084e4ae7dcc60e6a98768720a81841e8' },
  { framework: 'owasp-juice-shop', reference: 'bkimminich/juice-shop@sha256:67b87bff95f5719f9a31ab2bcf48cacc30fcc30d4662c2047ca0c0b8b4b7ebae', source_commit: 'c8c407d503ce9c8e6582b39b40db84db06989744' },
].map(item => {
  const inspected = JSON.parse(execFileSync('docker', ['image', 'inspect', item.reference], { encoding: 'utf8' }))[0];
  const user = String(inspected.Config?.User || '');
  if (!user || /^(?:0(?::0)?|root)$/i.test(user)) throw new Error(`ROOT_RUNTIME_USER:${item.framework}`);
  if (!/^sha256:[a-f0-9]{64}$/.test(inspected.Id)) throw new Error(`INVALID_LOCAL_IMAGE_ID:${item.framework}`);
  return { ...item, local_image_id: inspected.Id, runtime_user: user, runtime_ready: true };
});
fs.writeFileSync(output, `${JSON.stringify({
  schema: 'boqa.p21.runtime-digests.v1',
  frozen_before_baseline: true,
  source_image_correlation: { 'owasp-juice-shop': 'VERIFIED_OCI_PRIMARY_METADATA' },
  images,
}, null, 2)}\n`);
NODE
