#!/usr/bin/env bash
set -euo pipefail

DEST="${1:?destination directory required}"
mkdir -p "$DEST"

fetch() {
  local name="$1" url="$2" expected="$3"
  local archive="$DEST/$name.tar.gz"
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --output "$archive" "$url"
  local actual
  actual="$(sha256sum "$archive" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "SOURCE_ARCHIVE_DIGEST_MISMATCH:$name" >&2
    exit 1
  fi
  mkdir -p "$DEST/$name"
  tar --extract --gzip --file "$archive" --directory "$DEST/$name" --no-same-owner --no-same-permissions
}

fetch owasp-benchmark \
  https://codeload.github.com/OWASP-Benchmark/BenchmarkJava/tar.gz/79b9bd6177e07991a9c11dc19e457c840e229931 \
  4679d0b32200c6b62564c0d124c938412303330179589ffe8c91264667fc0f33
fetch owasp-nodegoat \
  https://codeload.github.com/OWASP/NodeGoat/tar.gz/c5cb68a7084e4ae7dcc60e6a98768720a81841e8 \
  f9455e6c5c57471fcc213959f523d640d9454337cbdf870c731f1b588a19b5c3
fetch owasp-juice-shop \
  https://codeload.github.com/juice-shop/juice-shop/tar.gz/c8c407d503ce9c8e6582b39b40db84db06989744 \
  1ee872e8ba1f97059bc76572c66af99a9e1b83413e295014922da5074da66b07
