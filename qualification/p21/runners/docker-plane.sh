#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUN_ID="p21-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
LABEL="boqa.p21.run=$RUN_ID"
NETWORK_A="${RUN_ID}-a"
NETWORK_B="${RUN_ID}-b"
LAB_A="${RUN_ID}-lab-a"
LAB_B="${RUN_ID}-lab-b"
RUNNER="${RUN_ID}-runner"
IMAGE="${RUN_ID}-smoke:local"
BRIDGE_A="p21a${RUN_ID//[^0-9]/}"
BRIDGE_B="p21b${RUN_ID//[^0-9]/}"
BRIDGE_A="${BRIDGE_A:0:15}"
BRIDGE_B="${BRIDGE_B:0:15}"
HOST_PORT=18080
HOST_CANARY_PID=""
TMP_RUN="$(mktemp -d)"
EVIDENCE="${P21_PLANE_EVIDENCE:-$ROOT/qualification/results/p21-plane-smoke.json}"

cleanup() {
  set +e
  docker rm -f "$RUNNER" "$LAB_A" "$LAB_B" >/dev/null 2>&1
  docker network rm "$NETWORK_A" "$NETWORK_B" >/dev/null 2>&1
  if [[ -n "$HOST_CANARY_PID" ]]; then kill "$HOST_CANARY_PID" >/dev/null 2>&1; fi
  if command -v sudo >/dev/null 2>&1; then
    sudo iptables -D INPUT -i "$BRIDGE_A" -j REJECT >/dev/null 2>&1
    sudo iptables -D INPUT -i "$BRIDGE_B" -j REJECT >/dev/null 2>&1
  fi
  rm -rf "$TMP_RUN"
}
trap cleanup EXIT INT TERM

mkdir -p "$(dirname "$EVIDENCE")"
docker build --pull --label "$LABEL" -t "$IMAGE" "$ROOT/qualification/p21/fixtures/smoke-lab"

docker network create --internal --subnet 172.31.1.0/24 \
  --opt "com.docker.network.bridge.name=$BRIDGE_A" \
  --label "$LABEL" "$NETWORK_A" >/dev/null
docker network create --internal --subnet 172.31.2.0/24 \
  --opt "com.docker.network.bridge.name=$BRIDGE_B" \
  --label "$LABEL" "$NETWORK_B" >/dev/null

if command -v sudo >/dev/null 2>&1; then
  sudo iptables -I INPUT -i "$BRIDGE_A" -j REJECT
  sudo iptables -I INPUT -i "$BRIDGE_B" -j REJECT
fi

node -e "require('http').createServer((q,s)=>s.end('host')).listen($HOST_PORT,'0.0.0.0')" &
HOST_CANARY_PID=$!

COMMON=(--read-only --cap-drop ALL --security-opt no-new-privileges --memory 128m --cpus 0.50 --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=8m --dns 127.0.0.1 --label "$LABEL")

docker run -d --name "$LAB_A" --network "$NETWORK_A" --ip 172.31.1.10 "${COMMON[@]}" "$IMAGE" >/dev/null
docker run -d --name "$LAB_B" --network "$NETWORK_B" --ip 172.31.2.10 "${COMMON[@]}" "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
  if docker exec "$LAB_A" node -e "require('http').get('http://127.0.0.1:8080/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"; then break; fi
  sleep 1
done

PROBE_ENV=(-e P21_ALLOWED_URL=http://lab-a:8080/health -e P21_GATEWAY_IP=172.31.1.1 -e P21_FOREIGN_IP=172.31.2.10 -e P21_HOST_PORT="$HOST_PORT")
docker run --name "$RUNNER" --network "$NETWORK_A" --ip 172.31.1.20 \
  --add-host lab-a:172.31.1.10 "${COMMON[@]}" "${PROBE_ENV[@]}" -e P21_PROBE_ROLE=boqa-runner \
  "$IMAGE" node isolation-probe.js >"$TMP_RUN/runner.json"
docker rm "$RUNNER" >/dev/null

docker exec \
  -e P21_ALLOWED_URL=http://127.0.0.1:8080/health \
  -e P21_GATEWAY_IP=172.31.1.1 \
  -e P21_FOREIGN_IP=172.31.2.10 \
  -e P21_HOST_PORT="$HOST_PORT" \
  -e P21_PROBE_ROLE=laboratory-a \
  "$LAB_A" node isolation-probe.js >"$TMP_RUN/lab-a.json"

docker exec \
  -e P21_ALLOWED_URL=http://127.0.0.1:8080/health \
  -e P21_GATEWAY_IP=172.31.2.1 \
  -e P21_FOREIGN_IP=172.31.1.10 \
  -e P21_HOST_PORT="$HOST_PORT" \
  -e P21_PROBE_ROLE=laboratory-b \
  "$LAB_B" node isolation-probe.js >"$TMP_RUN/lab-b.json"

node - "$TMP_RUN" "$EVIDENCE" <<'NODE'
const fs = require('fs');
const path = require('path');
const [dir, output] = process.argv.slice(2);
const probes = ['runner.json', 'lab-a.json', 'lab-b.json'].map(file => JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8')));
if (!probes.every(probe => probe.passed === true)) process.exit(1);
fs.writeFileSync(output, JSON.stringify({
  schema: 'boqa.p21.docker-plane-smoke.v1',
  internal_network: true,
  host_network: false,
  docker_socket_mounted: false,
  privileged: false,
  probes,
}, null, 2) + '\n');
NODE

cleanup
trap - EXIT INT TERM

if docker ps -aq --filter "label=$LABEL" | grep -q .; then echo "CONTAINER_CLEANUP_FAILED" >&2; exit 1; fi
if docker network ls -q --filter "label=$LABEL" | grep -q .; then echo "NETWORK_CLEANUP_FAILED" >&2; exit 1; fi
if docker volume ls -q --filter "label=$LABEL" | grep -q .; then echo "VOLUME_CLEANUP_FAILED" >&2; exit 1; fi
if [[ -e "$TMP_RUN" ]]; then echo "FILESYSTEM_CLEANUP_FAILED" >&2; exit 1; fi

node - "$EVIDENCE" <<'NODE'
const fs = require('fs');
const file = process.argv[2];
const evidence = JSON.parse(fs.readFileSync(file, 'utf8'));
evidence.cleanup_verified = true;
fs.writeFileSync(file, JSON.stringify(evidence, null, 2) + '\n');
NODE
