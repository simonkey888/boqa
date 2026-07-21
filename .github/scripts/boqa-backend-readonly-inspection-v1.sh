#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
hashv(){ printf '%s' "$1" | sha256sum | awk '{print $1}'; }
num(){ local x; x=$(printf '%s' "${1:-0}" | tr -cd '0-9'); printf '%s' "${x:-0}"; }
safe(){ printf '%s' "${1:-missing}" | tr -cd 'A-Za-z0-9_.:-' | cut -c1-48; }
jget(){ printf '%s' "$1" | jq -r "$2 // empty" 2>/dev/null || true; }

DOCKER_ACCESS=NO
if docker version >/dev/null 2>&1; then D=(docker); DOCKER_ACCESS=DIRECT
elif sudo -n docker version >/dev/null 2>&1; then D=(sudo -n docker); DOCKER_ACCESS=SUDO_READ_ONLY
else D=(); fi

C=0; IH=''; IIH=''; RS=unknown; MC=0; RWM=0; OM=false; PB=0
RC=0; RCH=''; HH=000; HS=missing; HRS=missing; UH=000; US=missing; UKH=''
LL=0; LE=0; LS=0; CLASS=BLOCKED_DOCKER_ACCESS

if [ "${#D[@]}" -gt 0 ]; then
  mapfile -t IDS < <("${D[@]}" ps --filter publish=80 --format '{{.ID}}' 2>/dev/null)
  C="${#IDS[@]}"
  if [ "$C" -eq 1 ]; then
    ID="${IDS[0]}"
    IMG=$("${D[@]}" inspect -f '{{.Config.Image}}' "$ID" 2>/dev/null || true)
    IID=$("${D[@]}" inspect -f '{{.Image}}' "$ID" 2>/dev/null || true)
    IH=$(hashv "$IMG"); IIH=$(hashv "$IID")
    RS=$(safe "$("${D[@]}" inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$ID" 2>/dev/null || echo unknown)")
    MC=$("${D[@]}" inspect -f '{{len .Mounts}}' "$ID" 2>/dev/null || echo 0)
    RWM=$("${D[@]}" inspect -f '{{range .Mounts}}{{if .RW}}1{{"\n"}}{{end}}' "$ID" 2>/dev/null | wc -l | tr -d ' ')
    "${D[@]}" inspect -f '{{range .Mounts}}{{println .Source "|" .Destination}}{{end}}' "$ID" 2>/dev/null |
      grep -Eq '(^|[|])/var/lib/boqa/output([|]|$)|[|]/app/output$' && OM=true || true
    PB=$("${D[@]}" inspect -f '{{len .NetworkSettings.Ports}}' "$ID" 2>/dev/null || echo 0)
    ENV=$("${D[@]}" inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$ID" 2>/dev/null || true)
    HRS=$(printf '%s\n' "$ENV" | sed -n 's/^BOQA_RELEASE_SHA=\([0-9a-fA-F]\{40\}\)$/\1/p' | head -1)
    [ -n "$HRS" ] || HRS=missing
    REPO="${IMG%%@*}"; REPO="${REPO%:*}"
    if [ -n "$REPO" ]; then
      mapfile -t RIDS < <("${D[@]}" image ls "$REPO" --format '{{.ID}}' 2>/dev/null | sort -u | grep -Fxv "$IID")
      RC="${#RIDS[@]}"; RCH=$(printf '%s\n' "${RIDS[@]:-}" | sha256sum | awk '{print $1}')
    fi
    HEALTH=$(curl -sS --max-time 8 http://127.0.0.1/api/health 2>/dev/null || true)
    HH=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 http://127.0.0.1/api/health 2>/dev/null || echo 000)
    HS=$(safe "$(jget "$HEALTH" '.status')"); [ -n "$HS" ] || HS=missing
    [ "$HRS" != missing ] || { X=$(jget "$HEALTH" '.release_sha'); [[ "$X" =~ ^[0-9a-fA-F]{40}$ ]] && HRS="$X"; }
    HUNTER=$(curl -sS --max-time 8 http://127.0.0.1/api/hunter/status 2>/dev/null || true)
    UH=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 http://127.0.0.1/api/hunter/status 2>/dev/null || echo 000)
    US=$(safe "$(jget "$HUNTER" '.state')"); [ -n "$US" ] || US=missing
    UKH=$(printf '%s' "$HUNTER" | jq -cS 'keys' 2>/dev/null | sha256sum | awk '{print $1}')
    LOGS=$("${D[@]}" logs --tail 200 "$ID" 2>&1 || true)
    LL=$(printf '%s\n' "$LOGS" | wc -l | tr -d ' ')
    LE=$(printf '%s\n' "$LOGS" | grep -Eic 'error|fatal|panic|exception' || true)
    LS=$(printf '%s\n' "$LOGS" | grep -Eic 'password|secret|token|api[_ -]?key|authorization' || true)
    CLASS=INSPECTED
  else CLASS=BLOCKED_CONTAINER_AMBIGUITY
  fi
fi

printf '{"v":1,"class":"%s","docker":"%s","containers":%s,"image_ref_sha":"%s","image_id_sha":"%s","restart":"%s","mounts":%s,"rw_mounts":%s,"output_mount":%s,"port_bindings":%s,"rollback_count":%s,"rollback_set_sha":"%s","health_http":"%s","health_status":"%s","release_sha":"%s","hunter_http":"%s","hunter_state":"%s","hunter_keys_sha":"%s","log_lines":%s,"log_critical":%s,"log_secret_terms":%s,"mutated":false}\n' \
  "$CLASS" "$DOCKER_ACCESS" "$C" "$IH" "$IIH" "$RS" "$(num "$MC")" "$(num "$RWM")" "$OM" "$(num "$PB")" "$RC" "$RCH" "$(safe "$HH")" "$HS" "$HRS" "$(safe "$UH")" "$US" "$UKH" "$(num "$LL")" "$(num "$LE")" "$(num "$LS")"
