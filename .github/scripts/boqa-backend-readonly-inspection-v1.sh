#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
h(){ printf '%s' "$1"|sha256sum|awk '{print $1}'; }
n(){ local x; x=$(printf '%s' "${1:-0}"|tr -cd '0-9'); printf '%s' "${x:-0}"; }
s(){ printf '%s' "${1:-missing}"|tr -cd 'A-Za-z0-9_.:-'|cut -c1-48; }
j(){ printf '%s' "$1"|jq -r "$2 // empty" 2>/dev/null||true; }
q(){ local x; x=$(curl -sS --max-time 8 -w $'\n%{http_code}' "$1" 2>/dev/null||true); printf '%s' "$x"; }

DA=NO
if docker version >/dev/null 2>&1;then D=(docker);DA=DIRECT
elif sudo -n docker version >/dev/null 2>&1;then D=(sudo -n docker);DA=SUDO_READ_ONLY
else D=();fi
C=0;IH='';IIH='';RS=unknown;MC=0;RWM=0;OM=false;PB=0;RC=0;RCH=''
HH=000;HS=missing;HJ=false;HRS=missing;UH=000;US=missing;UJ=false;UKH=''
LL=0;LE=0;LS=0;CLASS=BLOCKED_DOCKER_ACCESS

if [ "${#D[@]}" -gt 0 ];then
 mapfile -t IDS < <("${D[@]}" ps --filter publish=80 --format '{{.ID}}' 2>/dev/null)
 C=${#IDS[@]}
 if [ "$C" -eq 1 ];then
  ID=${IDS[0]};META=$("${D[@]}" inspect "$ID" 2>/dev/null||true)
  IMG=$(j "$META" '.[0].Config.Image');IID=$(j "$META" '.[0].Image')
  if [ -n "$IMG" ]&&[[ "$IID" =~ ^sha256:[0-9a-f]{64}$ ]];then
   IH=$(h "$IMG");IIH=$(h "$IID");RS=$(s "$(j "$META" '.[0].HostConfig.RestartPolicy.Name')")
   MC=$(j "$META" '.[0].Mounts|length');RWM=$(j "$META" '[.[0].Mounts[]?|select(.RW==true)]|length')
   OM=$(j "$META" '[.[0].Mounts[]?|select(.Source=="/var/lib/boqa/output" and .Destination=="/app/output" and .RW==true)]|length==1')
   PB=$(j "$META" '[.[0].NetworkSettings.Ports[]?|select(.!=null)]|length')
   HRS=$(j "$META" '[.[0].Config.Env[]?|select(test("^BOQA_RELEASE_SHA=[0-9a-fA-F]{40}$"))|split("=")[1]][0]')
   [ -n "$HRS" ]||HRS=missing
   REF=${IMG%%@*};LAST=${REF##*/};REPO=$REF;[[ "$LAST" == *:* ]]&&REPO=${REF%:*}
   mapfile -t RIDS < <("${D[@]}" image ls "$REPO" --no-trunc --format '{{.ID}}' 2>/dev/null|sort -u|grep -Fxv "$IID"||true)
   RC=${#RIDS[@]};[ "$RC" -eq 0 ]||RCH=$(printf '%s\n' "${RIDS[@]}"|sha256sum|awk '{print $1}')
   X=$(q http://127.0.0.1/api/health);HH=$(printf '%s\n' "$X"|tail -n1);HEALTH=$(printf '%s\n' "$X"|sed '$d')
   printf '%s' "$HEALTH"|jq -e 'type=="object"' >/dev/null 2>&1&&HJ=true||true
   HS=$(s "$(j "$HEALTH" '.status')");if [ "$HRS" = missing ];then Z=$(j "$HEALTH" '.release_sha');[[ "$Z" =~ ^[0-9a-fA-F]{40}$ ]]&&HRS=$Z;fi
   X=$(q http://127.0.0.1/api/hunter/status);UH=$(printf '%s\n' "$X"|tail -n1);HUNTER=$(printf '%s\n' "$X"|sed '$d')
   if printf '%s' "$HUNTER"|jq -e 'type=="object"' >/dev/null 2>&1;then UJ=true;US=$(s "$(j "$HUNTER" '.state')");UKH=$(printf '%s' "$HUNTER"|jq -cS 'keys'|sha256sum|awk '{print $1}');fi
   LOGS=$("${D[@]}" logs --tail 200 "$ID" 2>&1||true);if [ -n "$LOGS" ];then LL=$(printf '%s\n' "$LOGS"|wc -l|tr -d ' ');LE=$(printf '%s\n' "$LOGS"|grep -Eic 'error|fatal|panic|exception'||true);LS=$(printf '%s\n' "$LOGS"|grep -Eic 'password|secret|token|api[_ -]?key|authorization'||true);fi
   CLASS=INSPECTED
  else CLASS=BLOCKED_INSPECT_INCOMPLETE;fi
 else CLASS=BLOCKED_CONTAINER_AMBIGUITY;fi
fi
printf '{"v":1,"class":"%s","docker":"%s","containers":%s,"image_ref_sha":"%s","image_id_sha":"%s","restart":"%s","mounts":%s,"rw_mounts":%s,"output_mount":%s,"port_bindings":%s,"rollback_count":%s,"rollback_set_sha":"%s","health_http":"%s","health_status":"%s","health_json":%s,"release_sha":"%s","hunter_http":"%s","hunter_state":"%s","hunter_json":%s,"hunter_keys_sha":"%s","log_lines":%s,"log_critical":%s,"log_secret_terms":%s,"state_mutation_command_attempted":false}\n' "$CLASS" "$DA" "$C" "$IH" "$IIH" "$RS" "$(n "$MC")" "$(n "$RWM")" "$OM" "$(n "$PB")" "$RC" "$RCH" "$(s "$HH")" "$HS" "$HJ" "$HRS" "$(s "$UH")" "$US" "$UJ" "$UKH" "$(n "$LL")" "$(n "$LE")" "$(n "$LS")"
