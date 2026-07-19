#!/usr/bin/env bash
set -Eeuo pipefail
set +x

: "${CLOUDFLARE_ACCOUNT_ID:?missing account id}"
: "${CLOUDFLARE_API_TOKEN:?missing api token}"
: "${BOQA_HEAD_SHA:?missing head sha}"
: "${BOQA_HEAD_BRANCH:?missing head branch}"

WORKER_NAME="${WORKER_NAME:-boqa}"
OUT="output/cloudflare-preview-v6"
API="https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}"
AUTH=(-H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}")
mkdir -p "$OUT/browser"

test "$(git rev-parse HEAD)" = "$BOQA_HEAD_SHA"
test -z "$(git status --porcelain)"

jq -n --arg head "$BOQA_HEAD_SHA" --arg branch "$BOQA_HEAD_BRANCH" \
  '{schema_version:1,head_sha:$head,branch:$branch,production_accessed:false,production_changed:false,deploy_performed:false,rollback_executed:false}' \
  > "$OUT/manifest.json"

curl -fsS "${AUTH[@]}" "$API/workers/scripts" > /tmp/workers.json
worker_tag=$(jq -r --arg name "$WORKER_NAME" '.result[] | select(.id == $name) | .tag' /tmp/workers.json | head -1)
test -n "$worker_tag" && test "$worker_tag" != null

curl -fsS "${AUTH[@]}" "$API/builds/workers/${worker_tag}/triggers" > /tmp/triggers.json
curl -fsS "${AUTH[@]}" "$API/builds/account/limits" > /tmp/limits.json
curl -fsS "${AUTH[@]}" "$API/workers/scripts/${WORKER_NAME}/deployments" > /tmp/deployments-before.json
curl -fsS "${AUTH[@]}" "$API/workers/workers/${WORKER_NAME}/versions?per_page=100" > /tmp/versions-before.json
curl -fsS "${AUTH[@]}" "$API/workers/scripts/${WORKER_NAME}/subdomain" > /tmp/subdomain.json

production_count=$(jq '[.result[]? | select((.branch_includes // []) | index("main"))] | length' /tmp/triggers.json)
preview_count=$(jq '[.result[]? | select(((.branch_includes // []) | index("*")) and (((.branch_excludes // []) | index("main"))))] | length' /tmp/triggers.json)
test "$production_count" -eq 0
test "$preview_count" -eq 1

trigger_uuid=$(jq -r '.result[] | select(((.branch_includes // []) | index("*")) and (((.branch_excludes // []) | index("main")))) | .trigger_uuid' /tmp/triggers.json)
test -n "$trigger_uuid" && test "$trigger_uuid" != null

jq -e '.result[] | select(.trigger_uuid == $uuid) | (
  .repo_connection.provider_type == "github" and
  .repo_connection.repo_name == "boqa" and
  (.build_command | contains("npm")) and
  (.deploy_command | contains("versions upload")) and
  .build_caching_enabled == true
)' --arg uuid "$trigger_uuid" /tmp/triggers.json >/dev/null
jq -e '.result.has_reached_build_minutes_limit == false' /tmp/limits.json >/dev/null
jq -e '.result.previews_enabled == true' /tmp/subdomain.json >/dev/null

jq --arg uuid "$trigger_uuid" '{success,production_trigger_count:0,preview_trigger_count:1,preview_trigger:(.result[] | select(.trigger_uuid == $uuid) | {trigger_uuid,trigger_name,branch_includes,branch_excludes,build_command,deploy_command,root_directory,build_caching_enabled,repo_name:.repo_connection.repo_name,provider_type:.repo_connection.provider_type})}' \
  /tmp/triggers.json > "$OUT/configuration.json"
jq '{success,result:{has_reached_build_minutes_limit:.result.has_reached_build_minutes_limit,build_minutes_refresh_on:.result.build_minutes_refresh_on}}' \
  /tmp/limits.json > "$OUT/limits.json"
jq '{success,result:{enabled:.result.enabled,previews_enabled:.result.previews_enabled}}' \
  /tmp/subdomain.json > "$OUT/subdomain.json"
jq -S '{active:(.result.deployments[0] | {id,created_on,source,strategy,versions})}' \
  /tmp/deployments-before.json > "$OUT/deployment-before.json"
jq '{versions:[.result[]? | {id,number,created_on,urls,triggered_by:.annotations["workers/triggered_by"]}]}' \
  /tmp/versions-before.json > "$OUT/versions-before.json"
jq -r '.result[]?.id' /tmp/versions-before.json | sort -u > /tmp/version-ids-before.txt

payload=$(jq -cn --arg branch "$BOQA_HEAD_BRANCH" --arg commit "$BOQA_HEAD_SHA" '{branch:$branch,commit_hash:$commit}')
curl -fsS "${AUTH[@]}" -H 'Content-Type: application/json' -X POST -d "$payload" \
  "$API/builds/triggers/${trigger_uuid}/builds" > /tmp/build-create.json
jq -e '.success == true and (.result.build_uuid | type == "string")' /tmp/build-create.json >/dev/null
build_uuid=$(jq -r '.result.build_uuid' /tmp/build-create.json)

stopped=false
for _ in $(seq 1 120); do
  curl -fsS "${AUTH[@]}" "$API/builds/builds/${build_uuid}" > /tmp/build-detail.json
  status=$(jq -r '.result.status // "unknown"' /tmp/build-detail.json)
  if [ "$status" = stopped ]; then stopped=true; break; fi
  sleep 10
done
test "$stopped" = true
jq -e --arg head "$BOQA_HEAD_SHA" --arg branch "$BOQA_HEAD_BRANCH" --arg uuid "$build_uuid" '
  .success == true and
  .result.build_uuid == $uuid and
  .result.status == "stopped" and
  .result.build_outcome == "success" and
  .result.build_trigger_metadata.branch == $branch and
  .result.build_trigger_metadata.commit_hash == $head and
  (.result.build_trigger_metadata.build_trigger_source == "api" or .result.build_trigger_metadata.build_trigger_source == "manual")
' /tmp/build-detail.json >/dev/null

jq '{success,result:{build_uuid:.result.build_uuid,status:.result.status,build_outcome:.result.build_outcome,created_on:.result.created_on,running_on:.result.running_on,stopped_on:.result.stopped_on,trigger:{trigger_uuid:.result.trigger.trigger_uuid,trigger_name:.result.trigger.trigger_name},metadata:{branch:.result.build_trigger_metadata.branch,commit_hash:.result.build_trigger_metadata.commit_hash,source:.result.build_trigger_metadata.build_trigger_source,provider_type:.result.build_trigger_metadata.provider_type,repo_name:.result.build_trigger_metadata.repo_name,build_command:.result.build_trigger_metadata.build_command,deploy_command:.result.build_trigger_metadata.deploy_command}}}' \
  /tmp/build-detail.json > "$OUT/build.json"

curl -fsS "${AUTH[@]}" "$API/builds/builds/${build_uuid}/logs" > /tmp/build-logs.json
jq -r '.result.lines[]? | if type == "array" then .[-1] else . end' /tmp/build-logs.json \
  | grep -E 'Uploaded boqa|Worker Version ID|Version Preview URL' \
  | tail -20 > "$OUT/build-safe-lines.txt" || true

version_id=$(grep -Eo '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' "$OUT/build-safe-lines.txt" | tail -1 || true)
preview_url=$(grep -Eo 'https://[a-zA-Z0-9.-]+\.workers\.dev' "$OUT/build-safe-lines.txt" | tail -1 || true)

test -n "$version_id"
curl -fsS "${AUTH[@]}" "$API/workers/workers/${WORKER_NAME}/versions?per_page=100" > /tmp/versions-after.json
jq -r '.result[]?.id' /tmp/versions-after.json | sort -u > /tmp/version-ids-after.txt
comm -13 /tmp/version-ids-before.txt /tmp/version-ids-after.txt > /tmp/new-version-ids.txt
grep -Fx "$version_id" /tmp/new-version-ids.txt >/dev/null

curl -fsS "${AUTH[@]}" "$API/workers/workers/${WORKER_NAME}/versions/${version_id}" > /tmp/version-detail.json
jq -e --arg id "$version_id" '.success == true and .result.id == $id and (.result.urls | length) >= 1' /tmp/version-detail.json >/dev/null
if [ -z "$preview_url" ]; then
  preview_url=$(jq -r '.result.urls[]? | select(test("^https://.*\\.workers\\.dev/?$"))' /tmp/version-detail.json | head -1)
fi
preview_url=${preview_url%/}
test -n "$preview_url"
jq -e --arg url "$preview_url" '.result.urls | index($url) != null or index($url + "/") != null' /tmp/version-detail.json >/dev/null

jq '{success,result:{id:.result.id,number:.result.number,created_on:.result.created_on,urls:.result.urls,triggered_by:.result.annotations["workers/triggered_by"],message:.result.annotations["workers/message"]}}' \
  /tmp/version-detail.json > "$OUT/version.json"
jq '{versions:[.result[]? | {id,number,created_on,urls,triggered_by:.annotations["workers/triggered_by"]}]}' \
  /tmp/versions-after.json > "$OUT/versions-after.json"

curl -fsS "${AUTH[@]}" "$API/workers/scripts/${WORKER_NAME}/deployments" > /tmp/deployments-after.json
jq -S '{active:(.result.deployments[0] | {id,created_on,source,strategy,versions})}' \
  /tmp/deployments-after.json > "$OUT/deployment-after.json"
cmp "$OUT/deployment-before.json" "$OUT/deployment-after.json"

jq -n --arg build_uuid "$build_uuid" --arg version_id "$version_id" --arg preview_url "$preview_url" --arg head "$BOQA_HEAD_SHA" \
  '{build_uuid:$build_uuid,version_id:$version_id,preview_url:$preview_url,head_sha:$head,production_changed:false,deploy_performed:false}' \
  > "$OUT/candidate.json"

{
  echo "BOQA_VERSION_ID=$version_id"
  echo "BOQA_PREVIEW_URL=$preview_url"
} >> "${GITHUB_ENV:?missing GITHUB_ENV}"
