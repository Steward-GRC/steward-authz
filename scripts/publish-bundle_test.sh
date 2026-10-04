#!/usr/bin/env bash
# Tests for publish-bundle.sh, with a fake mc on PATH that logs its arguments.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cat > "$work/bin/mc" <<'MC'
#!/usr/bin/env bash
echo "$*" >> "$MC_LOG"
MC
chmod +x "$work/bin/mc"
printf 'bundle' > "$work/bundle.tar.gz"

fail=0
run() {
  : > "$work/mc.log"
  env -i PATH="$work/bin:/usr/bin:/bin" MC_LOG="$work/mc.log" "$@" bash "$here/publish-bundle.sh" > "$work/out" 2>&1
}
expect() {
  local name="$1" want="$2" got="$3"
  if [ "$want" != "$got" ]; then
    echo "FAIL $name: want [$want] got [$got]"; fail=1
  else
    echo "ok   $name"
  fi
}

base=(BUNDLE_PATH="$work/bundle.tar.gz" BUNDLE_S3_ENDPOINT=https://s3.example.org
  BUNDLE_S3_ACCESS_KEY=ak BUNDLE_S3_SECRET_KEY=sk BUNDLE_CHANNEL=stable BUNDLE_REVISION=3f2a9c41)

run "${base[@]}" && rc=0 || rc=$?
expect "publishes" 0 "$rc"
expect "versioned copy first, then the channel" \
  "alias set steward-bundles https://s3.example.org ak sk
mb --ignore-existing steward-bundles/steward-authz-bundles
cp $work/bundle.tar.gz steward-bundles/steward-authz-bundles/versions/3f2a9c41/bundle.tar.gz
cp $work/bundle.tar.gz steward-bundles/steward-authz-bundles/stable/bundle.tar.gz" "$(cat "$work/mc.log")"

for v in BUNDLE_S3_ENDPOINT BUNDLE_S3_ACCESS_KEY BUNDLE_S3_SECRET_KEY BUNDLE_CHANNEL BUNDLE_REVISION; do
  args=()
  for kv in "${base[@]}"; do [ "${kv%%=*}" = "$v" ] || args+=("$kv"); done
  run "${args[@]}" && rc=0 || rc=$?
  expect "refuses without $v" 1 "$rc"
  expect "nothing uploaded without $v" "" "$(cat "$work/mc.log")"
done

run "${base[@]}" BUNDLE_CHANNEL=../prod && rc=0 || rc=$?
expect "refuses a channel that is not a plain name" 1 "$rc"

run "${base[@]}" BUNDLE_REVISION=a/b && rc=0 || rc=$?
expect "refuses a revision that is not a plain name" 1 "$rc"

run "${base[@]}" BUNDLE_PATH="$work/missing.tar.gz" && rc=0 || rc=$?
expect "refuses a missing bundle" 1 "$rc"

exit "$fail"
