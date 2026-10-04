#!/bin/sh
# Tests for build-bundle.sh. Needs opa on PATH.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0
expect() {
  if [ "$2" != "$3" ]; then echo "FAIL $1: want [$2] got [$3]"; fail=1; else echo "ok   $1"; fi
}

rc=0; BUNDLE_REVISION=3f2a9c41 sh "$here/build-bundle.sh" "$work/a.tar.gz" >/dev/null 2>&1 || rc=$?
expect "builds" 0 "$rc"
expect "writes the bundle" yes "$([ -s "$work/a.tar.gz" ] && echo yes || echo no)"
expect "leaves the tests out" 0 "$(tar -tzf "$work/a.tar.gz" 2>/dev/null | grep -c '_test\.rego$' || true)"
expect "carries every policy" 8 "$(tar -tzf "$work/a.tar.gz" 2>/dev/null | grep -c '\.rego$' || true)"
mkdir "$work/x" && tar -xzf "$work/a.tar.gz" -C "$work/x" 2>/dev/null || true
expect "stamps the revision" 3f2a9c41 "$(sed -n 's/.*"revision":"\([^"]*\)".*/\1/p' "$work/x/.manifest" 2>/dev/null)"
expect "roots the bundle at steward" '"steward"' "$(sed -n 's/.*"roots":\[\([^]]*\)\].*/\1/p' "$work/x/.manifest" 2>/dev/null)"

sleep 1
BUNDLE_REVISION=3f2a9c41 sh "$here/build-bundle.sh" "$work/b.tar.gz" >/dev/null 2>&1 || true
expect "reproducible: the same input builds the same bytes" "$(cksum < "$work/a.tar.gz" 2>/dev/null)" "$(cksum < "$work/b.tar.gz" 2>/dev/null)"

rc=0; BUNDLE_REVISION=a/b sh "$here/build-bundle.sh" "$work/c.tar.gz" >/dev/null 2>&1 || rc=$?
expect "refuses a revision that is not a plain name" 1 "$rc"

rc=0; env PATH=/nonexistent BUNDLE_REVISION=r /bin/sh "$here/build-bundle.sh" "$work/d.tar.gz" >/dev/null 2>&1 || rc=$?
expect "refuses without opa" 1 "$rc"

exit "$fail"
