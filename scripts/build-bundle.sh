#!/bin/sh
# Build the OPA bundle from policies/ (no service image includes it today).
#
#   scripts/build-bundle.sh [output]   (default: bundle.tar.gz)
#
# BUNDLE_REVISION stamps the bundle manifest (default: the checked-out
# commit). The bundle holds policies/ without the tests, rooted at "steward".
# Run it with the OPA version the docs pin, so the same commit always builds
# the same bytes.
set -eu

here="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-bundle.tar.gz}"

if ! command -v opa >/dev/null 2>&1; then echo "opa is required on PATH" >&2; exit 1; fi
rev="${BUNDLE_REVISION:-$(git -C "$here" rev-parse HEAD 2>/dev/null || true)}"
case "$rev" in
  "" | . | .. | *[!A-Za-z0-9._-]*)
    echo "BUNDLE_REVISION must be a plain name (letters, digits, dot, dash, underscore)" >&2; exit 1 ;;
esac

opa build --bundle "$here/policies" --ignore '*_test.rego' --revision "$rev" --output "$out"
echo "built $out (revision $rev)"
