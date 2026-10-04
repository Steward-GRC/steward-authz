#!/usr/bin/env bash
# Publish an OPA bundle to any S3-compatible object store with the MinIO
# client (mc).
#
# Inputs (env):
#   BUNDLE_PATH           the bundle (default: bundle.tar.gz)
#   BUNDLE_S3_ENDPOINT    the store's URL, e.g. https://s3.example.org
#   BUNDLE_S3_ACCESS_KEY
#   BUNDLE_S3_SECRET_KEY
#   BUNDLE_BUCKET         default: steward-authz-bundles
#   BUNDLE_CHANNEL        the mutable channel OPA polls, e.g. stable
#   BUNDLE_REVISION       the immutable revision, normally the commit SHA
#
# Outputs:
#   <bucket>/versions/<revision>/bundle.tar.gz  immutable, for rollback
#   <bucket>/<channel>/bundle.tar.gz            mutable, what OPA polls
set -euo pipefail

BUNDLE_PATH="${BUNDLE_PATH:-bundle.tar.gz}"
BUNDLE_BUCKET="${BUNDLE_BUCKET:-steward-authz-bundles}"

for v in BUNDLE_S3_ENDPOINT BUNDLE_S3_ACCESS_KEY BUNDLE_S3_SECRET_KEY BUNDLE_CHANNEL BUNDLE_REVISION; do
  if [ -z "${!v:-}" ]; then echo "$v is required" >&2; exit 1; fi
done
plain='^[A-Za-z0-9._-]+$'
for v in BUNDLE_CHANNEL BUNDLE_REVISION BUNDLE_BUCKET; do
  if ! [[ ${!v} =~ $plain ]] || [ "${!v}" = . ] || [ "${!v}" = .. ]; then
    echo "$v must be a plain name (letters, digits, dot, dash, underscore)" >&2; exit 1
  fi
done
if [ ! -f "$BUNDLE_PATH" ]; then echo "bundle not found at $BUNDLE_PATH" >&2; exit 1; fi

echo "publishing $BUNDLE_PATH to $BUNDLE_BUCKET (channel=$BUNDLE_CHANNEL, revision=$BUNDLE_REVISION)"

mc alias set steward-bundles "$BUNDLE_S3_ENDPOINT" "$BUNDLE_S3_ACCESS_KEY" "$BUNDLE_S3_SECRET_KEY" >/dev/null
mc mb --ignore-existing "steward-bundles/$BUNDLE_BUCKET"
# The immutable copy goes first, so a failed upload never leaves the channel
# pointing at a bundle with no versioned twin.
mc cp "$BUNDLE_PATH" "steward-bundles/$BUNDLE_BUCKET/versions/$BUNDLE_REVISION/bundle.tar.gz"
mc cp "$BUNDLE_PATH" "steward-bundles/$BUNDLE_BUCKET/$BUNDLE_CHANNEL/bundle.tar.gz"

echo "published versions/$BUNDLE_REVISION and $BUNDLE_CHANNEL"
