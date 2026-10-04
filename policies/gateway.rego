# Gateway edge-level authorization.
#
# The gateway terminates HTTP and is the primary trust boundary. Most
# fine-grained authz happens in the per-service packages; the
# gateway-level rules here cover:
#
#   - Coarse "is this request allowed onto the platform at all?" gating
#     (e.g. CollabTokenService/IssueToken which originates at the gateway).
#   - Edge endpoints that don't proxy to a downstream gRPC method and so
#     don't get covered by per-service packages.
#
# Method strings here are either the gRPC method (for gateway-originated
# gRPC calls) or a synthetic "steward.gateway.v1.HTTP/<verb>:<path-tag>" string
# that the gateway's HTTP middleware constructs when it queries OPA.
package steward.gateway

import data.steward.common

default allow := false

# ---- CollabTokenService/IssueToken -------------------------------------
# Originates from a gateway resolver. Any authenticated caller can mint
# a collab token for themselves; the gateway already binds user_id from
# claims, so the actor_user_id field must match.
allow if {
	input.method == "steward.collab.v1.CollabTokenService/IssueToken"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.user_id
}

# ---- HTTP-edge synthetic methods ---------------------------------------
# The gateway HTTP middleware sets input.method to "steward.gateway.v1.HTTP/<tag>"
# for non-gRPC paths (e.g. /healthz, /query). These have no per-service
# package to fall through to, so the gateway rego owns them.

# /healthz is unauthenticated.
allow if {
	input.method == "steward.gateway.v1.HTTP/GET:/healthz"
}

# /readyz is unauthenticated (probes only).
allow if {
	input.method == "steward.gateway.v1.HTTP/GET:/readyz"
}

# POST /query — GraphQL endpoint. The HTTP middleware already requires
# a non-empty bearer; OPA confirms claims.user_id is present.
allow if {
	input.method == "steward.gateway.v1.HTTP/POST:/query"
	common.has_user_id(input.claims)
}
