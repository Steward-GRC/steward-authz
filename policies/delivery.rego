# Delivery service authorization.
#
# Magic links are a content-share primitive — the resolve path is
# intentionally permissive (anonymous viewers with a valid token are the
# whole point). Authoring + revocation are gated.
package steward.delivery

import data.steward.common

default allow := false

# ---- Rendered content / diff — reads ------------------------------------

allow if {
	input.method == "steward.delivery.v1.DeliveryService/GetRenderedContent"
	common.has_user_id(input.claims)
}

allow if {
	input.method == "steward.delivery.v1.DeliveryService/GetDiff"
	common.has_user_id(input.claims)
}

# ---- PDF export ---------------------------------------------------------
# Any authenticated caller can request an export; the requester field must
# match their own user id (the gateway already binds this — defence in
# depth).
allow if {
	input.method == "steward.delivery.v1.DeliveryService/RequestPDFExport"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.requester_user_id
}

allow if {
	input.method == "steward.delivery.v1.DeliveryService/GetPDFDownloadLink"
	common.has_user_id(input.claims)
}

# ---- Magic links -------------------------------------------------------

# Non-sensitive magic links: any author or approver can mint one for
# content they could otherwise share.
allow if {
	input.method == "steward.delivery.v1.DeliveryService/CreateMagicLink"
	input.request.sensitive == false
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.created_by_user_id
	common.is_author(input.claims)
}

allow if {
	input.method == "steward.delivery.v1.DeliveryService/CreateMagicLink"
	input.request.sensitive == false
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.created_by_user_id
	common.is_approver(input.claims)
}

# Sensitive magic links: only someone who may read that policy: its assigned
# authors and approvers, or an explicit grant.
allow if {
	input.method == "steward.delivery.v1.DeliveryService/CreateMagicLink"
	input.request.sensitive == true
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.created_by_user_id
	common.can_read_sensitive(input.claims, input.request.policy)
}

# Revocation: any authenticated user can revoke a link they created. We do not have the link's creator in input
# (it's an opaque token), so we authorize on user_id matching the request
# field and rely on the service to look up + 404 the creator mismatch.
allow if {
	input.method == "steward.delivery.v1.DeliveryService/RevokeMagicLink"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.revoked_by_user_id
}

# ---- Resolve magic link ------------------------------------------------
# Anonymous by design: the token is the credential. OPA still gates here so
# rate or network rules can be added later. Always allowed; the service
# validates the token.
allow if {
	input.method == "steward.delivery.v1.DeliveryService/ResolveMagicLink"
}
