# AI service authorization.
#
# The hard rule here is the authorized_group_ids enforcement: the AI
# service trusts the gateway to have computed the set of groups the
# caller has at least Viewer on, and OPA enforces that:
#   (a) the caller's claims.groups is a SUPERSET of authorized_group_ids,
#       i.e. every group_id in authorized_group_ids must be in
#       claims.groups; the gateway cannot widen the set.
#   (b) include_sensitive=true requires the sensitive role.
package steward.ai # scrub:allow=fqdn

import data.steward.common

default allow := false

# ---- SearchAndAnswer ---------------------------------------------------

# All authorized_group_ids must be present in the caller's claims.groups.
# Implementation: there exists no element of authorized_group_ids that is
# NOT in claims.groups.
authorized_groups_subset_of_claims if {
	not authorized_group_outside_claims
}

authorized_group_outside_claims if {
	some i
	gid := input.request.authorized_group_ids[i]
	not group_in_claims(gid)
}

group_in_claims(gid) if {
	some j
	input.claims.groups[j] == gid
}

# Base allow: authenticated caller, requester field matches user_id, the
# authorized_group_ids the caller submitted are all groups they actually
# belong to, and (when sensitive content is included) they hold the
# sensitive-content role.
allow if {
	input.method == "steward.ai.v1.AiService/SearchAndAnswer"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.actor_user_id
	authorized_groups_subset_of_claims
	not_sensitive_request
}

allow if {
	input.method == "steward.ai.v1.AiService/SearchAndAnswer"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.actor_user_id
	authorized_groups_subset_of_claims
	input.request.include_sensitive == true
	common.can_access_sensitive(input.claims)
}

not_sensitive_request if {
	input.request.include_sensitive == false
}

not_sensitive_request if {
	not input.request.include_sensitive
}

# ---- AuthoringAssist ---------------------------------------------------

# Authors editing a draft can use the assist; gateway binds actor_user_id.
allow if {
	input.method == "steward.ai.v1.AiService/AuthoringAssist"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.actor_user_id
	common.is_author(input.claims)
}
