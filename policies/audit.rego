# Audit service authorization.
#
# Audit queries are compliance-admin-only by design (cross-group read), with a
# narrow self-scope: any user can query the audit log for actions
# attributed to themselves. Exports are compliance-admin only.
package steward.audit

import data.steward.common

default allow := false

# ---- QueryAuditLog -----------------------------------------------------

# Platform-wide query (empty group_id) — compliance-admin only.
allow if {
	input.method == "steward.audit.v1.AuditService/QueryAuditLog"
	input.request.group_id == ""
	common.is_compliance_admin(input.claims)
}

# Group-scoped query — site-admin for that group, plus compliance-admin.
allow if {
	input.method == "steward.audit.v1.AuditService/QueryAuditLog"
	input.request.group_id != ""
	common.has_role(input.claims, "site-admin")
	common.in_group(input.claims, input.request.group_id)
}

allow if {
	input.method == "steward.audit.v1.AuditService/QueryAuditLog"
	input.request.group_id != ""
	common.is_compliance_admin(input.claims)
}

# Self-scope: a user can query for actions attributed to themselves
# regardless of group, provided they don't widen scope.
allow if {
	input.method == "steward.audit.v1.AuditService/QueryAuditLog"
	common.has_user_id(input.claims)
	input.request.actor_user_id == input.claims.user_id

	# Self-query may only inspect themselves, not the platform.
	input.request.actor_user_id != ""
}

# ---- ExportAuditSegment ------------------------------------------------

# Export is privileged — compliance-admin only. (Acknowledgement completion
# reports come from the obligations service, not this one.)
allow if {
	input.method == "steward.audit.v1.AuditService/ExportAuditSegment"
	common.is_compliance_admin(input.claims)
}

# ---- VerifyAuditChain --------------------------------------------------

# Chain-verification (hash-chain integrity) is compliance-admin only. Useful
# for both routine integrity checks and incident response.
allow if {
	input.method == "steward.audit.v1.AuditService/VerifyAuditChain"
	common.is_compliance_admin(input.claims)
}
