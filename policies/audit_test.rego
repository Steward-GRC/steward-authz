package steward.audit

# ---- QueryAuditLog -----------------------------------------------------

test_query_platform_wide_compliance_admin if {
	allow with input as {
		"method": "steward.audit.v1.AuditService/QueryAuditLog",
		"claims": {"user_id": "aud", "roles": ["compliance-admin"]},
		"request": {"group_id": "", "actor_user_id": "", "tier": "audit"},
	}
}

test_query_platform_wide_admin_role_denied if {
	not allow with input as {
		"method": "steward.audit.v1.AuditService/QueryAuditLog",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {"group_id": "", "actor_user_id": ""},
	}
}

test_query_platform_wide_author_denied if {
	not allow with input as {
		"method": "steward.audit.v1.AuditService/QueryAuditLog",
		"claims": {"user_id": "u1", "roles": ["author"]},
		"request": {"group_id": "", "actor_user_id": ""},
	}
}

test_query_group_scope_site_admin if {
	allow with input as {
		"method": "steward.audit.v1.AuditService/QueryAuditLog",
		"claims": {"user_id": "ga", "roles": ["site-admin"], "groups": ["g1"]},
		"request": {"group_id": "g1", "actor_user_id": ""},
	}
}

test_query_group_scope_site_admin_wrong_group_denied if {
	not allow with input as {
		"method": "steward.audit.v1.AuditService/QueryAuditLog",
		"claims": {"user_id": "ga", "roles": ["site-admin"], "groups": ["g2"]},
		"request": {"group_id": "g1", "actor_user_id": ""},
	}
}

test_query_self_scope if {
	# Plain user querying for their own actions.
	allow with input as {
		"method": "steward.audit.v1.AuditService/QueryAuditLog",
		"claims": {"user_id": "u1", "roles": ["author"]},
		"request": {"group_id": "", "actor_user_id": "u1"},
	}
}

test_query_self_scope_other_actor_denied if {
	# Plain user trying to query someone else.
	not allow with input as {
		"method": "steward.audit.v1.AuditService/QueryAuditLog",
		"claims": {"user_id": "u1", "roles": ["author"]},
		"request": {"group_id": "", "actor_user_id": "u2"},
	}
}

# ---- ExportAuditSegment ------------------------------------------------

test_export_segment_compliance_admin if {
	allow with input as {
		"method": "steward.audit.v1.AuditService/ExportAuditSegment",
		"claims": {"user_id": "aud", "roles": ["compliance-admin"]},
		"request": {"from_record_id": 1, "to_record_id": 100},
	}
}

test_export_segment_plain_author_denied if {
	not allow with input as {
		"method": "steward.audit.v1.AuditService/ExportAuditSegment",
		"claims": {"user_id": "co", "roles": ["author"]},
		"request": {"from_record_id": 1, "to_record_id": 100},
	}
}

# ---- VerifyAuditChain --------------------------------------------------

test_verify_chain_admin_role_denied if {
	not allow with input as {
		"method": "steward.audit.v1.AuditService/VerifyAuditChain",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {},
	}
}

test_verify_chain_author_denied if {
	not allow with input as {
		"method": "steward.audit.v1.AuditService/VerifyAuditChain",
		"claims": {"user_id": "u1", "roles": ["author"]},
		"request": {},
	}
}

test_unknown_method_denied if {
	not allow with input as {
		"method": "steward.audit.v1.AuditService/InventedRpc",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {},
	}
}
