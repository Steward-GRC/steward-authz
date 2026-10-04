package steward.common

# --- has_role -------------------------------------------------------------

test_has_role_present if {
	has_role({"roles": ["author", "approver"]}, "author")
}

test_has_role_missing if {
	not has_role({"roles": ["approver"]}, "author")
}

test_has_role_empty_roles if {
	not has_role({"roles": []}, "author")
}

test_has_role_no_roles_field if {
	not has_role({"user_id": "u1"}, "author")
}

# --- in_group -------------------------------------------------------------

test_in_group_present if {
	in_group({"groups": ["g1", "g2"]}, "g1")
}

test_in_group_missing if {
	not in_group({"groups": ["g2"]}, "g1")
}

test_in_group_empty_target_is_false if {
	# Refuse to match on an empty group id — that's a misuse.
	not in_group({"groups": ["", "g1"]}, "")
}

# --- in_any_group ---------------------------------------------------------

test_in_any_group_match if {
	in_any_group({"groups": ["g1", "g2"]}, ["g3", "g2"])
}

test_in_any_group_no_match if {
	not in_any_group({"groups": ["g1"]}, ["g2", "g3"])
}

# --- group_or_descendant --------------------------------------------------

test_group_or_descendant_in_leaf if {
	# leaf at index 0, ancestors above. Caller is in the leaf.
	group_or_descendant(
		{"groups": ["leaf"]},
		["leaf", "mid", "root"],
	)
}

test_group_or_descendant_in_ancestor if {
	# Caller is in a parent group, so they have access to the leaf resource.
	group_or_descendant(
		{"groups": ["root"]},
		["leaf", "mid", "root"],
	)
}

test_group_or_descendant_unrelated if {
	not group_or_descendant(
		{"groups": ["other"]},
		["leaf", "mid", "root"],
	)
}

# --- role shorthands ------------------------------------------------------

test_admin_is_not_a_role if {
	not is_site_admin({"roles": ["admin"]})
	not is_compliance_admin({"roles": ["admin"]})
	not is_author({"roles": ["admin"]})
	not is_approver({"roles": ["admin"]})
}

test_is_site_admin if {
	is_site_admin({"roles": ["site-admin"]})
	not is_site_admin({"roles": ["author"]})
}

test_is_compliance_admin if {
	is_compliance_admin({"roles": ["compliance-admin"]})
	not is_compliance_admin({"roles": ["author"]})
}

# --- has_scoped_role ------------------------------------------------------

test_has_scoped_role_category_match if {
	has_scoped_role(
		{"scoped_roles": [{"role": "author", "category": "Information"}]},
		"author",
		"Information",
	)
}

test_has_scoped_role_category_mismatch if {
	not has_scoped_role(
		{"scoped_roles": [{"role": "author", "category": "Information"}]},
		"author",
		"Finance",
	)
}

test_has_scoped_role_empty_category_falls_back_to_global if {
	has_scoped_role({"roles": ["author"]}, "author", "")
}

test_has_scoped_role_empty_category_no_global_denied if {
	not has_scoped_role({"roles": []}, "author", "")
}

# --- is_author ------------------------------------------------------------

test_is_author_global_role if {
	is_author({"roles": ["author"]})
}

test_is_author_scoped_only if {
	# Scoped-only author (no global role) must be authorized.
	is_author({"scoped_roles": [{"role": "author", "category": "Information"}], "roles": []})
}

test_is_author_denied_reader if {
	not is_author({"roles": ["reader"], "scoped_roles": []})
}

# --- is_approver ----------------------------------------------------------

test_is_approver_global_role if {
	is_approver({"roles": ["approver"]})
}

test_is_approver_scoped_only if {
	# Scoped-only approver (no global role) must be authorized.
	is_approver({"scoped_roles": [{"role": "approver", "category": "Finance"}], "roles": []})
}

test_is_approver_denied_reader if {
	not is_approver({"roles": ["reader"], "scoped_roles": []})
}

# --- sensitive reads ------------------------------------------------------
# A sensitive policy is read only by the authors and approvers assigned to
# it, and by explicit grants. No role reads it.

sensitive_policy := {
	"id": "POL-EXPENSES-000002",
	"assigned_author_ids": ["bob"],
	"assigned_approver_ids": ["carol"],
}

test_can_read_sensitive_assigned_author if {
	can_read_sensitive({"user_id": "bob", "roles": ["author"]}, sensitive_policy)
}

test_can_read_sensitive_assigned_approver if {
	can_read_sensitive({"user_id": "carol", "roles": ["approver"]}, sensitive_policy)
}

test_can_read_sensitive_unassigned_author_denied if {
	not can_read_sensitive(
		{"user_id": "dave", "roles": ["author"], "scoped_roles": [{"role": "author", "category": "Finance"}]},
		sensitive_policy,
	)
}

test_can_read_sensitive_unassigned_approver_denied if {
	not can_read_sensitive(
		{"user_id": "heidi", "roles": ["approver"], "scoped_roles": [{"role": "approver", "category": "Finance"}]},
		sensitive_policy,
	)
}

test_can_read_sensitive_individual_grant if {
	can_read_sensitive({"user_id": "frank", "roles": [], "read_sensitive": true}, sensitive_policy)
}

test_can_read_sensitive_policy_grant if {
	can_read_sensitive({"user_id": "frank", "roles": [], "sensitive_grants": ["POL-EXPENSES-000002"]}, sensitive_policy)
}

test_can_read_sensitive_other_policy_grant_denied if {
	not can_read_sensitive({"user_id": "frank", "roles": [], "sensitive_grants": ["POL-FACILITIES-000004"]}, sensitive_policy)
}

test_can_read_sensitive_roles_denied if {
	not can_read_sensitive({"user_id": "grace", "roles": ["compliance-admin"]}, sensitive_policy)
	not can_read_sensitive({"user_id": "alice", "roles": ["site-admin"]}, sensitive_policy)
	not can_read_sensitive({"user_id": "erin", "roles": ["reader"]}, sensitive_policy)
	not can_read_sensitive({"user_id": "ops", "roles": ["admin"]}, sensitive_policy)
}

test_can_read_sensitive_empty_user_id_denied if {
	not can_read_sensitive({"user_id": "", "roles": []}, {"id": "p", "assigned_author_ids": [""], "assigned_approver_ids": []})
}

test_has_sensitive_grant if {
	has_sensitive_grant({"user_id": "frank", "read_sensitive": true})
	not has_sensitive_grant({"user_id": "frank", "read_sensitive": false})
	not has_sensitive_grant({"user_id": "grace", "roles": ["compliance-admin"]})
	not has_sensitive_grant({"user_id": "bob", "roles": ["author"]})
}

# --- has_user_id ----------------------------------------------------------

test_has_user_id_present if {
	has_user_id({"user_id": "u1"})
}

test_has_user_id_empty if {
	not has_user_id({"user_id": ""})
}

test_has_user_id_missing if {
	not has_user_id({"roles": ["author"]})
}
