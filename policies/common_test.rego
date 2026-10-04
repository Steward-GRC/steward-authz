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

# --- can_access_sensitive -------------------------------------------------

test_can_access_sensitive_admin_role_denied if {
	not can_access_sensitive({"roles": ["admin"]})
}

test_can_access_sensitive_site_admin if {
	can_access_sensitive({"roles": ["site-admin"]})
}

test_can_access_sensitive_compliance_admin if {
	can_access_sensitive({"roles": ["compliance-admin"]})
}

test_can_access_sensitive_author if {
	can_access_sensitive({"roles": ["author"]})
}

test_can_access_sensitive_approver if {
	can_access_sensitive({"roles": ["approver"]})
}

test_can_access_sensitive_scoped_author if {
	# Scoped author (no global role) is elevated.
	can_access_sensitive({"roles": [], "scoped_roles": [{"role": "author", "category": "Information"}]})
}

test_can_access_sensitive_denied_empty_roles if {
	not can_access_sensitive({"roles": []})
}

test_can_access_sensitive_denied_reader if {
	not can_access_sensitive({"roles": ["reader"], "scoped_roles": []})
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
