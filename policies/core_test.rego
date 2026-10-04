package steward.core

# ---- PolicyService reads -------------------------------------------------

test_get_policy_allowed_for_any_authenticated if {
	allow with input as {
		"method": "steward.core.v1.PolicyService/GetPolicy",
		"claims": {"user_id": "u1", "roles": []},
		"request": {"policy_id": "p1"},
	}
}

test_get_policy_denied_unauthenticated if {
	not allow with input as {
		"method": "steward.core.v1.PolicyService/GetPolicy",
		"claims": {"user_id": ""},
		"request": {},
	}
}

test_list_policies_allowed if {
	allow with input as {
		"method": "steward.core.v1.PolicyService/ListPolicies",
		"claims": {"user_id": "u1"},
		"request": {},
	}
}

# ---- PolicyService writes ------------------------------------------------

test_create_policy_allowed_for_author_in_group if {
	allow with input as {
		"method": "steward.core.v1.PolicyService/CreatePolicy",
		"claims": {"user_id": "u1", "roles": ["author"], "groups": ["g1"]},
		"request": {"group_id": "g1"},
	}
}

test_create_policy_allowed_for_scoped_author_in_group if {
	# Scoped-only author (no global role) must be authorized.
	allow with input as {
		"method": "steward.core.v1.PolicyService/CreatePolicy",
		"claims": {
			"user_id": "u1",
			"roles": [],
			"groups": ["g1"],
			"scoped_roles": [{"role": "author", "category": "Information"}],
		},
		"request": {"group_id": "g1"},
	}
}

test_create_policy_denied_author_wrong_group if {
	not allow with input as {
		"method": "steward.core.v1.PolicyService/CreatePolicy",
		"claims": {"user_id": "u1", "roles": ["author"], "groups": ["g2"]},
		"request": {"group_id": "g1"},
	}
}

test_create_policy_denied_reader if {
	not allow with input as {
		"method": "steward.core.v1.PolicyService/CreatePolicy",
		"claims": {"user_id": "u1", "roles": ["reader"], "groups": ["g1"]},
		"request": {"group_id": "g1"},
	}
}

test_create_policy_admin_role_denied if {
	not allow with input as {
		"method": "steward.core.v1.PolicyService/CreatePolicy",
		"claims": {"user_id": "u1", "roles": ["admin"], "groups": []},
		"request": {"group_id": "g1"},
	}
}

test_publish_draft_requires_approver if {
	# Author alone is NOT enough — must be approver.
	not allow with input as {
		"method": "steward.core.v1.PolicyService/PublishDraft",
		"claims": {"user_id": "u1", "roles": ["author"], "groups": ["g1"]},
		"request": {"group_id": "g1", "draft_id": "d1"},
	}
}

test_publish_draft_approver_in_group if {
	allow with input as {
		"method": "steward.core.v1.PolicyService/PublishDraft",
		"claims": {"user_id": "u1", "roles": ["approver"], "groups": ["g1"]},
		"request": {"group_id": "g1", "draft_id": "d1"},
	}
}

test_publish_draft_scoped_approver_in_group if {
	# Scoped-only approver (no global role) must be authorized.
	allow with input as {
		"method": "steward.core.v1.PolicyService/PublishDraft",
		"claims": {
			"user_id": "u1",
			"roles": [],
			"groups": ["g1"],
			"scoped_roles": [{"role": "approver", "category": "Finance"}],
		},
		"request": {"group_id": "g1", "draft_id": "d1"},
	}
}

test_save_draft_author_in_group if {
	allow with input as {
		"method": "steward.core.v1.PolicyService/SaveDraft",
		"claims": {"user_id": "u1", "roles": ["author"], "groups": ["g1"]},
		"request": {"group_id": "g1"},
	}
}

# ---- TemplateService -----------------------------------------------------

test_create_template_template_admin if {
	allow with input as {
		"method": "steward.core.v1.TemplateService/CreateTemplate",
		"claims": {"user_id": "u1", "roles": ["template-admin"]},
		"request": {},
	}
}

test_create_template_denied_for_plain_author if {
	not allow with input as {
		"method": "steward.core.v1.TemplateService/CreateTemplate",
		"claims": {"user_id": "u1", "roles": ["author"]},
		"request": {},
	}
}

test_publish_template_version_admin_role_denied if {
	not allow with input as {
		"method": "steward.core.v1.TemplateService/PublishTemplateVersion",
		"claims": {"user_id": "u1", "roles": ["admin"]},
		"request": {},
	}
}

test_template_read_any_authenticated if {
	allow with input as {
		"method": "steward.core.v1.TemplateService/GetLatestTemplateVersion",
		"claims": {"user_id": "u1"},
		"request": {},
	}
}

# ---- GroupService --------------------------------------------------------

test_group_read_any_authenticated if {
	allow with input as {
		"method": "steward.core.v1.GroupService/GetGroup",
		"claims": {"user_id": "u1"},
		"request": {"group_id": "g1"},
	}
}

test_create_group_site_admin_in_parent if {
	allow with input as {
		"method": "steward.core.v1.GroupService/CreateGroup",
		"claims": {"user_id": "u1", "roles": ["site-admin"], "groups": ["parent"]},
		"request": {"parent_group_id": "parent", "name": "child"},
	}
}

test_create_group_denied_site_admin_of_other_group if {
	not allow with input as {
		"method": "steward.core.v1.GroupService/CreateGroup",
		"claims": {"user_id": "u1", "roles": ["site-admin"], "groups": ["unrelated"]},
		"request": {"parent_group_id": "parent"},
	}
}

test_set_group_defaults_site_admin if {
	allow with input as {
		"method": "steward.core.v1.GroupService/SetGroupDefaults",
		"claims": {"user_id": "u1", "roles": ["site-admin"], "groups": ["g1"]},
		"request": {"group_id": "g1"},
	}
}

test_default_deny_for_unknown_method if {
	not allow with input as {
		"method": "steward.core.v1.PolicyService/DoSomethingMadeUp",
		"claims": {"user_id": "u1", "roles": ["admin"]},
		"request": {},
	}
}
