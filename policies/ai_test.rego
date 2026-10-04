package steward.ai # scrub:allow=fqdn

# ---- SearchAndAnswer ---------------------------------------------------

test_search_authorized_groups_subset_ok if {
	allow with input as {
		"method": "steward.ai.v1.AiService/SearchAndAnswer",
		"claims": {"user_id": "u1", "roles": ["reader"], "groups": ["g1", "g2", "g3"]},
		"request": {
			"question": "what",
			"actor_user_id": "u1",
			"group_id": "g1",
			"authorized_group_ids": ["g1", "g2"],
			"include_sensitive": false,
		},
	}
}

test_search_denied_when_authorized_widens_beyond_claims if {
	# Caller is only in g1, but submitted g1+g2 — escalation attempt.
	not allow with input as {
		"method": "steward.ai.v1.AiService/SearchAndAnswer",
		"claims": {"user_id": "u1", "roles": ["reader"], "groups": ["g1"]},
		"request": {
			"actor_user_id": "u1",
			"authorized_group_ids": ["g1", "g2"],
			"include_sensitive": false,
		},
	}
}

test_search_denied_actor_mismatch if {
	not allow with input as {
		"method": "steward.ai.v1.AiService/SearchAndAnswer",
		"claims": {"user_id": "u1", "roles": ["reader"], "groups": ["g1"]},
		"request": {
			"actor_user_id": "u2",
			"authorized_group_ids": ["g1"],
		},
	}
}

test_search_sensitive_requires_sensitive_role if {
	# Plain reader requesting sensitive content -> denied.
	not allow with input as {
		"method": "steward.ai.v1.AiService/SearchAndAnswer",
		"claims": {"user_id": "u1", "roles": ["reader"], "groups": ["g1"]},
		"request": {
			"actor_user_id": "u1",
			"authorized_group_ids": ["g1"],
			"include_sensitive": true,
		},
	}
}

test_search_sensitive_allowed_with_elevated_role if {
	# Elevated role (author) grants sensitive access under the new model.
	allow with input as {
		"method": "steward.ai.v1.AiService/SearchAndAnswer",
		"claims": {"user_id": "u1", "roles": ["author"], "groups": ["g1"]},
		"request": {
			"actor_user_id": "u1",
			"authorized_group_ids": ["g1"],
			"include_sensitive": true,
		},
	}
}

test_search_sensitive_denied_empty_roles if {
	# No elevated role — plain reader (empty roles) must be denied.
	not allow with input as {
		"method": "steward.ai.v1.AiService/SearchAndAnswer",
		"claims": {"user_id": "u1", "roles": [], "groups": ["g1"]},
		"request": {
			"actor_user_id": "u1",
			"authorized_group_ids": ["g1"],
			"include_sensitive": true,
		},
	}
}

test_search_admin_role_denied if {
	not allow with input as {
		"method": "steward.ai.v1.AiService/SearchAndAnswer",
		"claims": {"user_id": "ops", "roles": ["admin"], "groups": ["g1"]},
		"request": {
			"actor_user_id": "ops",
			"authorized_group_ids": ["g1"],
			"include_sensitive": true,
		},
	}
}

test_search_empty_authorized_group_ids_is_fine if {
	# Cross-group search with no narrowing — vacuously subset-of-claims.
	allow with input as {
		"method": "steward.ai.v1.AiService/SearchAndAnswer",
		"claims": {"user_id": "u1", "groups": []},
		"request": {
			"actor_user_id": "u1",
			"authorized_group_ids": [],
			"include_sensitive": false,
		},
	}
}

# ---- AuthoringAssist ---------------------------------------------------

test_authoring_assist_author_self if {
	allow with input as {
		"method": "steward.ai.v1.AiService/AuthoringAssist",
		"claims": {"user_id": "u1", "roles": ["author"]},
		"request": {"actor_user_id": "u1", "policy_id": "p1"},
	}
}

test_authoring_assist_scoped_author_self if {
	# Scoped-only author (no global role) must be authorized.
	allow with input as {
		"method": "steward.ai.v1.AiService/AuthoringAssist",
		"claims": {
			"user_id": "u1",
			"roles": [],
			"scoped_roles": [{"role": "author", "category": "Information"}],
		},
		"request": {"actor_user_id": "u1", "policy_id": "p1"},
	}
}

test_authoring_assist_reader_denied if {
	not allow with input as {
		"method": "steward.ai.v1.AiService/AuthoringAssist",
		"claims": {"user_id": "u1", "roles": ["reader"]},
		"request": {"actor_user_id": "u1"},
	}
}

test_unknown_method_denied if {
	not allow with input as {
		"method": "steward.ai.v1.AiService/NotARpc",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {},
	}
}
