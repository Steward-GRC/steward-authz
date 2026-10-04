package steward.gateway

test_issue_token_self if {
	allow with input as {
		"method": "steward.collab.v1.CollabTokenService/IssueToken",
		"claims": {"user_id": "u1"},
		"request": {"user_id": "u1", "draft_id": "d1"},
	}
}

test_issue_token_other_denied if {
	not allow with input as {
		"method": "steward.collab.v1.CollabTokenService/IssueToken",
		"claims": {"user_id": "u1"},
		"request": {"user_id": "u2"},
	}
}

test_healthz_anonymous if {
	allow with input as {
		"method": "steward.gateway.v1.HTTP/GET:/healthz",
		"claims": {},
		"request": {},
	}
}

test_readyz_anonymous if {
	allow with input as {
		"method": "steward.gateway.v1.HTTP/GET:/readyz",
		"claims": {},
		"request": {},
	}
}

test_query_requires_user if {
	allow with input as {
		"method": "steward.gateway.v1.HTTP/POST:/query",
		"claims": {"user_id": "u1"},
		"request": {},
	}
}

test_query_anonymous_denied if {
	not allow with input as {
		"method": "steward.gateway.v1.HTTP/POST:/query",
		"claims": {"user_id": ""},
		"request": {},
	}
}

test_root_playground_denied if {
	not allow with input as {
		"method": "steward.gateway.v1.HTTP/GET:/",
		"claims": {},
		"request": {},
	}
}

test_unknown_path_denied if {
	not allow with input as {
		"method": "steward.gateway.v1.HTTP/GET:/admin/secret",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {},
	}
}
