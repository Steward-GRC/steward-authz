package steward.delivery

test_get_rendered_content_authenticated if {
	allow with input as {
		"method": "steward.delivery.v1.DeliveryService/GetRenderedContent",
		"claims": {"user_id": "u1"},
		"request": {"policy_version_id": "v1"},
	}
}

test_request_pdf_export_self if {
	allow with input as {
		"method": "steward.delivery.v1.DeliveryService/RequestPDFExport",
		"claims": {"user_id": "u1"},
		"request": {"policy_version_id": "v1", "requester_user_id": "u1"},
	}
}

test_request_pdf_export_impersonation_denied if {
	not allow with input as {
		"method": "steward.delivery.v1.DeliveryService/RequestPDFExport",
		"claims": {"user_id": "u1"},
		"request": {"requester_user_id": "u2"},
	}
}

test_create_magic_link_nonsensitive_author if {
	allow with input as {
		"method": "steward.delivery.v1.DeliveryService/CreateMagicLink",
		"claims": {"user_id": "u1", "roles": ["author"]},
		"request": {
			"policy_version_id": "v1",
			"created_by_user_id": "u1",
			"sensitive": false,
		},
	}
}

test_create_magic_link_nonsensitive_scoped_author if {
	# Scoped-only author (no global role) must be authorized.
	allow with input as {
		"method": "steward.delivery.v1.DeliveryService/CreateMagicLink",
		"claims": {
			"user_id": "u1",
			"roles": [],
			"scoped_roles": [{"role": "author", "category": "Information"}],
		},
		"request": {
			"created_by_user_id": "u1",
			"sensitive": false,
		},
	}
}

test_create_magic_link_nonsensitive_approver if {
	allow with input as {
		"method": "steward.delivery.v1.DeliveryService/CreateMagicLink",
		"claims": {"user_id": "u1", "roles": ["approver"]},
		"request": {
			"created_by_user_id": "u1",
			"sensitive": false,
		},
	}
}

test_create_magic_link_nonsensitive_reader_denied if {
	not allow with input as {
		"method": "steward.delivery.v1.DeliveryService/CreateMagicLink",
		"claims": {"user_id": "u1", "roles": ["reader"]},
		"request": {
			"created_by_user_id": "u1",
			"sensitive": false,
		},
	}
}

test_create_magic_link_sensitive_compliance_admin if {
	allow with input as {
		"method": "steward.delivery.v1.DeliveryService/CreateMagicLink",
		"claims": {"user_id": "u1", "roles": ["compliance-admin"]},
		"request": {
			"created_by_user_id": "u1",
			"sensitive": true,
		},
	}
}

test_create_magic_link_sensitive_author_denied if {
	# Plain author cannot mint a sensitive magic link.
	not allow with input as {
		"method": "steward.delivery.v1.DeliveryService/CreateMagicLink",
		"claims": {"user_id": "u1", "roles": ["author"]},
		"request": {
			"created_by_user_id": "u1",
			"sensitive": true,
		},
	}
}

test_revoke_magic_link_self if {
	allow with input as {
		"method": "steward.delivery.v1.DeliveryService/RevokeMagicLink",
		"claims": {"user_id": "u1"},
		"request": {"token": "t1", "revoked_by_user_id": "u1"},
	}
}

test_revoke_magic_link_for_other_admin_role_denied if {
	not allow with input as {
		"method": "steward.delivery.v1.DeliveryService/RevokeMagicLink",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {"token": "t1", "revoked_by_user_id": "u2"},
	}
}

test_resolve_magic_link_anonymous_allowed if {
	# Resolve is anonymous-by-design.
	allow with input as {
		"method": "steward.delivery.v1.DeliveryService/ResolveMagicLink",
		"claims": {},
		"request": {"token": "t1", "viewer_email": "v@example.com"},
	}
}

test_unknown_method_denied if {
	not allow with input as {
		"method": "steward.delivery.v1.DeliveryService/InventedRpc",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {},
	}
}
