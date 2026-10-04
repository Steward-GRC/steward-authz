package steward.obligations

# ---- CampaignService ---------------------------------------------------

test_create_campaign_compliance_admin if {
	allow with input as {
		"method": "steward.obligations.v1.CampaignService/CreateCampaign",
		"claims": {"user_id": "co1", "roles": ["compliance-admin"]},
		"request": {"policy_version_id": "v1"},
	}
}

test_create_campaign_denied_for_author if {
	not allow with input as {
		"method": "steward.obligations.v1.CampaignService/CreateCampaign",
		"claims": {"user_id": "u1", "roles": ["author"]},
		"request": {},
	}
}

test_close_campaign_admin_role_denied if {
	not allow with input as {
		"method": "steward.obligations.v1.CampaignService/CloseCampaign",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {"campaign_id": "c1"},
	}
}

# ---- AckService --------------------------------------------------------

test_record_ack_self if {
	allow with input as {
		"method": "steward.obligations.v1.AckService/RecordAck",
		"claims": {"user_id": "u1"},
		"request": {"user_id": "u1", "policy_version_id": "v1"},
	}
}

test_record_ack_other_denied if {
	not allow with input as {
		"method": "steward.obligations.v1.AckService/RecordAck",
		"claims": {"user_id": "u1"},
		"request": {"user_id": "u2"},
	}
}

test_record_ack_for_other_admin_role_denied if {
	not allow with input as {
		"method": "steward.obligations.v1.AckService/RecordAck",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {"user_id": "u2"},
	}
}

test_get_ack_status_self if {
	allow with input as {
		"method": "steward.obligations.v1.AckService/GetAckStatus",
		"claims": {"user_id": "u1"},
		"request": {"user_id": "u1"},
	}
}

test_get_ack_status_compliance_admin_anyone if {
	allow with input as {
		"method": "steward.obligations.v1.AckService/GetAckStatus",
		"claims": {"user_id": "aud", "roles": ["compliance-admin"]},
		"request": {"user_id": "u2"},
	}
}

test_get_ack_status_other_denied if {
	not allow with input as {
		"method": "steward.obligations.v1.AckService/GetAckStatus",
		"claims": {"user_id": "u1", "roles": ["author"]},
		"request": {"user_id": "u2"},
	}
}

# ---- NotifPrefService --------------------------------------------------

test_upsert_notif_pref_self if {
	allow with input as {
		"method": "steward.obligations.v1.NotifPrefService/UpsertNotifPref",
		"claims": {"user_id": "u1"},
		"request": {"pref": {"user_id": "u1", "email": true}},
	}
}

test_upsert_notif_pref_other_denied if {
	not allow with input as {
		"method": "steward.obligations.v1.NotifPrefService/UpsertNotifPref",
		"claims": {"user_id": "u1"},
		"request": {"pref": {"user_id": "u2"}},
	}
}

test_get_notif_pref_self if {
	allow with input as {
		"method": "steward.obligations.v1.NotifPrefService/GetNotifPref",
		"claims": {"user_id": "u1"},
		"request": {"user_id": "u1"},
	}
}

# ---- ReportingService --------------------------------------------------

test_completion_report_compliance_admin if {
	allow with input as {
		"method": "steward.obligations.v1.ReportingService/GetCompletionReport",
		"claims": {"user_id": "co", "roles": ["compliance-admin"]},
		"request": {"policy_version_id": "v1"},
	}
}

test_completion_report_author_denied if {
	not allow with input as {
		"method": "steward.obligations.v1.ReportingService/GetCompletionReport",
		"claims": {"user_id": "u1", "roles": ["author"]},
		"request": {},
	}
}

test_export_acks_compliance_admin if {
	allow with input as {
		"method": "steward.obligations.v1.ReportingService/ExportAcks",
		"claims": {"user_id": "aud", "roles": ["compliance-admin"]},
		"request": {"policy_version_id": "v1", "format": "csv"},
	}
}

test_unknown_method_denied if {
	not allow with input as {
		"method": "steward.obligations.v1.CampaignService/NotARpc",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {},
	}
}
