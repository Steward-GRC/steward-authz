package steward.ai # scrub:allow=fqdn

m(rpc) := sprintf("steward.ai.v1.AiService/%s", [rpc])

reader := {"user_id": "erin", "roles": [], "groups": ["All staff"]}

sensitive_reader := {"user_id": "erin", "roles": [], "groups": ["All staff"], "read_sensitive": true}

author := {"user_id": "bob", "roles": ["author"]}

scoped_author := {"user_id": "bob", "roles": [], "scoped_roles": [{"role": "author", "category": "Finance"}]}

site_admin := {"user_id": "alice", "roles": ["site-admin"]}

scope(ids) := {"category_ids": ids, "include_sensitive": false, "all_categories": false}

# ---- the read calls -----------------------------------------------------

test_read_calls_allow_a_signed_in_reader if {
	every rpc in ["SearchAndAnswer", "GetRelatedPolicies", "GetTopQuestions"] {
		allow with input as {"method": m(rpc), "claims": reader, "request": {"scope": scope(["cat-finance"])}}
	}
}

test_read_calls_allow_an_empty_scope if {
	allow with input as {"method": m("SearchAndAnswer"), "claims": reader, "request": {"question": "q"}}
}

test_read_calls_need_a_signed_in_caller if {
	not allow with input as {"method": m("SearchAndAnswer"), "claims": {"roles": []}, "request": {"scope": scope([])}}
}

test_sensitive_scope_needs_the_read_sensitive_grant if {
	req := {"scope": {"category_ids": ["cat-finance"], "include_sensitive": true}}
	not allow with input as {"method": m("SearchAndAnswer"), "claims": reader, "request": req}
	not allow with input as {"method": m("SearchAndAnswer"), "claims": author, "request": req}
	not allow with input as {"method": m("SearchAndAnswer"), "claims": site_admin, "request": req}
	not allow with input as {"method": m("GetRelatedPolicies"), "claims": reader, "request": req}
	allow with input as {"method": m("SearchAndAnswer"), "claims": sensitive_reader, "request": req}
}

test_all_categories_scope_needs_a_site_admin if {
	req := {"scope": {"all_categories": true}}
	not allow with input as {"method": m("SearchAndAnswer"), "claims": reader, "request": req}
	not allow with input as {"method": m("GetTopQuestions"), "claims": sensitive_reader, "request": req}
	allow with input as {"method": m("SearchAndAnswer"), "claims": site_admin, "request": req}
}

test_all_categories_with_sensitive_needs_both if {
	req := {"scope": {"all_categories": true, "include_sensitive": true}}
	not allow with input as {"method": m("SearchAndAnswer"), "claims": site_admin, "request": req}
	allow with input as {
		"method": m("SearchAndAnswer"),
		"claims": object.union(site_admin, {"read_sensitive": true}),
		"request": req,
	}
}

# ---- authoring ----------------------------------------------------------

test_assist_needs_an_author_grant if {
	allow with input as {"method": m("AuthoringAssist"), "claims": author, "request": {"policy_id": "p1"}}
	allow with input as {"method": m("AuthoringAssist"), "claims": scoped_author, "request": {"policy_id": "p1"}}
	not allow with input as {"method": m("AuthoringAssist"), "claims": reader, "request": {"policy_id": "p1"}}
}

test_authoring_jobs_need_an_author_grant if {
	every op in ["JOB_OPERATION_DRAFT", "JOB_OPERATION_REVISE", "JOB_OPERATION_REVIEW", "JOB_OPERATION_SUGGEST_ENRICHMENTS", "JOB_OPERATION_SUMMARIZE"] {
		allow with input as {"method": m("SubmitAIJob"), "claims": scoped_author, "request": {"operation": op}}
		not allow with input as {"method": m("SubmitAIJob"), "claims": reader, "request": {"operation": op}}
	}
}

test_qa_job_follows_the_read_rules if {
	allow with input as {"method": m("SubmitAIJob"), "claims": reader, "request": {"operation": "JOB_OPERATION_QA", "scope": scope(["cat-finance"])}}
	not allow with input as {"method": m("SubmitAIJob"), "claims": reader, "request": {"operation": "JOB_OPERATION_QA", "scope": {"include_sensitive": true}}}
}

test_service_started_jobs_are_refused if {
	every op in ["JOB_OPERATION_RELATED_REEVAL", "JOB_OPERATION_RELATIONSHIP_LEARN", "JOB_OPERATION_UNSPECIFIED"] {
		not allow with input as {"method": m("SubmitAIJob"), "claims": site_admin, "request": {"operation": op}}
	}
	not allow with input as {"method": m("SubmitAIJob"), "claims": site_admin, "request": {}}
}

# ---- the module's settings ---------------------------------------------

settings_rpcs := [
	"SetAIEnabled", "GetAIConfig", "SetProviderConfig", "SetProviderCredential", "TestProvider",
	"AcceptDataNotice", "SetMonthlyLimit", "GetUsage", "SetOrgContext", "SetAIRetrievalConfig",
	"SetUserAiQueryLimit",
]

test_settings_need_a_site_admin if {
	every rpc in settings_rpcs {
		allow with input as {"method": m(rpc), "claims": site_admin, "request": {}}
		not allow with input as {"method": m(rpc), "claims": author, "request": {}}
		not allow with input as {"method": m(rpc), "claims": {"user_id": "grace", "roles": ["compliance-admin"]}, "request": {}}
	}
}

test_admin_role_grants_nothing if {
	not allow with input as {"method": m("SetAIEnabled"), "claims": {"user_id": "ops", "roles": ["admin"]}, "request": {}}
}

# ---- status reads -------------------------------------------------------

test_status_reads_allow_a_signed_in_caller if {
	every rpc in ["GetAIEnabled", "GetProviderStatus", "GetPolicySummary", "GetAIJob"] {
		allow with input as {"method": m(rpc), "claims": reader, "request": {}}
		not allow with input as {"method": m(rpc), "claims": {}, "request": {}}
	}
}

test_unknown_method_denied if {
	not allow with input as {"method": m("NotARpc"), "claims": site_admin, "request": {}}
}
