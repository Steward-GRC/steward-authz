# AI service authorization.
#
# The gateway is the AI service's only caller. It sends the signed-in person
# as the actor (no user id in the request) and binds the read scope from
# their access: request.scope holds the category ids they may read,
# include_sensitive and all_categories. Which categories a person may read
# comes from the category rules, which this input doesn't carry, so the
# gateway computes the ids; this policy checks the two flags that widen a
# scope past them:
#   (a) include_sensitive needs the individual read-sensitive grant; no role
#       reads sensitive content across policies;
#   (b) all_categories needs the site admin role.
package steward.ai # scrub:allow=fqdn

import data.steward.common

default allow := false

method(rpc) := sprintf("steward.ai.v1.AiService/%s", [rpc])

read_calls := {method("SearchAndAnswer"), method("GetRelatedPolicies"), method("GetTopQuestions")}

status_calls := {method("GetAIEnabled"), method("GetProviderStatus"), method("GetPolicySummary"), method("GetAIJob")}

settings_calls := {
	method("SetAIEnabled"), method("GetAIConfig"), method("SetProviderConfig"),
	method("SetProviderCredential"), method("TestProvider"), method("AcceptDataNotice"),
	method("SetMonthlyLimit"), method("GetUsage"), method("SetOrgContext"),
	method("SetAIRetrievalConfig"), method("SetUserAiQueryLimit"),
}

# The operations a person submits to author content. QA follows the read
# rules; RELATED_REEVAL and RELATIONSHIP_LEARN are started by the service.
authoring_operations := {
	"JOB_OPERATION_DRAFT", "JOB_OPERATION_REWRITE", "JOB_OPERATION_CLARIFY",
	"JOB_OPERATION_SUMMARIZE", "JOB_OPERATION_REVIEW", "JOB_OPERATION_REVISE",
	"JOB_OPERATION_SUGGEST_ENRICHMENTS",
}

# scope_allowed holds when the request's scope widens nothing the caller
# doesn't hold. A request with no scope reads nothing past its categories.
scope_allowed if {
	not widens_sensitive
	not widens_all
}

widens_sensitive if {
	input.request.scope.include_sensitive == true
	not common.has_sensitive_grant(input.claims)
}

widens_all if {
	input.request.scope.all_categories == true
	not common.is_site_admin(input.claims)
}

allow if {
	input.method in read_calls
	common.has_user_id(input.claims)
	scope_allowed
}

allow if {
	input.method == method("AuthoringAssist")
	common.has_user_id(input.claims)
	common.is_author(input.claims)
}

allow if {
	input.method == method("SubmitAIJob")
	common.has_user_id(input.claims)
	input.request.operation in authoring_operations
	common.is_author(input.claims)
}

allow if {
	input.method == method("SubmitAIJob")
	common.has_user_id(input.claims)
	input.request.operation == "JOB_OPERATION_QA"
	scope_allowed
}

allow if {
	input.method in status_calls
	common.has_user_id(input.claims)
}

allow if {
	input.method in settings_calls
	common.has_user_id(input.claims)
	common.is_site_admin(input.claims)
}
