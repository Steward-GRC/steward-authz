# Core service authorization.
#
# Covers PolicyService, TemplateService and GroupService. Read paths are permissive (any authenticated caller). Write
# paths require role + group scoping.
package steward.core

import data.steward.common

default allow := false

# ---- PolicyService — reads ----------------------------------------------

allow if {
	input.method == "steward.core.v1.PolicyService/GetPolicy"
	common.has_user_id(input.claims)
}

allow if {
	input.method == "steward.core.v1.PolicyService/ListPolicies"
	common.has_user_id(input.claims)
}

allow if {
	input.method == "steward.core.v1.PolicyService/GetPolicyVersion"
	common.has_user_id(input.claims)
}

allow if {
	input.method == "steward.core.v1.PolicyService/GetEffectiveTemplate"
	common.has_user_id(input.claims)
}

allow if {
	input.method == "steward.core.v1.PolicyService/DiffVersions"
	common.has_user_id(input.claims)
}

# ---- PolicyService — writes ---------------------------------------------

# CreatePolicy: author in the target group.
allow if {
	input.method == "steward.core.v1.PolicyService/CreatePolicy"
	common.is_author(input.claims)
	common.in_group(input.claims, input.request.group_id)
}

# SaveDraft: author who belongs to the draft's group.
allow if {
	input.method == "steward.core.v1.PolicyService/SaveDraft"
	common.is_author(input.claims)
	common.in_group(input.claims, input.request.group_id)
}

# UpdateDraftContent: same envelope as SaveDraft — author bound to the
# draft's group.
allow if {
	input.method == "steward.core.v1.PolicyService/UpdateDraftContent"
	common.is_author(input.claims)
	common.in_group(input.claims, input.request.group_id)
}

# PublishDraft: approver role required. Authors create drafts;
# approvers ship them.
allow if {
	input.method == "steward.core.v1.PolicyService/PublishDraft"
	common.is_approver(input.claims)
	common.in_group(input.claims, input.request.group_id)
}

# ---- TemplateService — reads --------------------------------------------

allow if {
	input.method == "steward.core.v1.TemplateService/GetLatestTemplateVersion"
	common.has_user_id(input.claims)
}

# ---- TemplateService — writes -------------------------------------------

# Templates are platform-level artifacts edited by template authors. We
# don't tie them to a group; the template-admin role suffices.
allow if {
	input.method == "steward.core.v1.TemplateService/CreateTemplate"
	common.has_role(input.claims, "template-admin")
}

allow if {
	input.method == "steward.core.v1.TemplateService/CreateTemplateVersion"
	common.has_role(input.claims, "template-admin")
}

allow if {
	input.method == "steward.core.v1.TemplateService/PublishTemplateVersion"
	common.has_role(input.claims, "template-admin")
}

# ---- GroupService — reads -----------------------------------------------

allow if {
	input.method == "steward.core.v1.GroupService/GetGroup"
	common.has_user_id(input.claims)
}

allow if {
	input.method == "steward.core.v1.GroupService/ListGroupChildren"
	common.has_user_id(input.claims)
}

# ---- GroupService — writes ----------------------------------------------

# Creating a subgroup: site-admin scoped to the parent.
allow if {
	input.method == "steward.core.v1.GroupService/CreateGroup"
	common.has_role(input.claims, "site-admin")
	common.in_group(input.claims, input.request.parent_group_id)
}

# SetGroupDefaults: site-admin for the target group only.
allow if {
	input.method == "steward.core.v1.GroupService/SetGroupDefaults"
	common.has_role(input.claims, "site-admin")
	common.in_group(input.claims, input.request.group_id)
}
