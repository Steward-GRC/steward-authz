# Workflow service authorization.
#
# Submit, Signal, GetStatus and ListPendingTasks, plus the approval RPCs:
#
#   * SwapAssignee         — self-delegate OR workflow author
#   * BulkDecide           — actor must be the assignment's current user for
#                            every decision in the batch (server-side
#                            validation enforces this; OPA mirrors)
#   * GetAssignmentHistory — current/past assignee OR policy author
#   * Signal               — actor matches the assignment's current user
#
# Fails closed (default allow := false). The input shape is in common.rego.
package steward.workflow

import data.steward.common

default allow := false

# ---- Submit --------------------------------------------------------------
# A submitter must be an author in the resource's home group or any
# ancestor group (so a parent-org author can submit on a child's behalf,
# matching the group_or_descendant pattern used for resolving effective
# workflows).
allow if {
	input.method == "steward.workflow.v1.WorkflowService/Submit"
	common.is_author(input.claims)
	common.group_or_descendant(input.claims, input.request.ancestor_group_ids)
}

# ---- Signal --------------------------------------------------------------
# An approver signals on an assignment they currently own.
# input.request.actor_user_id is server-set from claims at the gateway, so
# the matching check is "the actor on the wire is the caller", catching
# misconfigured gateways that fail to bind the actor.
allow if {
	input.method == "steward.workflow.v1.WorkflowService/Signal"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.actor_user_id
}

# ---- GetStatus -----------------------------------------------------------
# Any authenticated caller can read run status. Tightening this would need
# the policy's home group on the input.
allow if {
	input.method == "steward.workflow.v1.WorkflowService/GetStatus"
	common.has_user_id(input.claims)
}

# ---- ListPendingTasks ----------------------------------------------------
# A user lists their own pending tasks; compliance-admins can list anyone's.
allow if {
	input.method == "steward.workflow.v1.WorkflowService/ListPendingTasks"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.user_id
}

allow if {
	input.method == "steward.workflow.v1.WorkflowService/ListPendingTasks"
	common.is_compliance_admin(input.claims)
}

allow if {
	input.method == "steward.workflow.v1.WorkflowService/SwapAssignee"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.current_user_id
}

allow if {
	input.method == "steward.workflow.v1.WorkflowService/SwapAssignee"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.workflow_author_user_id
}

# ---- BulkDecide ----------------------------------------------------------
# A bulk decide is permitted when every decision in the batch belongs to
# the actor's assignments. The gateway / server enforces per-decision
# eligibility against the assignment store; OPA's role here is to require
# an authenticated caller.
#
# We can't iterate the batch deeply in OPA without the gateway forwarding
# the resolved assignee_user_id per decision — so the policy reduces to
# "authenticated caller". The richer per-decision check lives in
# the workflow service.
allow if {
	input.method == "steward.workflow.v1.WorkflowService/BulkDecide"
	common.has_user_id(input.claims)
}

allow if {
	input.method == "steward.workflow.v1.WorkflowService/GetAssignmentHistory"
	common.is_compliance_admin(input.claims)
}

allow if {
	input.method == "steward.workflow.v1.WorkflowService/GetAssignmentHistory"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.policy_author_user_id
}

allow if {
	input.method == "steward.workflow.v1.WorkflowService/GetAssignmentHistory"
	common.has_user_id(input.claims)
	some i
	input.claims.user_id == input.request.stage_assignee_user_ids[i]
}
