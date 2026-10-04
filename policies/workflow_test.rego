package steward.workflow

test_submit_author_in_home_group if {
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/Submit",
		"claims": {"user_id": "u1", "roles": ["author"], "groups": ["leaf"]},
		"request": {
			"policy_id": "p1",
			"group_id": "leaf",
			"ancestor_group_ids": ["leaf", "mid", "root"],
		},
	}
}

test_submit_author_in_ancestor_group if {
	# Author in the root group can submit on behalf of a leaf.
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/Submit",
		"claims": {"user_id": "u1", "roles": ["author"], "groups": ["root"]},
		"request": {
			"policy_id": "p1",
			"group_id": "leaf",
			"ancestor_group_ids": ["leaf", "mid", "root"],
		},
	}
}

test_submit_scoped_author_in_group if {
	# Scoped-only author (no global role) must be authorized.
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/Submit",
		"claims": {
			"user_id": "u1",
			"roles": [],
			"groups": ["leaf"],
			"scoped_roles": [{"role": "author", "category": "People"}],
		},
		"request": {
			"policy_id": "p1",
			"group_id": "leaf",
			"ancestor_group_ids": ["leaf", "mid", "root"],
		},
	}
}

test_submit_denied_unrelated_group if {
	not allow with input as {
		"method": "steward.workflow.v1.WorkflowService/Submit",
		"claims": {"user_id": "u1", "roles": ["author"], "groups": ["other"]},
		"request": {
			"group_id": "leaf",
			"ancestor_group_ids": ["leaf", "mid", "root"],
		},
	}
}

test_submit_denied_reader_in_group if {
	not allow with input as {
		"method": "steward.workflow.v1.WorkflowService/Submit",
		"claims": {"user_id": "u1", "roles": ["reader"], "groups": ["leaf"]},
		"request": {"ancestor_group_ids": ["leaf"]},
	}
}

test_signal_actor_matches_user if {
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/Signal",
		"claims": {"user_id": "u1"},
		"request": {"run_id": "r1", "task_id": "t1", "actor_user_id": "u1"},
	}
}

test_signal_actor_mismatch_denied if {
	not allow with input as {
		"method": "steward.workflow.v1.WorkflowService/Signal",
		"claims": {"user_id": "u1"},
		"request": {"actor_user_id": "u2"},
	}
}

test_signal_for_anyone_admin_role_denied if {
	not allow with input as {
		"method": "steward.workflow.v1.WorkflowService/Signal",
		"claims": {"user_id": "ops1", "roles": ["admin"]},
		"request": {"actor_user_id": "u2"},
	}
}

test_get_status_authenticated if {
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/GetStatus",
		"claims": {"user_id": "u1"},
		"request": {"run_id": "r1"},
	}
}

test_list_pending_tasks_self if {
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/ListPendingTasks",
		"claims": {"user_id": "u1"},
		"request": {"user_id": "u1"},
	}
}

test_list_pending_tasks_other_denied if {
	not allow with input as {
		"method": "steward.workflow.v1.WorkflowService/ListPendingTasks",
		"claims": {"user_id": "u1"},
		"request": {"user_id": "u2"},
	}
}

test_list_pending_tasks_compliance_admin_for_anyone if {
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/ListPendingTasks",
		"claims": {"user_id": "aud", "roles": ["compliance-admin"]},
		"request": {"user_id": "u2"},
	}
}

test_unknown_method_denied if {
	not allow with input as {
		"method": "steward.workflow.v1.WorkflowService/NotARpc",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {},
	}
}

# ---- SwapAssignee --------------------------------------------------------

test_swap_admin_role_denied if {
	not allow with input as {
		"method": "steward.workflow.v1.WorkflowService/SwapAssignee",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {"current_user_id": "u1", "new_user_id": "u2"},
	}
}

test_swap_self_delegate_allowed if {
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/SwapAssignee",
		"claims": {"user_id": "u1"},
		"request": {"current_user_id": "u1", "new_user_id": "u2"},
	}
}

test_swap_self_delegate_mismatch_denied if {
	not allow with input as {
		"method": "steward.workflow.v1.WorkflowService/SwapAssignee",
		"claims": {"user_id": "u3"},
		"request": {"current_user_id": "u1", "new_user_id": "u2"},
	}
}

test_swap_workflow_author_allowed if {
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/SwapAssignee",
		"claims": {"user_id": "author-1"},
		"request": {
			"current_user_id": "u1",
			"new_user_id": "u2",
			"workflow_author_user_id": "author-1",
		},
	}
}

test_swap_random_denied if {
	not allow with input as {
		"method": "steward.workflow.v1.WorkflowService/SwapAssignee",
		"claims": {"user_id": "rando", "roles": ["reader"]},
		"request": {"current_user_id": "u1", "new_user_id": "u2"},
	}
}

# ---- BulkDecide ----------------------------------------------------------

test_bulk_decide_authenticated_allowed if {
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/BulkDecide",
		"claims": {"user_id": "u1"},
		"request": {"decisions": []},
	}
}

test_bulk_decide_admin_allowed if {
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/BulkDecide",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {"decisions": []},
	}
}

test_bulk_decide_anonymous_denied if {
	not allow with input as {
		"method": "steward.workflow.v1.WorkflowService/BulkDecide",
		"claims": {"user_id": ""},
		"request": {"decisions": []},
	}
}

# ---- GetAssignmentHistory ------------------------------------------------

test_history_admin_role_denied if {
	not allow with input as {
		"method": "steward.workflow.v1.WorkflowService/GetAssignmentHistory",
		"claims": {"user_id": "ops", "roles": ["admin"]},
		"request": {"policy_version_id": "pv-1", "stage_index": 0},
	}
}

test_history_compliance_admin if {
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/GetAssignmentHistory",
		"claims": {"user_id": "aud", "roles": ["compliance-admin"]},
		"request": {"policy_version_id": "pv-1", "stage_index": 0},
	}
}

test_history_policy_author if {
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/GetAssignmentHistory",
		"claims": {"user_id": "author-1"},
		"request": {
			"policy_version_id": "pv-1",
			"stage_index": 0,
			"policy_author_user_id": "author-1",
		},
	}
}

test_history_stage_assignee if {
	allow with input as {
		"method": "steward.workflow.v1.WorkflowService/GetAssignmentHistory",
		"claims": {"user_id": "approver-2"},
		"request": {
			"policy_version_id": "pv-1",
			"stage_index": 0,
			"stage_assignee_user_ids": ["approver-1", "approver-2", "approver-3"],
		},
	}
}

test_history_random_denied if {
	not allow with input as {
		"method": "steward.workflow.v1.WorkflowService/GetAssignmentHistory",
		"claims": {"user_id": "rando"},
		"request": {
			"policy_version_id": "pv-1",
			"stage_index": 0,
			"policy_author_user_id": "author-1",
			"stage_assignee_user_ids": ["approver-1"],
		},
	}
}
