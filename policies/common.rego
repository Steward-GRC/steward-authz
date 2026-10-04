# Helpers shared by every service package.
#
# Every service asks the same question with the same input shape:
#
#   {
#     "method": "steward.<svc>.v1.<Service>/<RPC>",
#     "claims": {
#       "user_id": "erin",
#       "email":   "erin@example.org",
#       "roles":   ["author"],                                  # catalog roles; reader is implicit, never listed
#       "scoped_roles": [{"role": "author", "category": "Finance"}],
#       "groups":  ["g1", "g2"]                                 # directory group IDs
#     },
#     "request": { ... the gRPC request fields ... }
#   }
#
# Roles are the steward-authz catalog roles. There is no platform-wide "admin"
# role: it grants nothing. Every helper is false when a field is missing, so a
# malformed input fails closed.
package steward.common

# has_role returns true when the caller's claims include the named role.
has_role(claims, role) if {
	some i
	claims.roles[i] == role
}

# in_group returns true when the caller is a direct member of group_id.
# Group-hierarchy resolution (ancestors / descendants) is done by callers
# that need it — see group_or_descendant below for the common case.
in_group(claims, group_id) if {
	group_id != ""
	some i
	claims.groups[i] == group_id
}

# in_any_group returns true when the caller is in at least one of group_ids.
in_any_group(claims, group_ids) if {
	some i, j
	claims.groups[i] == group_ids[j]
}

# group_or_descendant returns true when the caller is in target_group OR in
# any of ancestor_groups (which the caller supplies as the leaf→root chain
# for the resource's home group). Callers using this helper must pass the
# full chain including the home group itself at index 0.
#
# This matches the workflow Submit request shape, where the gateway passes
# ancestor_group_ids (leaf→root) so the workflow service can resolve the
# effective workflow without a cross-service call.
group_or_descendant(claims, ancestor_groups) if {
	some i
	in_group(claims, ancestor_groups[i])
}

# is_site_admin is true for the site administrator.
is_site_admin(claims) if {
	has_role(claims, "site-admin")
}

# is_compliance_admin is true for the compliance administrator (campaigns,
# acknowledgement reports and the cross-group audit read).
is_compliance_admin(claims) if {
	has_role(claims, "compliance-admin")
}

# has_scoped_role is true when the caller holds the given category-scoped role
# for the given category. Empty category falls back to a global grant.
has_scoped_role(claims, role, category) if {
	category == ""
	has_role(claims, role)
}

has_scoped_role(claims, role, category) if {
	category != ""
	some i
	claims.scoped_roles[i].role == role
	claims.scoped_roles[i].category == category
}

# is_author is true when the caller is an author globally or in ANY category.
# The per-category check against a resource is the in-process engine's job.
is_author(claims) if {
	has_role(claims, "author")
}

is_author(claims) if {
	some i
	claims.scoped_roles[i].role == "author"
}

# is_approver is true when the caller is an approver globally or in ANY
# category, as for is_author.
is_approver(claims) if {
	has_role(claims, "approver")
}

is_approver(claims) if {
	some i
	claims.scoped_roles[i].role == "approver"
}

# can_access_sensitive is true for any caller holding an elevated role, never
# for the implicit reader.
can_access_sensitive(claims) if {
	is_site_admin(claims)
}

can_access_sensitive(claims) if {
	is_compliance_admin(claims)
}

can_access_sensitive(claims) if {
	is_author(claims)
}

can_access_sensitive(claims) if {
	is_approver(claims)
}

# has_user_id returns true when the caller has a non-empty subject. Every
# write path requires this — nothing is changed anonymously.
has_user_id(claims) if {
	claims.user_id != ""
}
