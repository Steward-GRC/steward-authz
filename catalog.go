// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package stewardauthz

import (
	"context"
	"slices"
	"strings"

	"github.com/Bugs5382/go-apperr"
	goauthz "github.com/Bugs5382/go-authz"
)

// Permission is one entry of the catalog, written "<resource>.<verb>".
type Permission string

// The permission catalog.
const (
	PolicyRead          Permission = "policy.read"
	PolicyReadSensitive Permission = "policy.read_sensitive"
	PolicyAuthor        Permission = "policy.author"
	PolicySubmit        Permission = "policy.submit"
	PolicyApprove       Permission = "policy.approve"
	TemplateManage      Permission = "template.manage"
	WorkflowManage      Permission = "workflow.manage"
	GroupManage         Permission = "group.manage"
	UserManage          Permission = "user.manage"
	RoleManage          Permission = "role.manage"
	AuditRead           Permission = "audit.read"
	ComplianceManage    Permission = "compliance.manage"
	ComplianceReport    Permission = "compliance.report"
	SettingsManage      Permission = "settings.manage"
	DeliveryManage      Permission = "delivery.manage"
	SessionManage       Permission = "session.manage"
)

var permissions = []Permission{
	PolicyRead, PolicyReadSensitive, PolicyAuthor, PolicySubmit, PolicyApprove,
	TemplateManage, WorkflowManage, GroupManage, UserManage, RoleManage,
	AuditRead, ComplianceManage, ComplianceReport, SettingsManage,
	DeliveryManage, SessionManage,
}

// Permissions returns the whole catalog, in a stable order.
func Permissions() []Permission { return slices.Clone(permissions) }

// Resource is the part before the first dot ("policy" in "policy.read").
func (p Permission) Resource() string {
	r, _, _ := strings.Cut(string(p), ".")
	return r
}

// Verb is the part after the first dot ("read" in "policy.read").
func (p Permission) Verb() string {
	_, v, _ := strings.Cut(string(p), ".")
	return v
}

// Scoped reports whether the permission only takes effect inside the
// categories a subject holds a scoped grant for.
func (p Permission) Scoped() bool {
	return p == PolicyAuthor || p == PolicySubmit || p == PolicyApprove
}

// ParsePermission checks a permission name read from outside (storage, a
// token, an admin form) against the catalog.
func ParsePermission(s string) (Permission, error) {
	p := Permission(s)
	if !slices.Contains(permissions, p) {
		return "", apperr.WithMeta(apperr.Coded(CodeUnknownPermission, ErrUnknownPermission), apperr.Meta("permission", s))
	}
	return p, nil
}

// Role is a named bundle of permissions.
type Role string

// The roles. Every signed-in subject is a reader implicitly; the role is never
// stored.
const (
	RoleReader          Role = "reader"
	RoleAuthor          Role = "author"
	RoleApprover        Role = "approver"
	RoleTemplateAdmin   Role = "template-admin"
	RoleComplianceAdmin Role = "compliance-admin"
	RoleSiteAdmin       Role = "site-admin"
)

var roles = []Role{RoleReader, RoleAuthor, RoleApprover, RoleTemplateAdmin, RoleComplianceAdmin, RoleSiteAdmin}

// Roles returns every role, in a stable order.
func Roles() []Role { return slices.Clone(roles) }

// ParseRole checks a role name read from outside against the catalog.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !slices.Contains(roles, r) {
		return "", apperr.WithMeta(apperr.Coded(CodeUnknownRole, ErrUnknownRole), apperr.Meta("role", s))
	}
	return r, nil
}

// grants is the role-to-permission table as a responsibility matrix: the
// subject dimension is the role. Site admin holds a wildcard, so a permission
// added to the catalog later is covered without touching this table. No role
// ever grants policy.read_sensitive: it is an individual grant only, so its
// cell is denied ahead of the wildcard.
var grants = func() *goauthz.Matrix {
	m := goauthz.NewMatrix("catalog")
	table := map[Role][]Permission{
		RoleReader:          {PolicyRead},
		RoleAuthor:          {PolicyRead, PolicyAuthor, PolicySubmit},
		RoleApprover:        {PolicyRead, PolicyApprove},
		RoleTemplateAdmin:   {PolicyRead, TemplateManage, WorkflowManage},
		RoleComplianceAdmin: {PolicyRead, ComplianceManage, ComplianceReport, AuditRead},
	}
	for role, perms := range table {
		for _, p := range perms {
			m.Allow(string(role), p.Resource(), p.Verb())
		}
	}
	m.Allow(string(RoleSiteAdmin), goauthz.Wildcard, goauthz.Wildcard)
	m.Deny(goauthz.Wildcard, PolicyReadSensitive.Resource(), PolicyReadSensitive.Verb())
	return m
}()

func roleHolds(role Role, p Permission) bool {
	effect, matched := grants.Eval(context.Background(), goauthz.Request{
		Subject: string(role), Resource: p.Resource(), Action: p.Verb(),
	})
	return matched && effect == goauthz.Allow
}

// RolePermissions returns the catalog permissions the given roles grant
// together, in catalog order. The reader baseline is always included, and an
// unknown role adds nothing.
func RolePermissions(rs ...Role) []Permission {
	rs = append([]Role{RoleReader}, rs...)
	var out []Permission
	for _, p := range permissions {
		if slices.ContainsFunc(rs, func(r Role) bool { return roleHolds(r, p) }) {
			out = append(out, p)
		}
	}
	return out
}
