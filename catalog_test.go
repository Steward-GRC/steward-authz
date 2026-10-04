// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package stewardauthz_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/Bugs5382/go-apperr"

	authz "github.com/Steward-GRC/steward-authz"
)

func TestRolePermissions(t *testing.T) {
	cases := []struct {
		role authz.Role
		want []authz.Permission
	}{
		{authz.RoleReader, []authz.Permission{authz.PolicyRead}},
		{authz.RoleAuthor, []authz.Permission{authz.PolicyRead, authz.PolicyAuthor, authz.PolicySubmit}},
		{authz.RoleApprover, []authz.Permission{authz.PolicyRead, authz.PolicyApprove}},
		{authz.RoleTemplateAdmin, []authz.Permission{authz.PolicyRead, authz.TemplateManage, authz.WorkflowManage}},
		{authz.RoleComplianceAdmin, []authz.Permission{
			authz.PolicyRead, authz.PolicyReadSensitive, authz.ComplianceManage, authz.ComplianceReport, authz.AuditRead,
		}},
	}
	for _, c := range cases {
		t.Run(string(c.role), func(t *testing.T) {
			got := authz.RolePermissions(c.role)
			for _, p := range c.want {
				if !slices.Contains(got, p) {
					t.Errorf("role %q: missing permission %q (got %v)", c.role, p, got)
				}
			}
		})
	}
}

func TestRolePermissions_SiteAdminHoldsTheWholeCatalog(t *testing.T) {
	got := authz.RolePermissions(authz.RoleSiteAdmin)
	for _, p := range authz.Permissions() {
		if !slices.Contains(got, p) {
			t.Errorf("site-admin missing %q", p)
		}
	}
}

func TestRolePermissions_UnknownRoleGrantsOnlyTheReaderBaseline(t *testing.T) {
	got := authz.RolePermissions("admin")
	if len(got) != 1 || got[0] != authz.PolicyRead {
		t.Fatalf("an unknown role must grant only the implicit reader baseline, got %v", got)
	}
}

func TestRolePermissions_NoRolesStillReads(t *testing.T) {
	if got := authz.RolePermissions(); !slices.Contains(got, authz.PolicyRead) {
		t.Fatalf("no roles must still grant the implicit reader baseline, got %v", got)
	}
}

func TestRolePermissions_Snapshot(t *testing.T) {
	want := map[authz.Role]int{
		authz.RoleReader:          1,
		authz.RoleAuthor:          3,
		authz.RoleApprover:        2,
		authz.RoleTemplateAdmin:   3,
		authz.RoleComplianceAdmin: 5,
		authz.RoleSiteAdmin:       len(authz.Permissions()),
	}
	for role, n := range want {
		if got := len(authz.RolePermissions(role)); got != n {
			t.Errorf("role %q permission count = %d, want %d (update the snapshot only on purpose)", role, got, n)
		}
	}
}

func TestCatalogSnapshot(t *testing.T) {
	want := []authz.Permission{
		"policy.read", "policy.read_sensitive", "policy.author", "policy.submit", "policy.approve",
		"template.manage", "workflow.manage", "group.manage", "user.manage", "role.manage",
		"audit.read", "compliance.manage", "compliance.report", "settings.manage",
		"delivery.manage", "session.manage",
	}
	if got := authz.Permissions(); !slices.Equal(got, want) {
		t.Fatalf("catalog changed (update the snapshot only on purpose):\n got %v\nwant %v", got, want)
	}
	roles := []authz.Role{"reader", "author", "approver", "template-admin", "compliance-admin", "site-admin"}
	if got := authz.Roles(); !slices.Equal(got, roles) {
		t.Fatalf("roles changed: got %v want %v", got, roles)
	}
}

func TestPermission_Parts(t *testing.T) {
	p := authz.PolicyReadSensitive
	if p.Resource() != "policy" || p.Verb() != "read_sensitive" {
		t.Fatalf("parts of %q = %q, %q", p, p.Resource(), p.Verb())
	}
}

func TestPermission_Scoped(t *testing.T) {
	for _, p := range authz.Permissions() {
		want := p == authz.PolicyAuthor || p == authz.PolicySubmit || p == authz.PolicyApprove
		if got := p.Scoped(); got != want {
			t.Errorf("%q scoped = %v, want %v", p, got, want)
		}
	}
}

func TestHasCapability_SiteAdminWildcardCoversPermissionsAddedLater(t *testing.T) {
	if !authz.HasCapability(authz.Subject{Roles: []authz.Role{authz.RoleSiteAdmin}}, "report.export") {
		t.Fatal("site-admin holds every capability, including ones not yet in the catalog")
	}
	if authz.HasCapability(authz.Subject{Roles: []authz.Role{authz.RoleComplianceAdmin}}, "report.export") {
		t.Fatal("a non-wildcard role must not hold a permission outside its grants")
	}
}

func TestParsePermission(t *testing.T) {
	p, err := authz.ParsePermission("audit.read")
	if err != nil || p != authz.AuditRead {
		t.Fatalf("ParsePermission(audit.read) = %q, %v", p, err)
	}
	_, err = authz.ParsePermission("policy.delete")
	if !errors.Is(err, authz.ErrUnknownPermission) {
		t.Fatalf("want ErrUnknownPermission, got %v", err)
	}
	if code, ok := apperr.Code(err); !ok || code != authz.CodeUnknownPermission {
		t.Fatalf("want code %d, got %d (%v)", authz.CodeUnknownPermission, code, ok)
	}
	if got := apperr.Metadata(err)["permission"]; got != "policy.delete" {
		t.Fatalf("want permission metadata, got %q", got)
	}
}

func TestParseRole(t *testing.T) {
	r, err := authz.ParseRole("template-admin")
	if err != nil || r != authz.RoleTemplateAdmin {
		t.Fatalf("ParseRole(template-admin) = %q, %v", r, err)
	}
	_, err = authz.ParseRole("admin")
	if !errors.Is(err, authz.ErrUnknownRole) {
		t.Fatalf("the dropped admin role must not parse, got %v", err)
	}
	if code, ok := apperr.Code(err); !ok || code != authz.CodeUnknownRole {
		t.Fatalf("want code %d, got %d (%v)", authz.CodeUnknownRole, code, ok)
	}
}
