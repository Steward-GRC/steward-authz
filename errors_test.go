// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package stewardauthz_test

import (
	"testing"

	"github.com/Bugs5382/go-apperr"

	authz "github.com/Steward-GRC/steward-authz"
)

func TestEntries_FormAValidRegistry(t *testing.T) {
	reg, err := apperr.NewRegistry(authz.Entries(), apperr.WithService(authz.CodeBand), apperr.WithCodeDigits(4))
	if err != nil {
		t.Fatalf("the library's codes must form a valid registry: %v", err)
	}
	for _, c := range []int{authz.CodeDenied, authz.CodeInvalidRule, authz.CodeUnknownPermission, authz.CodeUnknownRole} {
		e, ok := reg.Describe(c)
		if !ok || e.Symbol == "" {
			t.Errorf("code %d: registered=%v symbol=%q", c, ok, e.Symbol)
		}
	}
}

func TestEntries_Categories(t *testing.T) {
	reg, err := apperr.NewRegistry(authz.Entries())
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]apperr.Category{
		authz.CodeDenied:            apperr.CategoryPermissionDenied,
		authz.CodeInvalidRule:       apperr.CategoryInvalid,
		authz.CodeUnknownPermission: apperr.CategoryInvalid,
		authz.CodeUnknownRole:       apperr.CategoryInvalid,
	}
	for code, cat := range want {
		if got := reg.Category(apperr.Coded(code, nil)); got != cat {
			t.Errorf("code %d category = %v, want %v", code, got, cat)
		}
	}
}

func TestEntries_PresentUserSafeMessages(t *testing.T) {
	reg, err := apperr.NewRegistry(authz.Entries())
	if err != nil {
		t.Fatal(err)
	}
	_, perr := authz.ParsePermission("policy.delete")
	msg, code := reg.Present(perr, 0)
	if code != authz.CodeUnknownPermission || msg != "policy.delete is not a known permission." {
		t.Fatalf("Present = %q, %d", msg, code)
	}
	msg, _ = reg.Present(authz.Authorize(authz.Subject{}, authz.AuditRead, nil).Err(), 0)
	if msg != "You don't have permission to do that." {
		t.Fatalf("denied message = %q", msg)
	}
}
