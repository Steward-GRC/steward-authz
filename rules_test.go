// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package stewardauthz_test

import (
	"errors"
	"testing"

	"github.com/Bugs5382/go-apperr"

	authz "github.com/Steward-GRC/steward-authz"
)

func TestCategoryRuleset_Validate(t *testing.T) {
	ok := ruleset("Finance", []string{"dave"},
		everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow, authz.ActionAuthor: authz.GrantBlank}),
		group("Finance team", map[authz.Action]authz.Grant{authz.ActionApprove: authz.GrantDeny}),
		rule(authz.SubjectUser, "erin", map[authz.Action]authz.Grant{authz.ActionAcknowledge: authz.GrantAllow}),
	)
	if err := ok.Validate(); err != nil {
		t.Fatalf("a well-formed ruleset: %v", err)
	}

	cases := []struct {
		name string
		r    authz.Rule
		why  string
	}{
		{"unknown subject kind", rule("role", "reader", nil), "subject"},
		{"group with no name", group("", nil), "subject"},
		{"user with no id", rule(authz.SubjectUser, " ", nil), "subject"},
		{"everyone with a name", rule(authz.SubjectEveryone, "All staff", nil), "subject"},
		{"unknown action", everyone(map[authz.Action]authz.Grant{"C": authz.GrantAllow}), "action"},
		{"unknown grant", everyone(map[authz.Action]authz.Grant{authz.ActionRead: "maybe"}), "grant"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bad := ruleset("Finance", nil, everyone(nil), c.r)
			err := bad.Validate()
			if !errors.Is(err, authz.ErrInvalidRule) {
				t.Fatalf("want ErrInvalidRule, got %v", err)
			}
			if code, ok := apperr.Code(err); !ok || code != authz.CodeInvalidRule {
				t.Fatalf("want code %d, got %d (%v)", authz.CodeInvalidRule, code, ok)
			}
			md := apperr.Metadata(err)
			if md["category"] != "Finance" || md["rule"] != "2" || md["problem"] != c.why {
				t.Fatalf("metadata = %v", md)
			}
		})
	}
}

func TestCategoryRuleset_ValidateOwners(t *testing.T) {
	err := ruleset("Finance", []string{"dave", ""}).Validate()
	if !errors.Is(err, authz.ErrInvalidRule) || apperr.Metadata(err)["problem"] != "owner" {
		t.Fatalf("an empty owner id must be refused, got %v (%v)", err, apperr.Metadata(err))
	}
}
