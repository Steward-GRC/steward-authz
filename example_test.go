// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package stewardauthz_test

import (
	"context"
	"fmt"

	authz "github.com/Steward-GRC/steward-authz"
)

func ExampleCompile() {
	chain := []authz.CategoryRuleset{
		{Name: "Facilities", Rules: []authz.Rule{
			{Subject: authz.RuleSubject{Kind: authz.SubjectGroup, Name: "Facilities team"},
				Grants: map[authz.Action]authz.Grant{authz.ActionAuthor: authz.GrantAllow}},
		}},
		{Name: "Workplace", Owners: []string{"dave"}, Rules: []authz.Rule{
			{Subject: authz.RuleSubject{Kind: authz.SubjectEveryone},
				Grants: map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow, authz.ActionAcknowledge: authz.GrantAllow}},
		}},
	}
	ev := authz.Compile(chain)
	erin := authz.Subject{UserID: "erin", Groups: []string{"All staff"}}
	r := ev.Resolve(context.Background(), erin)
	fmt.Println(r.Read.Allowed, r.Read)
	fmt.Println(r.Acknowledge.Allowed, r.Author)
	// Output:
	// true ↳ Workplace #1 allow everyone
	// true no rule → default deny
}

func ExampleAuthorize() {
	bob := authz.Subject{
		UserID:       "bob",
		Roles:        []authz.Role{authz.RoleAuthor},
		ScopedGrants: []authz.ScopedGrant{{Role: authz.RoleAuthor, Category: "Workplace"}},
	}
	doc := &authz.Resource{ID: "POL-FACILITIES-000001", Category: "Facilities", CategoryLineage: []string{"Facilities", "Workplace"}}
	fmt.Println(authz.Authorize(bob, authz.PolicySubmit, doc).Effect)
	fmt.Println(authz.Authorize(bob, authz.PolicyApprove, doc).Reason)
	// Output:
	// allow
	// missing_capability
}
