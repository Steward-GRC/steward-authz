// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package stewardauthz_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	authz "github.com/Steward-GRC/steward-authz"
)

func ruleset(name string, owners []string, rules ...authz.Rule) authz.CategoryRuleset {
	return authz.CategoryRuleset{Name: name, Owners: owners, Rules: rules}
}

func rule(kind authz.SubjectKind, name string, g map[authz.Action]authz.Grant) authz.Rule {
	return authz.Rule{Subject: authz.RuleSubject{Kind: kind, Name: name}, Grants: g}
}

func everyone(g map[authz.Action]authz.Grant) authz.Rule { return rule(authz.SubjectEveryone, "", g) }

func group(name string, g map[authz.Action]authz.Grant) authz.Rule {
	return rule(authz.SubjectGroup, name, g)
}

func resolve(s authz.Subject, chain ...authz.CategoryRuleset) authz.Result {
	return authz.Resolve(context.Background(), s, chain)
}

func decide(s authz.Subject, act authz.Action, chain ...authz.CategoryRuleset) authz.RuleDecision {
	return resolve(s, chain...).Get(act)
}

var (
	erin  = authz.Subject{UserID: "erin", Groups: []string{"Finance team"}}
	alice = authz.Subject{UserID: "alice", Roles: []authz.Role{authz.RoleSiteAdmin}}
	dave  = authz.Subject{UserID: "dave"}
)

func TestResolve_SingleCategory(t *testing.T) {
	everyoneReads := everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow})
	denyApprove := group("Finance team", map[authz.Action]authz.Grant{authz.ActionApprove: authz.GrantDeny})
	allowApprove := group("Finance team", map[authz.Action]authz.Grant{authz.ActionApprove: authz.GrantAllow})

	t.Run("everyone allow read", func(t *testing.T) {
		if d := decide(erin, authz.ActionRead, ruleset("Finance", nil, everyoneReads)); !d.Allowed {
			t.Fatalf("want allowed, got %+v", d)
		}
	})
	t.Run("default deny when no rule matches", func(t *testing.T) {
		d := decide(erin, authz.ActionApprove, ruleset("Finance", nil, everyoneReads))
		if d.Allowed || d.Reason != authz.ReasonDefaultDeny || d.Rule != nil {
			t.Fatalf("want default deny, got %+v", d)
		}
	})
	t.Run("default deny with no rules at all", func(t *testing.T) {
		r := resolve(erin, ruleset("Finance", nil))
		for _, act := range authz.Actions() {
			if r.Get(act).Allowed {
				t.Fatalf("%s: want denied, got %+v", act, r.Get(act))
			}
		}
	})
	t.Run("first match wins: a deny above an allow", func(t *testing.T) {
		chain := ruleset("Finance", nil, everyoneReads, denyApprove, allowApprove)
		d := decide(erin, authz.ActionApprove, chain)
		if d.Allowed || d.Reason != authz.ReasonRuleDeny || d.Rule == nil || d.Rule.Index != 1 {
			t.Fatalf("the first match (deny, rule 2) must win, got %+v", d)
		}
	})
	t.Run("first match wins: an allow above a deny", func(t *testing.T) {
		chain := ruleset("Finance", nil, everyoneReads, allowApprove, denyApprove)
		if d := decide(erin, authz.ActionApprove, chain); !d.Allowed || d.Rule.Index != 1 {
			t.Fatalf("the first match (allow, rule 2) must win, got %+v", d)
		}
	})
	t.Run("a blank cell falls through to the next rule", func(t *testing.T) {
		blank := group("Finance team", map[authz.Action]authz.Grant{authz.ActionApprove: authz.GrantBlank})
		allow := everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow, authz.ActionApprove: authz.GrantAllow})
		if d := decide(erin, authz.ActionApprove, ruleset("Finance", nil, blank, allow)); !d.Allowed || d.Rule.Index != 1 {
			t.Fatalf("blank must fall through to the allow, got %+v", d)
		}
	})
	t.Run("a rule that names another action is not a match", func(t *testing.T) {
		readOnly := group("Finance team", map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantDeny})
		allow := everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow, authz.ActionAuthor: authz.GrantAllow})
		d := decide(erin, authz.ActionAuthor, ruleset("Finance", nil, readOnly, allow))
		if d.Rule == nil || d.Rule.Index != 1 {
			t.Fatalf("a rule silent on author must not decide author, got %+v", d)
		}
	})
	t.Run("site admin reads whatever the rules say", func(t *testing.T) {
		deny := everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantDeny})
		d := decide(alice, authz.ActionRead, ruleset("Finance", nil, deny))
		if !d.Allowed || d.Reason != authz.ReasonSiteAdminRead {
			t.Fatalf("site admin must read, got %+v", d)
		}
	})
	t.Run("root reads whatever the rules say", func(t *testing.T) {
		root := authz.Subject{UserID: "alice", Root: true}
		if d := decide(root, authz.ActionRead, ruleset("Finance", nil)); !d.Allowed || d.Reason != authz.ReasonSiteAdminRead {
			t.Fatalf("root must read, got %+v", d)
		}
	})
	t.Run("site admin is not an automatic approver or author", func(t *testing.T) {
		r := resolve(alice, ruleset("Finance", nil))
		if r.Approve.Allowed || r.Author.Allowed || r.Acknowledge.Allowed {
			t.Fatalf("site admin must not auto approve, author or acknowledge, got %+v", r)
		}
	})
	t.Run("owner reads, approves and authors automatically", func(t *testing.T) {
		chain := ruleset("Finance", []string{"dave"})
		for _, act := range []authz.Action{authz.ActionRead, authz.ActionApprove, authz.ActionAuthor} {
			if d := decide(dave, act, chain); !d.Allowed || d.Reason != authz.ReasonOwner {
				t.Fatalf("owner should have %s, got %+v", act, d)
			}
		}
	})
	t.Run("owner beats an explicit deny", func(t *testing.T) {
		deny := rule(authz.SubjectUser, "dave", map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantDeny})
		if d := decide(dave, authz.ActionRead, ruleset("Finance", []string{"dave"}, deny)); !d.Allowed {
			t.Fatalf("owners are evaluated before the rules, got %+v", d)
		}
	})
	t.Run("owner is not asked to acknowledge automatically", func(t *testing.T) {
		if d := decide(dave, authz.ActionAcknowledge, ruleset("Finance", []string{"dave"})); d.Allowed {
			t.Fatalf("owner acknowledge must follow the rules, got %+v", d)
		}
	})
}

func TestResolve_SubjectMatching(t *testing.T) {
	read := map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow}
	cases := []struct {
		name string
		subj authz.RuleSubject
		want bool
	}{
		{"everyone matches anyone", authz.RuleSubject{Kind: authz.SubjectEveryone}, true},
		{"a group the user is in", authz.RuleSubject{Kind: authz.SubjectGroup, Name: "Finance team"}, true},
		{"a group the user is not in", authz.RuleSubject{Kind: authz.SubjectGroup, Name: "Facilities team"}, false},
		{"group names match case-insensitively", authz.RuleSubject{Kind: authz.SubjectGroup, Name: "FINANCE TEAM"}, true},
		{"the exact user id", authz.RuleSubject{Kind: authz.SubjectUser, Name: "erin"}, true},
		{"another user id", authz.RuleSubject{Kind: authz.SubjectUser, Name: "bob"}, false},
		{"user ids match exactly", authz.RuleSubject{Kind: authz.SubjectUser, Name: "Erin"}, false},
		{"an unknown kind matches no one", authz.RuleSubject{Kind: "role", Name: "reader"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			chain := ruleset("Finance", nil, authz.Rule{Subject: c.subj, Grants: read})
			if got := decide(erin, authz.ActionRead, chain).Allowed; got != c.want {
				t.Fatalf("matched = %v, want %v", got, c.want)
			}
		})
	}
}

func TestResolve_ReadGating(t *testing.T) {
	chain := ruleset("Finance", nil,
		everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantDeny}),
		group("Finance team", map[authz.Action]authz.Grant{authz.ActionAcknowledge: authz.GrantAllow}),
	)
	got := resolve(erin, chain)
	if got.Read.Allowed {
		t.Fatal("read should be denied")
	}
	if got.Acknowledge.Allowed || got.Acknowledge.Reason != authz.ReasonRequiresRead {
		t.Fatalf("acknowledge must be gated off when read is denied, got %+v", got.Acknowledge)
	}
	if got.Acknowledge.String() != "requires read" {
		t.Fatalf("want 'requires read', got %q", got.Acknowledge.String())
	}
}

func TestResolve_ReadableUserActs(t *testing.T) {
	chain := ruleset("Finance", nil,
		everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow, authz.ActionAcknowledge: authz.GrantAllow}),
		group("Finance team", map[authz.Action]authz.Grant{authz.ActionApprove: authz.GrantAllow}),
	)
	got := resolve(erin, chain)
	if !got.Read.Allowed || !got.Acknowledge.Allowed || !got.Approve.Allowed {
		t.Fatalf("want read, acknowledge and approve, got %+v", got)
	}
	if got.Author.Allowed {
		t.Fatal("author had no allow rule and must be denied")
	}
}

func TestResolve_AuthorImpliesRead(t *testing.T) {
	chain := ruleset("Finance", nil,
		everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantDeny}),
		group("Finance team", map[authz.Action]authz.Grant{authz.ActionAuthor: authz.GrantAllow}),
	)
	got := resolve(erin, chain)
	if !got.Read.Allowed || got.Read.Reason != authz.ReasonAuthorImpliesRead {
		t.Fatalf("author should imply read, got %+v", got.Read)
	}
	if got.Read.String() != "author implies read" {
		t.Fatalf("want 'author implies read', got %q", got.Read.String())
	}
	if !got.Author.Allowed {
		t.Fatalf("author should be allowed, got %+v", got.Author)
	}

	contractor := authz.Subject{UserID: "ivan", Groups: []string{"Contractors"}}
	other := resolve(contractor, chain)
	if other.Read.Allowed || other.Author.Allowed {
		t.Fatalf("author-implies-read must not leak to non-authors, got %+v", other)
	}
}

func TestResolve_ApproverImpliesRead(t *testing.T) {
	chain := ruleset("Finance", nil,
		everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantDeny}),
		group("Finance team", map[authz.Action]authz.Grant{authz.ActionApprove: authz.GrantAllow}),
	)
	got := resolve(erin, chain)
	if !got.Read.Allowed || got.Read.Reason != authz.ReasonApproverImpliesRead {
		t.Fatalf("approver should imply read, got %+v", got.Read)
	}
	if got.Read.String() != "approver implies read" {
		t.Fatalf("want 'approver implies read', got %q", got.Read.String())
	}
	if !got.Approve.Allowed {
		t.Fatalf("approve should be allowed, got %+v", got.Approve)
	}
}

func TestResolve_AcknowledgeDoesNotImplyRead(t *testing.T) {
	chain := ruleset("Finance", nil,
		everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantDeny}),
		group("Finance team", map[authz.Action]authz.Grant{authz.ActionAcknowledge: authz.GrantAllow}),
	)
	got := resolve(erin, chain)
	if got.Read.Allowed || got.Acknowledge.Allowed {
		t.Fatalf("acknowledge must not confer read, got %+v", got)
	}
}

func TestResolve_InheritDown(t *testing.T) {
	facilities := authz.Subject{UserID: "bob", Groups: []string{"Facilities team"}}
	finance := authz.Subject{UserID: "erin", Groups: []string{"Finance team"}}

	parentAllowsEveryoneRead := ruleset("Workplace", nil, everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow}))
	parentDeniesFinance := ruleset("Workplace", nil, group("Finance team", map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantDeny}))

	t.Run("a parent allow inherits to a silent child", func(t *testing.T) {
		got := decide(facilities, authz.ActionRead, ruleset("Facilities", nil), parentAllowsEveryoneRead)
		if !got.Allowed || got.Rule.Category != "Workplace" || got.Rule.Depth != 1 {
			t.Fatalf("child should inherit the parent's allow, got %+v", got)
		}
	})
	t.Run("the child's own rule is evaluated before the parent's", func(t *testing.T) {
		child := ruleset("Facilities", nil, everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow}))
		if got := decide(finance, authz.ActionRead, child, parentDeniesFinance); !got.Allowed || got.Rule.Depth != 0 {
			t.Fatalf("the child's allow should be read first, got %+v", got)
		}
	})
	t.Run("a parent deny applies when the child is silent", func(t *testing.T) {
		got := decide(finance, authz.ActionRead, ruleset("Facilities", nil), parentDeniesFinance)
		if got.Allowed || got.Reason != authz.ReasonRuleDeny {
			t.Fatalf("the parent's deny should inherit, got %+v", got)
		}
		if got.String() != "↳ Workplace #1 deny group Finance team" {
			t.Fatalf("ancestor reason: %q", got.String())
		}
	})
	t.Run("an owner of the parent owns the child", func(t *testing.T) {
		got := resolve(dave, ruleset("Facilities", nil), ruleset("Workplace", []string{"dave"}))
		if !got.Read.Allowed || !got.Approve.Allowed || !got.Author.Allowed {
			t.Fatalf("the parent's owner should own the child, got %+v", got)
		}
	})
}

func TestResolve_DraftChainPreview(t *testing.T) {
	ivan := authz.Subject{UserID: "ivan", Groups: []string{"Contractors"}}
	saved := ruleset("Finance", nil, everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow}))
	draft := ruleset("Finance", nil,
		group("Contractors", map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantDeny}),
		everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow}),
	)
	if !resolve(ivan, saved).Read.Allowed {
		t.Fatal("saved: a contractor should read")
	}
	if resolve(ivan, draft).Read.Allowed {
		t.Fatal("draft: a contractor should be denied (the simulator preview)")
	}
}

func TestRuleDecision_String(t *testing.T) {
	chain := ruleset("Finance", []string{"dave"},
		rule(authz.SubjectUser, "erin", map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow}),
	)
	cases := []struct {
		d    authz.RuleDecision
		want string
	}{
		{decide(erin, authz.ActionRead, chain), "rule #1 allow user erin"},
		{decide(erin, authz.ActionAuthor, chain), "no rule → default deny"},
		{decide(alice, authz.ActionRead, chain), "site-admin reads all"},
		{decide(dave, authz.ActionApprove, chain), "owner (auto read/approve/author)"},
		{decide(erin, authz.ActionRead, ruleset("Finance", nil, everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow}))), "rule #1 allow everyone"},
	}
	for _, c := range cases {
		if got := c.d.String(); got != c.want {
			t.Errorf("String() = %q, want %q", got, c.want)
		}
	}
}

func TestEvaluator_IsReusableAcrossSubjects(t *testing.T) {
	ev := authz.Compile([]authz.CategoryRuleset{ruleset("Finance", nil,
		group("Finance team", map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow}),
	)})
	ctx := context.Background()
	if !ev.Resolve(ctx, erin).Read.Allowed {
		t.Fatal("a member reads")
	}
	if ev.Resolve(ctx, authz.Subject{UserID: "bob"}).Read.Allowed {
		t.Fatal("a non-member is denied by default")
	}
}

func TestEvaluator_LogsDecisions(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ev := authz.Compile([]authz.CategoryRuleset{ruleset("Finance", nil)}, authz.WithLogger(logger))
	ev.Resolve(context.Background(), erin)
	if !strings.Contains(buf.String(), "authz decision") || !strings.Contains(buf.String(), "subject=erin") {
		t.Fatalf("want a debug decision line, got %q", buf.String())
	}
}

func TestAcknowledgement(t *testing.T) {
	t.Run("an everyone acknowledge allow is not gated by read", func(t *testing.T) {
		chain := ruleset("Workplace", nil, everyone(map[authz.Action]authz.Grant{authz.ActionAcknowledge: authz.GrantAllow}))
		if got := authz.Acknowledgement(context.Background(), erin, []authz.CategoryRuleset{chain}); !got.Allowed {
			t.Fatalf("want allowed, got %+v", got)
		}
		if resolve(erin, chain).Acknowledge.Allowed {
			t.Fatal("Resolve gates acknowledge off without read")
		}
	})
	t.Run("no acknowledge rule is denied", func(t *testing.T) {
		chain := ruleset("Finance", nil, everyone(map[authz.Action]authz.Grant{authz.ActionRead: authz.GrantAllow}))
		if authz.Acknowledgement(context.Background(), erin, []authz.CategoryRuleset{chain}).Allowed {
			t.Fatal("want denied")
		}
	})
	t.Run("a group acknowledge rule matches its members only", func(t *testing.T) {
		chain := []authz.CategoryRuleset{ruleset("Workplace", nil, group("All staff", map[authz.Action]authz.Grant{authz.ActionAcknowledge: authz.GrantAllow}))}
		member := authz.Subject{UserID: "erin", Groups: []string{"All staff"}}
		if !authz.Acknowledgement(context.Background(), member, chain).Allowed {
			t.Fatal("member: want allowed")
		}
		if authz.Acknowledgement(context.Background(), authz.Subject{UserID: "ivan", Groups: []string{"Contractors"}}, chain).Allowed {
			t.Fatal("non-member: want denied")
		}
	})
	t.Run("an owner is not asked to acknowledge automatically", func(t *testing.T) {
		chain := []authz.CategoryRuleset{ruleset("Workplace", []string{"dave"})}
		if authz.Acknowledgement(context.Background(), dave, chain).Allowed {
			t.Fatal("owner should not auto acknowledge")
		}
	})
}
