// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package stewardauthz

import (
	"context"
	"log/slog"
	"slices"
	"strconv"

	goauthz "github.com/Bugs5382/go-authz"
)

// The reasons the rule engine returns.
const (
	ReasonSiteAdminRead       Reason = "site_admin_read"
	ReasonOwner               Reason = "owner"
	ReasonRuleAllow           Reason = "rule_allow"
	ReasonRuleDeny            Reason = "rule_deny"
	ReasonDefaultDeny         Reason = "default_deny"
	ReasonAuthorImpliesRead   Reason = "author_implies_read"
	ReasonApproverImpliesRead Reason = "approver_implies_read"
	ReasonRequiresRead        Reason = "requires_read"
)

// RuleRef points at the rule that decided: Depth 0 is the target category,
// 1 its parent, and so on; Index is 0-based within that category.
type RuleRef struct {
	Category string
	Depth    int
	Index    int
	Subject  RuleSubject
}

// RuleDecision is the outcome for one action. Rule is set when a rule
// decided, and nil for the built-in outcomes.
type RuleDecision struct {
	Allowed bool
	Reason  Reason
	Rule    *RuleRef
}

// String explains the decision in the words the access simulator shows.
func (d RuleDecision) String() string {
	switch d.Reason {
	case ReasonSiteAdminRead:
		return "site-admin reads all"
	case ReasonOwner:
		return "owner (auto read/approve/author)"
	case ReasonDefaultDeny:
		return "no rule → default deny"
	case ReasonAuthorImpliesRead:
		return "author implies read"
	case ReasonApproverImpliesRead:
		return "approver implies read"
	case ReasonRequiresRead:
		return "requires read"
	case ReasonRuleAllow, ReasonRuleDeny:
		if d.Rule == nil {
			break
		}
		loc := "rule #" + strconv.Itoa(d.Rule.Index+1)
		if d.Rule.Depth > 0 {
			loc = "↳ " + d.Rule.Category + " #" + strconv.Itoa(d.Rule.Index+1)
		}
		effect := "allow"
		if d.Reason == ReasonRuleDeny {
			effect = "deny"
		}
		who := string(d.Rule.Subject.Kind)
		if d.Rule.Subject.Name != "" {
			who += " " + d.Rule.Subject.Name
		}
		return loc + " " + effect + " " + who
	}
	return string(d.Reason)
}

// Result is the decision for each of the four actions.
type Result struct {
	Read        RuleDecision
	Acknowledge RuleDecision
	Approve     RuleDecision
	Author      RuleDecision
}

// Get returns the decision for one action.
func (r Result) Get(a Action) RuleDecision {
	switch a {
	case ActionRead:
		return r.Read
	case ActionAcknowledge:
		return r.Acknowledge
	case ActionApprove:
		return r.Approve
	case ActionAuthor:
		return r.Author
	}
	return RuleDecision{Reason: ReasonDefaultDeny}
}

// Option configures Compile.
type Option func(*options)

type options struct{ logger *slog.Logger }

// WithLogger logs every decision at debug level through l.
func WithLogger(l *slog.Logger) Option { return func(o *options) { o.logger = l } }

// Evaluator is a compiled category chain. It is read-only once built and safe
// to share between goroutines.
type Evaluator struct {
	target   string
	policies map[Action]*goauthz.Policy
	refs     map[string]RuleRef
}

const (
	attrSubject       = "steward.subject"
	ruleSiteAdminRead = "site-admin-read"
	ruleOwner         = "owner"
)

func subjectOf(req goauthz.Request) Subject {
	s, _ := req.Attr(attrSubject)
	subject, _ := s.(Subject)
	return subject
}

// Compile builds an Evaluator for chain: the target category first, then its
// ancestors up to the root. For each action the order is: site admin and
// root read; owners anywhere in the chain read, approve and author; then every
// rule top-down, target category first. The first rule with a non-blank cell
// for the action decides, and anything left is denied.
//
// Compile is also the access simulator: pass a draft chain to preview unsaved
// rules.
func Compile(chain []CategoryRuleset, opts ...Option) *Evaluator {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	e := &Evaluator{policies: map[Action]*goauthz.Policy{}, refs: map[string]RuleRef{}}
	if len(chain) > 0 {
		e.target = chain[0].Name
	}
	var owners []string
	for _, c := range chain {
		owners = append(owners, c.Owners...)
	}
	for _, act := range actions {
		p := goauthz.NewPolicy(goauthz.WithLogger(o.logger))
		if act == ActionRead {
			p.Add(goauthz.AllowWhen(ruleSiteAdminRead, func(_ context.Context, req goauthz.Request) bool {
				s := subjectOf(req)
				return s.SiteAdmin() || s.Root
			}))
		}
		if act != ActionAcknowledge {
			p.Add(goauthz.AllowWhen(ruleOwner, func(_ context.Context, req goauthz.Request) bool {
				return slices.Contains(owners, subjectOf(req).UserID)
			}))
		}
		for depth, c := range chain {
			for idx, r := range c.Rules {
				effect := goauthz.Deny
				switch r.Grants[act] {
				case GrantAllow:
					effect = goauthz.Allow
				case GrantDeny:
				default:
					continue
				}
				id := strconv.Itoa(depth) + "." + strconv.Itoa(idx)
				e.refs[id] = RuleRef{Category: c.Name, Depth: depth, Index: idx, Subject: r.Subject}
				subject := r.Subject
				p.Add(goauthz.NewRule(id, effect, func(_ context.Context, req goauthz.Request) bool {
					return subject.matches(subjectOf(req))
				}))
			}
		}
		e.policies[act] = p
	}
	return e
}

func (e *Evaluator) decide(ctx context.Context, s Subject, act Action) RuleDecision {
	d := e.policies[act].Decide(ctx, goauthz.Request{
		Subject: s.UserID, Resource: e.target, Action: string(act),
		Attributes: map[string]any{attrSubject: s},
	})
	switch d.RuleID {
	case "":
		return RuleDecision{Reason: ReasonDefaultDeny}
	case ruleSiteAdminRead:
		return RuleDecision{Allowed: true, Reason: ReasonSiteAdminRead}
	case ruleOwner:
		return RuleDecision{Allowed: true, Reason: ReasonOwner}
	}
	ref := e.refs[d.RuleID]
	if d.Allowed() {
		return RuleDecision{Allowed: true, Reason: ReasonRuleAllow, Rule: &ref}
	}
	return RuleDecision{Reason: ReasonRuleDeny, Rule: &ref}
}

// Resolve decides all four actions. Read gates the others, and an allowed
// author or approve confers read: no one authors or approves what they can't
// read. Acknowledge confers nothing.
func (e *Evaluator) Resolve(ctx context.Context, s Subject) Result {
	read := e.decide(ctx, s, ActionRead)
	if !read.Allowed {
		if e.decide(ctx, s, ActionAuthor).Allowed {
			read = RuleDecision{Allowed: true, Reason: ReasonAuthorImpliesRead}
		} else if e.decide(ctx, s, ActionApprove).Allowed {
			read = RuleDecision{Allowed: true, Reason: ReasonApproverImpliesRead}
		}
	}
	gate := func(act Action) RuleDecision {
		if !read.Allowed {
			return RuleDecision{Reason: ReasonRequiresRead}
		}
		return e.decide(ctx, s, act)
	}
	return Result{
		Read:        read,
		Acknowledge: gate(ActionAcknowledge),
		Approve:     gate(ActionApprove),
		Author:      gate(ActionAuthor),
	}
}

// Acknowledgement is the acknowledge decision without the read gate, for a
// caller that settles read some other way, such as a per-document override.
// Owners, site admins and root are never asked to acknowledge automatically.
func (e *Evaluator) Acknowledgement(ctx context.Context, s Subject) RuleDecision {
	return e.decide(ctx, s, ActionAcknowledge)
}

// Resolve compiles chain and resolves it for s. Compile once and reuse the
// Evaluator when deciding for many subjects.
func Resolve(ctx context.Context, s Subject, chain []CategoryRuleset) Result {
	return Compile(chain).Resolve(ctx, s)
}

// Acknowledgement compiles chain and returns the ungated acknowledge decision.
func Acknowledgement(ctx context.Context, s Subject, chain []CategoryRuleset) RuleDecision {
	return Compile(chain).Acknowledgement(ctx, s)
}
