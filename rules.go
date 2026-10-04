// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package stewardauthz

import (
	"slices"
	"strconv"
	"strings"

	"github.com/Bugs5382/go-apperr"
)

// Action is one of the four governed actions on a category's documents.
type Action string

// The actions. Read gates the other three.
const (
	ActionRead        Action = "read"
	ActionAcknowledge Action = "acknowledge"
	ActionApprove     Action = "approve"
	ActionAuthor      Action = "author"
)

var actions = []Action{ActionRead, ActionAcknowledge, ActionApprove, ActionAuthor}

// Actions returns the four actions, in display order.
func Actions() []Action { return slices.Clone(actions) }

// Grant is the three-state value of one action cell in a rule.
type Grant string

// The grants. A blank cell has no opinion, so evaluation falls through to the
// next rule.
const (
	GrantBlank Grant = ""
	GrantAllow Grant = "allow"
	GrantDeny  Grant = "deny"
)

// SubjectKind says what a rule targets.
type SubjectKind string

// The subject kinds.
const (
	SubjectEveryone SubjectKind = "everyone"
	SubjectGroup    SubjectKind = "group"
	SubjectUser     SubjectKind = "user"
)

// RuleSubject is who a rule targets. Name is a group name or a user ID, and
// empty for SubjectEveryone.
type RuleSubject struct {
	Kind SubjectKind
	Name string
}

func (rs RuleSubject) matches(s Subject) bool {
	switch rs.Kind {
	case SubjectEveryone:
		return true
	case SubjectUser:
		return rs.Name == s.UserID
	case SubjectGroup:
		// Group names come from the directory on one side and an admin picker on
		// the other, so case drift must not drop a member. User IDs are opaque
		// and stay exact.
		return slices.ContainsFunc(s.Groups, func(g string) bool { return strings.EqualFold(g, rs.Name) })
	}
	return false
}

// Rule is one ordered row of a category's rule list: a subject with a grant
// per action. A missing action means GrantBlank.
type Rule struct {
	Subject RuleSubject
	Grants  map[Action]Grant
}

// CategoryRuleset is one category's owners and its ordered rules.
type CategoryRuleset struct {
	Name string
	// Owners are user IDs. An owner reads, approves and authors in this
	// category and every category below it, ahead of any rule.
	Owners []string
	Rules  []Rule
}

// Validate checks a ruleset read from outside (storage, the admin editor). The
// error is coded CodeInvalidRule, matches ErrInvalidRule, and carries the
// category, the 1-based rule number and the problem as wire metadata.
func (c CategoryRuleset) Validate() error {
	for _, o := range c.Owners {
		if strings.TrimSpace(o) == "" {
			return invalidRule(c.Name, "", "owner")
		}
	}
	for i, r := range c.Rules {
		n := strconv.Itoa(i + 1)
		named := strings.TrimSpace(r.Subject.Name) != ""
		switch r.Subject.Kind {
		case SubjectEveryone:
			if r.Subject.Name != "" {
				return invalidRule(c.Name, n, "subject")
			}
		case SubjectGroup, SubjectUser:
			if !named {
				return invalidRule(c.Name, n, "subject")
			}
		default:
			return invalidRule(c.Name, n, "subject")
		}
		keys := make([]Action, 0, len(r.Grants))
		for a := range r.Grants {
			keys = append(keys, a)
		}
		slices.Sort(keys)
		for _, a := range keys {
			if !slices.Contains(actions, a) {
				return invalidRule(c.Name, n, "action")
			}
			switch r.Grants[a] {
			case GrantBlank, GrantAllow, GrantDeny:
			default:
				return invalidRule(c.Name, n, "grant")
			}
		}
	}
	return nil
}

func invalidRule(category, rule, problem string) error {
	meta := []apperr.MetaPair{apperr.Meta("category", category), apperr.Meta("problem", problem)}
	if rule != "" {
		meta = append(meta, apperr.Meta("rule", rule))
	}
	return apperr.WithMeta(apperr.Coded(CodeInvalidRule, ErrInvalidRule), meta...)
}
