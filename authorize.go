// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package stewardauthz

import (
	"fmt"
	"slices"

	"github.com/Bugs5382/go-apperr"
)

// Effect is the outcome of Authorize.
type Effect string

// The effects. Obfuscate means the subject may see that the resource exists,
// but not its content.
const (
	EffectDeny      Effect = "deny"
	EffectAllow     Effect = "allow"
	EffectObfuscate Effect = "obfuscate"
)

// Reason is a stable, machine-readable code for why a decision came out as it
// did, for decision logs and the access simulator.
type Reason string

// The reasons Authorize returns.
const (
	ReasonGranted           Reason = "granted"
	ReasonMissingCapability Reason = "missing_capability"
	ReasonOutOfScope        Reason = "out_of_category_scope"
	ReasonOverrideAllow     Reason = "override_allow"
	ReasonBreakGlass        Reason = "break_glass"
	ReasonExcluded          Reason = "excluded"
	ReasonSensitive         Reason = "sensitive"
	ReasonAssigned          Reason = "assigned"
)

// ScopedGrant gives a role inside one category and, through the category
// lineage, every category below it.
type ScopedGrant struct {
	Role     Role
	Category string
}

// Override pins one resource for one subject: GrantAllow always shows it,
// GrantDeny excludes it.
type Override struct {
	ResourceID string
	Grant      Grant
}

// Subject is the signed-in person a decision is made for.
type Subject struct {
	UserID string
	Roles  []Role
	// Groups are directory group names; rule subjects match them ignoring case.
	Groups        []string
	ScopedGrants  []ScopedGrant
	Overrides     []Override
	ReadSensitive bool
	Root          bool
	// BreakGlass holds the resource IDs the subject has an active break-glass
	// grant for.
	BreakGlass map[string]bool
}

// SiteAdmin reports whether the subject holds the site-admin role.
func (s Subject) SiteAdmin() bool { return slices.Contains(s.Roles, RoleSiteAdmin) }

func (s Subject) override(id string) Grant {
	for _, o := range s.Overrides {
		if o.ResourceID == id {
			return o.Grant
		}
	}
	return GrantBlank
}

func (s Subject) holds(p Permission) bool {
	return slices.ContainsFunc(s.Roles, func(r Role) bool { return roleHolds(r, p) })
}

// scopedIn reports whether the subject holds the scoped role for p in any
// category of the lineage. Site admin authors and submits anywhere, but
// approves only where an approver grant says so.
func (s Subject) scopedIn(p Permission, lineage []string) bool {
	role := RoleAuthor
	if p == PolicyApprove {
		role = RoleApprover
	}
	if role != RoleApprover && s.SiteAdmin() {
		return true
	}
	return slices.ContainsFunc(s.ScopedGrants, func(g ScopedGrant) bool {
		return g.Role == role && slices.Contains(lineage, g.Category)
	})
}

// Resource is what an action is aimed at.
type Resource struct {
	ID       string
	Category string
	// CategoryLineage is the category names from this resource's category up
	// to the root. When it is empty, Category alone is used.
	CategoryLineage []string
	Sensitive       bool
	// Authors and Approvers are the user IDs assigned to this document. On a
	// sensitive document they are the only subjects, besides explicit grants,
	// who may read it.
	Authors   []string
	Approvers []string
}

// Decision is the outcome of Authorize.
type Decision struct {
	Effect Effect
	Reason Reason
}

// Allowed reports whether the decision is a plain allow.
func (d Decision) Allowed() bool { return d.Effect == EffectAllow }

// Err returns nil for an allow, and otherwise an error coded CodeDenied that
// matches ErrDenied. The reason stays in the internal cause and is never sent
// to the client.
func (d Decision) Err() error {
	if d.Allowed() {
		return nil
	}
	return apperr.Coded(CodeDenied, fmt.Errorf("%w: %s", ErrDenied, d.Reason))
}

// HasCapability reports whether the subject could be allowed p in at least one
// scope: through a role, the individual read-sensitive grant, or, for a scoped
// permission, any scoped grant whose role confers it. It is the coarse check
// for work that spans categories; Authorize makes the per-resource decision.
func HasCapability(s Subject, p Permission) bool {
	if roleHolds(RoleReader, p) || s.holds(p) {
		return true
	}
	if p == PolicyReadSensitive && s.ReadSensitive {
		return true
	}
	if p.Scoped() {
		return slices.ContainsFunc(s.ScopedGrants, func(g ScopedGrant) bool { return roleHolds(g.Role, p) })
	}
	return false
}

// Authorize decides p for the subject on r. r is nil for an action that is not
// aimed at one resource. A sensitive document is read only by its assigned
// authors and approvers and by explicit grants (the individual read-sensitive
// grant, an override allow, break glass); no role reads it.
func Authorize(s Subject, p Permission, r *Resource) Decision {
	if !HasCapability(s, p) {
		return Decision{EffectDeny, ReasonMissingCapability}
	}
	if p.Scoped() {
		if r == nil {
			return Decision{EffectDeny, ReasonOutOfScope}
		}
		lineage := r.CategoryLineage
		if len(lineage) == 0 {
			lineage = []string{r.Category}
		}
		if !s.scopedIn(p, lineage) {
			return Decision{EffectDeny, ReasonOutOfScope}
		}
		return Decision{EffectAllow, ReasonGranted}
	}
	if p != PolicyRead || r == nil {
		return Decision{EffectAllow, ReasonGranted}
	}
	switch s.override(r.ID) {
	case GrantAllow:
		return Decision{EffectAllow, ReasonOverrideAllow}
	case GrantDeny:
		if s.SiteAdmin() {
			return Decision{EffectObfuscate, ReasonExcluded}
		}
		return Decision{EffectDeny, ReasonExcluded}
	}
	if s.BreakGlass[r.ID] {
		return Decision{EffectAllow, ReasonBreakGlass}
	}
	if r.Sensitive && !s.ReadSensitive {
		if s.UserID != "" && (slices.Contains(r.Authors, s.UserID) || slices.Contains(r.Approvers, s.UserID)) {
			return Decision{EffectAllow, ReasonAssigned}
		}
		return Decision{EffectDeny, ReasonSensitive}
	}
	return Decision{EffectAllow, ReasonGranted}
}
