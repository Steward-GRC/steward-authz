// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package stewardauthz is Steward's access engine, evaluated in-process by the
// services that need an access decision. It has two parts.
//
// The permission catalog (Permission, Role, RolePermissions) names every
// permission and the roles that grant it. Authorize decides one permission for
// a Subject on a Resource: the capability gate, then category scope for the
// scoped permissions (a grant on a category covers every category below it),
// then, for a read, per-document overrides, break glass and sensitivity.
//
// The category rule engine (CategoryRuleset, Compile, Resolve) decides the four
// governed actions, read, acknowledge, approve and author, from a category's
// ordered rules and those of its ancestors. The first rule with an opinion on
// the action wins, and anything no rule decides is denied. Read gates the other
// actions. Owners and site admins have the fixed rights listed on Compile.
//
// Both parts run on github.com/Bugs5382/go-authz, and the errors the package
// returns carry go-apperr codes (see Entries). The package does no I/O.
package stewardauthz
