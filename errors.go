// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package stewardauthz

import (
	"errors"

	"github.com/Bugs5382/go-apperr"
)

// CodeBand is the leading digit of every code this library emits, so its codes
// stay apart from the services' own bands.
const CodeBand = 9

// The codes this library attaches to the errors it returns.
const (
	CodeDenied            = 9001
	CodeInvalidRule       = 9002
	CodeUnknownPermission = 9003
	CodeUnknownRole       = 9004
)

// Sentinel errors, matched with errors.Is. Each one reaches a caller wrapped in
// its code (see Entries).
var (
	ErrDenied            = errors.New("authz: access denied")
	ErrInvalidRule       = errors.New("authz: invalid access rule")
	ErrUnknownPermission = errors.New("authz: unknown permission")
	ErrUnknownRole       = errors.New("authz: unknown role")
)

// Entries returns the go-apperr entries for this library's codes. A service
// adds them to the registry it builds at startup, so a coded error from here
// presents with the right category, symbol and user-safe message.
func Entries() []apperr.Entry {
	return []apperr.Entry{
		{
			Code: CodeDenied, Symbol: "AUTHZ_DENIED", Category: apperr.CategoryPermissionDenied,
			Title: "authz", Cause: "the access decision denied the request",
			UserSafe: true, Message: "You don't have permission to do that.",
		},
		{
			Code: CodeInvalidRule, Symbol: "AUTHZ_INVALID_RULE", Category: apperr.CategoryInvalid,
			Title: "authz", Cause: "a category ruleset failed validation",
			UserSafe: true, Message: "Access rule {rule} in {category} is not valid ({problem}).",
		},
		{
			Code: CodeUnknownPermission, Symbol: "AUTHZ_UNKNOWN_PERMISSION", Category: apperr.CategoryInvalid,
			Title: "authz", Cause: "a permission name is not in the catalog",
			UserSafe: true, Message: "{permission} is not a known permission.",
		},
		{
			Code: CodeUnknownRole, Symbol: "AUTHZ_UNKNOWN_ROLE", Category: apperr.CategoryInvalid,
			Title: "authz", Cause: "a role name is not in the catalog",
			UserSafe: true, Message: "{role} is not a known role.",
		},
	}
}
