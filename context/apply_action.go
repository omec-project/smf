// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package context

type ApplyAction struct {
	// Dupl is not stored with the session. Only Lawful Interception sets it, and the stored
	// session names the subscriber; it is derived again from the tasking.
	Dupl bool `json:"-" yaml:"-" bson:"-"`
	Nocp bool
	Buff bool
	Forw bool
	Drop bool
}
