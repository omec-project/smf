// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

// A null session rule cannot create an association: there is nothing in it to validate or use.
func TestValidateSmPolicyDecisionRejectsNullSessionRule(t *testing.T) {
	decision := models.NewSmPolicyDecision()
	decision.SetSessRules(map[string]*models.SessionRule{"active": nil})

	if err := validateSmPolicyDecision(decision); err == nil {
		t.Fatal("a null session rule passed validation")
	}
}
