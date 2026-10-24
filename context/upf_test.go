// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

func TestGetInterfaceReturnsActualSliceElement(t *testing.T) {
	upf := &UPF{
		N3Interfaces: []UPFInterfaceInfo{{NetworkInstance: "internet"}},
		N9Interfaces: []UPFInterfaceInfo{{NetworkInstance: "core"}},
	}

	iface := upf.GetInterface(models.UPINTERFACETYPE_N3, "internet")
	if iface == nil {
		t.Fatal("expected interface match")
		return
	}
	iface.NetworkInstance = "changed"
	if upf.N3Interfaces[0].NetworkInstance != "changed" {
		t.Fatal("expected returned pointer to reference underlying slice element")
	}

	n9 := upf.GetInterface(models.UPINTERFACETYPE_N9, "core")
	if n9 == nil {
		t.Fatal("expected N9 interface match")
	}
}

// A negative precedence is out of a PDR's unsigned range. Converted, it wrapped to about 4 billion
// and put the rule last; left zero it is read as unset, and the tunnel build gives the PDR its default.
func TestAPccRuleWithANegativePrecedenceBuildsAPDRWithNone(t *testing.T) {
	upf := NewUPF(NewNodeID("10.0.0.2"), nil)
	upf.UPFStatus = AssociatedSetUpSuccess
	flow := models.FlowInformation{
		FlowDescription: new("permit out ip from any to assigned"), PackFiltId: new("1"),
	}

	for _, tc := range []struct {
		decided int32
		want    uint32
	}{{-5, 0}, {0, 0}, {7, 7}} {
		rule := &models.PccRule{
			PccRuleId: "app", FlowInfos: []models.FlowInformation{flow}, Precedence: new(tc.decided),
		}
		pdr, err := upf.BuildCreatePdrFromPccRule(rule)
		if err != nil {
			t.Fatalf("precedence %d: %v", tc.decided, err)
		}
		if pdr.Precedence != tc.want {
			t.Errorf("precedence %d built a PDR with %d, want %d", tc.decided, pdr.Precedence, tc.want)
		}
	}
}
