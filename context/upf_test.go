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
