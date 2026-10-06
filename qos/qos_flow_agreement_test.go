// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

// The two halves of one modification have to name the same flow. The NGAP release list resolves a
// withdrawn flow from committed QoS data; the NAS descriptions read the map key and parsed it as a
// number, so with this core's own names -- "QosData7" for the flow whose id is 7 -- the UE was
// told nothing while the radio was asked to release the bearer. The UE then keeps a flow
// description for a bearer that is gone.
func TestAWithdrawnFlowNamedByAReferenceIsAlsoWithdrawnFromTheUe(t *testing.T) {
	committed := map[string]*models.QosData{"QosData7": {QosId: "7"}}

	// A decision withdraws it: an entry with nothing in it, under the same key.
	update := GetQosFlowDescUpdate(map[string]models.QosData{"QosData7": {}}, committed)
	if update == nil {
		t.Fatal("no update produced for a decision that withdraws a flow")
	}

	descriptions := BuildAuthorizedQosFlowDescriptions(&PolicyUpdate{QosFlowUpdate: update})
	if len(descriptions.Content) == 0 {
		t.Fatal("the UE is told nothing about a flow the radio is asked to release")
	}

	if qfi := descriptions.Content[0]; qfi != 7 {
		t.Errorf("the UE is told to drop QFI %d, want 7", qfi)
	}
}

// And an identifier that cannot be one reaches neither end. Narrowing to uint8 before the range
// check made 257 into flow 1, so the UE was told to create a flow belonging to nothing.
func TestAnIdentifierThatCannotBeAFlowReachesTheUeAsNothing(t *testing.T) {
	update := GetQosFlowDescUpdate(
		map[string]models.QosData{"QosData257": {QosId: "257"}},
		map[string]*models.QosData{},
	)
	if update == nil {
		t.Fatal("no update produced")
	}

	descriptions := BuildAuthorizedQosFlowDescriptions(&PolicyUpdate{QosFlowUpdate: update})
	if len(descriptions.Content) != 0 {
		t.Errorf("the UE was given QFI %d for an identifier that cannot be one", descriptions.Content[0])
	}
}
