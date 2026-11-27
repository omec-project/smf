// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"testing"

	"github.com/omec-project/util/li/store"
	"github.com/omec-project/util/li/types"
)

// TestTheWatcherDoesNotWatchMDF2ForAContentOnlyTask: a task ordering only content is
// triggered at the UPF and delivers no xIRI from this element, so the configured MDF2 is not
// its destination. Watched for it, an MDF2 whose last delivery failed — under an IRI warrant
// since withdrawn — would be reported unreachable for as long as the content task lived, while
// the status answer, which asks only about tasks wanting xIRI, said nothing was in use.
func TestTheWatcherDoesNotWatchMDF2ForAContentOnlyTask(t *testing.T) {
	st := store.New()
	sub := &subsystem{store: st, mdf2: testDestinationAddr}
	down := func(string) bool { return true }

	if !st.Activate(types.InterceptTask{
		XID:      "11111111-1111-1111-1111-111111111111",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "001010000000001"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	}) {
		t.Fatal("activate the content task")
	}
	if h := sub.x2Health(down); len(h) != 0 {
		t.Errorf("the watcher samples %v for a content-only task; it delivers no xIRI from here", h)
	}
	if got := sub.destinationsInUse(); len(got) != 0 {
		t.Errorf("destinations in use %v for a content-only task", got)
	}

	// The commonest IRI configuration still is watched: a task naming no destination, served
	// by the configured MDF2 and reported at element scope.
	if !st.Activate(types.InterceptTask{
		XID:      "22222222-2222-2222-2222-222222222222",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "001010000000002"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	}) {
		t.Fatal("activate the IRI task")
	}
	h := sub.x2Health(down)
	if len(h) != 1 || h[0].Address != testDestinationAddr || h[0].DID != "" || !h[0].Unreachable {
		t.Errorf("the watcher samples %+v, want the configured MDF2 once, unreachable, at element scope", h)
	}
}
