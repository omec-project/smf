// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"testing"

	"github.com/omec-project/util/li/store"
	"github.com/omec-project/util/li/types"
)

// ActivateForTest installs a subsystem whose store holds task, for a test outside this package,
// and returns the X1 activation of task: the scan of live sessions reportStartOfInterception runs,
// waited for.
func ActivateForTest(t *testing.T, task types.InterceptTask) (activate func()) {
	t.Helper()
	st := store.New()
	if !st.Activate(task) {
		t.Fatalf("failed to activate test task %+v", task)
	}
	sub := &subsystem{store: st}
	active.Store(sub)
	t.Cleanup(func() { active.Store(nil) })

	return func() {
		sub.reportStartOfInterception(task, nil)
		sub.scans.Wait()
	}
}
