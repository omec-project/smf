// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package context_test

import (
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
)

// Given PFCP port is not set in the configuration, then the default port should be used.
func TestInitSmfContextPFCPDefaultPort(t *testing.T) {
	config := &factory.Config{
		Info: &factory.Info{
			Version: "1.0",
		},
		Configuration: &factory.Configuration{
			SmfName: "smf",
			PFCP: &factory.PFCP{
				Addr: "1.2.3.4",
			},
			Sbi: &factory.Sbi{},
		},
	}

	smfContext := context.InitSmfContext(config)

	if smfContext.PFCPPort != 8805 {
		t.Errorf("Expected 8805, got %d", smfContext.PFCPPort)
	}
}
