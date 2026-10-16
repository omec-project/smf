// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package fsm

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/transaction"
	"go.uber.org/zap"
)

// dispatchNetworkUpdate drives an UpdateSmContext carrying no N1 message -- e.g. a hoState or
// upCnxState update an AMF can send independently of any NAS message -- through the real FSM
// dispatch SmfFsmHandler uses in production.
func dispatchNetworkUpdate(t *testing.T, state smf_context.SMContextState, jsonData models.SmContextUpdateData) (*smf_context.SMContext, error) {
	t.Helper()

	prevConfig := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prevConfig })
	disabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &disabled}},
	}

	sm := &smf_context.SMContext{
		PDUSessionID:   10,
		SMContextState: state,
		// Tunnel is nil: releaseTunnel has already cleared it by the time a session reaches
		// SmStateInit or SmStateInActivePending, and HandleUpdateHoState/HandleUpCnxState must not
		// dereference it.
		Tunnel:        nil,
		SubPduSessLog: zap.NewNop().Sugar(),
		SubCtxLog:     zap.NewNop().Sugar(),
		SubGsmLog:     zap.NewNop().Sugar(),
		SubFsmLog:     zap.NewNop().Sugar(),
	}

	var body models.UpdateSmContextRequest
	body.SetJsonData(jsonData)

	txn := &transaction.Transaction{Req: body, Ctxt: sm}
	err := HandleEvent(sm, SmEventPduSessModify, SmEventData{Txn: txn})
	return sm, err
}

// Reject inactive updates before reactivation or cleared-tunnel access: a hoState update for a
// session that was never established or is being torn down must not move it back to
// SmStateActive, and an upCnxState update must not dereference the Tunnel releaseTunnel already
// cleared.
func TestNetworkUpdateAgainstAnInactiveSessionDoesNotReactivateOrPanic(t *testing.T) {
	tests := []struct {
		name     string
		state    smf_context.SMContextState
		jsonData func() models.SmContextUpdateData
	}{
		{
			name:  "delayed hoState COMPLETED while session is on its way out",
			state: smf_context.SmStateInActivePending,
			jsonData: func() models.SmContextUpdateData {
				jd := *models.NewSmContextUpdateData()
				jd.SetHoState(models.HOSTATE_COMPLETED)
				return jd
			},
		},
		{
			name:  "upCnxState ACTIVATING during teardown",
			state: smf_context.SmStateInActivePending,
			jsonData: func() models.SmContextUpdateData {
				jd := *models.NewSmContextUpdateData()
				jd.SetUpCnxState(models.UPCNXSTATE_ACTIVATING)
				return jd
			},
		},
		{
			name:  "upCnxState ACTIVATING for a session never established",
			state: smf_context.SmStateInit,
			jsonData: func() models.SmContextUpdateData {
				jd := *models.NewSmContextUpdateData()
				jd.SetUpCnxState(models.UPCNXSTATE_ACTIVATING)
				return jd
			},
		},
		{
			// N2SMINFOTYPE_PATH_SWITCH_REQ dereferences Tunnel.DataPathPool directly in
			// HandleUpdateN2Msg, same hazard as upCnxState ACTIVATING above.
			name:  "N2 path switch request during teardown",
			state: smf_context.SmStateInActivePending,
			jsonData: func() models.SmContextUpdateData {
				jd := *models.NewSmContextUpdateData()
				jd.SetN2SmInfoType(models.N2SMINFOTYPE_PATH_SWITCH_REQ)
				return jd
			},
		},
		{
			name:  "N2 handover required for a session never established",
			state: smf_context.SmStateInit,
			jsonData: func() models.SmContextUpdateData {
				jd := *models.NewSmContextUpdateData()
				jd.SetN2SmInfoType(models.N2SMINFOTYPE_HANDOVER_REQUIRED)
				return jd
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sm, err := dispatchNetworkUpdate(t, tc.state, tc.jsonData())
			if err != nil {
				t.Fatalf("HandleEvent returned an error: %v", err)
			}
			if sm.SMContextState == smf_context.SmStateActive {
				t.Errorf("SM context state = %v, want it to remain inactive; the update reactivated a session that was never established or is being torn down",
					sm.SMContextState.String())
			}
		})
	}
}
