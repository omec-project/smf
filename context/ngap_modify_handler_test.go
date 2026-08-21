// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/omec-project/ngap/v2/aper"
	"github.com/omec-project/ngap/v2/ngapType"
	"go.uber.org/zap"
)

func modifyResponseBytes(t *testing.T, established, refused []int64) []byte {
	t.Helper()

	// DLNGUUPTNLInformation and ULNGUUPTNLInformation are OPTIONAL in TS 38.413 but the generated
	// type marks them mandatory, so they must be populated for the encoder to accept the message.
	// See TestModifyResponseWithoutTunnelInformation for why that matters.
	tnl := &ngapType.UPTransportLayerInformation{
		Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
		GTPTunnel: &ngapType.GTPTunnel{
			TransportLayerAddress: ngapType.TransportLayerAddress{Value: aper.BitString{Bytes: []byte{10, 0, 0, 1}, BitLength: 32}},
			GTPTEID:               ngapType.GTPTEID{Value: []byte{0, 0, 0, 1}},
		},
	}
	transfer := ngapType.PDUSessionResourceModifyResponseTransfer{
		DLNGUUPTNLInformation: tnl,
		ULNGUUPTNLInformation: tnl,
	}

	if len(established) > 0 {
		list := &ngapType.QosFlowAddOrModifyResponseList{}
		for _, qfi := range established {
			list.List = append(list.List, ngapType.QosFlowAddOrModifyResponseItem{
				QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: qfi},
			})
		}
		transfer.QosFlowAddOrModifyResponseList = list
	}

	if len(refused) > 0 {
		list := &ngapType.QosFlowListWithCause{}
		for _, qfi := range refused {
			list.List = append(list.List, ngapType.QosFlowWithCauseItem{
				QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: qfi},
				Cause: ngapType.Cause{
					Present: ngapType.CausePresentRadioNetwork,
					RadioNetwork: &ngapType.CauseRadioNetwork{
						Value: ngapType.CauseRadioNetworkPresentNotSupported5QIValue,
					},
				},
			})
		}
		transfer.QosFlowFailedToAddOrModifyList = list
	}

	b, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		t.Fatalf("encoding the modify response failed: %v", err)
	}
	return b
}

// A partial rejection cannot be produced with one flow, and it is the case the realignment
// exists for. This drives a genuinely encoded response through the decoder.
func TestModifyResponseClassification(t *testing.T) {
	ctx := &SMContext{SubPduSessLog: zap.NewNop().Sugar()}

	tests := []struct {
		name              string
		established       []int64
		refused           []int64
		wantWholeRejected bool
		wantPartial       bool
	}{
		{"all flows established", []int64{1, 2, 3}, nil, false, false},
		{"some established, some refused", []int64{1, 2}, []int64{3}, false, true},
		{"more refused than established", []int64{1}, []int64{2, 3, 4}, false, true},
		{"none established", nil, []int64{1, 2}, true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := HandlePDUSessionResourceModifyResponseTransfer(
				modifyResponseBytes(t, tc.established, tc.refused), ctx)
			if err != nil {
				t.Fatalf("decoding failed: %v", err)
			}

			if len(result.AcceptedQFIs) != len(tc.established) {
				t.Errorf("established = %v, want %v", result.AcceptedQFIs, tc.established)
			}
			if len(result.RejectedQFIs) != len(tc.refused) {
				t.Errorf("refused = %v, want %v", result.RejectedQFIs, tc.refused)
			}
			if got := result.WhollyRejected(); got != tc.wantWholeRejected {
				t.Errorf("WhollyRejected = %v, want %v", got, tc.wantWholeRejected)
			}
			if got := result.PartiallyRejected(); got != tc.wantPartial {
				t.Errorf("PartiallyRejected = %v, want %v", got, tc.wantPartial)
			}
		})
	}
}

// A whole rejection and a partial rejection are handled differently, so they must not be
// confusable. This pins the boundary between them.
func TestWholeAndPartialRejectionAreDistinct(t *testing.T) {
	ctx := &SMContext{SubPduSessLog: zap.NewNop().Sugar()}

	whole, err := HandlePDUSessionResourceModifyResponseTransfer(
		modifyResponseBytes(t, nil, []int64{1, 2}), ctx)
	if err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	partial, err := HandlePDUSessionResourceModifyResponseTransfer(
		modifyResponseBytes(t, []int64{1}, []int64{2}), ctx)
	if err != nil {
		t.Fatalf("decoding failed: %v", err)
	}

	if whole.PartiallyRejected() {
		t.Error("a response establishing nothing must not be treated as partial; it is abandoned, not realigned")
	}
	if partial.WhollyRejected() {
		t.Error("a response establishing something must not be treated as whole; part of it has to be kept")
	}
}

// TS 38.413 makes DL/UL NG-U UP TNL Information OPTIONAL in
// PDUSessionResourceModifyResponseTransfer, but omec-project/ngap v2.1.3 generates them without
// the aper "optional" tag, which makes them mandatory to the codec. A gNB that omits them —
// the ordinary case for a modification that changes QoS without moving the tunnel — produces a
// message this decoder cannot read.
//
// This test documents the deviation rather than working around it. If it starts failing, the
// generated type has been corrected upstream and the SMF should take that version.
func TestModifyResponseTunnelInformationIsWronglyMandatory(t *testing.T) {
	withoutTunnels := ngapType.PDUSessionResourceModifyResponseTransfer{
		QosFlowAddOrModifyResponseList: &ngapType.QosFlowAddOrModifyResponseList{
			List: []ngapType.QosFlowAddOrModifyResponseItem{
				{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}},
			},
		},
	}

	if _, err := aper.MarshalWithParams(withoutTunnels, "valueExt"); err == nil {
		t.Fatal("DL/UL NG-U UP TNL Information now encode as optional; the generated type has " +
			"been fixed upstream, so take that version and drop this test")
	}
}
