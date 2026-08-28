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

// conformantModifyResponseTransfer is PDUSessionResourceModifyResponseTransfer as TS 38.413
// defines it, with DL/UL NG-U UP TNL Information OPTIONAL. It stands in for what a real gNB
// encodes against, so the test below decodes a peer's encoding rather than its own: encoder and
// decoder agreeing with each other is precisely what hid the defect this guards against.
type conformantModifyResponseTransfer struct {
	DLNGUUPTNLInformation                *ngapType.UPTransportLayerInformation                                              `aper:"valueLB:0,valueUB:1,optional"`
	ULNGUUPTNLInformation                *ngapType.UPTransportLayerInformation                                              `aper:"valueLB:0,valueUB:1,optional"`
	QosFlowAddOrModifyResponseList       *ngapType.QosFlowAddOrModifyResponseList                                           `aper:"optional"`
	AdditionalDLQosFlowPerTNLInformation *ngapType.QosFlowPerTNLInformationList                                             `aper:"optional"`
	QosFlowFailedToAddOrModifyList       *ngapType.QosFlowListWithCause                                                     `aper:"optional"`
	IEExtensions                         *ngapType.ProtocolExtensionContainerPDUSessionResourceModifyResponseTransferExtIEs `aper:"optional"`
}

// The SMF has to read a conformant gNB's modification response in both the form that omits the
// tunnel information and the form that carries it.
//
// omec-project/ngap generated DL/UL NG-U UP TNL Information without the aper "optional" tag up to
// and including v2.1.3, so the codec treated them as always present. A modification that changes
// QoS without moving the tunnel — the ordinary case, and what this change produces — has a gNB omit
// both fields, and its encoding then carries six optionality bits where that decoder expected four.
// The decode failed on the misalignment. Fixed upstream in ngap#118 and released in v2.1.4, which
// this module now requires; the two tests that documented the broken state are gone with it.
func TestModifyResponseReadsAConformantGnbMessage(t *testing.T) {
	base := conformantModifyResponseTransfer{
		QosFlowAddOrModifyResponseList: &ngapType.QosFlowAddOrModifyResponseList{
			List: []ngapType.QosFlowAddOrModifyResponseItem{
				{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 5}},
			},
		},
	}
	withTunnel := base
	withTunnel.DLNGUUPTNLInformation = &ngapType.UPTransportLayerInformation{
		Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
		GTPTunnel: &ngapType.GTPTunnel{
			TransportLayerAddress: ngapType.TransportLayerAddress{
				Value: aper.BitString{Bytes: []byte{10, 0, 0, 1}, BitLength: 32},
			},
			GTPTEID: ngapType.GTPTEID{Value: []byte{0, 0, 0, 7}},
		},
	}

	for name, msg := range map[string]conformantModifyResponseTransfer{
		"tunnel omitted": base,
		"tunnel present": withTunnel,
	} {
		t.Run(name, func(t *testing.T) {
			wire, err := aper.MarshalWithParams(msg, "valueExt")
			if err != nil {
				t.Fatalf("could not build a conformant peer's message: %v", err)
			}

			var got ngapType.PDUSessionResourceModifyResponseTransfer
			if err := aper.UnmarshalWithParams(wire, &got, "valueExt"); err != nil {
				t.Fatalf("the shipped type could not decode a conformant gNB message (% x): %v", wire, err)
			}
			if got.QosFlowAddOrModifyResponseList == nil || len(got.QosFlowAddOrModifyResponseList.List) != 1 {
				t.Fatal("the QoS flow list was lost")
			}
			if (msg.DLNGUUPTNLInformation != nil) != (got.DLNGUUPTNLInformation != nil) {
				t.Error("tunnel information presence did not survive the decode")
			}
		})
	}
}
