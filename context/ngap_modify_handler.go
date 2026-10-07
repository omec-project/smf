// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"github.com/omec-project/ngap/v2/aper"
	"github.com/omec-project/ngap/v2/ngapType"
)

// ModifyResponse is what the radio access network made of a modification: which QoS flows it
// established and which it refused.
//
// The distinction between refusing some and refusing all is not cosmetic. A whole refusal means
// the UE never received the authorized parameters, so the modification is abandoned. A partial
// refusal means the UE was told about flows that were not established, and the network owes it a
// further modification saying which are actually in force.
type ModifyResponse struct {
	AcceptedQFIs []int64
	RejectedQFIs []int64
}

// WhollyRejected reports that the radio access network established none of the flows.
func (r ModifyResponse) WhollyRejected() bool {
	return len(r.AcceptedQFIs) == 0 && len(r.RejectedQFIs) > 0
}

// PartiallyRejected reports that some flows were established and some were not.
func (r ModifyResponse) PartiallyRejected() bool {
	return len(r.AcceptedQFIs) > 0 && len(r.RejectedQFIs) > 0
}

// HandlePDUSessionResourceModifyResponseTransfer decodes the radio access network's answer to a
// PDU session modification.
func HandlePDUSessionResourceModifyResponseTransfer(b []byte, ctx *SMContext) (ModifyResponse, error) {
	transfer := ngapType.PDUSessionResourceModifyResponseTransfer{}
	if err := aper.UnmarshalWithParams(b, &transfer, "valueExt"); err != nil {
		return ModifyResponse{}, err
	}

	var result ModifyResponse

	if transfer.QosFlowAddOrModifyResponseList != nil {
		for _, item := range transfer.QosFlowAddOrModifyResponseList.List {
			result.AcceptedQFIs = append(result.AcceptedQFIs, item.QosFlowIdentifier.Value)
		}
	}

	if transfer.QosFlowFailedToAddOrModifyList != nil {
		for _, item := range transfer.QosFlowFailedToAddOrModifyList.List {
			result.RejectedQFIs = append(result.RejectedQFIs, item.QosFlowIdentifier.Value)
		}
	}

	ctx.SubPduSessLog.Infof("PDU session resource modify response: %d flows established, %d refused",
		len(result.AcceptedQFIs), len(result.RejectedQFIs))

	return result, nil
}

// HandlePDUSessionResourceModifyUnsuccessfulTransfer decodes the radio access network's refusal
// of a modification in its entirety.
func HandlePDUSessionResourceModifyUnsuccessfulTransfer(b []byte, ctx *SMContext) (ngapType.Cause, error) {
	transfer := ngapType.PDUSessionResourceModifyUnsuccessfulTransfer{}
	if err := aper.UnmarshalWithParams(b, &transfer, "valueExt"); err != nil {
		return ngapType.Cause{}, err
	}

	ctx.SubPduSessLog.Warnf("PDU session resource modify refused in its entirety, cause present %d",
		transfer.Cause.Present)

	return transfer.Cause, nil
}

// PendingRealignment records that the radio access network established only some of the flows a
// modification authorized, so the UE is holding a view of the session that is wider than what
// exists.
//
// TS 23.502 clause 4.3.3.2 puts the corrective procedure after step 11 — after the UE has
// acknowledged the first modification — so the need is recorded when the response arrives and
// acted on when that acknowledgement comes. Sending a second command while the first is still
// unacknowledged would collide with it.
type PendingRealignment struct {
	EstablishedQFIs []int64
	RefusedQFIs     []int64
}
