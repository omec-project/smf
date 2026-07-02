// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/omec-project/ngap/v2/aper"
	"github.com/omec-project/ngap/v2/ngapConvert"
	"github.com/omec-project/ngap/v2/ngapType"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/qos"
)

const DefaultNonGBR5QI = 9

func buildAllocationAndRetentionPriority(qosFlow *models.QosData, sessRule *models.SessionRule) ngapType.AllocationAndRetentionPriority {
	priorityLevel := int64(8)
	preemptCap := ngapType.PreEmptionCapabilityPresentMayTriggerPreEmption
	preemptVul := ngapType.PreEmptionVulnerabilityPresentNotPreEmptable

	if sessRule != nil && sessRule.AuthDefQos != nil {
		if value := sessRule.AuthDefQos.GetPriorityLevel(); value > 0 {
			priorityLevel = int64(value)
		}
		if sessRule.AuthDefQos.Arp != nil {
			if value := sessRule.AuthDefQos.Arp.GetPriorityLevel(); value > 0 {
				priorityLevel = int64(value)
			}
			if sessRule.AuthDefQos.Arp.PreemptCap == models.PREEMPTIONCAPABILITY_NOT_PREEMPT {
				preemptCap = ngapType.PreEmptionCapabilityPresentShallNotTriggerPreEmption
			}
			if sessRule.AuthDefQos.Arp.PreemptVuln == models.PREEMPTIONVULNERABILITY_PREEMPTABLE {
				preemptVul = ngapType.PreEmptionVulnerabilityPresentPreEmptable
			}
		}
	}

	if qosFlow != nil {
		if value := qosFlow.GetPriorityLevel(); value > 0 {
			priorityLevel = int64(value)
		}
		if qosFlow.Arp != nil {
			if value := qosFlow.Arp.GetPriorityLevel(); value > 0 {
				priorityLevel = int64(value)
			}
			if qosFlow.Arp.PreemptCap == models.PREEMPTIONCAPABILITY_NOT_PREEMPT {
				preemptCap = ngapType.PreEmptionCapabilityPresentShallNotTriggerPreEmption
			}
			if qosFlow.Arp.PreemptVuln == models.PREEMPTIONVULNERABILITY_PREEMPTABLE {
				preemptVul = ngapType.PreEmptionVulnerabilityPresentPreEmptable
			}
		}
	}

	return ngapType.AllocationAndRetentionPriority{
		PriorityLevelARP:        ngapType.PriorityLevelARP{Value: priorityLevel},
		PreEmptionCapability:    ngapType.PreEmptionCapability{Value: preemptCap},
		PreEmptionVulnerability: ngapType.PreEmptionVulnerability{Value: preemptVul},
	}
}

func BuildPDUSessionResourceSetupRequestTransfer(ctx *SMContext) ([]byte, error) {
	ANUPF := ctx.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode
	UpNode := ANUPF.UPF
	teidOct := make([]byte, 4)
	binary.BigEndian.PutUint32(teidOct, ANUPF.UpLinkTunnel.TEID)

	resourceSetupRequestTransfer := ngapType.PDUSessionResourceSetupRequestTransfer{}

	// PDU Session Aggregate Maximum Bit Rate
	// This IE is Conditional and shall be present when at least one NonGBR QoS flow is being setup.
	// TODO: should check if there is at least one NonGBR QoS flow
	ie := ngapType.PDUSessionResourceSetupRequestTransferIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionAggregateMaximumBitRate
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	sessRule := ctx.SelectedSessionRule()
	if sessRule == nil || sessRule.AuthSessAmbr == nil {
		return nil, fmt.Errorf("no PDU Session AMBR")
	}
	ie.Value = ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
		Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentPDUSessionAggregateMaximumBitRate,
		PDUSessionAggregateMaximumBitRate: &ngapType.PDUSessionAggregateMaximumBitRate{
			PDUSessionAggregateMaximumBitRateDL: ngapType.BitRate{
				Value: ngapConvert.UEAmbrToInt64(sessRule.AuthSessAmbr.Downlink),
			},
			PDUSessionAggregateMaximumBitRateUL: ngapType.BitRate{
				Value: ngapConvert.UEAmbrToInt64(sessRule.AuthSessAmbr.Uplink),
			},
		},
	}
	resourceSetupRequestTransfer.ProtocolIEs.List = append(resourceSetupRequestTransfer.ProtocolIEs.List, ie)

	// UL NG-U UP TNL Information
	ie = ngapType.PDUSessionResourceSetupRequestTransferIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDULNGUUPTNLInformation
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	UpNode.UpfLock.RLock()
	if len(UpNode.N3Interfaces) == 0 {
		UpNode.UpfLock.RUnlock()
		return nil, fmt.Errorf("no N3Interfaces available in UPF node")
	}
	n3IP, err := UpNode.N3Interfaces[0].IP(ctx.SelectedPDUSessionType)
	UpNode.UpfLock.RUnlock()
	if err != nil {
		return nil, err
	}
	ie.Value = ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
		Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentULNGUUPTNLInformation,
		ULNGUUPTNLInformation: &ngapType.UPTransportLayerInformation{
			Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
			GTPTunnel: &ngapType.GTPTunnel{
				TransportLayerAddress: ngapType.TransportLayerAddress{
					Value: aper.BitString{
						Bytes:     n3IP,
						BitLength: uint64(len(n3IP) * 8),
					},
				},
				GTPTEID: ngapType.GTPTEID{Value: teidOct},
			},
		},
	}

	resourceSetupRequestTransfer.ProtocolIEs.List = append(resourceSetupRequestTransfer.ProtocolIEs.List, ie)

	// PDU Session Type
	ie = ngapType.PDUSessionResourceSetupRequestTransferIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionType
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value = ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
		Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentPDUSessionType,
		PDUSessionType: &ngapType.PDUSessionType{
			Value: ngapType.PDUSessionTypePresentIpv4,
		},
	}
	resourceSetupRequestTransfer.ProtocolIEs.List = append(resourceSetupRequestTransfer.ProtocolIEs.List, ie)

	// Get Qos Flows
	var qosAddFlows map[string]*models.QosData

	// Initialise QosFlows with existing Ctxt QosFlows, if any
	if len(ctx.SmPolicyData.SmCtxtQosData.QosData) > 0 {
		qosAddFlows = ctx.SmPolicyData.SmCtxtQosData.QosData
	}

	// PCF has provided some update
	if len(ctx.SmPolicyUpdates) > 0 {
		smPolicyUpdates := ctx.SmPolicyUpdates[0]
		if smPolicyUpdates.QosFlowUpdate != nil && smPolicyUpdates.QosFlowUpdate.GetAddQosFlowUpdate() != nil {
			qosAddFlows = smPolicyUpdates.QosFlowUpdate.GetAddQosFlowUpdate()
		}
	}

	// QoS Flow Setup Request List
	if len(qosAddFlows) > 0 {
		ie = ngapType.PDUSessionResourceSetupRequestTransferIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDQosFlowSetupRequestList
		ie.Criticality.Value = ngapType.CriticalityPresentReject

		var qosFlowsList []ngapType.QosFlowSetupRequestItem
		for _, qosFlow := range qosAddFlows {
			allocationAndRetentionPriority := buildAllocationAndRetentionPriority(qosFlow, sessRule)

			qosFlowItem := ngapType.QosFlowSetupRequestItem{
				QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: int64(qos.GetQosFlowIdFromQosId(qosFlow.GetQosId()))},
				QosFlowLevelQosParameters: ngapType.QosFlowLevelQosParameters{
					QosCharacteristics: ngapType.QosCharacteristics{
						Present: ngapType.QosCharacteristicsPresentNonDynamic5QI,
						NonDynamic5QI: &ngapType.NonDynamic5QIDescriptor{
							FiveQI: ngapType.FiveQI{
								Value: int64(qosFlow.GetVar5qi()),
							},
						},
					},
					AllocationAndRetentionPriority: allocationAndRetentionPriority,
				},
			}
			qosFlowsList = append(qosFlowsList, qosFlowItem)
		}

		ie.Value = ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
			Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentQosFlowSetupRequestList,
			QosFlowSetupRequestList: &ngapType.QosFlowSetupRequestList{
				List: qosFlowsList,
			},
		}

		resourceSetupRequestTransfer.ProtocolIEs.List = append(resourceSetupRequestTransfer.ProtocolIEs.List, ie)
	}
	/*else {
		//Do not Delete- Might have to enable default Session rule based flow later

		// QoS Flow Setup Request List
		// Get QFI from PCF
		ie = ngapType.PDUSessionResourceSetupRequestTransferIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDQosFlowSetupRequestList
		ie.Criticality.Value = ngapType.CriticalityPresentReject

		arpPreemptCap := ngapType.PreEmptionCapabilityPresentMayTriggerPreEmption
		if sessRule.AuthDefQos.Arp.PreemptCap == models.PREEMPTIONCAPABILITY_NOT_PREEMPT {
			arpPreemptCap = ngapType.PreEmptionCapabilityPresentShallNotTriggerPreEmption
		}

		arpPreemptVul := ngapType.PreEmptionVulnerabilityPresentNotPreEmptable
		if sessRule.AuthDefQos.Arp.PreemptVuln == models.PREEMPTIONVULNERABILITY_PREEMPTABLE {
			arpPreemptVul = ngapType.PreEmptionVulnerabilityPresentPreEmptable
		}
		//Default Session Rule
		ie.Value = ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
			Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentQosFlowSetupRequestList,
			QosFlowSetupRequestList: &ngapType.QosFlowSetupRequestList{

				List: []ngapType.QosFlowSetupRequestItem{
					{
						QosFlowIdentifier: ngapType.QosFlowIdentifier{
							Value: int64(sessRule.AuthDefQos.Var5qi), //DefaultNonGBR5QI,
						},
						QosFlowLevelQosParameters: ngapType.QosFlowLevelQosParameters{
							QosCharacteristics: ngapType.QosCharacteristics{
								Present: ngapType.QosCharacteristicsPresentNonDynamic5QI,
								NonDynamic5QI: &ngapType.NonDynamic5QIDescriptor{
									FiveQI: ngapType.FiveQI{
										Value: int64(sessRule.AuthDefQos.Var5qi), //DefaultNonGBR5QI,
									},
								},
							},
							AllocationAndRetentionPriority: ngapType.AllocationAndRetentionPriority{
								PriorityLevelARP: ngapType.PriorityLevelARP{
									Value: int64(sessRule.AuthDefQos.Arp.PriorityLevel), //15,
								},
								PreEmptionCapability: ngapType.PreEmptionCapability{
									Value: arpPreemptCap, //ngapType.PreEmptionCapabilityPresentShallNotTriggerPreEmption,
								},
								PreEmptionVulnerability: ngapType.PreEmptionVulnerability{
									Value: arpPreemptVul, //ngapType.PreEmptionVulnerabilityPresentNotPreEmptable,
								},
							},
						},
					},
				},
			},
		}
		resourceSetupRequestTransfer.ProtocolIEs.List = append(resourceSetupRequestTransfer.ProtocolIEs.List, ie)
	}*/

	if buf, err := aper.MarshalWithParams(resourceSetupRequestTransfer, "valueExt"); err != nil {
		return nil, fmt.Errorf("encode resourceSetupRequestTransfer failed: %s", err)
	} else {
		return buf, nil
	}
}

// BuildPDUSessionResourceModifyRequestTransfer builds and encodes
// the NGAP PDUSessionResourceModifyRequestTransfer message.
// This is used to update the RAN with QoS flow changes (add/modify/delete).
// 3GPP TS 38.413 8.2.3v16.2.0 (NGAP: PDU Session Resource Modify Request)
func BuildPDUSessionResourceModifyRequestTransfer(ctx *SMContext) ([]byte, error) {
	// Start logging with SUPI and Session ID
	ctx.SubPduSessLog.Infof(
		"Building PDUSessionResourceModifyRequestTransfer for SUPI[%s], PDU Session ID[%d]",
		ctx.Supi, ctx.PDUSessionID,
	)

	resourceModifyRequestTransfer := ngapType.PDUSessionResourceModifyRequestTransfer{}

	// ----------------------------------------------------
	// Step 1: Check if only QosFlowToReleaseList should be sent
	// ----------------------------------------------------
	shouldSendReleaseOnly := false
	if len(ctx.SmPolicyUpdates) > 0 && ctx.SmPolicyUpdates[0].SmPolicyDecision.PccRules != nil {
		// If PccRules map is empty → release only
		if len(ctx.SmPolicyUpdates[0].SmPolicyDecision.PccRules) == 0 {
			shouldSendReleaseOnly = true
			logger.PduSessLog.Warnln("PccRules map is empty, setting shouldSendReleaseOnly = true")
		} else {
			// If any PCC rule is invalid (nil or empty ID) → release only
			for ruleId, rule := range ctx.SmPolicyUpdates[0].SmPolicyDecision.PccRules {
				if ruleId == "" || rule.PccRuleId == "" {
					shouldSendReleaseOnly = true
					logger.PduSessLog.Warnf("Invalid PCC Rule found (ruleId='%s'), setting shouldSendReleaseOnly = true", ruleId)
					break
				}
			}
		}
	}

	// ----------------------------------------------------
	// Step 2: Handle Release-Only Case
	// ----------------------------------------------------
	if shouldSendReleaseOnly {
		ctx.SubPduSessLog.Info("PCC rule ID is nil, sending only QosFlowToReleaseList")

		// Determine QFI to release from the existing SM context QoS data (QosId carries the QFI)
		var qfi int32
		for _, qd := range ctx.SmPolicyData.SmCtxtQosData.QosData {
			if qd != nil && qd.GetDefQosFlowIndication() {
				qfi = int32(qos.GetQosFlowIdFromQosId(qd.GetQosId()))
				break
			}
		}
		if qfi == 0 {
			ctx.SubPduSessLog.Error("could not determine default QFI to release from SM context")
			return nil, fmt.Errorf("default QFI not found")
		}

		// Build QoS Flow Release List
		qosFlowToReleaseList := ngapType.QosFlowListWithCause{}
		qosFlowToReleaseList.List = append(qosFlowToReleaseList.List, ngapType.QosFlowWithCauseItem{
			QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: int64(qfi)},
			Cause: ngapType.Cause{
				Present: ngapType.CausePresentNas,
				Nas:     &ngapType.CauseNas{Value: ngapType.CauseNasPresentNormalRelease},
			},
		})

		// Add IE to NGAP transfer message
		ie := ngapType.PDUSessionResourceModifyRequestTransferIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDQosFlowToReleaseList},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.PDUSessionResourceModifyRequestTransferIEsValue{
				Present:              ngapType.PDUSessionResourceModifyRequestTransferIEsPresentQosFlowToReleaseList,
				QosFlowToReleaseList: &qosFlowToReleaseList,
			},
		}
		resourceModifyRequestTransfer.ProtocolIEs.List = append(resourceModifyRequestTransfer.ProtocolIEs.List, ie)
		ctx.SubPduSessLog.Infof("Appended QosFlowToReleaseList with %d entries", len(qosFlowToReleaseList.List))

		// Encode the NGAP message and return
		ctx.SubPduSessLog.Info("Encoding PDUSessionResourceModifyRequestTransfer structure (QosFlowToReleaseList only)")
		if buf, err := aper.MarshalWithParams(resourceModifyRequestTransfer, "valueExt"); err != nil {
			ctx.SubPduSessLog.Errorf("Failed to encode PDUSessionResourceModifyRequestTransfer: %v", err)
			return nil, fmt.Errorf("encode resourceModifyRequestTransfer failed: %w", err)
		} else {
			ctx.SubPduSessLog.Infof("Successfully built and encoded PDUSessionResourceModifyRequestTransfer (QosFlowToReleaseList only)")
			return buf, nil
		}
	}

	// ----------------------------------------------------
	// Step 3: Normal QoS Add/Modify Case
	// ----------------------------------------------------

	// Get selected session rule
	sessRule := ctx.SelectedSessionRule()
	if sessRule == nil {
		ctx.SubPduSessLog.Error("SelectedSessionRule is nil")
		return nil, fmt.Errorf("sessRule is nil")
	}

	// Session AMBR must be present
	if sessRule.AuthSessAmbr == nil {
		ctx.SubPduSessLog.Error("AuthSessAmbr is nil")
		return nil, fmt.Errorf("no PDU Session AMBR")
	}

	// Extract AMBR values
	gbdownlink := ngapConvert.UEAmbrToInt64(sessRule.AuthSessAmbr.Downlink)
	gbuplink := ngapConvert.UEAmbrToInt64(sessRule.AuthSessAmbr.Uplink)

	// Default QoS params
	var qfi int32
	var qi int32
	priority := int32(8)

	// Prefer deriving QFI from existing SM context QoS data (QosId carries the QFI)
	for _, qd := range ctx.SmPolicyData.SmCtxtQosData.QosData {
		if qd != nil && qd.GetDefQosFlowIndication() {
			qfi = int32(qos.GetQosFlowIdFromQosId(qd.GetQosId()))
			break
		}
	}

	if sessRule.AuthDefQos != nil {
		qi = sessRule.AuthDefQos.GetVar5qi()
		if sessRule.AuthDefQos.Arp != nil {
			if v := sessRule.AuthDefQos.Arp.GetPriorityLevel(); v > 0 {
				priority = v
			}
		}
	}

	// ----------------------------------------------------
	// Step 4: Check QoS Policy Decision overrides
	// ----------------------------------------------------
	if len(ctx.SmPolicyUpdates) > 0 {
		policyDecision := ctx.SmPolicyUpdates[0].SmPolicyDecision
		if policyDecision != nil {
			for _, qos := range policyDecision.GetQosDecs() {
				// Use the default QoS flow to derive session-level parameters to avoid
				// nondeterminism when multiple QoS decisions exist.
				if !qos.GetDefQosFlowIndication() {
					continue
				}

				ctx.SubPduSessLog.Infof(
					"QoSId=%s, Var5QI=%d, GBR: UL=%s, DL=%s, MBR: UL=%s, DL=%s",
					qos.GetQosId(), qos.GetVar5qi(), qos.GetGbrUl(), qos.GetGbrDl(), qos.GetMaxbrUl(), qos.GetMaxbrDl(),
				)
				// Override AMBR with GBR if available
				if qos.GetGbrDl() != "" {
					if val, err := StringToBitRate(qos.GetGbrDl()); err == nil {
						gbdownlink = int64(val)
					}
				}
				if qos.GetGbrUl() != "" {
					if val, err := StringToBitRate(qos.GetGbrUl()); err == nil {
						gbuplink = int64(val)
					}
				}
				qi = qos.GetVar5qi()
				break
			}
		}
	}
	ctx.SubPduSessLog.Infof("Using QoS: DL = %d bps, UL = %d bps, qfi = %d , arp = %d ",
		gbdownlink, gbuplink, qfi, priority)

	// Add AMBR IE to NGAP message
	ie := ngapType.PDUSessionResourceModifyRequestTransferIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionAggregateMaximumBitRate},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.PDUSessionResourceModifyRequestTransferIEsValue{
			Present: ngapType.PDUSessionResourceModifyRequestTransferIEsPresentPDUSessionAggregateMaximumBitRate,
			PDUSessionAggregateMaximumBitRate: &ngapType.PDUSessionAggregateMaximumBitRate{
				PDUSessionAggregateMaximumBitRateDL: ngapType.BitRate{Value: gbdownlink},
				PDUSessionAggregateMaximumBitRateUL: ngapType.BitRate{Value: gbuplink},
			},
		},
	}
	resourceModifyRequestTransfer.ProtocolIEs.List = append(resourceModifyRequestTransfer.ProtocolIEs.List, ie)

	// Default ARP values
	arpPreemptCap := ngapType.PreEmptionCapabilityPresentMayTriggerPreEmption
	arpPreemptVul := ngapType.PreEmptionVulnerabilityPresentNotPreEmptable

	// ----------------------------------------------------
	// Step 5: Handle policy updates (QoS flow add/modify)
	// ----------------------------------------------------
	if len(ctx.SmPolicyUpdates) > 0 {
		policyUpdate := ctx.SmPolicyUpdates[0]
		if policyUpdate != nil && policyUpdate.QosFlowUpdate != nil {
			ctx.SubPduSessLog.Infof("Found QoS flow updates in policy updates")

			// Handle modified flows first
			if len(policyUpdate.QosFlowUpdate.GetModified()) > 0 {
				for qosId, qosData := range policyUpdate.QosFlowUpdate.GetModified() {
					if qosData != nil {
						ctx.SubPduSessLog.Infof("Modified QoS data: QosId[%s], Var5QI=%d", qosId, qosData.GetVar5qi())
						// Convert QosId string to int
						if qfiVal, err := strconv.Atoi(qosData.GetQosId()); err == nil {
							qfi = int32(qfiVal)
						} else {
							ctx.SubPduSessLog.Errorf("Invalid QosId string: %s", qosData.GetQosId())
						}
						// Apply priority and ARP if present
						if qosData.GetPriorityLevel() > 0 {
							if pl := qosData.PriorityLevel.Get(); pl != nil {
								priority = *pl
							}
						}
						if qosData.Arp != nil {
							if pl := qosData.Arp.PriorityLevel.Get(); pl != nil {
								priority = *pl
							}
							if qosData.Arp.PreemptCap == models.PREEMPTIONCAPABILITY_NOT_PREEMPT {
								arpPreemptCap = ngapType.PreEmptionCapabilityPresentShallNotTriggerPreEmption
							}
							if qosData.Arp.PreemptVuln == models.PREEMPTIONVULNERABILITY_PREEMPTABLE {
								arpPreemptVul = ngapType.PreEmptionVulnerabilityPresentPreEmptable
							}
						}
						break
					}
				}
			}

			// Handle added flows if no modified ones
			if len(policyUpdate.QosFlowUpdate.GetAdded()) > 0 {
				for qosId, qosData := range policyUpdate.QosFlowUpdate.GetAdded() {
					if qosData != nil {
						ctx.SubPduSessLog.Infof("Added QoS data: QosId[%s], Var5QI=%d", qosId, qosData.GetVar5qi())
						if qfiVal, err := strconv.Atoi(qosData.GetQosId()); err == nil {
							qfi = int32(qfiVal)
						} else {
							ctx.SubPduSessLog.Errorf("Invalid QosId string: %s", qosData.GetQosId())
						}
						if qosData.GetPriorityLevel() > 0 {
							if pl := qosData.PriorityLevel.Get(); pl != nil {
								priority = *pl
							}
						}
						if qosData.Arp != nil {
							if pl := qosData.Arp.PriorityLevel.Get(); pl != nil {
								priority = *pl
							}
							if qosData.Arp.PreemptCap == models.PREEMPTIONCAPABILITY_NOT_PREEMPT {
								arpPreemptCap = ngapType.PreEmptionCapabilityPresentShallNotTriggerPreEmption
							}
							if qosData.Arp.PreemptVuln == models.PREEMPTIONVULNERABILITY_PREEMPTABLE {
								arpPreemptVul = ngapType.PreEmptionVulnerabilityPresentPreEmptable
							}
						}
						break
					}
				}
			}
		}
	}

	// Apply ARP defaults from session rule if not overridden
	if sessRule.AuthDefQos != nil && sessRule.AuthDefQos.Arp != nil {
		if sessRule.AuthDefQos.Arp.PreemptCap == models.PREEMPTIONCAPABILITY_NOT_PREEMPT {
			arpPreemptCap = ngapType.PreEmptionCapabilityPresentShallNotTriggerPreEmption
		}
		if sessRule.AuthDefQos.Arp.PreemptVuln == models.PREEMPTIONVULNERABILITY_PREEMPTABLE {
			arpPreemptVul = ngapType.PreEmptionVulnerabilityPresentPreEmptable
		}
	}

	ctx.SubPduSessLog.Infof(
		"Final QoS Flow: QFI = %d, Priority = %d, PreemptCap = %d, PreemptVul = %d",
		qfi, priority, arpPreemptCap, arpPreemptVul,
	)

	// Build QoS AddOrModify IE
	ie = ngapType.PDUSessionResourceModifyRequestTransferIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDQosFlowAddOrModifyRequestList},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.PDUSessionResourceModifyRequestTransferIEsValue{
			Present: ngapType.PDUSessionResourceModifyRequestTransferIEsPresentQosFlowAddOrModifyRequestList,
			QosFlowAddOrModifyRequestList: &ngapType.QosFlowAddOrModifyRequestList{
				List: []ngapType.QosFlowAddOrModifyRequestItem{{
					QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: int64(qfi)},
					QosFlowLevelQosParameters: &ngapType.QosFlowLevelQosParameters{
						QosCharacteristics: ngapType.QosCharacteristics{
							Present: ngapType.QosCharacteristicsPresentNonDynamic5QI,
							NonDynamic5QI: &ngapType.NonDynamic5QIDescriptor{
								FiveQI: ngapType.FiveQI{Value: int64(qi)},
							},
						},
						AllocationAndRetentionPriority: ngapType.AllocationAndRetentionPriority{
							PriorityLevelARP:        ngapType.PriorityLevelARP{Value: int64(priority)},
							PreEmptionCapability:    ngapType.PreEmptionCapability{Value: arpPreemptCap},
							PreEmptionVulnerability: ngapType.PreEmptionVulnerability{Value: arpPreemptVul},
						},
					},
				}},
			},
		},
	}

	resourceModifyRequestTransfer.ProtocolIEs.List = append(resourceModifyRequestTransfer.ProtocolIEs.List, ie)

	// ----------------------------------------------------
	// Step 6: Encode NGAP message
	// ----------------------------------------------------
	ctx.SubPduSessLog.Info("Encoding PDUSessionResourceModifyRequestTransfer structure")
	if buf, err := aper.MarshalWithParams(resourceModifyRequestTransfer, "valueExt"); err != nil {
		ctx.SubPduSessLog.Errorf("Failed to encode PDUSessionResourceModifyRequestTransfer: %v", err)
		return nil, fmt.Errorf("encode resourceModifyRequestTransfer failed: %w", err)
	} else {
		ctx.SubPduSessLog.Infof("Successfully built and encoded PDUSessionResourceModifyRequestTransfer")
		return buf, nil
	}
}

// This function is needed because QoS parameters in 3GPP specifications (e.g., GBR, MBR)
// are often provisioned or configured as strings with units (kbps/mbps),
// but internally the SMF/UPF and PFCP signaling require numeric values in bps.
//
// Supported units:
//   - "bps"  → bits per second (multiplied by 1)
//   - "kbps" → kilobits per second (multiplied by 1,000)
//   - "mbps" → megabits per second (multiplied by 1,000,000)
//   - "gbps" → gigabits per second (multiplied by 1,000,000,000)
//   - "tbps" → terabits per second (multiplied by 1,000,000,000,000)
func StringToBitRate(s string) (uint64, error) {
	s = strings.ToLower(strings.TrimSpace(s))

	mult := float64(0)
	switch {
	case strings.HasSuffix(s, "tbps"):
		mult = 1e12
		s = strings.TrimSuffix(s, "tbps")
	case strings.HasSuffix(s, "gbps"):
		mult = 1e9
		s = strings.TrimSuffix(s, "gbps")
	case strings.HasSuffix(s, "mbps"):
		mult = 1e6
		s = strings.TrimSuffix(s, "mbps")
	case strings.HasSuffix(s, "kbps"):
		mult = 1e3
		s = strings.TrimSuffix(s, "kbps")
	case strings.HasSuffix(s, "bps"):
		mult = 1
		s = strings.TrimSuffix(s, "bps")
	default:
		return 0, fmt.Errorf("unsupported bitrate format: %q", s)
	}

	val, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	if val < 0 {
		return 0, fmt.Errorf("negative bitrate: %q", strings.TrimSpace(s))
	}
	return uint64(val*mult + 0.5), nil
}

func BuildPDUSessionResourceReleaseCommandTransfer(ctx *SMContext) (buf []byte, err error) {
	resourceReleaseCommandTransfer := ngapType.PDUSessionResourceReleaseCommandTransfer{
		Cause: ngapType.Cause{
			Present: ngapType.CausePresentNas,
			Nas: &ngapType.CauseNas{
				Value: ngapType.CauseNasPresentNormalRelease,
			},
		},
	}
	buf, err = aper.MarshalWithParams(resourceReleaseCommandTransfer, "valueExt")
	if err != nil {
		return nil, err
	}
	return
}

// TS 38.413 9.3.4.9
func BuildPathSwitchRequestAcknowledgeTransfer(ctx *SMContext) ([]byte, error) {
	ANUPF := ctx.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode
	UpNode := ANUPF.UPF
	teidOct := make([]byte, 4)
	binary.BigEndian.PutUint32(teidOct, ANUPF.UpLinkTunnel.TEID)

	pathSwitchRequestAcknowledgeTransfer := ngapType.PathSwitchRequestAcknowledgeTransfer{}

	// UL NG-U UP TNL Information(optional) TS 38.413 9.3.2.2
	pathSwitchRequestAcknowledgeTransfer.
		ULNGUUPTNLInformation = new(ngapType.UPTransportLayerInformation)

	ULNGUUPTNLInformation := pathSwitchRequestAcknowledgeTransfer.ULNGUUPTNLInformation
	ULNGUUPTNLInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	ULNGUUPTNLInformation.GTPTunnel = new(ngapType.GTPTunnel)

	if n3IP, err := UpNode.N3Interfaces[0].IP(ctx.SelectedPDUSessionType); err != nil {
		return nil, err
	} else {
		gtpTunnel := ULNGUUPTNLInformation.GTPTunnel
		gtpTunnel.GTPTEID.Value = teidOct
		gtpTunnel.TransportLayerAddress.Value = aper.BitString{
			Bytes:     n3IP,
			BitLength: uint64(len(n3IP) * 8),
		}
	}

	// Security Indication(optional) TS 38.413 9.3.1.27
	pathSwitchRequestAcknowledgeTransfer.SecurityIndication = new(ngapType.SecurityIndication)
	securityIndication := pathSwitchRequestAcknowledgeTransfer.SecurityIndication
	// TODO: use real value
	securityIndication.IntegrityProtectionIndication.Value = ngapType.IntegrityProtectionIndicationPresentNotNeeded
	// TODO: use real value
	securityIndication.ConfidentialityProtectionIndication.Value = ngapType.ConfidentialityProtectionIndicationPresentNotNeeded

	integrityProtectionInd := securityIndication.IntegrityProtectionIndication.Value
	if integrityProtectionInd == ngapType.IntegrityProtectionIndicationPresentRequired ||
		integrityProtectionInd == ngapType.IntegrityProtectionIndicationPresentPreferred {
		securityIndication.MaximumIntegrityProtectedDataRateUL = new(ngapType.MaximumIntegrityProtectedDataRate)
		// TODO: use real value
		securityIndication.MaximumIntegrityProtectedDataRateUL.Value = ngapType.MaximumIntegrityProtectedDataRatePresentBitrate64kbs
	}

	if buf, err := aper.MarshalWithParams(pathSwitchRequestAcknowledgeTransfer, "valueExt"); err != nil {
		return nil, err
	} else {
		return buf, nil
	}
}

func BuildHandoverCommandTransfer(ctx *SMContext) ([]byte, error) {
	ANUPF := ctx.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode
	UpNode := ANUPF.UPF
	teidOct := make([]byte, 4)
	binary.BigEndian.PutUint32(teidOct, ANUPF.UpLinkTunnel.TEID)
	handoverCommandTransfer := ngapType.HandoverCommandTransfer{}

	handoverCommandTransfer.DLForwardingUPTNLInformation = new(ngapType.UPTransportLayerInformation)
	handoverCommandTransfer.DLForwardingUPTNLInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	handoverCommandTransfer.DLForwardingUPTNLInformation.GTPTunnel = new(ngapType.GTPTunnel)

	if n3IP, err := UpNode.N3Interfaces[0].IP(ctx.SelectedPDUSessionType); err != nil {
		return nil, err
	} else {
		gtpTunnel := handoverCommandTransfer.DLForwardingUPTNLInformation.GTPTunnel
		gtpTunnel.GTPTEID.Value = teidOct
		gtpTunnel.TransportLayerAddress.Value = aper.BitString{
			Bytes:     n3IP,
			BitLength: uint64(len(n3IP) * 8),
		}
	}

	if buf, err := aper.MarshalWithParams(handoverCommandTransfer, "valueExt"); err != nil {
		return nil, err
	} else {
		return buf, nil
	}
}
