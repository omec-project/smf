// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package svcmsgtypes

type SmfMsgType string

// List of Msgs
const (

	//N11 Service
	MsgTypeNone           SmfMsgType = "none"
	CreateSmContext       SmfMsgType = "CreateSmContext"
	UpdateSmContext       SmfMsgType = "UpdateSmContext"
	ReleaseSmContext      SmfMsgType = "ReleaseSmContext"
	NotifySmContextStatus SmfMsgType = "NotifySmContextStatus"
	RetrieveSmContext     SmfMsgType = "RetrieveSmContext"
	NsmfPDUSessionCreate  SmfMsgType = "Create"  //Create a PDU session in the H-SMF
	NsmfPDUSessionUpdate  SmfMsgType = "Update"  //Update a PDU session in the H-SMF or V- SMF
	NsmfPDUSessionRelease SmfMsgType = "Release" //Release a PDU session in the H-SMF

	//NNRF_NFManagement
	NnrfNFRegister           SmfMsgType = "NfRegister"
	NnrfNFDeRegister         SmfMsgType = "NfDeRegister"
	NnrfNFInstanceDeRegister SmfMsgType = "NnrfNFInstanceDeRegister"
	NnrfNFDiscoveryUdm       SmfMsgType = "NfDiscoveryUdm"
	NnrfNFDiscoveryPcf       SmfMsgType = "NfDiscoveryPcf"
	NnrfNFDiscoveryAmf       SmfMsgType = "NfDiscoveryAmf"

	//NUDM_
	SmSubscriptionDataRetrieval SmfMsgType = "SmSubscriptionDataRetrieval"

	//NPCF_
	SmPolicyAssociationCreate       SmfMsgType = "SmPolicyAssociationCreate"
	SmPolicyAssociationDelete       SmfMsgType = "SmPolicyAssociationDelete"
	SmPolicyUpdateNotification      SmfMsgType = "SmPolicyUpdateNotification"
	SmPolicyTerminationNotification SmfMsgType = "SmPolicyTerminationNotification"

	//AMF_
	N1N2MessageTransfer                    SmfMsgType = "N1N2MessageTransfer"
	N1N2MessageTransferFailureNotification SmfMsgType = "N1N2MessageTransferFailureNotification"

	//PFCP
	PfcpSessCreate  SmfMsgType = "PfcpSessCreate"
	PfcpSessModify  SmfMsgType = "PfcpSessModify"
	PfcpSessRelease SmfMsgType = "PfcpSessRelease"
)
