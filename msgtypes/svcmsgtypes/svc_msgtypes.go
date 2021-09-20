// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package svcmsgtypes

type SmfMsgType string

// List of Msgs
const (

	//N11 Service
	MsgTypeNone                         SmfMsgType = "none"
	NsmfPDUSessionCreateSmContext       SmfMsgType = "CreateSmContext"
	NsmfPDUSessionUpdateSmContext       SmfMsgType = "UpdateSmContext"
	NsmfPDUSessionReleaseSmContext      SmfMsgType = "ReleaseSmContext"
	NsmfPDUSessionNotifySmContextStatus SmfMsgType = "NotifySmContextStatus"
	NsmfPDUSessionRetrieveSmContext     SmfMsgType = "RetrieveSmContext"
	NsmfPDUSessionCreate                SmfMsgType = "Create"  //Create a PDU session in the H-SMF
	NsmfPDUSessionUpdate                SmfMsgType = "Update"  //Update a PDU session in the H-SMF or V- SMF
	NsmfPDUSessionRelease               SmfMsgType = "Release" //Release a PDU session in the H-SMF

	//NNRF_NFManagement
	NnrfNFRegister           SmfMsgType = "NfRegister"
	NnrfNFDeRegister         SmfMsgType = "NfDeRegister"
	NnrfNFInstanceDeRegister SmfMsgType = "NnrfNFInstanceDeRegister"
	NnrfNFDiscoveryUdm       SmfMsgType = "NfDiscoveryUdm"
	NnrfNFDiscoveryPcf       SmfMsgType = "NfDiscoveryPcf"
	NnrfNFDiscoveryAmf       SmfMsgType = "NfDiscoveryAmf"

	//NUDM_
	NudmSmSubscriptionDataRetrieval SmfMsgType = "NudmSmSubscriptionDataRetrieval"

	//NPCF_
	NpcfSmPolicyAssociationCreate SmfMsgType = "NpcfSmPolicyAssociationCreate"

	//AMF_
	NamfCommunicationN1N2MessageTransfer SmfMsgType = "NamfCommunicationN1N2MessageTransfer"
	//PFCP
	SmEventPfcpSessCreate  SmfMsgType = "SmEventPfcpSessCreate"
	SmEventPfcpSessModify  SmfMsgType = "SmEventPfcpSessModify"
	SmEventPfcpSessRelease SmfMsgType = "SmEventPfcpSessRelease"
)
