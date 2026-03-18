// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/omec-project/nas"
	"github.com/omec-project/nas/nasConvert"
	"github.com/omec-project/nas/nasMessage"
	"github.com/omec-project/nas/nasType"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/qos"
	errors "github.com/omec-project/smf/smferrors"
)

const (
	PTI uint8 = 0 // indicates that the request is initiated by the core network.
)

type AuthorizedQosRules struct {
	Iei    uint8
	Len    uint16
	Buffer []uint8
}

func BuildGSMPDUSessionEstablishmentAccept(smContext *SMContext) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionEstablishmentAccept)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionEstablishmentAccept = nasMessage.NewPDUSessionEstablishmentAccept(0x0)
	pDUSessionEstablishmentAccept := m.PDUSessionEstablishmentAccept

	sessRule := smContext.SmPolicyUpdates[0].SessRuleUpdate.ActiveSessRule

	pDUSessionEstablishmentAccept.SetPDUSessionID(uint8(smContext.PDUSessionID))
	pDUSessionEstablishmentAccept.SetMessageType(nas.MsgTypePDUSessionEstablishmentAccept)
	pDUSessionEstablishmentAccept.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pDUSessionEstablishmentAccept.SetPTI(smContext.Pti)

	if v := smContext.EstAcceptCause5gSMValue; v != 0 {
		pDUSessionEstablishmentAccept.Cause5GSM = nasType.NewCause5GSM(nasMessage.PDUSessionEstablishmentAcceptCause5GSMType)
		pDUSessionEstablishmentAccept.SetCauseValue(v)
	}
	pDUSessionEstablishmentAccept.SetPDUSessionType(smContext.SelectedPDUSessionType)

	pDUSessionEstablishmentAccept.SetSSCMode(1)
	pDUSessionEstablishmentAccept.SessionAMBR = nasConvert.ModelsToSessionAMBR(sessRule.AuthSessAmbr)
	pDUSessionEstablishmentAccept.SessionAMBR.SetLen(uint8(len(pDUSessionEstablishmentAccept.SessionAMBR.Octet)))

	qoSRules := qos.BuildQosRules(smContext.SmPolicyUpdates[0])

	qosRulesBytes, err := qoSRules.MarshalBinary()
	if err != nil {
		return nil, err
	}

	pDUSessionEstablishmentAccept.AuthorizedQosRules.SetLen(uint16(len(qosRulesBytes)))
	pDUSessionEstablishmentAccept.SetQosRule(qosRulesBytes)

	if smContext.PDUAddress.Ip != nil {
		addr, addrLen := smContext.PDUAddressToNAS()
		pDUSessionEstablishmentAccept.PDUAddress = nasType.NewPDUAddress(nasMessage.PDUSessionEstablishmentAcceptPDUAddressType)
		pDUSessionEstablishmentAccept.PDUAddress.SetLen(addrLen)
		pDUSessionEstablishmentAccept.SetPDUSessionTypeValue(smContext.SelectedPDUSessionType)
		pDUSessionEstablishmentAccept.SetPDUAddressInformation(addr)
	}

	// Get Authorized QoS Flow Descriptions
	authQfd := qos.BuildAuthorizedQosFlowDescriptions(smContext.SmPolicyUpdates[0])
	// Add Default Qos Flow
	// authQfd.AddDefaultQosFlowDescription(smContext.SmPolicyUpdates[0].SessRuleUpdate.ActiveSessRule)

	pDUSessionEstablishmentAccept.AuthorizedQosFlowDescriptions = nasType.NewAuthorizedQosFlowDescriptions(nasMessage.PDUSessionEstablishmentAcceptAuthorizedQosFlowDescriptionsType)
	pDUSessionEstablishmentAccept.AuthorizedQosFlowDescriptions.SetLen(authQfd.IeLen)
	pDUSessionEstablishmentAccept.SetQoSFlowDescriptions(authQfd.Content)
	// pDUSessionEstablishmentAccept.AuthorizedQosFlowDescriptions.SetLen(6)
	// pDUSessionEstablishmentAccept.SetQoSFlowDescriptions([]uint8{uint8(authDefQos.Var5qi), 0x20, 0x41, 0x01, 0x01, 0x09})

	var sd [3]uint8

	if byteArray, err := hex.DecodeString(smContext.Snssai.Sd); err != nil {
		return nil, err
	} else {
		copy(sd[:], byteArray)
	}

	pDUSessionEstablishmentAccept.SNSSAI = nasType.NewSNSSAI(nasMessage.ULNASTransportSNSSAIType)
	pDUSessionEstablishmentAccept.SNSSAI.SetLen(4)
	pDUSessionEstablishmentAccept.SetSST(uint8(smContext.Snssai.Sst))
	pDUSessionEstablishmentAccept.SetSD(sd)

	dnn := []byte(smContext.Dnn)
	pDUSessionEstablishmentAccept.DNN = nasType.NewDNN(nasMessage.ULNASTransportDNNType)
	pDUSessionEstablishmentAccept.DNN.SetLen(uint8(len(dnn)))
	pDUSessionEstablishmentAccept.SetDNN(dnn)

	if smContext.ProtocolConfigurationOptions.DNSIPv4Request || smContext.ProtocolConfigurationOptions.DNSIPv6Request || smContext.ProtocolConfigurationOptions.IPv4LinkMTURequest {
		pDUSessionEstablishmentAccept.ExtendedProtocolConfigurationOptions = nasType.NewExtendedProtocolConfigurationOptions(
			nasMessage.PDUSessionEstablishmentAcceptExtendedProtocolConfigurationOptionsType,
		)
		protocolConfigurationOptions := nasConvert.NewProtocolConfigurationOptions()

		// IPv4 DNS
		if smContext.ProtocolConfigurationOptions.DNSIPv4Request {
			err := protocolConfigurationOptions.AddDNSServerIPv4Address(smContext.DNNInfo.DNS.IPv4Addr)
			if err != nil {
				smContext.SubGsmLog.Warnln("Error while adding DNS IPv4 Addr: ", err)
			}
		}

		// IPv6 DNS
		if smContext.ProtocolConfigurationOptions.DNSIPv6Request {
			err := protocolConfigurationOptions.AddDNSServerIPv6Address(smContext.DNNInfo.DNS.IPv6Addr)
			if err != nil {
				smContext.SubGsmLog.Warnln("Error while adding DNS IPv6 Addr: ", err)
			}
		}

		// MTU
		if smContext.ProtocolConfigurationOptions.IPv4LinkMTURequest {
			err := protocolConfigurationOptions.AddIPv4LinkMTU(smContext.DNNInfo.MTU)
			if err != nil {
				smContext.SubGsmLog.Warnln("Error while adding MTU: ", err)
			}
		}

		// IPv4 P-CSCF
		if smContext.ProtocolConfigurationOptions.PCSCFIPv4Request {
			pcsfIpStr := factory.SmfConfig.Configuration.PCSCFInfo.IPv4Addr
			smContext.SubGsmLog.Infof("PCSCF Info from configuration: ", pcsfIpStr)
			smContext.SubGsmLog.Infof("PCSCF Info: ", smfContext.PCSCFInfo)
			if smfContext.PCSCFInfo.IPv4Addr != "" {
				pcsfIpStr = smfContext.PCSCFInfo.IPv4Addr
			} else {
				smContext.SubGsmLog.Warn("PCSCFInfo.IPv4Addr is empty in smfContext, using config fallback")
			}
			smContext.SubGsmLog.Infof("PCSCF Ip: ", pcsfIpStr)
			pcscfIP := net.ParseIP(pcsfIpStr)
			if pcscfIP == nil {
				smContext.SubGsmLog.Warnln("Invalid P-CSCF IP address")
			} else {
				err := protocolConfigurationOptions.AddPCSCFIPv4Address(pcscfIP)
				if err != nil {
					smContext.SubGsmLog.Warnln("Error while adding P-CSCF IPv4 Addr: ", err)
				}
			}
		}

		pcoContents := protocolConfigurationOptions.Marshal()
		pcoContentsLength := len(pcoContents)
		pDUSessionEstablishmentAccept.
			ExtendedProtocolConfigurationOptions.
			SetLen(uint16(pcoContentsLength))
		pDUSessionEstablishmentAccept.SetExtendedProtocolConfigurationOptionsContents(pcoContents)
	}
	return m.PlainNasEncode()
}

func BuildGSMPDUSessionEstablishmentReject(smContext *SMContext, cause uint8) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionEstablishmentReject)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionEstablishmentReject = nasMessage.NewPDUSessionEstablishmentReject(0x0)
	pDUSessionEstablishmentReject := m.PDUSessionEstablishmentReject

	pDUSessionEstablishmentReject.SetMessageType(nas.MsgTypePDUSessionEstablishmentReject)
	pDUSessionEstablishmentReject.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pDUSessionEstablishmentReject.SetPDUSessionID(uint8(smContext.PDUSessionID))
	pDUSessionEstablishmentReject.SetCauseValue(cause)
	pDUSessionEstablishmentReject.SetPTI(smContext.Pti)

	return m.PlainNasEncode()
}

/*func BuildGSMPDUSessionModificationReject(smContext *SMContext, cause uint8) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionModificationReject)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionModificationReject = nasMessage.NewPDUSessionModificationReject(0x0)
	pDUSessionModificationReject := m.PDUSessionModificationReject

	pDUSessionModificationReject.SetMessageType(nas.MsgTypePDUSessionModificationReject)
	pDUSessionModificationReject.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pDUSessionModificationReject.SetPDUSessionID(uint8(smContext.PDUSessionID))
	pDUSessionModificationReject.SetCauseValue(cause)

	return m.PlainNasEncode()
}*/

func BuildGSMPDUSessionReleaseCommand(smContext *SMContext) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionReleaseCommand)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionReleaseCommand = nasMessage.NewPDUSessionReleaseCommand(0x0)
	pDUSessionReleaseCommand := m.PDUSessionReleaseCommand

	pDUSessionReleaseCommand.SetMessageType(nas.MsgTypePDUSessionReleaseCommand)
	pDUSessionReleaseCommand.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pDUSessionReleaseCommand.SetPDUSessionID(uint8(smContext.PDUSessionID))
	pDUSessionReleaseCommand.SetPTI(smContext.Pti)
	pDUSessionReleaseCommand.SetCauseValue(0x0)

	return m.PlainNasEncode()
}

// 3GPP Reference: TS 24.501, Section 8.3.4 – "PDU Session Modification Command"
func BuildGSMPDUSessionModificationCommand(smContext *SMContext) ([]byte, error) {
	// Initialize NAS message
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()

	// Set NAS Message Type and Extended Protocol Discriminator for SM messages
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionModificationCommand)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)

	// Create PDUSessionModificationCommand IE
	m.PDUSessionModificationCommand = nasMessage.NewPDUSessionModificationCommand(0x0)
	pDUSessionModificationCommand := m.PDUSessionModificationCommand

	pDUSessionModificationCommand.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pDUSessionModificationCommand.SetPDUSessionID(uint8(smContext.PDUSessionID))

	// PTI = 0 indicates core-initiated request
	pDUSessionModificationCommand.SetPTI(PTI)

	pDUSessionModificationCommand.SetMessageType(nas.MsgTypePDUSessionModificationCommand)

	// ===============================
	// Set Session-AMBR if available
	// ===============================
	if len(smContext.SmPolicyUpdates) > 0 &&
		smContext.SmPolicyUpdates[0].SessRuleUpdate != nil &&
		smContext.SmPolicyUpdates[0].SessRuleUpdate.ActiveSessRule != nil &&
		smContext.SmPolicyUpdates[0].SessRuleUpdate.ActiveSessRule.AuthSessAmbr != nil {
		modAmbr := nasConvert.ModelsToSessionAMBR(smContext.SmPolicyUpdates[0].SessRuleUpdate.ActiveSessRule.AuthSessAmbr)
		pDUSessionModificationCommand.SessionAMBR = &modAmbr
		pDUSessionModificationCommand.SessionAMBR.SetLen(uint8(len(pDUSessionModificationCommand.SessionAMBR.Octet)))

		smContext.SubGsmLog.Infof("Session-AMBR set for PDU Session Modification Command")
	}

	// ===============================
	// Build Authorized QoS Flow Descriptions
	// ===============================
	authQfd := qos.BuildAuthorizedQosFlowDescriptions(smContext.SmPolicyUpdates[0])
	if pDUSessionModificationCommand.AuthorizedQosFlowDescriptions == nil {
		pDUSessionModificationCommand.AuthorizedQosFlowDescriptions = nasType.NewAuthorizedQosFlowDescriptions(
			nasMessage.PDUSessionModificationCommandAuthorizedQosFlowDescriptionsType)
	}
	pDUSessionModificationCommand.AuthorizedQosFlowDescriptions.SetLen(authQfd.IeLen)
	pDUSessionModificationCommand.AuthorizedQosFlowDescriptions.SetQoSFlowDescriptions(authQfd.Content)

	// ===============================
	// Build Authorized QoS Rules
	// ===============================
	if len(smContext.SmPolicyUpdates) > 0 {
		qoSRules := qos.BuildQosRulespdumod(smContext.SmPolicyUpdates[0])

		for _, r := range qoSRules {
			smContext.SubGsmLog.Debugf("Built QoS Rule ID: %d, QFI: %d, PF Count: %d",
				r.Identifier, r.QFI, len(r.PacketFilterList))
			for _, pf := range r.PacketFilterList {
				smContext.SubGsmLog.Debugf("PF ID: %d, Dir: %d, Content: %s",
					pf.Identifier, pf.Direction, pf.Content)
			}
		}

		// Marshal QoS rules to binary
		qosRulesBytes, err := qoSRules.MarshalBinary()
		if err != nil {
			smContext.SubGsmLog.Errorf("Failed to marshal QoS rules: %v", err)
			return nil, fmt.Errorf("failed to marshal QoS rules: %w", err)
		}

		smContext.SubGsmLog.Debugf("QoS Rules raw (hex): %x", qosRulesBytes)
		smContext.SubGsmLog.Debugf("QoS Rules length: %d", len(qosRulesBytes))

		// If there are QoS rules, create the Authorized QoS Rules IE
		if len(qosRulesBytes) > 0 {
			pDUSessionModificationCommand.AuthorizedQosRules = nasType.NewAuthorizedQosRules(
				nas.MsgTypePDUSessionModificationCommand)
			pDUSessionModificationCommand.AuthorizedQosRules.SetIei(0x7A)
			pDUSessionModificationCommand.AuthorizedQosRules.SetLen(uint16(len(qosRulesBytes)))
			pDUSessionModificationCommand.AuthorizedQosRules.SetQosRule(qosRulesBytes)

			smContext.SubGsmLog.Debugf("AuthorizedQoS IE len: %d", pDUSessionModificationCommand.AuthorizedQosRules.GetLen())
			smContext.SubGsmLog.Debugf("AuthorizedQoS IE hex: %x", pDUSessionModificationCommand.AuthorizedQosRules.GetQosRule())
		}
	}

	smContext.SubGsmLog.Infof("PDU Session Modification Command built successfully for Session ID: %d", smContext.PDUSessionID)

	// Encode NAS message to bytes
	encoded, err := m.PlainNasEncode()
	if err != nil {
		smContext.SubGsmLog.Errorf("Encoding failed: %v", err)
		return nil, err
	}

	smContext.SubGsmLog.Infof("Successfully encoded message, length: %d, hex: %x", len(encoded), encoded)
	return encoded, nil
}

func BuildGSMPDUSessionReleaseReject(smContext *SMContext) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionReleaseReject)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionReleaseReject = nasMessage.NewPDUSessionReleaseReject(0x0)
	pDUSessionReleaseReject := m.PDUSessionReleaseReject

	pDUSessionReleaseReject.SetMessageType(nas.MsgTypePDUSessionReleaseReject)
	pDUSessionReleaseReject.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)

	pDUSessionReleaseReject.SetPDUSessionID(uint8(smContext.PDUSessionID))

	pDUSessionReleaseReject.SetPTI(smContext.Pti)
	// TODO: fix to real value
	pDUSessionReleaseReject.SetCauseValue(nasMessage.Cause5GSMRequestRejectedUnspecified)

	return m.PlainNasEncode()
}

func BuildGSMPDUSessionReleaseRejectWithCause(smContext *SMContext, pduSessionID int32, cause string) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionReleaseReject)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionReleaseReject = nasMessage.NewPDUSessionReleaseReject(0x0)
	pDUSessionReleaseRejectWithCause := m.PDUSessionReleaseReject
	pDUSessionReleaseRejectWithCause.SetMessageType(nas.MsgTypePDUSessionReleaseReject)
	pDUSessionReleaseRejectWithCause.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pDUSessionReleaseRejectWithCause.SetPDUSessionID(uint8(pduSessionID))
	pDUSessionReleaseRejectWithCause.SetPTI(smContext.Pti)
	uint8Cause := errors.ErrorCause[cause]
	pDUSessionReleaseRejectWithCause.SetCauseValue(uint8Cause)
	return m.PlainNasEncode()
}

func (a *AuthorizedQosRules) SetQosRule(qosRule []uint8) {
	a.Buffer = make([]byte, len(qosRule)) // fresh buffer
	copy(a.Buffer, qosRule)
}
