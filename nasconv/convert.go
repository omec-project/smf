// SPDX-FileCopyrightText: 2026 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

// Package nasconv translates between OpenAPI models and NAS protocol types.
//
// It is owned by SMF so the NAS protocol library can remain independent of
// OpenAPI-generated SBI models.
package nasconv

import (
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/omec-project/nas/v2/logger"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/nas/v2/nasType"
	"github.com/omec-project/openapi/v2/models"
)

func PDUSessionTypeToModels(nasPDUSessionType uint8) models.PduSessionType {
	switch nasPDUSessionType {
	case nasMessage.PDUSessionTypeIPv4:
		return models.PDUSESSIONTYPE_IPV4
	case nasMessage.PDUSessionTypeIPv6:
		return models.PDUSESSIONTYPE_IPV6
	case nasMessage.PDUSessionTypeIPv4IPv6:
		return models.PDUSESSIONTYPE_IPV4_V6
	case nasMessage.PDUSessionTypeUnstructured:
		return models.PDUSESSIONTYPE_UNSTRUCTURED
	case nasMessage.PDUSessionTypeEthernet:
		return models.PDUSESSIONTYPE_ETHERNET
	default:
		return ""
	}
}

func ModelsToPDUSessionType(pduSessionType models.PduSessionType) uint8 {
	switch pduSessionType {
	case models.PDUSESSIONTYPE_IPV4:
		return nasMessage.PDUSessionTypeIPv4
	case models.PDUSESSIONTYPE_IPV6:
		return nasMessage.PDUSessionTypeIPv6
	case models.PDUSESSIONTYPE_IPV4_V6:
		return nasMessage.PDUSessionTypeIPv4IPv6
	case models.PDUSESSIONTYPE_UNSTRUCTURED:
		return nasMessage.PDUSessionTypeUnstructured
	case models.PDUSESSIONTYPE_ETHERNET:
		return nasMessage.PDUSessionTypeEthernet
	default:
		return 0
	}
}

func ModelsToSessionAMBR(ambr *models.Ambr) nasType.SessionAMBR {
	logger.ConvertLog.Infof("%v", ambr)

	result := nasType.SessionAMBR{}
	encodeSessionAMBR(ambr.Uplink, result.SetSessionAMBRForUplink, result.SetUnitForSessionAMBRForUplink, "uplink")
	encodeSessionAMBR(ambr.Downlink, result.SetSessionAMBRForDownlink, result.SetUnitForSessionAMBRForDownlink, "downlink")
	return result
}

func encodeSessionAMBR(value string, setRate func([2]byte), setUnit func(uint8), direction string) {
	parts := strings.Split(value, " ")
	if bitRate, err := strconv.ParseUint(parts[0], 10, 16); err != nil {
		logger.ConvertLog.Warnf("%s AMBR parse failed: %+v", direction, err)
	} else {
		var bitRateBytes [2]byte
		binary.BigEndian.PutUint16(bitRateBytes[:], uint16(bitRate))
		setRate(bitRateBytes)
	}
	setUnit(ambrUnit(parts[1]))
}

func ambrUnit(unit string) uint8 {
	switch unit {
	case "bps":
		return nasMessage.SessionAMBRUnitNotUsed
	case "Kbps":
		return nasMessage.SessionAMBRUnit1Kbps
	case "Mbps":
		return nasMessage.SessionAMBRUnit1Mbps
	case "Gbps":
		return nasMessage.SessionAMBRUnit1Gbps
	case "Tbps":
		return nasMessage.SessionAMBRUnit1Tbps
	case "Pbps":
		return nasMessage.SessionAMBRUnit1Pbps
	default:
		return nasMessage.SessionAMBRUnitNotUsed
	}
}
