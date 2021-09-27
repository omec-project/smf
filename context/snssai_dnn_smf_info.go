// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package context

import (
	"net"

	"github.com/free5gc/openapi/models"
)

// SnssaiSmfInfo records the SMF S-NSSAI related information
type SnssaiSmfInfo struct {
	Snssai   SNssai
	DnnInfos map[string]*SnssaiSmfDnnInfo
	PlmnId   models.PlmnId
}

// SnssaiSmfDnnInfo records the SMF per S-NSSAI DNN information
type SnssaiSmfDnnInfo struct {
	DNS           DNS
	UeIPAllocator *IPAllocator
	MTU           uint16
}

type DNS struct {
	IPv4Addr net.IP
	IPv6Addr net.IP
}
