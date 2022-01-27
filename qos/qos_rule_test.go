// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package qos_test

import (
	"fmt"
	"testing"

	"github.com/free5gc/smf/qos"
)

var flowDesc = []string{
	"permit out ip from 1.1.1.1 1000 to 2.2.2.2 2000",
	"permit out ip from 1.1.1.1/24 1000 to 2.2.2.2/24 2000",
	"permit out ip from any 1000 to 2.2.2.2/24 2000",
	"permit out ip from any 1000 to assigned 2000",
	"permit out 17 from 1.1.1.1/24 1000-1200 to 2.2.2.2/24 2000-2500"}

func TestDecodeFlowDescToIPFilters(t *testing.T) {
	for i, flow := range flowDesc {
		ipf := qos.DecodeFlowDescToIPFilters(flow)
		fmt.Printf("Flow: %v %v\n", i, ipf.String())
	}
}

func TestGetPfContent(t *testing.T) {
	for i, flow := range flowDesc {
		pfcList := qos.GetPfContent(flow)
		fmt.Println("Flow:", i)
		for _, pfc := range pfcList {
			fmt.Printf("%v", pfc.String())
		}
	}
}

/*
func TestBuildPFCompProtocolId(t *testing.T) {
	pfc := qos.BuildPFCompProtocolId("17")
	fmt.Printf("PFC: %v \n", pfc.String())
}
*/
