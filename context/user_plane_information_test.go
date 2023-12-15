// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/pfcp/pfcpType"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
)

var configuration = &factory.UserPlaneInformation{
	UPNodes: map[string]factory.UPNode{
		"GNodeB": {
			Type:   "AN",
			NodeID: "192.168.179.100",
		},
		"UPF1": {
			Type:   "UPF",
			NodeID: "192.168.179.1",
			SNssaiInfos: []models.SnssaiUpfInfoItem{
				{
					SNssai: &models.Snssai{
						Sst: 1,
						Sd:  "112232",
					},
					DnnUpfInfoList: []models.DnnUpfInfoItem{
						{Dnn: "internet"},
					},
				},
				{
					SNssai: &models.Snssai{
						Sst: 1,
						Sd:  "112235",
					},
					DnnUpfInfoList: []models.DnnUpfInfoItem{
						{Dnn: "internet"},
					},
				},
			},
		},
		"UPF2": {
			Type:   "UPF",
			NodeID: "192.168.179.2",
			SNssaiInfos: []models.SnssaiUpfInfoItem{
				{
					SNssai: &models.Snssai{
						Sst: 2,
						Sd:  "112233",
					},
					DnnUpfInfoList: []models.DnnUpfInfoItem{
						{Dnn: "internet"},
					},
				},
			},
		},
		"UPF3": {
			Type:   "UPF",
			NodeID: "192.168.179.3",
			SNssaiInfos: []models.SnssaiUpfInfoItem{
				{
					SNssai: &models.Snssai{
						Sst: 3,
						Sd:  "112234",
					},
					DnnUpfInfoList: []models.DnnUpfInfoItem{
						{Dnn: "internet"},
					},
				},
			},
		},
		"UPF4": {
			Type:   "UPF",
			NodeID: "192.168.179.4",
			SNssaiInfos: []models.SnssaiUpfInfoItem{
				{
					SNssai: &models.Snssai{
						Sst: 1,
						Sd:  "112235",
					},
					DnnUpfInfoList: []models.DnnUpfInfoItem{
						{Dnn: "internet"},
					},
				},
			},
		},
	},
	Links: []factory.UPLink{
		{
			A: "GNodeB",
			B: "UPF1",
		},
		{
			A: "UPF1",
			B: "UPF2",
		},
		{
			A: "UPF2",
			B: "UPF3",
		},
		{
			A: "UPF3",
			B: "UPF4",
		},
	},
}

func TestNewUserPlaneInformation(t *testing.T) {
	userplaneInformation := context.NewUserPlaneInformation(configuration)

	require.NotNil(t, userplaneInformation.AccessNetwork["GNodeB"])

	require.NotNil(t, userplaneInformation.UPFs["UPF1"])
	require.NotNil(t, userplaneInformation.UPFs["UPF2"])
	require.NotNil(t, userplaneInformation.UPFs["UPF3"])
	require.NotNil(t, userplaneInformation.UPFs["UPF4"])

	// check links
	require.Contains(t, userplaneInformation.AccessNetwork["GNodeB"].Links, userplaneInformation.UPFs["UPF1"])
	require.Contains(t, userplaneInformation.UPFs["UPF1"].Links, userplaneInformation.UPFs["UPF2"])
	require.Contains(t, userplaneInformation.UPFs["UPF2"].Links, userplaneInformation.UPFs["UPF3"])
	require.Contains(t, userplaneInformation.UPFs["UPF3"].Links, userplaneInformation.UPFs["UPF4"])
}

func TestGenerateDefaultPath(t *testing.T) {
	configuration.Links = []factory.UPLink{
		{
			A: "GNodeB",
			B: "UPF1",
		},
		{
			A: "GNodeB",
			B: "UPF2",
		},
		{
			A: "GNodeB",
			B: "UPF3",
		},
		{
			A: "UPF1",
			B: "UPF4",
		},
	}

	testCases := []struct {
		name     string
		param    *context.UPFSelectionParams
		expected bool
	}{
		{
			"S-NSSAI 01112232 and DNN internet ok",
			&context.UPFSelectionParams{
				SNssai: &context.SNssai{
					Sst: 1,
					Sd:  "112232",
				},
				Dnn: "internet",
			},
			true,
		},
		{
			"S-NSSAI 02112233 and DNN internet ok",
			&context.UPFSelectionParams{
				SNssai: &context.SNssai{
					Sst: 2,
					Sd:  "112233",
				},
				Dnn: "internet",
			},
			true,
		},
		{
			"S-NSSAI 03112234 and DNN internet ok",
			&context.UPFSelectionParams{
				SNssai: &context.SNssai{
					Sst: 3,
					Sd:  "112234",
				},
				Dnn: "internet",
			},
			true,
		},
		{
			"S-NSSAI 01112235 and DNN internet ok",
			&context.UPFSelectionParams{
				SNssai: &context.SNssai{
					Sst: 1,
					Sd:  "112235",
				},
				Dnn: "internet",
			},
			true,
		},
		{
			"S-NSSAI 01010203 and DNN internet fail",
			&context.UPFSelectionParams{
				SNssai: &context.SNssai{
					Sst: 1,
					Sd:  "010203",
				},
				Dnn: "internet",
			},
			false,
		},
	}

	userplaneInformation := context.NewUserPlaneInformation(configuration)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pathExist := userplaneInformation.GenerateDefaultPath(tc.param)
			require.Equal(t, tc.expected, pathExist)
		})
	}
}

func TestUpdateSmfUserPlaneNode_NodeIDChange(t *testing.T) {
	upi := &context.UserPlaneInformation{
		UPNodes:              make(map[string]*context.UPNode),
		UPFs:                 make(map[string]*context.UPNode),
		AccessNetwork:        make(map[string]*context.UPNode),
		UPFIPToName:          make(map[string]string),
		UPFsID:               make(map[string]string),
		UPFsIPtoID:           make(map[string]string),
		DefaultUserPlanePath: make(map[string][]*context.UPNode),
	}

	nodeID := pfcpType.NodeID{
		NodeIdType:  pfcpType.NodeIdTypeIpv4Address,
		NodeIdValue: []byte(net.ParseIP("1.2.3.4").To4()),
	}

	// Create an existing UPNode with a specific UPF instance
	originalUPF := context.NewUPF(&nodeID, nil)
	existingNode := &context.UPNode{
		Type:   "UPF",
		NodeID: nodeID,
		Port:   1234,
		UPF:    originalUPF,
		Links: []*context.UPNode{
			{
				Type: context.UPNODE_AN,
				NodeID: pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv4Address,
					NodeIdValue: []byte(net.ParseIP("5.6.7.8").To4()),
				},
				Port: 0,
			},
		},
	}

	upi.UPNodes["testNode"] = existingNode

	// Create a new UPNode with the same NodeID
	newNode := &factory.UPNode{
		Type:   "UPF",
		NodeID: "1.2.3.4",
		Port:   4321,
		SNssaiInfos: []models.SnssaiUpfInfoItem{
			{
				SNssai: &models.Snssai{
					Sst: 1,
					Sd:  "112235",
				},
				DnnUpfInfoList: []models.DnnUpfInfoItem{
					{Dnn: "internet2"},
				},
			},
		},
	}

	err := upi.UpdateSmfUserPlaneNode("testNode", newNode)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	updatedUPF := upi.UPNodes["testNode"].UPF
	if updatedUPF != originalUPF {
		t.Errorf("Expected UPF instance to remain unchanged, but it was recreated")
	}

	_, upfExists := upi.UPFs["testNode"]
	require.True(t, upfExists)
	if upi.UPFs["testNode"].UPF.SNssaiInfos[0].DnnList[0].Dnn != "internet2" {
		t.Errorf("Expected UPF DNN to be updated")
	}

	updatedUPNode, exists := upi.UPNodes["testNode"]
	if !exists {
		t.Errorf("Expected UPNode to exist")
	}

	if updatedUPNode.Port != 4321 {
		t.Errorf("Expected UPNode port to be updated")
	}

	if updatedUPNode.NodeID.ResolveNodeIdToIp().String() != "1.2.3.4" {
		t.Errorf("Expected UPNode NodeID to be updated")
	}

	if updatedUPNode.Links[0].NodeID.ResolveNodeIdToIp().String() != "5.6.7.8" {
		t.Errorf("Expected UPNode NodeID to be updated")
	}

}
