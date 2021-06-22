// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package context

import (
	"github.com/free5gc/flowdesc"
	"github.com/free5gc/smf/logger"
	"reflect"
)

type BPManager struct {
	BPStatus       BPStatus
	AddingPSAState AddingPSAState
	// Need these variable conducting Add additional PSA (TS23.502 4.3.5.4)
	// There value will change from time to time

	PendingUPF            PendingUPF
	ActivatedPaths        []*DataPath
	ActivatingPath        *DataPath
	UpdatedBranchingPoint map[*UPF]int
	ULCL                  *UPF
}
type BPStatus int

const (
	UnInitialized BPStatus = iota
	AddingPSA
	AddPSASuccess
	InitializedSuccess
	InitializedFail
)

type AddingPSAState int

const (
	ActivatingDataPath AddingPSAState = iota
	EstablishingNewPSA
	EstablishingULCL
	UpdatingPSA2DownLink
	UpdatingRANAndIUPFUpLink
	Finished
)

type PendingUPF map[string]bool

func NewBPManager(supi string) (bpManager *BPManager) {
	bpManager = &BPManager{
		BPStatus:              UnInitialized,
		AddingPSAState:        ActivatingDataPath,
		ActivatedPaths:        make([]*DataPath, 0),
		UpdatedBranchingPoint: make(map[*UPF]int),
		PendingUPF:            make(PendingUPF),
	}

	return
}

func (bpMGR *BPManager) SelectPSA2DataPath(flowDesc string, smContext *SMContext) {
	flow_Desc := flowdesc.NewIPFilterRule()
	err := flowdesc.Decode(flowDesc, flow_Desc)
	if err != nil {
		logger.PduSessLog.Errorf("Invalid flow Description: %s\n", err)
	}

	hasSelectPSA2 := false
	bpMGR.ActivatedPaths = []*DataPath{}
	for _, dataPath := range smContext.Tunnel.DataPathPool {

		if dataPath.Activated {
			bpMGR.ActivatedPaths = append(bpMGR.ActivatedPaths, dataPath)
		}
		if !hasSelectPSA2 {
			if dataPath.Destination.DestinationIP == flow_Desc.GetDestinationIP() && dataPath.Destination.DestinationPort == flow_Desc.GetDestinationPorts() {
				// changing the datapath acitvated to false. To override the pre-configured path to AF requested path
				dataPath.Activated = false
				bpMGR.ActivatingPath = dataPath
				hasSelectPSA2 = true
			}
		}
	}

	// if no path is matched, add the new path for requested flow.
	if !hasSelectPSA2 {
		logger.PduSessLog.Traceln("create new data path")
		// Create DataPath for the input flow discription.
		dataPath := GenerateDataPathForIUPF(bpMGR.ULCL, smContext)
		dataPath.Destination.DestinationIP = flow_Desc.GetDestinationIP()
		dataPath.Destination.DestinationPort = flow_Desc.GetDestinationPorts()
		dataPath.IsDefaultPath = false
		smContext.Tunnel.AddDataPath(dataPath)
		bpMGR.ActivatingPath = dataPath
		hasSelectPSA2 = true
	}
}

func (bpMGR *BPManager) SelectPSA2(smContext *SMContext) {
	hasSelectPSA2 := false
	bpMGR.ActivatedPaths = []*DataPath{}
	for _, dataPath := range smContext.Tunnel.DataPathPool {
		if dataPath.Activated {
			bpMGR.ActivatedPaths = append(bpMGR.ActivatedPaths, dataPath)
		} else {
			if !hasSelectPSA2 {
				bpMGR.ActivatingPath = dataPath
				hasSelectPSA2 = true
			}
		}
	}
}

func (bpMGR *BPManager) FindULCL(smContext *SMContext) error {
	bpMGR.UpdatedBranchingPoint = make(map[*UPF]int)
	activatingPath := bpMGR.ActivatingPath
	for _, psa1Path := range bpMGR.ActivatedPaths {
		depth := 0
		psa1CurDPNode := psa1Path.FirstDPNode
		for psa2CurDPNode := activatingPath.FirstDPNode; psa2CurDPNode != nil; psa2CurDPNode = psa2CurDPNode.Next() {
			if reflect.DeepEqual(psa2CurDPNode.UPF.NodeID, psa1CurDPNode.UPF.NodeID) {
				psa1CurDPNode = psa1CurDPNode.Next()
				depth++

				if _, exist := bpMGR.UpdatedBranchingPoint[psa2CurDPNode.UPF]; !exist {
					bpMGR.UpdatedBranchingPoint[psa2CurDPNode.UPF] = depth
				}
			} else {
				break
			}
		}
	}

	maxDepth := 0
	for upf, depth := range bpMGR.UpdatedBranchingPoint {
		if depth > maxDepth {
			bpMGR.ULCL = upf
			maxDepth = depth
		}
	}
	return nil
}

func (pendingUPF PendingUPF) IsEmpty() bool {
	if len(pendingUPF) == 0 {
		return true
	} else {
		return false
	}
}
