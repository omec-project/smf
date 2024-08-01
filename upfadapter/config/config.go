// SPDX-FileCopyrightText: 2022-present Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package config

import (
	"bytes"
	"net"
	"os"
	"sync"
	"time"

	"upf-adapter/logger"
	"upf-adapter/types"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type UPFStatus int

const MaxUpfProbeRetryInterval time.Duration = 5 // Seconds

var UpfCfg Config

const (
	NotAssociated          UPFStatus = 0
	AssociatedSettingUp    UPFStatus = 1
	AssociatedSetUpSuccess UPFStatus = 2
)

// UPF structure
type UPNode struct {
	UpfName     string
	NodeID      types.NodeID
	ANIP        net.IP
	State       UPFStatus
	LastAssoRsp message.AssociationSetupResponse
	LastHBRsp   message.HeartbeatResponse
	UpfLock     sync.RWMutex
}

// All UPF nodes
type Config struct {
	UpfListLock sync.RWMutex
	UPFs        map[string]*UPNode
}

type UdpPodMsgType int

type adapterMessage struct {
	Body []byte `json:"body"`
}

type UdpPodPfcpMsg struct {
	SmfIp    string       `json:"smfIp"`
	UpNodeID types.NodeID `json:"upNodeID"`
	// message type contains in Msg.Header
	Msg  adapterMessage `json:"pfcpMsg"`
	Addr *net.UDPAddr   `json:"addr"`
}

type PfcpHttpRsp struct {
	Rsp []byte
	Err error
}

type PfcpTxnChan chan PfcpHttpRsp

var (
	UpfTxns      map[uint32]PfcpTxnChan
	UpfTxnsMutex = sync.RWMutex{}
)

var (
	UpfAdapterIp       net.IP
	UpfServerStartTime time.Time
)

func init() {
	podIpStr := os.Getenv("POD_IP")
	podIp := net.ParseIP(podIpStr)
	UpfAdapterIp = podIp.To4()

	UpfCfg = Config{
		UPFs: make(map[string]*UPNode),
	}

	UpfTxns = make(map[uint32]PfcpTxnChan)
}

// BuildPfcpHeartbeatRequest shall trigger hearbeat request to all Attached UPFs
func BuildPfcpHeartbeatRequest() (*message.HeartbeatRequest, error) {
	msg := message.NewHeartbeatRequest(
		0,
		ie.NewRecoveryTimeStamp(UpfServerStartTime),
		nil,
	)
	return msg, nil
}

func IsUpfAssociated(nodeId types.NodeID) bool {
	UpfCfg.UpfListLock.RLock()
	defer UpfCfg.UpfListLock.RUnlock()

	logger.CfgLog.Debugf("associated upfs: [ %v]", UpfCfg.UPFs)

	if upf := UpfCfg.UPFs[string(nodeId.NodeIdValue)]; upf != nil {
		if upf.State == AssociatedSetUpSuccess {
			logger.CfgLog.Debugf("upf:[%v] associated", string(nodeId.NodeIdValue))
			return true
		}
		logger.CfgLog.Debugf("upf:[%v] not associated", string(nodeId.NodeIdValue))
		return false
	}

	logger.CfgLog.Debugf("upf:[%v] not configured yet", string(nodeId.NodeIdValue))
	return false
}

func GetUpfFromNodeId(nodeId *types.NodeID) *UPNode {
	UpfCfg.UpfListLock.RLock()
	defer UpfCfg.UpfListLock.RUnlock()

	logger.CfgLog.Debugf("getting upf from node id [%v] ", nodeId)
	logger.CfgLog.Debugf("content of upf config [%v] ", UpfCfg.UPFs)

	for _, upf := range UpfCfg.UPFs {
		if nodeId.NodeIdType == types.NodeIdTypeIpv4Address {
			if bytes.Equal(upf.ANIP.To4(), nodeId.NodeIdValue) {
				logger.CfgLog.Debugf("getting upf from node id, ip-addr [%v, %v] successful", nodeId, upf.ANIP.To4())
				return upf
			}
		} else if nodeId.NodeIdType == types.NodeIdTypeFqdn &&
			upf.NodeID.NodeIdType == types.NodeIdTypeFqdn {
			if bytes.Equal(nodeId.NodeIdValue, upf.NodeID.NodeIdValue) {
				logger.CfgLog.Debugf("getting upf from node id, fqdn [%v, %v] successful", nodeId, nodeId.NodeIdValue)
				return upf
			}
		}
	}
	logger.CfgLog.Errorf("getting upf from node id [%v] failure", nodeId)
	return nil
}

func InsertUpfNode(nodeId types.NodeID) {
	UpfCfg.UpfListLock.Lock()
	defer UpfCfg.UpfListLock.Unlock()

	// if UPF is already not added
	if _, ok := UpfCfg.UPFs[string(nodeId.NodeIdValue)]; !ok {

		upf := UPNode{
			UpfName: string(nodeId.NodeIdValue),
			State:   NotAssociated,
			NodeID:  nodeId,
			ANIP:    nodeId.ResolveNodeIdToIp(),
		}
		UpfCfg.UPFs[string(nodeId.NodeIdValue)] = &upf
		logger.CfgLog.Infof("inserting upf node [%v] ", string(nodeId.NodeIdValue))
	}
}

func ActivateUpfNode(nodeId *types.NodeID) *UPNode {
	logger.CfgLog.Infof("activating upf node [%v]", nodeId)
	if upf := GetUpfFromNodeId(nodeId); upf != nil {
		UpfCfg.UpfListLock.Lock()
		upf.State = AssociatedSetUpSuccess
		UpfCfg.UpfListLock.Unlock()
		return upf
	}
	logger.CfgLog.Errorf("upf node [%v] not found ", nodeId)
	return nil
}

func RemoveUpfNode(upfName string) {
	UpfCfg.UpfListLock.Lock()
	defer UpfCfg.UpfListLock.Unlock()

	if upf, ok := UpfCfg.UPFs[upfName]; ok {
		delete(UpfCfg.UPFs, upf.UpfName)
		logger.CfgLog.Infof("deleting upf node [%v] ", upf.UpfName)
	}
}

func InsertUpfPfcpTxn(seq uint32, pfcpTxnChan PfcpTxnChan) {
	logger.CfgLog.Debugf(" inserting transaction with sequence number [%v]", seq)
	UpfTxnsMutex.Lock()
	UpfTxns[seq] = pfcpTxnChan
	UpfTxnsMutex.Unlock()
}

func GetUpfPfcpTxn(seq uint32) PfcpTxnChan {
	UpfTxnsMutex.Lock()
	defer UpfTxnsMutex.Unlock()
	pfcpTxnChan := UpfTxns[seq]
	if pfcpTxnChan != nil {
		delete(UpfTxns, seq)
		logger.CfgLog.Debugf("fetch transaction with sequence number [%v] successful", seq)
		return pfcpTxnChan
	}
	logger.CfgLog.Errorf("fetch transaction with sequence number [%v] failure", seq)

	return nil
}

func (upf *UPNode) PreservePfcpAssociationRsp(pfcpRspBody message.AssociationSetupResponse) {
	// find the UPF
	logger.CfgLog.Debugf("storing pfcp association response for upf [%v] ", upf)
	upf.UpfLock.Lock()
	defer upf.UpfLock.Unlock()
	upf.LastAssoRsp = pfcpRspBody
}

func (upf *UPNode) PreservePfcpHeartBeatRsp(pfcpRspBody message.HeartbeatResponse) {
	// find the UPF
	logger.CfgLog.Debugf("storing pfcp heartbeat response for upf [%v] ", upf)
	upf.UpfLock.Lock()
	defer upf.UpfLock.Unlock()
	upf.LastHBRsp = pfcpRspBody
}
