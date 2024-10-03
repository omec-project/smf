// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"fmt"

	smf_context "github.com/omec-project/smf/context"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
)

func SendPfcpSessionModifyReq(smContext *smf_context.SMContext, pfcpParam *pfcpParam) error {
	defaultPath := smContext.Tunnel.DataPathPool.GetDefaultPath()
	ANUPF := defaultPath.FirstDPNode
	err := pfcp_message.SendPfcpSessionModificationRequest(ANUPF.UPF.NodeID, smContext,
		pfcpParam.pdrList, pfcpParam.farList, pfcpParam.barList, pfcpParam.qerList, ANUPF.UPF.Port)
	if err != nil {
		smContext.SubCtxLog.Errorf("pfcp session modification failure: %+v", err)
	}

	PFCPResponseStatus := <-smContext.SBIPFCPCommunicationChan

	switch PFCPResponseStatus {
	case smf_context.SessionUpdateSuccess:
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, PFCP Session Update Success")

	case smf_context.SessionUpdateFailed:
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, PFCP Session Update Failed")
		fallthrough
	case smf_context.SessionUpdateTimeout:
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, PFCP Session Modification Timeout")

		err := fmt.Errorf("pfcp modification failure")
		return err
	}

	return nil
}

func SendPfcpSessionReleaseReq(smContext *smf_context.SMContext) error {
	// release UPF data tunnel
	releaseTunnel(smContext)

	PFCPResponseStatus := <-smContext.SBIPFCPCommunicationChan
	switch PFCPResponseStatus {
	case smf_context.SessionReleaseSuccess:
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, PFCP Session Release Success")
		return nil
	case smf_context.SessionReleaseTimeout:
		smContext.SubCtxLog.Errorln("PDUSessionSMContextUpdate, PFCP Session Release Failed")
		return fmt.Errorf("pfcp session release timeout")
	case smf_context.SessionReleaseFailed:
		smContext.SubCtxLog.Errorln("PDUSessionSMContextUpdate, PFCP Session Release Failed")
		return fmt.Errorf("pfcp session release failed")
	}
	return nil
}
