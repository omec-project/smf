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

// sendModificationRequest is the send SendPfcpSessionModifyReq makes, replaceable so a test can have
// the request go out and then hand the caller the user plane's answer.
var sendModificationRequest = pfcp_message.SendPfcpSessionModificationRequest

func SendPfcpSessionModifyReq(smContext *smf_context.SMContext, pfcpParam *pfcpParam) error {
	// Read before the send rather than dereferenced through it. A session being torn down while a
	// modification is on its way has no tunnel, and the callers that revert a modification reach
	// here precisely when something has gone wrong -- so the path that exists to put a session
	// back must not be the one that ends the process.
	//
	// Read once. The policy-update caller drops SMLock before calling this, and release clears the
	// tunnel under that lock, so a check followed by a second read of the field can find it gone
	// between the two -- the guard would narrow the window, not close it.
	tunnel := smContext.Tunnel
	if tunnel == nil {
		return fmt.Errorf("pfcp session modification not sent: it has no tunnel to send through")
	}

	defaultPath := tunnel.DataPathPool.GetDefaultPath()
	if defaultPath == nil || defaultPath.FirstDPNode == nil || defaultPath.FirstDPNode.UPF == nil {
		return fmt.Errorf("pfcp session modification not sent: it has no user plane on its default path")
	}

	ANUPF := defaultPath.FirstDPNode

	if err := sendModificationRequest(ANUPF.UPF.NodeID, smContext,
		pfcpParam.pdrList, pfcpParam.farList, pfcpParam.barList, pfcpParam.qerList,
		pfcpParam.removePDR, pfcpParam.removeFAR, pfcpParam.removeQER, ANUPF.UPF.Port); err != nil {
		// Returning rather than waiting, whatever failed: the answer that ends the wait is put on
		// the channel by dispatching the user plane's response, and every failure here is a
		// failure to dispatch one. Waiting would wait for a response nobody will send.
		smContext.SubCtxLog.Errorf("pfcp session modification failure: %+v", err)

		return fmt.Errorf("pfcp session modification failed: %w", err)
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
