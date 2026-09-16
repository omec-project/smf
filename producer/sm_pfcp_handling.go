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
	// Read before the send rather than dereferenced through it. A session being torn down while a
	// modification is on its way has no tunnel, and the callers that revert a modification reach
	// here precisely when something has gone wrong -- so the path that exists to put a session
	// back must not be the one that ends the process.
	if smContext.Tunnel == nil {
		return fmt.Errorf("pfcp session modification has no tunnel to send through")
	}

	defaultPath := smContext.Tunnel.DataPathPool.GetDefaultPath()
	if defaultPath == nil || defaultPath.FirstDPNode == nil || defaultPath.FirstDPNode.UPF == nil {
		return fmt.Errorf("pfcp session modification has no user plane on its default path")
	}

	ANUPF := defaultPath.FirstDPNode

	if err := pfcp_message.SendPfcpSessionModificationRequest(ANUPF.UPF.NodeID, smContext,
		pfcpParam.pdrList, pfcpParam.farList, pfcpParam.barList, pfcpParam.qerList,
		pfcpParam.removePDR, pfcpParam.removeFAR, pfcpParam.removeQER, ANUPF.UPF.Port); err != nil {
		// Returning rather than waiting. Every error that function reports is raised before
		// anything can answer: the PFCP context is missing, the request could not be built, the
		// adapter refused it, or the adapter's reply could not be parsed -- and in the adapter
		// case that reply is the only thing that would have signalled this channel. Waiting then
		// waits for a response nobody will send, and this goroutine never returns to undo the
		// modification it was starting.
		smContext.SubCtxLog.Errorf("pfcp session modification failure: %+v", err)

		return fmt.Errorf("pfcp session modification request was not sent: %w", err)
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
