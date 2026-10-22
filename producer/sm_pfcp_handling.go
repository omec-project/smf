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
var sendModificationRequest = pfcp_message.SendAwaitedPfcpSessionModificationRequest

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
		pfcpParam.removePDR, pfcpParam.removeFAR, pfcpParam.removeQER, ANUPF.UPF.PFCPPort()); err != nil {
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

// RollbackFailedCreate undoes what a create that has failed leaves behind, ahead of the context's
// removal. A create fails as a whole -- one UPF rejected its leg, or one that had accepted its own
// was lost to a restart -- while the UPFs that did accept still hold a PFCP session and forwarding
// rules, and the SMF still holds the PDR, FAR and QER allocations the data path made. Removing the
// context alone drops the only record of both: the SEID mapping goes, so nothing can ever delete the
// accepted sessions, and the allocations are never returned to their UPFs' pools.
//
// It is the release procedure run on a session that never became active: the state moves to
// SmStatePfcpRelease, which is what the deletion response handlers and the send-failure answers are
// gated on, releaseTunnel deactivates the data path and sends the deletions, and the wait for the
// verdict is the same. A leg that holds no session -- the one that rejected -- answers its deletion
// with a refusal, which ends the wait the same way an acceptance does.
//
// Nothing is done for a context with no tunnel (already released, so nothing is held) or one that
// has been purged and replaced: the replacement's own release owns its teardown, and the handlers
// do not answer a purged context's deletions, so waiting on one would never return.
//
// A failed or unanswered deletion is logged and not returned: the create has failed whatever it
// says, and the context is removed either way.
func RollbackFailedCreate(smContext *smf_context.SMContext) {
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	if smContext.Tunnel == nil {
		return
	}
	if smContext.LocalPurged.Load() {
		smContext.SubPfcpLog.Infof("session has been purged and replaced; leaving its teardown to the replacement")
		return
	}

	smContext.ChangeState(smf_context.SmStatePfcpRelease)
	if err := SendPfcpSessionReleaseReq(smContext); err != nil {
		smContext.SubPfcpLog.Warnf("rolling back the failed create: %v", err)
	}
}
