// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"fmt"

	smf_context "github.com/omec-project/smf/context"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
)

// ErrModificationNotSent marks a modification that never reached the user plane, which is what
// tells a caller its session is untouched. The callers move the session into SmStatePfcpModify
// before calling, and that state has no FSM handlers at all -- so a session left in it answers
// every later event with "unhandled event" and can no longer be modified or released. A session
// whose modification was never sent has to be put back.
var ErrModificationNotSent = errors.New("pfcp session modification was not sent")

// RestoreStateIfNothingWasSent puts a session back where it was before a modification that never
// left the SMF. The caller holds SMLock.
//
// Only for that case. When the user plane answered and refused, or answered nothing at all, what
// it did with the request is not known here, and a session reported active on that evidence would
// be a claim this cannot make.
//
// Through abandonPendingModify, which is this package's existing answer to the same question and
// does the half a state change leaves behind: the pending user-plane entries. An entry for a
// request that was never sent is deleted by no answer, and the modification response handler
// signals the session's channel only once they are all gone -- so leaving one behind means the
// next operation to wait on that channel waits for good. Putting the state back and leaving that
// entry would have traded one indefinite wait for another.
//
// previous has to be the state the session held before the modification sequence began, not the
// one it is in when a failure is noticed: ChangeState returns early on a same-state transition,
// so restoring SmStatePfcpModify to itself is a no-op that reads like a fix.
func RestoreStateIfNothingWasSent(smContext *smf_context.SMContext, previous smf_context.SMContextState, err error) {
	if !errors.Is(err, ErrModificationNotSent) {
		return
	}

	smContext.SubCtxLog.Infof("the modification never reached the user plane; putting the session back in %s", previous)
	abandonPendingModify(smContext, previous)
}

func SendPfcpSessionModifyReq(smContext *smf_context.SMContext, pfcpParam *pfcpParam) error {
	// Read before the send rather than dereferenced through it. A session being torn down while a
	// modification is on its way has no tunnel, and the callers that revert a modification reach
	// here precisely when something has gone wrong -- so the path that exists to put a session
	// back must not be the one that ends the process.
	if smContext.Tunnel == nil {
		return fmt.Errorf("%w: it has no tunnel to send through", ErrModificationNotSent)
	}

	defaultPath := smContext.Tunnel.DataPathPool.GetDefaultPath()
	if defaultPath == nil || defaultPath.FirstDPNode == nil || defaultPath.FirstDPNode.UPF == nil {
		return fmt.Errorf("%w: it has no user plane on its default path", ErrModificationNotSent)
	}

	ANUPF := defaultPath.FirstDPNode

	if err := pfcp_message.SendPfcpSessionModificationRequest(ANUPF.UPF.NodeID, smContext,
		pfcpParam.pdrList, pfcpParam.farList, pfcpParam.barList, pfcpParam.qerList,
		pfcpParam.removePDR, pfcpParam.removeFAR, pfcpParam.removeQER, ANUPF.UPF.Port); err != nil {
		// Returning rather than waiting, whatever failed: the answer that ends the wait is put on
		// the channel by dispatching the user plane's response, and every failure here is a
		// failure to dispatch one. Waiting would wait for a response nobody will send.
		//
		// What differs is what the caller may conclude from it. Only the failures raised before
		// anything went on the wire say the session is untouched. A reply that arrived and could
		// not be read, or a POST the adapter refused after it may already have forwarded the
		// request, say nothing about what the user plane did -- and putting such a session back
		// as though nothing had happened would be asserting it.
		smContext.SubCtxLog.Errorf("pfcp session modification failure: %+v", err)

		if errors.Is(err, pfcp_message.ErrRequestNotSent) {
			return fmt.Errorf("%w: %w", ErrModificationNotSent, err)
		}

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
