// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"maps"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/logger"
)

// RevertOf returns the update that takes a session's user plane from the committed policy with
// abandoned applied back to the committed policy: the rules abandoned added are deleted, the ones
// it deleted are added back, and QoS data it changed is changed back. It is an update to program,
// never one to commit or to tell the UE about -- the UE was never told about abandoned.
//
// Built by diffing, so that it goes through the same builder as any other update. The committed
// policy is not changed.
func RevertOf(committed *SmCtxtPolicyData, abandoned *PolicyUpdate) *PolicyUpdate {
	applied := committed.clone()
	if err := CommitSmPolicyDecision(&applied, abandoned); err != nil {
		// It returns none today; were it to, the revert computed from a partial application would
		// still undo whatever of the modification did apply.
		logger.CtxLog.Errorf("applying the abandoned update to compute its revert: %v", err)
	}

	target := &models.SmPolicyDecision{
		PccRules: backTo(committed.SmCtxtPccRules.PccRules, applied.SmCtxtPccRules.PccRules),
	}
	qosDecs := backTo(committed.SmCtxtQosData.QosData, applied.SmCtxtQosData.QosData)
	target.QosDecs = &qosDecs
	tcDecs := backTo(committed.SmCtxtTCData.TrafficControlData, applied.SmCtxtTCData.TrafficControlData)
	target.TraffContDecs = &tcDecs

	// Session rules are left out. The user plane carries none of them directly, and with none in
	// the update the session rule in force is read from the committed record, which is the one to
	// fall back on when a flow names no rate of its own.
	return BuildSmPolicyUpdate(&applied, target)
}

// backTo is the decision entries that turn applied into committed: each committed entry as it is,
// and an empty one -- which is how a decision says "delete" -- for each entry only applied has.
func backTo[T any](committed, applied map[string]*T) map[string]T {
	out := make(map[string]T, len(committed)+len(applied))
	for name, entry := range committed {
		out[name] = *entry
	}
	for name := range applied {
		if _, kept := committed[name]; !kept {
			var deleted T
			out[name] = deleted
		}
	}
	return out
}

// clone copies the maps, not their entries. Committing an update into the copy assigns and deletes
// entries and never writes through one, so the original is left as it was. A map the original never
// allocated is allocated in the copy: the revert runs on its own goroutine, where writing to a nil
// map takes the SMF down rather than failing one request.
func (obj *SmCtxtPolicyData) clone() SmCtxtPolicyData {
	c := *obj
	c.SmCtxtPccRules.PccRules = cloneOrNew(obj.SmCtxtPccRules.PccRules)
	c.SmCtxtQosData.QosData = cloneOrNew(obj.SmCtxtQosData.QosData)
	c.SmCtxtTCData.TrafficControlData = cloneOrNew(obj.SmCtxtTCData.TrafficControlData)
	c.SmCtxtChargingData.ChargingData = cloneOrNew(obj.SmCtxtChargingData.ChargingData)
	c.SmCtxtCondData.CondData = cloneOrNew(obj.SmCtxtCondData.CondData)
	c.SmCtxtSessionRules.SessionRules = cloneOrNew(obj.SmCtxtSessionRules.SessionRules)
	return c
}

func cloneOrNew[T any](m map[string]*T) map[string]*T {
	if m == nil {
		return make(map[string]*T)
	}
	return maps.Clone(m)
}
