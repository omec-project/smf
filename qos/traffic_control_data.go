// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos

import "github.com/omec-project/openapi/models"

type TrafficControlUpdate struct {
	add, mod, del map[string]*models.TrafficControlData
}

func GetTrafficControlUpdate(tcData, ctxtTcData map[string]*models.TrafficControlData) *TrafficControlUpdate {
	if len(tcData) == 0 {
		return nil
	}

	change := TrafficControlUpdate{
		add: make(map[string]*models.TrafficControlData),
		mod: make(map[string]*models.TrafficControlData),
		del: make(map[string]*models.TrafficControlData),
	}

	// Compare against Ctxt rules to get added or modified rules
	for name, pcfTc := range tcData {
		// if pcfRule is nil then it need to be deleted
		if pcfTc == nil {
			change.del[name] = pcfTc // nil
			continue
		}

		// match against SM ctxt Rules for add/mod
		if ctxtTc := ctxtTcData[name]; ctxtTc == nil {
			change.add[name] = pcfTc
		} else if GetTCDataChanges(pcfTc, ctxtTc) {
			change.mod[name] = pcfTc
		}
	}

	return &change
}

func CommitTrafficControlUpdate(smCtxtPolData *SmCtxtPolicyData, update *TrafficControlUpdate) {
	// Iterate through Add/Mod/Del TC

	// Add new tc
	if len(update.add) > 0 {
		for name, tc := range update.add {
			smCtxtPolData.SmCtxtTCData.TrafficControlData[name] = tc
		}
	}

	// Mod rules
	// TODO

	// Del Rules
	if len(update.del) > 0 {
		for name := range update.del {
			delete(smCtxtPolData.SmCtxtTCData.TrafficControlData, name)
		}
	}
}

func GetTCDataChanges(pcfTc, ctxtTc *models.TrafficControlData) bool {
	if pcfTc == nil || ctxtTc == nil {
		return true
	}

	if pcfTc.TcId != ctxtTc.TcId ||
		pcfTc.FlowStatus != ctxtTc.FlowStatus ||
		pcfTc.MuteNotif != ctxtTc.MuteNotif ||
		pcfTc.TrafficSteeringPolIdDl != ctxtTc.TrafficSteeringPolIdDl ||
		pcfTc.TrafficSteeringPolIdUl != ctxtTc.TrafficSteeringPolIdUl {
		return true
	}

	if !compareRedirectInfo(pcfTc.RedirectInfo, ctxtTc.RedirectInfo) {
		return true
	}

	if !compareRouteToLocations(pcfTc.RouteToLocs, ctxtTc.RouteToLocs) {
		return true
	}

	if !compareUpPathChgEvent(pcfTc.UpPathChgEvent, ctxtTc.UpPathChgEvent) {
		return true
	}

	return false
}

func compareRedirectInfo(a, b *models.RedirectInformation) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	return a.RedirectEnabled == b.RedirectEnabled &&
		a.RedirectAddressType == b.RedirectAddressType &&
		a.RedirectServerAddress == b.RedirectServerAddress
}

func compareRouteToLocations(a, b []models.RouteToLocation) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i].Dnai != b[i].Dnai ||
			a[i].RouteProfId != b[i].RouteProfId ||
			!compareRouteInformation(a[i].RouteInfo, b[i].RouteInfo) {
			return false
		}
	}
	return true
}

func compareRouteInformation(a, b *models.RouteInformation) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	return a.Ipv4Addr == b.Ipv4Addr &&
		a.Ipv6Addr == b.Ipv6Addr &&
		a.PortNumber == b.PortNumber
}

func compareUpPathChgEvent(a, b *models.UpPathChgEvent) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.NotificationUri == b.NotificationUri &&
		a.NotifCorreId == b.NotifCorreId &&
		a.DnaiChgType == b.DnaiChgType
}

func GetTcDataFromPolicyDecision(smPolicyDecision *models.SmPolicyDecision, refTcData string) *models.TrafficControlData {
	return smPolicyDecision.TraffContDecs[refTcData]
}
