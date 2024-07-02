// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package context

import (
	"fmt"
	"net"
	"time"

	"github.com/omec-project/smf/logger"
)

const (
	NodeIdTypeIpv4Address uint8 = iota
	NodeIdTypeIpv6Address
	NodeIdTypeFqdn
)

type NodeID struct {
	NodeIdValue []byte
	NodeIdType  uint8
}

var dnsHostIpCache map[string]net.IP

func init() {
	dnsHostIpCache = make(map[string]net.IP)
	ticker := time.NewTicker(time.Minute)

	go func() {
		for {
			<-ticker.C
			RefreshDnsHostIpCache()
		}
	}()
}

func NewNodeID(nodeId string) NodeID {
	if ip := net.ParseIP(nodeId); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return NodeID{
				NodeIdValue: v4,
				NodeIdType:  NodeIdTypeIpv4Address,
			}
		} else {
			return NodeID{
				NodeIdValue: ip.To16(),
				NodeIdType:  NodeIdTypeIpv6Address,
			}
		}
	} else {
		return NodeID{
			NodeIdValue: []byte(nodeId),
			NodeIdType:  NodeIdTypeFqdn,
		}
	}
}

func (n *NodeID) ResolveNodeIdToIp() net.IP {
	switch n.NodeIdType {
	case NodeIdTypeIpv4Address, NodeIdTypeIpv6Address:
		return net.IP(n.NodeIdValue)
	case NodeIdTypeFqdn:
		if ip, err := getDnsHostIp(string(n.NodeIdValue)); err != nil {
			logger.PfcpLog.Warnf("host [%v] not found in smf dns cache ", string(n.NodeIdValue))
			if ns, err := net.LookupHost(string(n.NodeIdValue)); err != nil {
				logger.PfcpLog.Warnf("Host lookup failed: %+v", err)
				return net.IPv4zero
			} else {
				logger.PfcpLog.Infof("host [%v] dns resolved, updating smf dns cache ", string(n.NodeIdValue))
				InsertDnsHostIp(string(n.NodeIdValue), net.ParseIP(ns[0]))
				return net.ParseIP(ns[0])
			}
		} else {
			logger.PfcpLog.Debugf("host [%v] found in smf dns cache ", string(n.NodeIdValue))
			return ip
		}
	default:
		return net.IPv4zero
	}
}

func RefreshDnsHostIpCache() {
	for hostName := range dnsHostIpCache {
		logger.PfcpLog.Debugf("refreshing DNS for host [%v] ", hostName)
		if ns, err := net.LookupHost(hostName); err != nil {
			logger.PfcpLog.Warnf("Host lookup failed: %+v", err)
			deleteDnsHost(hostName)
			continue
		} else if !dnsHostIpCache[hostName].Equal(net.ParseIP(ns[0])) {
			logger.PfcpLog.Infof("smf dns cache updated for host [%v]: [%v] ", hostName, net.ParseIP(ns[0]).String())
			dnsHostIpCache[hostName] = net.ParseIP(ns[0])
		}
	}
}

func getDnsHostIp(hostName string) (net.IP, error) {
	if ip, ok := dnsHostIpCache[hostName]; !ok {
		return nil, fmt.Errorf("host [%v] not found in smf dns cache", hostName)
	} else {
		return ip, nil
	}
}

func InsertDnsHostIp(hostName string, ip net.IP) {
	dnsHostIpCache[hostName] = ip
}

func deleteDnsHost(hostName string) {
	delete(dnsHostIpCache, hostName)
}
