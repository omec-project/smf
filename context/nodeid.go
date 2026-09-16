// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package context

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
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
	NodeIdType  uint8 // 0x00001111
}

// dnsHostIpCacheMu guards dnsHostIpCache and dnsHostIpGen: they're read/written from
// PFCP/session handling goroutines (via ResolveNodeIdToIp) and from the periodic refresh
// goroutine below. dnsHostIpGen counts writes (inserts, refresh updates, and refresh
// deletes) per host, so a refresh that ran without the lock held can tell whether the
// entry it observed was touched by someone else in the meantime, even if that other
// write happened to land on the same value or removed the entry outright.
var (
	dnsHostIpCache   map[string]net.IP
	dnsHostIpGen     map[string]uint64
	dnsHostIpCacheMu sync.RWMutex
)

func NewNodeID(nodeID string) *NodeID {
	ip := net.ParseIP(nodeID)
	if ip == nil {
		return &NodeID{
			NodeIdType:  NodeIdTypeFqdn,
			NodeIdValue: []byte(nodeID),
		}
	} else if ip.To4() != nil {
		return &NodeID{
			NodeIdType:  NodeIdTypeIpv4Address,
			NodeIdValue: ip.To4(),
		}
	} else {
		return &NodeID{
			NodeIdType:  NodeIdTypeIpv6Address,
			NodeIdValue: ip.To16(),
		}
	}
}

func (n *NodeID) Equal(other NodeID) bool {
	if n.NodeIdType != other.NodeIdType {
		return false
	}
	return bytes.Equal(n.NodeIdValue, other.NodeIdValue)
}

func (n *NodeID) ResolveNodeIdToIp() net.IP {
	switch n.NodeIdType {
	case NodeIdTypeIpv4Address, NodeIdTypeIpv6Address:
		return n.NodeIdValue
	case NodeIdTypeFqdn:
		if ip, err := getDnsHostIp(string(n.NodeIdValue)); err != nil {
			logger.CtxLog.Warnf("host [%v] not found in smf dns cache", string(n.NodeIdValue))
			resolver := net.Resolver{}
			ns, err := resolver.LookupHost(context.Background(), string(n.NodeIdValue))
			if err != nil {
				logger.CtxLog.Warnf("host lookup failed: %+v", err)
				return net.IPv4zero
			} else {
				logger.CtxLog.Infof("host [%v] dns resolved, updating smf dns cache", string(n.NodeIdValue))
				InsertDnsHostIp(string(n.NodeIdValue), net.ParseIP(ns[0]))
				return net.ParseIP(ns[0])
			}
		} else {
			logger.CtxLog.Debugf("host [%v] found in smf dns cache", string(n.NodeIdValue))
			return ip
		}
	default:
		return net.IPv4zero
	}
}

// ResolveNodeIdToIpCached returns the currently known IP for the NodeID without ever
// triggering a synchronous DNS lookup: for an FQDN it returns the cached value (nil on a
// cache miss) instead of resolving on demand. Callers that can tolerate a stale/empty
// result (e.g. informational Kafka events) should prefer this over ResolveNodeIdToIp so a
// slow or unresponsive resolver can't block them.
func (n *NodeID) ResolveNodeIdToIpCached() net.IP {
	switch n.NodeIdType {
	case NodeIdTypeIpv4Address, NodeIdTypeIpv6Address:
		return n.NodeIdValue
	case NodeIdTypeFqdn:
		if ip, err := getDnsHostIp(string(n.NodeIdValue)); err == nil {
			return ip
		}
		return nil
	default:
		return nil
	}
}

func init() {
	dnsHostIpCache = make(map[string]net.IP)
	dnsHostIpGen = make(map[string]uint64)
	ticker := time.NewTicker(time.Minute)

	go func() {
		for {
			<-ticker.C
			RefreshDnsHostIpCache()
		}
	}()
}

func RefreshDnsHostIpCache() {
	dnsHostIpCacheMu.RLock()
	// Snapshot the generation alongside each host, not just its value: the lookups below
	// run without the lock held (so a slow/stuck resolver can't stall every other cache
	// reader, e.g. the Kafka publish path), and RefreshDnsHostIpCache can itself be called
	// concurrently (e.g. also triggered on PFCP send failure). Comparing the generation
	// on write - rather than comparing the resolved value - means this only applies its
	// result if nothing else touched the entry since it was observed, whether that other
	// write landed on the same value, a different one, or removed the entry outright; a
	// value-only comparison would let a failed lookup here delete an entry a concurrent
	// successful refresh had just installed.
	observed := make(map[string]uint64, len(dnsHostIpCache))
	for hostName := range dnsHostIpCache {
		observed[hostName] = dnsHostIpGen[hostName]
	}
	dnsHostIpCacheMu.RUnlock()

	for hostName, observedGen := range observed {
		logger.CtxLog.Debugf("refreshing DNS for host [%v]", hostName)
		resolver := net.Resolver{}
		ns, err := resolver.LookupHost(context.Background(), hostName)
		if err != nil {
			logger.CtxLog.Warnf("host lookup failed: %+v", err)
			dnsHostIpCacheMu.Lock()
			if dnsHostIpGen[hostName] == observedGen {
				// The generation is never reclaimed, only ever incremented: deleting it would
				// let it read back as 0, and a later InsertDnsHostIp starting a host over from
				// generation 1 could then collide with a generation this (or another slow,
				// stale) refresh had already observed before the eviction, letting a stale
				// result overwrite a newer insert it was never compared against.
				delete(dnsHostIpCache, hostName)
				dnsHostIpGen[hostName]++
			}
			dnsHostIpCacheMu.Unlock()
			continue
		}
		newIP := net.ParseIP(ns[0])
		dnsHostIpCacheMu.Lock()
		if dnsHostIpGen[hostName] == observedGen {
			if !dnsHostIpCache[hostName].Equal(newIP) {
				logger.CtxLog.Infof("smf dns cache updated for host [%v]: [%v]", hostName, newIP.String())
				dnsHostIpCache[hostName] = newIP
			}
			dnsHostIpGen[hostName]++
		}
		dnsHostIpCacheMu.Unlock()
	}
}

func getDnsHostIp(hostName string) (net.IP, error) {
	dnsHostIpCacheMu.RLock()
	defer dnsHostIpCacheMu.RUnlock()
	if ip, ok := dnsHostIpCache[hostName]; !ok {
		return nil, fmt.Errorf("host [%v] not found in smf dns cache", hostName)
	} else {
		return ip, nil
	}
}

func InsertDnsHostIp(hostName string, ip net.IP) {
	dnsHostIpCacheMu.Lock()
	defer dnsHostIpCacheMu.Unlock()
	dnsHostIpCache[hostName] = ip
	dnsHostIpGen[hostName]++
}
