// SPDX-FileCopyrightText: 2022-present Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/omec-project/smf/logger"
)

type IPAllocator struct {
	ipNetwork *net.IPNet
	g         *_IDPool
}

func NewIPAllocator(cidr string) (*IPAllocator, error) {
	allocator := &IPAllocator{}

	if _, ipnet, err := net.ParseCIDR(cidr); err != nil {
		return nil, err
	} else {
		allocator.ipNetwork = ipnet
	}
	allocator.g = newIDPool(1, 1<<int64(32-maskBits(allocator.ipNetwork.Mask))-2)

	return allocator, nil
}

func maskBits(mask net.IPMask) int {
	var cnt int
	for _, b := range mask {
		for b != 0 {
			cnt += int(b & 1)
			b >>= 1
		}
	}
	return cnt
}

// IPAddrWithOffset add offset on base ip
func IPAddrWithOffset(ip net.IP, offset int) net.IP {
	retIP := make(net.IP, len(ip))
	copy(retIP, ip)

	var carry int
	for i := len(retIP) - 1; i >= 0; i-- {
		if offset == 0 {
			break
		}

		val := int(retIP[i]) + carry + offset%256
		retIP[i] = byte(val % 256)
		carry = val / 256

		offset /= 256
	}

	return retIP
}

// IPAddrOffset calculate the input ip with base ip offset
func IPAddrOffset(in, base net.IP) int {
	offset := 0
	exp := 1
	for i := len(base) - 1; i >= 0; i-- {
		offset += int(in[i]-base[i]) * exp
		exp *= 256
	}
	return offset
}

// StaticIpForImsi returns the address configured for imsi in staticIpInfo, or nil for none.
func (a *IPAllocator) StaticIpForImsi(imsi string) net.IP {
	if a.g.staticIps == nil {
		return nil
	}
	ipStr := (*a.g.staticIps)[imsi]
	if ipStr == "" {
		return nil
	}
	return net.ParseIP(ipStr).To4()
}

// Allocate will allocate the IP address and returns it
func (a *IPAllocator) Allocate(imsi string) (net.IP, error) {
	// check if static IP already reserved for this IMSI
	if ip := a.StaticIpForImsi(imsi); ip != nil {
		return ip, nil
	}

	// The offset is the address's place in the pool; nothing is added to it. The old
	// (SMF_COUNT-1)*5000 shift meant a range per instance, but SMF_COUNT counts starts and not
	// instances (see SetupSmfCollection), so it did not survive a restart; nothing bounded it by
	// the pool either, and Release and BlockIp never applied it.
	offset, err := a.g.allocate()
	if err != nil {
		return nil, fmt.Errorf("ip allocation failed: %w", err)
	}

	ip := IPAddrWithOffset(a.ipNetwork.IP, int(offset))
	logger.CtxLog.Infof("allocated UE address %v, offset %v in pool %v", ip, offset, a.ipNetwork)

	return ip, nil
}

func (a *IPAllocator) ReserveStaticIps(ips *map[string]string) {
	a.g.staticIps = ips
	for _, ipStr := range *ips {
		if ip := net.ParseIP(ipStr).To4(); ip != nil {
			// block static IPs in pool to avoid dynamic allocation
			a.BlockIp(ip)
		}
	}
}

func (a *IPAllocator) BlockIp(ip net.IP) {
	offset := IPAddrOffset(ip, a.ipNetwork.IP)
	a.g.block(int64(offset))
}

func (a *IPAllocator) Release(imsi string, ip net.IP) {
	// Don't release static IPs
	if a.StaticIpForImsi(imsi) != nil {
		return
	}

	offset := IPAddrOffset(ip, a.ipNetwork.IP)
	a.g.release(int64(offset))
}

type _IDPool struct {
	staticIps *map[string]string // map of [imsi]ip
	isUsed    map[int64]bool
	minValue  int64
	maxValue  int64
	index     int64
	lock      sync.Mutex
}

func newIDPool(minValue int64, maxValue int64) (idPool *_IDPool) {
	idPool = new(_IDPool)
	idPool.minValue = minValue
	idPool.maxValue = maxValue
	idPool.isUsed = make(map[int64]bool)
	idPool.index = 1
	return
}

func (i *_IDPool) allocate() (id int64, err error) {
	i.lock.Lock()
	defer i.lock.Unlock()

	for id = i.index; id <= i.maxValue; id++ {
		if _, exist := i.isUsed[id]; !exist {
			i.isUsed[id] = true
			i.index = (id % i.maxValue) + 1
			return id, nil
		}
	}

	for id = 1; id < i.index; id++ {
		if _, exist := i.isUsed[id]; !exist {
			i.isUsed[id] = true
			i.index = id + 1
			return id, nil
		}
	}

	return 0, errors.New("no available value range to allocate id")
}

func (i *_IDPool) block(id int64) {
	i.lock.Lock()
	defer i.lock.Unlock()
	i.isUsed[id] = true
}

func (i *_IDPool) release(id int64) {
	i.lock.Lock()
	defer i.lock.Unlock()
	delete(i.isUsed, id)
}
