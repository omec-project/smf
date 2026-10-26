// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package context_test

import (
	"net"
	"testing"

	smf_context "github.com/omec-project/smf/context"
)

func TestIPPoolAlloc(t *testing.T) {
	allocator, err := smf_context.NewIPAllocator("192.168.1.0/24")
	if err != nil {
		t.Errorf("failed to allocate pool %v", err)
	}

	var allocAddresses []string
	// check if we can allocate 254 addresses
	for i := 1; i <= 254; i++ {
		ip, err := allocator.Allocate("")
		if err != nil {
			t.Errorf("failed to allocate pool %v", err)
		}
		t.Logf("allocated address = %v", ip)
		allocAddresses = append(allocAddresses, ip.String())
	}

	// Test what happens if we releae all addresses
	for _, ips := range allocAddresses {
		ip := net.ParseIP(ips)
		allocator.Release("", ip)
	}

	// Check what happens if we try to release unknown address
	ip := net.ParseIP("192.168.2.1")
	allocator.Release("", ip)
}

func TestIPPoolAllocRelease(t *testing.T) {
	allocator, err := smf_context.NewIPAllocator("192.168.1.0/24")
	if err != nil {
		t.Errorf("failed to allocate pool %v", err)
	}

	ip1 := net.ParseIP("192.168.1.1")
	for i := 1; i <= 255; i++ {
		ip, err := allocator.Allocate("")
		if err != nil {
			t.Errorf("failed to allocate pool %v", err)
		}
		t.Logf("allocated address = %v", ip)
		if i == 1 {
			if ip.Equal(ip1) == false {
				t.Errorf("address not allocated in order ? allocated address %v", ip1)
			}
			allocator.Release("", ip)
		}
		if i == 2 {
			ip2 := net.ParseIP("192.168.1.2")
			if ip.Equal(ip2) == false {
				t.Errorf("address not allocated in order ? allocated address %v", ip2)
			}
		}
		// rollover, we should be using first address again
		if i == 255 && ip.Equal(ip1) != true {
			t.Errorf("Failed to allocate IP address = %v %v \n", ip, ip1)
		}
	}
}

func TestIPPoolAllocLeastRecentlyUsed(t *testing.T) {
	allocator, err := smf_context.NewIPAllocator("192.168.1.0/24")
	if err != nil {
		t.Errorf("failed to allocate pool %v", err)
	}

	ip1, err := allocator.Allocate("")
	if err != nil {
		t.Errorf("failed to allocate pool %v", err)
	}
	t.Logf("allocated address = %v", ip1)
	allocator.Release("", ip1)
	ip2, err := allocator.Allocate("")
	if err != nil {
		t.Errorf("failed to allocate pool %v", err)
	}
	t.Logf("allocated address = %v", ip2)

	// Same address is not allocate again..
	if ip1.Equal(ip2) {
		t.Errorf("ip1 %v & ip2 %v same ", ip1, ip2)
	}
}

// SMF_COUNT is the "smfCount" counter, incremented once per start with enableDbStore set.
const restartedSmfCount = "3"

// Each restart used to move the whole range further out of the subnet: on a 192.168.100.0/24 pool
// the third start allocated 192.168.139.17 and up, which no route or NAT rule for the pool covers.
func TestAllocationStaysInThePoolAfterRestarts(t *testing.T) {
	const pool = "192.168.100.0/24"

	t.Setenv("SMF_COUNT", restartedSmfCount)

	allocator, err := smf_context.NewIPAllocator(pool)
	if err != nil {
		t.Fatalf("NewIPAllocator(%q): %v", pool, err)
	}

	_, ipNet, err := net.ParseCIDR(pool)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", pool, err)
	}

	for i := 1; i <= 254; i++ {
		ip, err := allocator.Allocate("")
		if err != nil {
			t.Fatalf("allocation %d of a pool of 254: %v", i, err)
		}
		if !ipNet.Contains(ip) {
			t.Fatalf("allocation %d is %v, outside the configured pool %s", i, ip, pool)
		}
	}
}

// The first address of the pool belongs to the first session, restarts or not.
func TestARestartDoesNotMoveTheStartOfThePool(t *testing.T) {
	t.Setenv("SMF_COUNT", restartedSmfCount)

	allocator, err := smf_context.NewIPAllocator("192.168.100.0/24")
	if err != nil {
		t.Fatalf("NewIPAllocator: %v", err)
	}

	ip, err := allocator.Allocate("")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	if want := net.IPv4(192, 168, 100, 1).To4(); !ip.Equal(want) {
		t.Errorf("first allocation is %v, want %v", ip, want)
	}
}

// The shift made Allocate and Release disagree about what an offset means, so a release freed an
// id that had never been handed out and the one in use stayed held. A pool of two then runs out.
func TestAReleasedAddressIsAllocatedAgainAfterRestarts(t *testing.T) {
	t.Setenv("SMF_COUNT", restartedSmfCount)

	allocator, err := smf_context.NewIPAllocator("192.168.100.0/30")
	if err != nil {
		t.Fatalf("NewIPAllocator: %v", err)
	}

	first, err := allocator.Allocate("imsi-1")
	if err != nil {
		t.Fatalf("first allocation: %v", err)
	}
	if _, err := allocator.Allocate("imsi-2"); err != nil {
		t.Fatalf("second allocation: %v", err)
	}

	allocator.Release("imsi-1", first)

	if _, err := allocator.Allocate("imsi-3"); err != nil {
		t.Errorf("allocation after %v was released: %v", first, err)
	}
}

// Every method of an allocator with no pool panicked before; see IPAllocator for the two ways a
// caller comes to hold one.
func TestIPAllocatorWithNoPool(t *testing.T) {
	const imsi = "imsi-208930100007487"

	for name, allocator := range map[string]*smf_context.IPAllocator{
		"nil allocator":      nil,
		"restored allocator": {},
	} {
		t.Run(name, func(t *testing.T) {
			ip, err := allocator.Allocate(imsi)
			if err == nil {
				t.Errorf("Allocate returned %v and no error", ip)
			}
			if ip != nil {
				t.Errorf("Allocate returned address %v alongside its error", ip)
			}

			allocator.Release(imsi, net.ParseIP("192.168.1.5"))
			allocator.BlockIp(net.ParseIP("192.168.1.6"))
			static := map[string]string{imsi: "192.168.1.7"}
			allocator.ReserveStaticIps(&static)
		})
	}
}
