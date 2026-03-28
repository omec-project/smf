// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package context

type PCSCFInfo struct {
	IPv4Addr string `yaml:"ipv4,omitempty"`
	IPv6Addr string `yaml:"ipv6,omitempty"`
}
