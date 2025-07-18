// SPDX-FileCopyrightText: 2025 Canonical Ltd
// SPDX-License-Identifier: Apache-2.0
//

package context

import (
	"sync"
)

// UERoutingManager manages per-UE preconfigured data paths
type UERoutingManager struct {
	pathPool map[string]*UEPreConfigPaths
	mu       sync.RWMutex
}

func NewUERoutingManager() *UERoutingManager {
	return &UERoutingManager{
		pathPool: make(map[string]*UEPreConfigPaths),
	}
}

func (m *UERoutingManager) AddPath(supi string, paths *UEPreConfigPaths) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pathPool[supi] = paths
}

func (m *UERoutingManager) GetPath(supi string) (*UEPreConfigPaths, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.pathPool[supi]
	return p, ok
}

func (m *UERoutingManager) HasPath(supi string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.pathPool[supi]
	return ok
}
