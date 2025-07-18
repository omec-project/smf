package context

import (
	"testing"

	"github.com/omec-project/util/idgenerator"
)

func pathsEqual(a, b *UEPreConfigPaths) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.DataPathPool) != len(b.DataPathPool) {
		return false
	}
	for id, aPath := range a.DataPathPool {
		bPath, ok := b.DataPathPool[id]
		if !ok {
			return false
		}
		if string(aPath.FirstDPNode.UPF.NodeID.NodeIdValue) != string(bPath.FirstDPNode.UPF.NodeID.NodeIdValue) {
			return false
		}
	}
	return true
}

func TestUERoutingManager(t *testing.T) {
	type testCase struct {
		name       string
		preload    map[string]*UEPreConfigPaths
		querySUPI  string
		expectPath *UEPreConfigPaths
		expectOK   bool
		setup      func(mgr *UERoutingManager)
	}

	paths1 := &UEPreConfigPaths{
		DataPathPool: DataPathPool{
			1: &DataPath{
				FirstDPNode: &DataPathNode{
					UPF: &UPF{
						NodeID: NodeID{
							NodeIdValue: []byte("upf-1"),
						},
					},
				},
			},
		},
		PathIDGenerator: idgenerator.NewGenerator(1, 100),
	}

	paths2 := &UEPreConfigPaths{
		DataPathPool: DataPathPool{
			1: &DataPath{
				FirstDPNode: &DataPathNode{
					UPF: &UPF{
						NodeID: NodeID{
							NodeIdValue: []byte("upf-2"),
						},
					},
				},
			},
		},
		PathIDGenerator: idgenerator.NewGenerator(1, 100),
	}
	paths3 := &UEPreConfigPaths{}
	tests := []testCase{
		{
			name:       "Path exists",
			preload:    map[string]*UEPreConfigPaths{"imsi-001": paths1},
			querySUPI:  "imsi-001",
			expectPath: paths1,
			expectOK:   true,
		},
		{
			name:       "Path does not exist",
			preload:    map[string]*UEPreConfigPaths{"imsi-001": paths1},
			querySUPI:  "imsi-999",
			expectPath: nil,
			expectOK:   false,
		},
		{
			name:       "Empty path pool",
			preload:    map[string]*UEPreConfigPaths{},
			querySUPI:  "imsi-001",
			expectPath: nil,
			expectOK:   false,
		},
		{
			name:       "Multiple entries, query one",
			preload:    map[string]*UEPreConfigPaths{"imsi-001": paths3, "imsi-002": paths2},
			querySUPI:  "imsi-002",
			expectPath: paths2,
			expectOK:   true,
		},
		{
			name: "Overwrite existing path",
			preload: map[string]*UEPreConfigPaths{
				"imsi-001": paths1,
			},
			querySUPI:  "imsi-001",
			expectPath: paths2,
			expectOK:   true,
			setup: func(mgr *UERoutingManager) {
				mgr.AddPath("imsi-001", paths2)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mgr := NewUERoutingManager()
			for supi, path := range tc.preload {
				mgr.AddPath(supi, path)
			}
			if tc.setup != nil {
				tc.setup(mgr)
			}
			got, ok := mgr.GetPath(tc.querySUPI)
			if ok != tc.expectOK {
				t.Errorf("expected ok=%v, got %v", tc.expectOK, ok)
			}

			if !pathsEqual(got, tc.expectPath) {
				t.Errorf("expected path %+v, got %+v", tc.expectPath, got)
			}

			if has := mgr.HasPath(tc.querySUPI); has != tc.expectOK {
				t.Errorf("HasPath: expected %v, got %v", tc.expectOK, has)
			}
		})
	}
}
