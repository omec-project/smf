// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// n1n2DataHandler is the file of the N1 and N2 update handlers, named by the placement guards.
const n1n2DataHandler = "n1n2_data_handler.go"

// TestPartialSendsReDeriveOnlyTheFARsTheySend pins the call at each handler that sends part of a
// session's rules. lawfulintercept.ApplyCCTrigger re-derives every forwarding FAR, and at these
// sites the ones the request does not carry are left duplicating in memory and unsent, where a
// pending warrant scan then finds nothing to change. They call ApplyCCTriggerTo with the FARs
// they send. TestAPartialSendLeavesOtherFARsToTheScan covers the behaviour.
func TestPartialSendsReDeriveOnlyTheFARsTheySend(t *testing.T) {
	for _, tt := range []struct{ file, fn string }{
		{n1n2DataHandler, "HandleUpdateN2Msg"},
		{"callback.go", "programAddedRule"},
		{"ulcl_procedure.go", "EstablishRANTunnelInfo"},
	} {
		t.Run(tt.fn, func(t *testing.T) {
			parsed, err := parser.ParseFile(token.NewFileSet(), tt.file, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", tt.file, err)
			}

			var target *ast.FuncDecl
			for _, decl := range parsed.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == tt.fn {
					target = fd
				}
			}
			if target == nil {
				t.Fatalf("no %s in %s; if it was renamed, move this guard with it", tt.fn, tt.file)
			}

			calls := map[string]int{}
			ast.Inspect(target, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "lawfulintercept" {
							calls[sel.Sel.Name]++
						}
					}
				}
				return true
			})

			if calls["ApplyCCTrigger"] != 0 {
				t.Errorf("%s calls lawfulintercept.ApplyCCTrigger, which re-derives FARs the "+
					"request does not carry", tt.fn)
			}
			if calls["ApplyCCTriggerTo"] == 0 {
				t.Errorf("%s does not re-derive duplication on the FARs it sends", tt.fn)
			}
		})
	}
}
