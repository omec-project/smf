// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestEveryTeardownPathReportsAndUntasks pins the call sites, which is what the existing coverage
// cannot do.
//
// `reportAndUntask` exists so that a session ending is reported to the agency and its content
// trigger withdrawn from the UPF, on *every* path that ends one. The only test of it calls it
// directly — so it passes whether the function is reached from five paths, from one, or from none,
// which is exactly how a missing call site survives. Two of the five had a behavioural test; the
// other three had nothing at all.
//
// A path that tears a session down while leaving the interception state that session created is
// the shape `li-content-interception` forbids outright: the trigger stays installed at a UPF for a
// session that no longer exists, and the agency is never told the session ended.
//
// This is a source-level assertion because the alternative is an integration fixture per path for a
// property that is really about placement. It fails when a call site is removed, and it fails when
// a teardown path is renamed — at which point the person renaming it decides whether the
// obligation moved with it.
func TestEveryTeardownPathReportsAndUntasks(t *testing.T) {
	const pduSession = "pdu_session.go"

	for _, tt := range []struct {
		file string
		fn   string
		why  string
	}{
		{
			pduSession, "HandlePduSessionContextReplacement",
			"a session replaced by a new one for the same subscriber ends without ever being released",
		},
		{
			pduSession, "ReleaseRestoredSession",
			"a session read back from the datastore ends when its PDU session ID is established again",
		},
		{
			"restoration.go", "markReleasedAndBuild",
			"a restoration releases the sessions a restarted UPF would not take back, and those read back from the datastore",
		},
		{
			pduSession, "HandlePDUSessionSMContextUpdate",
			"an update that deletes the session is a teardown the release handler never sees",
		},
		{
			pduSession, "HandlePDUSessionSMContextRelease",
			"the ordinary release, over the service-based interface",
		},
		{
			pduSession, "HandlePFCPResponse",
			"the N4-timeout release, where the user plane never answered",
		},
		{
			n1n2DataHandler, "HandleUpdateN1Msg",
			"the UE's Release Complete after a Release Command that answered a failed modification, which no release reported",
		},
		{
			n1n2DataHandler, "HandleUpdateN2Msg",
			"a duplicate PDU session identifier tears the earlier session down",
		},
	} {
		t.Run(tt.fn, func(t *testing.T) {
			fset := token.NewFileSet()

			parsed, err := parser.ParseFile(fset, tt.file, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("parsing %s: %v", tt.file, err)
			}

			var target *ast.FuncDecl

			for _, decl := range parsed.Decls {
				if fd, isFunc := decl.(*ast.FuncDecl); isFunc && fd.Name != nil && fd.Name.Name == tt.fn {
					target = fd
					break
				}
			}

			if target == nil {
				t.Fatalf("no %s in %s. If this teardown path was renamed, move this guard with it "+
					"rather than deleting it: the obligation is that every path ending a session "+
					"reports it and withdraws its content trigger (%s)", tt.fn, tt.file, tt.why)
			}

			var found bool

			ast.Inspect(target, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}

				if ident, isIdent := call.Fun.(*ast.Ident); isIdent && ident.Name == "reportAndUntask" {
					found = true
				}

				return true
			})

			if !found {
				t.Errorf("%s does not call reportAndUntask — %s. The session ends with its content "+
					"trigger still installed at the UPF and the agency never told it ended, and "+
					"nothing in this element can notice: from here the teardown looks complete.",
					tt.fn, tt.why)
			}
		})
	}
}

// TestEveryEstablishmentRejectIsReported: a PDU session establishment reject built anywhere
// but rejectEstablishment reaches the UE without the unsuccessful-procedure record a tasked
// subscriber's refused establishment owes the agency, and nothing else would notice.
func TestEveryEstablishmentRejectIsReported(t *testing.T) {
	fset := token.NewFileSet()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the producer package: %v", err)
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		file, parseErr := parser.ParseFile(fset, entry.Name(), nil, 0)
		if parseErr != nil {
			t.Fatalf("parsing %s: %v", entry.Name(), parseErr)
		}

		for _, decl := range file.Decls {
			fd, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fd.Body == nil || fd.Name.Name == "rejectEstablishment" {
				continue
			}

			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				if sel, isSel := call.Fun.(*ast.SelectorExpr); isSel &&
					sel.Sel.Name == "GeneratePDUSessionEstablishmentReject" {
					t.Errorf("%s: %s builds an establishment reject directly; use "+
						"rejectEstablishment, which also reports it", fset.Position(call.Pos()), fd.Name.Name)
				}

				return true
			})
		}
	}
}
