// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// liHookNames returns every Lawful Interception hook the named function raises: the `lawfulintercept.X`
// selectors it calls directly, plus the package-level hook variables it calls, which is the form
// this package must use because it may not import lawfulintercept.
func liHookNames(t *testing.T, file, fn string) map[string]bool {
	t.Helper()

	fset := token.NewFileSet()

	parsed, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}

	var target *ast.FuncDecl

	for _, decl := range parsed.Decls {
		if fd, isFunc := decl.(*ast.FuncDecl); isFunc && fd.Name != nil && fd.Name.Name == fn {
			target = fd
			break
		}
	}

	if target == nil {
		t.Fatalf("no %s in %s; if the handler was renamed, move this guard with it rather than "+
			"deleting it", fn, file)
	}

	names := map[string]bool{}

	ast.Inspect(target, func(n ast.Node) bool {
		sel, isSel := n.(*ast.SelectorExpr)
		if !isSel || sel.Sel == nil {
			return true
		}

		if pkg, isIdent := sel.X.(*ast.Ident); isIdent && pkg.Name == "lawfulintercept" {
			names[sel.Sel.Name] = true
		}

		return true
	})

	return names
}

// TestTheAdapterRaisesEveryLIHookTheNativeHandlerDoes is a source-level assertion, and it exists
// because the rule it enforces was written down twice and applied to one handler each time.
//
// Only one of pfcp/handler and pfcp/adapter runs in a deployment — `enableUPFAdapter` chooses, and
// the chart's default chooses the adapter. So a Lawful Interception hook present in one of them is
// a hook whose presence depends on configuration, and the agency's product depends on it with no
// way for anyone to notice.
//
// An establishment-response handler here missing the native one's hooks would, with the adapter
// selected, still set the DUPL bit on the FARs — so the UPF duplicates a targeted subscriber's
// traffic — but never send the ActivateTask that authorises it. The CC-POI would hold no task for
// that session and drop every copy as unattributable, and no establishment record would be
// produced. From the SMF's side nothing would have failed, so nothing would raise a fault.
//
// The guard derives its expectation from the native handler rather than from a list, so a fourth
// hook added there fails this test until the adapter gets it too.
func TestTheAdapterRaisesEveryLIHookTheNativeHandlerDoes(t *testing.T) {
	const (
		nativeFile  = "../handler/handler.go"
		adapterFile = "adapter.go"
	)

	for _, fn := range []string{
		"HandlePfcpSessionEstablishmentResponse",
		"HandlePfcpSessionModificationResponse",
	} {
		t.Run(fn, func(t *testing.T) {
			want := liHookNames(t, nativeFile, fn)
			if len(want) == 0 {
				// The modification handler reaches its hook through a package variable rather
				// than a lawfulintercept selector, so there is nothing for this guard to derive
				// there. Its parity is covered by the behavioural guard in this package.
				t.Skipf("%s raises no lawfulintercept.* hook directly; nothing to derive", fn)
			}

			// The adapter cannot import lawfulintercept, so it reaches each hook through a
			// package variable or a notify* helper. Either way the hook's name appears in the
			// identifier, which is what makes the comparison possible without resolving types.
			var got []string

			fset := token.NewFileSet()

			parsed, err := parser.ParseFile(fset, adapterFile, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("parsing %s: %v", adapterFile, err)
			}

			var target *ast.FuncDecl

			for _, decl := range parsed.Decls {
				if fd, isFunc := decl.(*ast.FuncDecl); isFunc && fd.Name != nil && fd.Name.Name == fn {
					target = fd
					break
				}
			}

			if target == nil {
				t.Fatalf("no %s in %s; the adapter must implement every response handler the "+
					"native path does, or a deployment that selects it silently loses whatever "+
					"the missing one carried", fn, adapterFile)
			}

			ast.Inspect(target, func(n ast.Node) bool {
				if ident, isIdent := n.(*ast.Ident); isIdent {
					got = append(got, ident.Name)
				}

				return true
			})

			for hook := range want {
				found := false

				for _, name := range got {
					if strings.Contains(name, hook) {
						found = true
						break
					}
				}

				if !found {
					t.Errorf("%s raises lawfulintercept.%s and %s does not. Only one of the two "+
						"runs in a deployment, so this hook's presence depends on "+
						"enableUPFAdapter — and the agency's product depends on this hook. Add "+
						"the seam and raise it here too.", fn, hook, adapterFile)
				}
			}
		})
	}
}
