// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package smferrors

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// `ErrorType` and `ErrorCause` are two tables keyed by the same strings, and every rejection
// site looks up both with one key: `ErrorType` builds the HTTP problem details and the NAS
// reject, `ErrorCause` supplies the 5GSM cause that reject carries. Nothing held the two key
// sets together, and nothing checked that a key used at a call site was in either.
//
// **A key in neither is not a degraded rejection — it is a panic on the PDU session
// establishment path.** `GeneratePDUSessionEstablishmentReject` does
// `int(*errors.ErrorType[cause].Status)`, and a map miss yields the zero `ExtProblemDetails`
// whose `Status` is a nil `*int32`. A typo in a rejection path's key takes the SMF down.
//
// **A key in `ErrorType` and not in `ErrorCause` is the quiet one.** The reject goes out with a
// 5GSM cause of 0, which TS 24.501 does not assign — clause 9.11.4.2 has the UE treat an
// undefined cause as #31 "request rejected, unspecified", so the specific reason is silently
// flattened rather than refused. It reaches the LI record for a tasked subscriber too, in a
// field TS 33.128 makes mandatory.
//
// Both are the same shape as `smferrors`' other defect: two tables describing one concept, kept
// in step by nobody. `TestErrorCauseValuesAre5GSMCauses` on `fix-5gsm-cause-for-dnn-reject`
// covers the *values*; this covers the *keys*, and the two are complementary — a table can hold
// only defined 5GSM causes and still be missing the entry a rejection site asks for.
//
// The keys are all string literals, so a test-time check is a complete guarantee rather than a
// sample: there is no key this element computes at run time, and the scan below fails if one
// appears.

// causeOnlyKeys are the `ErrorCause` entries with no `ErrorType` counterpart, with the reason.
//
// Recorded rather than inferred, because "this key is deliberately cause-only" and "somebody
// removed the ErrorType entry" are indistinguishable from the tables. Same shape as the
// disposition maps in `li/iri`.
var causeOnlyKeys = map[string]string{
	// Raised on the release path, not the establishment path: n1n2_data_handler reports a
	// release reject for a PDU session identity the SMF does not know. That path answers the
	// AMF over N1N2 rather than building a PostSmContexts 400, so it needs the 5GSM cause and
	// has no use for the problem details.
	"InvalidPDUSessionIdentity": "release path only; reports a 5GSM cause without building a " +
		"PDU session establishment reject, so it needs no ErrorType entry",
}

// TestEveryErrorTypeKeyHasACause holds the two tables' key sets together.
//
// One direction is an invariant: a rejection site that builds an `ErrorType` reject also asks
// `ErrorCause` what cause to put in it, so a key in the first and not the second sends a 5GSM
// cause of 0. The other direction is a recorded decision, because a cause-only key is
// legitimate — and recording it is what makes an accidentally deleted `ErrorType` entry visible.
func TestEveryErrorTypeKeyHasACause(t *testing.T) {
	if len(ErrorType) == 0 || len(ErrorCause) == 0 {
		t.Fatal("one of the tables is empty, so every assertion below passes against nothing")
	}

	for key := range ErrorType {
		cause, ok := ErrorCause[key]
		switch {
		case !ok:
			t.Errorf("ErrorType has %q and ErrorCause does not: a rejection built from this key "+
				"carries a 5GSM cause of 0, which TS 24.501 does not assign. The UE treats an "+
				"undefined cause as #31 per clause 9.11.4.2, so the specific reason is silently "+
				"flattened rather than refused — and for a tasked subscriber the same 0 reaches "+
				"the SMFUnsuccessfulProcedure record in a field TS 33.128 makes mandatory", key)
		case cause == 0:
			t.Errorf("ErrorCause[%q] is 0, which is not an assigned 5GSM cause value; the entry "+
				"exists and says nothing", key)
		}
	}

	for key := range ErrorCause {
		if _, ok := ErrorType[key]; ok {
			continue
		}
		if why, recorded := causeOnlyKeys[key]; !recorded || why == "" {
			t.Errorf("ErrorCause has %q and ErrorType does not, and nothing records why. A "+
				"cause-only key is legitimate — the release path needs one — but an ErrorType "+
				"entry deleted by accident looks exactly the same, so say which this is in "+
				"causeOnlyKeys", key)
		}
	}

	// A stale exemption is the other direction of the same problem.
	for key := range causeOnlyKeys {
		cause, ok := ErrorCause[key]
		if !ok {
			t.Errorf("%q is recorded as a cause-only key and ErrorCause does not have it; remove "+
				"the entry rather than leaving an exemption for a key that has gone", key)

			continue
		}
		// The loop above only reaches values for keys ErrorType also has, so without this a
		// cause-only entry could hold the 0 this whole file exists to refuse.
		if cause == 0 {
			t.Errorf("ErrorCause[%q] is 0, which is not an assigned 5GSM cause value; the entry "+
				"exists and says nothing", key)
		}
		if _, ok := ErrorType[key]; ok {
			t.Errorf("%q is recorded as cause-only and ErrorType now has it; remove the entry, "+
				"or the reason recorded beside it is no longer true", key)
		}
	}
}

// keyTaker is a function that indexes one of the tables with one of its own parameters, so a
// string literal at that argument position is a table key.
type keyTaker struct {
	param int
	// which tables a literal reaching this parameter ends up indexing, transitively.
	usesType, usesCause bool
}

// keySite is one string literal used as a table key.
type keySite struct {
	key                 string
	file                string
	line                int
	needType, needCause bool
}

// TestEveryErrorKeyLiteralResolves is the half a key-set assertion alone does not cover: a
// literal that is in neither table.
//
// **It discovers the key-taking functions rather than listing them.** A list would go stale the
// moment somebody adds a wrapper, which is how the indirection got here in the first place —
// `rejectEstablishment` was introduced precisely so sixteen rejection paths could not come apart
// from their LI hook, and it made the key one call further from the table. So the scan looks for
// the *shape*: a function that indexes `ErrorType` or `ErrorCause` with one of its own
// parameters takes a key at that position, and so does a function that passes a parameter into
// one of those at the key position. That closure is computed rather than declared, so a
// second wrapper is found the day it is written.
func TestEveryErrorKeyLiteralResolves(t *testing.T) {
	files := parseModule(t)

	takers := discoverKeyTakers(t, files)
	if len(takers) == 0 {
		t.Fatal("found no function that indexes ErrorType or ErrorCause with one of its own " +
			"parameters; the indirection this scan follows is what it is looking for, so " +
			"finding none means the scan is broken rather than the code being simple")
	}

	sites := collectKeySites(t, files, takers)
	if len(sites) == 0 {
		t.Fatal("found no string literal used as an ErrorType or ErrorCause key anywhere in the " +
			"module, so this test asserts nothing")
	}

	for _, s := range sites {
		if s.needType {
			if _, ok := ErrorType[s.key]; !ok {
				t.Errorf("%s:%d uses %q as an error key and ErrorType has no such entry. "+
					"GeneratePDUSessionEstablishmentReject dereferences "+
					"ErrorType[cause].Status, and a map miss yields the zero ExtProblemDetails "+
					"whose Status is a nil *int32 — so this is a panic on the PDU session "+
					"establishment path, not a degraded rejection", s.file, s.line, s.key)
			}
		}
		if s.needCause {
			if c, ok := ErrorCause[s.key]; !ok || c == 0 {
				t.Errorf("%s:%d uses %q as an error key and ErrorCause has no usable entry, so "+
					"the reject carries a 5GSM cause of 0 — a value TS 24.501 does not assign",
					s.file, s.line, s.key)
			}
		}
	}

	var listed []string
	for _, s := range sites {
		listed = append(listed, s.file+":"+strconv.Itoa(s.line)+" "+strconv.Quote(s.key))
	}
	t.Logf("%d key-taking function(s), %d literal key site(s):\n  %s",
		len(takers), len(sites), strings.Join(listed, "\n  "))
}

// parseModule returns every non-test Go file in this module, parsed.
func parseModule(t *testing.T) map[string]*ast.File {
	t.Helper()

	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolving the module root: %v", err)
	}
	// A check that cannot run is not a check that passes.
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("%s has no go.mod, so this scan is not looking at the module it thinks: %v",
			root, err)
	}

	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "testdata", ".git", "bin":
				return fs.SkipDir
			}

			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			// Not fatal: a file the parser cannot read is a build failure the compiler reports
			// better than this test can, and failing here would hide it behind this one.
			t.Logf("skipping %s: %v", path, parseErr)

			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		out[rel] = file

		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking %s: %v", root, walkErr)
	}
	if len(out) == 0 {
		t.Fatalf("parsed no Go files under %s", root)
	}
	// Positions are needed for the failure messages, and they live in the fileset.
	fileLines = fset

	return out
}

// fileLines is the fileset the scan's positions resolve against. Package-level because the two
// halves of the scan are separate functions and threading a fileset through both would say
// nothing a reader needs.
var fileLines *token.FileSet

// tableIndexed reports which of the two tables an expression indexes, if either.
//
// Matches on the identifier's name rather than on a resolved package, because the tables are
// reached under three spellings in this module — bare inside `smferrors`, `smferrors.ErrorType`
// in `producer`, and `errors.ErrorType` in `context`, where the import is aliased. No other
// package in the tree declares either name, so matching by name is exact here and would need
// revisiting only if one did.
func tableIndexed(n ast.Node) (isType, isCause bool) {
	idx, ok := n.(*ast.IndexExpr)
	if !ok {
		return false, false
	}

	var name string
	switch x := idx.X.(type) {
	case *ast.Ident:
		name = x.Name
	case *ast.SelectorExpr:
		name = x.Sel.Name
	default:
		return false, false
	}

	return name == "ErrorType", name == "ErrorCause"
}

// discoverKeyTakers finds every function that turns one of its own parameters into a table key,
// directly or by passing it to another such function.
//
// A bounded fixed point rather than one pass, because the indirection is two deep already:
// `rejectEstablishment` indexes `ErrorCause` with its `cause` parameter *and* hands the same
// parameter to `GeneratePDUSessionEstablishmentReject`, which indexes `ErrorType`. A single pass
// would check literals passed to it against one table and not the other.
func discoverKeyTakers(t *testing.T, files map[string]*ast.File) map[string]keyTaker {
	t.Helper()

	takers := map[string]keyTaker{}

	record := func(name string, param int, isType, isCause bool) bool {
		prev, seen := takers[name]
		if seen && prev.param != param {
			// Two functions of the same name taking a key at different positions. Not present
			// today; saying so is cheaper than a silently wrong answer if it appears.
			t.Errorf("%s takes an error key at argument %d and also at %d; this scan keys on "+
				"the function name and cannot tell the two apart", name, prev.param, param)

			return false
		}
		next := keyTaker{param: param, usesType: prev.usesType || isType, usesCause: prev.usesCause || isCause}
		if seen && next == prev {
			return false
		}
		takers[name] = next

		return true
	}

	// Bounded: each round can only add information, and the call graph this follows is a
	// handful of functions deep. Ten is far above what the module has and stops a cycle.
	for round := 0; round < 10; round++ {
		changed := false

		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				params := paramNames(fn)
				if len(params) == 0 {
					continue
				}

				ast.Inspect(fn.Body, func(n ast.Node) bool {
					// A parameter used to index one of the tables directly.
					if isType, isCause := tableIndexed(n); isType || isCause {
						key, _ := n.(*ast.IndexExpr).Index.(*ast.Ident)
						if key != nil {
							if pos, ok := params[key.Name]; ok && record(fn.Name.Name, pos, isType, isCause) {
								changed = true
							}
						}

						return true
					}

					// A parameter handed to a known key-taker at its key position.
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					callee, ok := takers[calleeName(call)]
					if !ok || callee.param >= len(call.Args) {
						return true
					}
					arg, ok := call.Args[callee.param].(*ast.Ident)
					if !ok {
						return true
					}
					if pos, ok := params[arg.Name]; ok &&
						record(fn.Name.Name, pos, callee.usesType, callee.usesCause) {
						changed = true
					}

					return true
				})
			}
		}

		if !changed {
			break
		}
	}

	return takers
}

// paramNames maps a function's parameter names to their argument positions.
func paramNames(fn *ast.FuncDecl) map[string]int {
	out := map[string]int{}
	if fn.Type.Params == nil {
		return out
	}
	pos := 0
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			pos++

			continue
		}
		for _, name := range field.Names {
			if name.Name != "_" {
				out[name.Name] = pos
			}
			pos++
		}
	}

	return out
}

// calleeName is the called function's own name, ignoring any receiver or package qualifier.
// Two functions of the same name in different packages would be conflated; discoverKeyTakers
// reports the one shape where that could matter.
func calleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}

	return ""
}

// collectKeySites finds every string literal that reaches one of the tables, whether by
// indexing directly or through a discovered key-taker.
func collectKeySites(t *testing.T, files map[string]*ast.File, takers map[string]keyTaker) []keySite {
	t.Helper()

	var sites []keySite
	for name, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			if isType, isCause := tableIndexed(n); isType || isCause {
				idx, _ := n.(*ast.IndexExpr)
				if key, ok := literal(idx.Index); ok {
					sites = append(sites, keySite{
						key: key, file: name, line: fileLines.Position(idx.Pos()).Line,
						needType: isType, needCause: isCause,
					})
				}

				return true
			}

			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee, ok := takers[calleeName(call)]
			if !ok || callee.param >= len(call.Args) {
				return true
			}
			if key, ok := literal(call.Args[callee.param]); ok {
				sites = append(sites, keySite{
					key: key, file: name, line: fileLines.Position(call.Pos()).Line,
					needType: callee.usesType, needCause: callee.usesCause,
				})
			}

			return true
		})
	}

	sort.Slice(sites, func(i, j int) bool {
		if sites[i].file != sites[j].file {
			return sites[i].file < sites[j].file
		}

		return sites[i].line < sites[j].line
	})

	return sites
}

// literal unquotes a string literal expression, reporting whether it was one.
//
// A non-literal key is not silently skipped: TestNoErrorKeyIsComputed refuses the shape, because
// a computed key is what turns this complete check into a sample.
func literal(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}

	return s, true
}

// TestNoErrorKeyIsComputed is what makes the scan above a guarantee rather than a sample.
//
// Every key in this module is a string literal, so checking the literals checks every key. A key
// built at run time — from a config value, an error string, a concatenation — would be outside
// what any test can enumerate, and the scan would go on reporting the literals it does find as
// though the set were complete.
//
// A key reaches a table by one of two routes, and both are refused here. It is either passed to a
// discovered key-taker, or used to index a table directly. In each case the key is enumerable
// only if it is a string literal, which TestEveryErrorKeyLiteralResolves checks against the
// table, or a parameter of the enclosing function, which discoverKeyTakers follows out to that
// function's own callers. Anything else — a local variable, a concatenation, a call — is neither,
// and is exactly what this test exists to refuse.
func TestNoErrorKeyIsComputed(t *testing.T) {
	files := parseModule(t)
	takers := discoverKeyTakers(t, files)

	for name, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			// Route one: a table indexed directly. Checked as well as the call route below,
			// because a direct index with a computed key is the same hole reached one step
			// earlier — TestEveryErrorKeyLiteralResolves skips it for not being a literal and
			// discoverKeyTakers skips it for not being a parameter, so without this nothing
			// looks at it at all.
			if isType, isCause := tableIndexed(n); isType || isCause {
				idx, _ := n.(*ast.IndexExpr)
				if !keyIsEnumerable(file, idx.Index, idx) {
					table := "ErrorCause"
					if isType {
						table = "ErrorType"
					}
					t.Errorf("%s:%d indexes %s with a computed error key. Every key in this "+
						"module is a literal or a parameter, which is what lets a test check "+
						"them all; a computed one is outside what "+
						"TestEveryErrorKeyLiteralResolves can enumerate, so it would report the "+
						"remaining literals as though the set were still complete",
						name, fileLines.Position(idx.Pos()).Line, table)
				}

				return true
			}

			// Route two: a key handed to a function that indexes a table with it.
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee, ok := takers[calleeName(call)]
			if !ok || callee.param >= len(call.Args) {
				return true
			}
			if keyIsEnumerable(file, call.Args[callee.param], call) {
				return true
			}
			t.Errorf("%s:%d passes a computed error key to %s. Every key in this module is a "+
				"literal or a parameter, which is what lets a test check them all; a computed "+
				"one is outside what TestEveryErrorKeyLiteralResolves can enumerate, so it "+
				"would report the remaining literals as though the set were still complete",
				name, fileLines.Position(call.Pos()).Line, calleeName(call))

			return true
		})
	}
}

// keyIsEnumerable reports whether a key expression is one the scan can account for: a string
// literal, which TestEveryErrorKeyLiteralResolves checks against the tables, or a parameter of
// the function containing it, which discoverKeyTakers follows out to that function's callers. A
// parameter passed straight through is the indirection itself, already followed.
func keyIsEnumerable(file *ast.File, key ast.Expr, at ast.Node) bool {
	if _, isLiteral := literal(key); isLiteral {
		return true
	}
	ident, isIdent := key.(*ast.Ident)
	if !isIdent {
		return false
	}
	_, isParam := paramNames(enclosingFunc(file, at))[ident.Name]

	return isParam
}

// enclosingFunc returns the function declaration containing pos, or a stub if there is none.
func enclosingFunc(file *ast.File, node ast.Node) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Pos() <= node.Pos() && node.Pos() <= fn.End() {
			return fn
		}
	}

	return &ast.FuncDecl{Type: &ast.FuncType{}}
}
