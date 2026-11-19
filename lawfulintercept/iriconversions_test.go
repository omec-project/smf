// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

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

// Every value this element puts into a TS 33.128 record arrives through a conversion into one
// of `li/iri`'s types, and a raw cast is where such a conversion goes wrong silently.
//
// Casting NGAP's cause value or handover type straight into the record type would put the wrong
// cause in every handover record, and `intra5gs(0)` would make every intra-5GS handover record
// undecodable on receipt. Neither shows until a delivered record is read and found wrong, so
// every raw cast into a record enumeration needs a check that does not depend on reading.
//
// **This keys on the shape, not on a list of enumerations.** The tempting design is "for each
// known `iri` enum type, require an assertion", and that list is the thing that goes stale: a
// new enumeration in `li` is invisible to a list maintained here. Inverted, the staleness works
// for us — every conversion `iri.T(x)` whose argument is not one of the package's own `iri.`
// constants must be recorded, so a new enumerated conversion arrives as an unlisted site rather
// than as a type nobody added.
//
// Same trade as `li/iri`'s `unrestrictedBareFields`: a one-time cost of writing the entries, for
// the next one being a decision rather than a diff nobody reads.
//
// **What it cannot see**, said out loud because the gap is real: an *implicit* conversion. A
// function declared to return `iri.AccessType` that writes `return 0` produces a value of that
// type with no conversion expression for this scan to find, and `DeregistrationScope` in the AMF
// does exactly that. The encode-time guard in `li/iri` is what covers those, and the two halves
// are complementary rather than redundant — this one catches an unasserted correspondence, that
// one catches a value the enumeration does not define however it got there.

// conversionKind is what an entry claims about the conversion.
type conversionKind int

const (
	// carried — the target is not an enumeration, so there are no two numberings to reconcile.
	// A DNN is a DNN; a PDU session ID is an integer in both definitions.
	carried conversionKind = iota
	// mapped — the target is an enumeration, and some other definition numbers the same
	// concept. The correspondence has to be asserted somewhere, and the entry names where.
	mapped
	// built — not a conversion at all but a call into `li/iri`, whose own correctness is that
	// package's. Recorded because the scan cannot tell a type from a function, and saying which
	// is which is cheaper than a scan that guesses.
	built
)

// iriConversion is one recorded conversion target.
type iriConversion struct {
	kind conversionKind
	// why, for carried and built.
	note string
	// assertion, for mapped only: the name of the test that establishes the correspondence, so
	// a reader does not have to re-derive whether the cast is safe. Asserted to exist — a note
	// naming a test nobody wrote is the same claim-with-nothing-behind-it the cast was.
	assertion string
}

// recordedConversions are every `iri.X(...)` this package's module performs on something other
// than one of `li/iri`'s own constants.
//
// The distinction between *carried* and *mapped* is the whole point: it is the difference
// between a value that means the same thing in both definitions and a value whose meaning
// depends on two enumerations agreeing. A cast is a correspondence claim with nothing behind it,
// and it looks identical either way from the call site.
var recordedConversions = map[string]iriConversion{
	// The one enumerated conversion in this module: a direct
	// cast from the NAS value, correct today because TS 24.501 and TS 33.128 happen to number
	// the concept identically, with nothing holding it there.
	"PDUSessionType": {
		kind: mapped,
		note: "TS 24.501 numbers the PDU session types 1..5 and TS33128Payloads.asn numbers " +
			"them identically; the cast stays and the agreement is asserted member by member " +
			"against both definitions rather than assumed",
		assertion: "TestPDUSessionTypeCorrespondsToTS24501",
	},

	// Identity leaves. Their values come from the SM context, ultimately from a task that
	// li/x1 validated on the decode path, and none of them is an enumeration.
	"IMSI":   {kind: carried, note: "SUPI CHOICE arm; digits, no second numbering"},
	"NAI":    {kind: carried, note: "SUPI CHOICE arm; a string, no second numbering"},
	"IMEI":   {kind: carried, note: "PEI CHOICE arm"},
	"IMEISV": {kind: carried, note: "PEI CHOICE arm"},
	"MSISDN": {kind: carried, note: "GPSI CHOICE arm"},

	// Session and network identifiers. Integers and strings in both definitions; the range
	// each one has to stay inside is enforced by li/iri's constraint tables, which is a
	// different question from whether two enumerations agree.
	"PDUSessionID": {kind: carried, note: "INTEGER (0..255) in the module, uint8 in the SM context"},
	"DNN":          {kind: carried, note: "UTF8String; the DNN string verbatim"},
	"TEID":         {kind: carried, note: "INTEGER (0..4294967295)"},
	"IPv4Address":  {kind: carried, note: "OCTET STRING (SIZE(4)); the address octets"},
	"IPv6Address":  {kind: carried, note: "OCTET STRING (SIZE(16)); the address octets"},
	"MCC":          {kind: carried, note: "NumericString (SIZE(3)); the PLMN digits"},
	"MNC":          {kind: carried, note: "NumericString (SIZE(2..3)); the PLMN digits"},
	"NID":          {kind: carried, note: "UTF8String (SIZE(11)); the SNPN network identifier"},
	"AMFRegionID":  {kind: carried, note: "INTEGER (0..255); a field of the GUAMI"},
	"AMFSetID":     {kind: carried, note: "INTEGER (0..1023); a field of the GUAMI"},
	"AMFPointer":   {kind: carried, note: "INTEGER (0..63); a field of the GUAMI"},

	// SliceServiceType is an inline INTEGER (0..255) in the module, not an ENUMERATED — TS
	// 23.501's SST values are integers in the same space, so there is no second numbering
	// even though the concept has named values.
	"SliceServiceType":    {kind: carried, note: "inline INTEGER (0..255); the SST octet"},
	"SliceDifferentiator": {kind: carried, note: "OCTET STRING (SIZE(3)); the SD octets"},

	// A BOOLEAN, which has no numbering to reconcile. Declared as a pointer wherever it
	// appears so that false is distinguishable from absent; see iri.go.
	"SUPIUnauthenticatedIndication": {kind: carried, note: "BOOLEAN"},

	// Calls into li/iri rather than conversions.
	"EncodeXIRI": {kind: built, note: "the encode entry point, which is where validateConstraints runs"},
	"UEEndpoint": {kind: built, note: "builds the ueEndpoint CHOICE list, discriminating v4 from v6"},
	"UEEndpointAddress": {kind: built, note: "builds the single UEEndpointAddress alternative " +
		"SMFPDUSessionModification's uEEndpoint is, discriminating v4 from v6 as UEEndpoint does"},
	"FiveGSMCause": {kind: carried, note: "INTEGER (0..255). **Not mapped, and the distinction is " +
		"recorded rather than obvious**: the module gives the field an integer range, not an " +
		"enumeration, so a receiver validates any octet and there is no second enumeration to " +
		"correspond to. TS 24.501's 5GSM cause values start at 8, so zero is not one — but " +
		"guarding zero here would refuse a record a conformant receiver accepts. See the " +
		"change's design note on FiveGSMCause"},
}

// conversionSite is one occurrence, for the failure messages: a check that says only which type
// was unrecorded leaves the reader grepping.
type conversionSite struct {
	target string
	file   string
	line   int
}

// scanIRIConversions walks every non-test Go file in this module that imports `li/iri` and
// returns each conversion whose argument is not one of that package's own constants.
//
// **The whole module, not just this package.** The check belongs beside the conversions, and
// this package is where they all are — but `amf/ngap` imports `li/iri` too, and a conversion
// added in a sibling package would be invisible to a scan of one directory. Widening it costs a
// directory walk and closes that by construction.
func scanIRIConversions(t *testing.T) []conversionSite {
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

	var sites []conversionSite
	fset := token.NewFileSet()
	filesScanned := 0

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

		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			// Not fatal: a file this parser cannot read is a build failure the compiler
			// reports better than a test can, and failing here would hide it behind this one.
			t.Logf("skipping %s: %v", path, err)

			return nil
		}

		alias := iriImportAlias(file)
		if alias == "" {
			return nil
		}
		filesScanned++

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != alias {
				return true
			}
			// A conversion whose argument is one of `li/iri`'s own constants —
			// `iri.AccessType(iri.AccessBoth)` — reconciles nothing and is not what this
			// check is about.
			if len(call.Args) == 1 && isQualifiedBy(call.Args[0], alias) {
				return true
			}
			sites = append(sites, conversionSite{
				target: sel.Sel.Name,
				file:   rel,
				line:   fset.Position(sel.Sel.Pos()).Line,
			})

			return true
		})

		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking %s: %v", root, walkErr)
	}
	if filesScanned == 0 {
		t.Fatalf("no non-test file in %s imports li/iri, so this scan found nothing to check "+
			"and would pass against a package that had stopped building records entirely", root)
	}

	sort.Slice(sites, func(i, j int) bool {
		if sites[i].target != sites[j].target {
			return sites[i].target < sites[j].target
		}
		if sites[i].file != sites[j].file {
			return sites[i].file < sites[j].file
		}

		return sites[i].line < sites[j].line
	})

	return sites
}

// iriImportAlias returns the local name file gives `li/iri`, or "" if it does not import it.
func iriImportAlias(file *ast.File) string {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != "github.com/omec-project/util/li/iri" {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}

		return "iri"
	}

	return ""
}

// isQualifiedBy reports whether e is `alias.Something` — one of the imported package's own
// identifiers rather than a value from elsewhere in this element.
func isQualifiedBy(e ast.Expr, alias string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)

	return ok && pkg.Name == alias
}

// declaredTests are the test functions this module declares, keyed by name, so an entry naming
// an assertion can be checked against the assertions that exist.
//
// **The module, not this package.** The conversions are here and the assertions that cover them
// need not be: the handover cause and type mappings are asserted in `amf/ngap`, beside the
// mapping functions and the two definitions they read. A per-package scan would have forced
// either a duplicate assertion or a note naming nothing.
func declaredTests(t *testing.T) map[string]bool {
	t.Helper()

	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolving the module root: %v", err)
	}

	fset := token.NewFileSet()
	out := map[string]bool{}
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
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Logf("skipping %s: %v", path, parseErr)

			return nil
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				out[fn.Name.Name] = true
			}
		}

		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking %s: %v", root, walkErr)
	}
	if len(out) == 0 {
		t.Fatal("found no test functions in this module, so the assertion-exists check below " +
			"would reject every mapped entry for the wrong reason")
	}

	return out
}

// TestEveryIRIConversionIsRecorded finds every conversion into a TS 33.128 record field and fails
// on one that is not recorded above.
//
// Without the `PDUSessionType` entry it fails naming `PDUSessionType`: a cast with nothing
// holding the correspondence is found by the check rather than by reading.
func TestEveryIRIConversionIsRecorded(t *testing.T) {
	// It reads source files and nothing else.
	t.Parallel()

	sites := scanIRIConversions(t)
	if len(sites) == 0 {
		t.Fatal("the scan found no conversion into an li/iri type, so it is asserting nothing")
	}
	tests := declaredTests(t)

	seen := map[string]bool{}
	for _, s := range sites {
		seen[s.target] = true

		entry, recorded := recordedConversions[s.target]
		if !recorded {
			t.Errorf("%s:%d converts into iri.%s and nothing records what that conversion "+
				"claims. If iri.%s is an enumeration, this is a correspondence claim with "+
				"nothing behind it — the construct that made every handover record carry the "+
				"wrong cause — and it needs an assertion against both definitions, recorded "+
				"here as `mapped`. If it is not, record it as `carried` and say why there is "+
				"nothing to reconcile", s.file, s.line, s.target, s.target)

			continue
		}
		if entry.note == "" {
			t.Errorf("iri.%s is recorded with no note; an entry that says nothing is "+
				"indistinguishable from an omission", s.target)
		}
		if entry.kind != mapped {
			if entry.assertion != "" {
				t.Errorf("iri.%s is not recorded as mapped and names an assertion (%s); the two "+
					"fields say different things and only mapped needs the second",
					s.target, entry.assertion)
			}

			continue
		}
		switch {
		case entry.assertion == "":
			t.Errorf("iri.%s is recorded as mapped and names no assertion. `mapped` means two "+
				"enumerations number the same concept and something checks they still agree; "+
				"without naming that something the entry is a claim, not a check", s.target)
		case !tests[entry.assertion]:
			t.Errorf("iri.%s names %s as the assertion covering it and no test of that name "+
				"exists in this module. A note naming a test nobody wrote is exactly the "+
				"claim-with-nothing-behind-it that the bare cast was",
				s.target, entry.assertion)
		}
	}

	// A stale entry is the other direction: an exemption lying where a future conversion of
	// that name can find it, granted by nobody.
	for target := range recordedConversions {
		if !seen[target] {
			t.Errorf("iri.%s is recorded as a conversion this module performs and it performs "+
				"none; remove the entry rather than leaving a recorded claim for a conversion "+
				"that has gone", target)
		}
	}

	var listed []string
	for _, s := range sites {
		listed = append(listed, s.file+":"+strconv.Itoa(s.line)+" iri."+s.target)
	}
	t.Logf("%d conversion sites over %d targets:\n  %s",
		len(sites), len(seen), strings.Join(listed, "\n  "))
}
