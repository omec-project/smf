// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/util/li/iri"
)

// `smfEstablishment` builds the record's pDUSessionType as
// `iri.PDUSessionType(sc.SelectedPDUSessionType)` — a direct cast from the NAS value, with no
// member-by-member assertion between the two definitions.
//
// **A direct cast is a correspondence claim with nothing behind it.** It states that TS 24.501's
// PDU session types and TS 33.128's `PDUSessionType` number the concept identically, in a form
// that cannot be checked and does not fail when they stop agreeing — which is the same claim a
// conversion function makes, minus the place to write the assertion. That the claim is true today
// is a fact about the current releases of both documents, not a property of this code.
//
// It is also the construct behind the AMF's `handoverCause` and `handoverType` mappings, which
// are asserted the same way.
//
// So the cast stays — replacing it with a switch would add a mapping nobody needs and a
// `default` arm whose value would be a guess — and this test is the assertion behind it.
// The shape is `amf/ngap`'s TestTheCauseMappingIsTotalOverNGAP: derive from both definitions by
// name, then assert the code agrees.

// ts33128Module locates the TS 33.128 ASN.1 module under `li/` in the pinned util module.
//
// Read from the module cache rather than copied here, so the assertion follows the pin: bumping
// `li` to a release built against a later TS 33.128 changes what this checks against, which is
// the point. A second copy in this repository would be a transcription with nothing keeping it
// honest.
//
// **Fatal, not skipped.** A skip is a green run that checked nothing, and this is the only thing
// standing between a later release of either document and every PDU session establishment record
// naming the wrong session type.
func ts33128Module(t *testing.T) string {
	t.Helper()

	out, err := exec.CommandContext(t.Context(),
		"go", "list", "-m", "-f", "{{.Dir}}", "github.com/omec-project/util").Output()
	if err != nil {
		t.Fatalf("cannot locate the util module (%v); this test checks the PDU session type "+
			"correspondence against the TS 33.128 module that module carries, and without it "+
			"nothing here is checked", err)
	}
	dir := strings.TrimSpace(string(out))

	// Under the workspace `go list -m` answers with the local ./util checkout, not the version
	// go.mod pins — so this can check against a module the shipped binary does not contain.
	// Harmless while the two agree, load-bearing the moment they diverge.
	if want := pinnedUtilVersion(t); want != "" {
		if strings.Contains(dir, "/pkg/mod/") {
			if !strings.Contains(dir, want) {
				t.Fatalf("checking the correspondence against %s while go.mod pins %s: this "+
					"assertion would then pass against a module the shipped binary does not "+
					"contain", dir, want)
			}
		} else {
			t.Logf("correspondence checked against the local tree %s, not the pinned %s; run "+
				"with GOWORK=off to assert the pin", dir, want)
		}
	}

	path := filepath.Join(dir, "li", "iri", "testdata", "asn1", "TS33128Payloads.asn")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the util module at %s does not carry %s (%v)", dir, path, err)
	}

	return path
}

// pinnedUtilVersion is the util version, which carries `li`, that this module actually builds
// against, or "" if it cannot be read. It is used to say which module this assertion ran
// against rather than leaving it assumed.
//
// **A replace directive governs, not the require.** When go.mod replaces util, the
// replacement is what is compiled and the require line is only a floor, so a replace is
// returned in preference to the require wherever it appears.
//
// Duplicated from amf/ngap's licause_test.go rather than shared, because the two are separate
// modules and a test helper is not worth a package to hold it.
func pinnedUtilVersion(t *testing.T) string {
	t.Helper()

	mod, err := os.ReadFile(filepath.Join("..", "go.mod"))
	if err != nil {
		t.Logf("cannot read ../go.mod (%v), so the pin is not asserted", err)

		return ""
	}

	var required string

	for _, line := range strings.Split(string(mod), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "omec-project/util") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// A replace is definitive; keep looking past a require in case one follows.
		if strings.HasPrefix(line, "replace ") {
			return fields[len(fields)-1]
		}

		if required == "" {
			required = fields[len(fields)-1]
		}
	}

	return required
}

// normalisePDUSessionTypeName reduces an identifier to what the two documents agree on: letters
// and digits, lowercased.
func normalisePDUSessionTypeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}

	return b.String()
}

// pduSessionTypeSpellingAliases are the members the two documents name differently enough that
// normalisation does not join them. The key is the NAS name normalised, the value the TS 33.128
// name normalised.
//
// Listed individually rather than fuzzy-matched, for the same reason the cause mapping does it:
// a fuzzy match would silently pair members that are not the same member, which is the failure
// this whole assertion exists to prevent.
var pduSessionTypeSpellingAliases = map[string]string{
	// TS 24.501 writes "IPv4IPv6"; TS 33.128 writes "iPv4v6". Both are the dual-stack type and
	// both sit at position 3 in their enumerations.
	"ipv4ipv6": "ipv4v6",
}

// ts33128PDUSessionTypes parses TS 33.128's PDUSessionType members, keyed by normalised name.
func ts33128PDUSessionTypes(t *testing.T, modulePath string) map[string]int64 {
	t.Helper()

	src, err := os.ReadFile(modulePath)
	if err != nil {
		t.Fatalf("reading %s: %v", modulePath, err)
	}
	block := regexp.MustCompile(`(?ms)^PDUSessionType ::= ENUMERATED\s*\{(.*?)^\}`).FindSubmatch(src)
	if block == nil {
		t.Fatalf("PDUSessionType is not defined in %s, so there is nothing to correspond to",
			modulePath)
	}

	out := map[string]int64{}
	for _, m := range regexp.MustCompile(`([A-Za-z][\w-]*)\s*\((\d+)\)`).
		FindAllStringSubmatch(string(block[1]), -1) {
		v, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil {
			t.Fatalf("PDUSessionType: %q is not a number", m[2])
		}
		out[normalisePDUSessionTypeName(m[1])] = v
	}
	if len(out) == 0 {
		t.Fatalf("PDUSessionType parsed to no members, so this test would pass against anything")
	}

	return out
}

// nasPDUSessionTypes are TS 24.501's PDU session type values, keyed by normalised name.
//
// **Listed here, unlike the cause mapping's NGAP side, and the difference is worth stating.**
// The NGAP constants are a generated file whose shape a regexp can read, so that test parses
// them; `nasMessage` declares these five by hand in a const block shared with unrelated values,
// and a regexp over it would be matching prose. So this is a transcription — and it is the
// pinned module's own constants that are transcribed, referenced as symbols rather than as
// numbers, so a value the `nas` pin changes fails to compile or fails below rather than passing.
var nasPDUSessionTypes = map[string]iri.PDUSessionType{
	"ipv4":         iri.PDUSessionType(nasMessage.PDUSessionTypeIPv4),
	"ipv6":         iri.PDUSessionType(nasMessage.PDUSessionTypeIPv6),
	"ipv4ipv6":     iri.PDUSessionType(nasMessage.PDUSessionTypeIPv4IPv6),
	"unstructured": iri.PDUSessionType(nasMessage.PDUSessionTypeUnstructured),
	"ethernet":     iri.PDUSessionType(nasMessage.PDUSessionTypeEthernet),
}

// TestPDUSessionTypeCorrespondsToTS24501 is the assertion the cast was missing.
//
// For every PDU session type TS 24.501 defines: TS 33.128 must define a member of the same name,
// and the value the record carries for it — read through the builder the SMF actually calls, not
// through the cast in isolation — must be *that* member's value. A member TS 33.128 numbers
// differently would be a record naming a different session type, which decodes, validates and
// is indistinguishable from the truth at both ends.
func TestPDUSessionTypeCorrespondsToTS24501(t *testing.T) {
	// It parses definitions and builds records from sessions of its own; nothing package-level
	// is read or written.
	t.Parallel()

	module := ts33128PDUSessionTypes(t, ts33128Module(t))

	for name, nasValue := range nasPDUSessionTypes {
		key := name
		if alias, ok := pduSessionTypeSpellingAliases[name]; ok {
			key = alias
		}

		want, defined := module[key]
		if !defined {
			t.Errorf("TS 24.501 defines PDU session type %q as %d and TS 33.128's PDUSessionType "+
				"has no member of that name; the cast in smfEstablishment would carry it into a "+
				"value the record's enumeration does not define, which no receiver can interpret",
				name, nasValue)

			continue
		}

		// From the SM context through the builder the SMF calls, so the cast and the field it
		// lands in are checked together rather than the cast alone.
		sc := fullSession()
		sc.SelectedPDUSessionType = uint8(nasValue)

		for _, tc := range []struct {
			record string
			got    iri.PDUSessionType
		}{
			{testRecEstablishment, smfEstablishment(sc).PDUSessionType},
			{testRecStartOfInterception, smfStartOfInterception(sc).PDUSessionType},
		} {
			if int64(tc.got) != want {
				t.Errorf("%s/pDUSessionType for %q is %d, and TS 33.128 defines %s as %d — the "+
					"record names a different session type than the one the UE established, and "+
					"it decodes cleanly either way", tc.record, name, tc.got, key, want)
			}
		}
	}

	// The other direction: a member TS 33.128 defines and TS 24.501 has no equivalent for is
	// not a defect in this element — it is a value this element can never produce, and saying
	// so keeps the correspondence total rather than merely one-sided.
	covered := map[string]bool{}
	for name := range nasPDUSessionTypes {
		key := name
		if alias, ok := pduSessionTypeSpellingAliases[name]; ok {
			key = alias
		}
		covered[key] = true
	}
	for name := range module {
		if !covered[name] {
			t.Errorf("TS 33.128 defines PDUSessionType member %q and TS 24.501 has no PDU "+
				"session type this element maps to it; either the pin moved or a member of the "+
				"nas table above is missing", name)
		}
	}

	// A correspondence over an empty set is total. TS 24.501 defines five PDU session types.
	if len(nasPDUSessionTypes) != 5 || len(module) != 5 {
		t.Errorf("checked %d NAS types against %d module members; both were five when this was "+
			"written, so one of the two definitions has moved and the correspondence above is "+
			"worth re-deriving rather than trusting", len(nasPDUSessionTypes), len(module))
	}
}

// TestAPDUSessionTypeMismatchWouldBeCaught proves the assertion above can fail. Without it, a
// parser that produced no members and a table that mapped nothing would agree perfectly.
func TestAPDUSessionTypeMismatchWouldBeCaught(t *testing.T) {
	// It parses definitions and builds records from sessions of its own; nothing package-level
	// is read or written.
	t.Parallel()

	module := ts33128PDUSessionTypes(t, ts33128Module(t))

	// The value the record must carry for an Ethernet session, and the value it would carry if
	// the two documents disagreed by one — which is exactly how the handover cause defect
	// presented: a plausible member of the right enumeration.
	want, ok := module["ethernet"]
	if !ok {
		t.Fatal("TS 33.128's PDUSessionType has no `ethernet` member, so the parse is wrong")
	}

	sc := fullSession()
	sc.SelectedPDUSessionType = nasMessage.PDUSessionTypeEthernet
	got := int64(smfEstablishment(sc).PDUSessionType)

	if got != want {
		t.Fatalf("the correspondence is already broken for ethernet: record carries %d, module "+
			"defines %d", got, want)
	}
	// And the neighbouring value is a different, legal member of the same enumeration — which
	// is why "the record validated" is no evidence at all, and why this has to be an assertion
	// against the two definitions rather than a range check.
	for name, v := range module {
		if v == want-1 {
			t.Logf("a one-off error would carry %q, a legal member of the same enumeration — "+
				"the reason this assertion exists rather than a range check", name)

			return
		}
	}
	t.Errorf("no module member sits at %d, so a one-off error would be caught by the range "+
		"check alone and this assertion is weaker evidence than it claims", want-1)
}
