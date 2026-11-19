// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestStrictLiBlockDoesNotFailTheConfigurationLoad is a source-level assertion, and it covers
// the frame `service/li_block_containment_test.go` cannot see.
//
// That test asserts that the Lawful Interception block cannot return from Start. Both of its
// guards would pass while this network function refused to start over a single mistyped LI key,
// if the refusal sat one call frame earlier, in this package. A guard scoped to one place does
// not follow the property, and it reads as coverage while the property is violated somewhere
// else.
//
// So the rule here is the other half: `strictLiBlock`'s verdict is *recorded*, never returned.
// Returning it fails InitConfigFactory, which fails Initialize, which reaches a Fatalf — taking
// PFCP, the service-based interface, NRF registration and every subscriber's session with it, over
// an optional subsystem. It is also the loudest possible disclosure that this element is
// LI-provisioned: a network function that will not start is visible to every operator, every peer
// and every monitoring system, where a log line is visible only to whoever reads logs.
//
// The refusal still happens, and interception does not start on it. The LI subsystem acts on it,
// at a point where the ADMF can be told. See LiBlockError.
func TestStrictLiBlockDoesNotFailTheConfigurationLoad(t *testing.T) {
	const file = "factory.go"

	fset := token.NewFileSet()

	parsed, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}

	var (
		found    bool
		recorded bool
	)

	ast.Inspect(parsed, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}

		ident, isIdent := call.Fun.(*ast.Ident)
		if !isIdent || ident.Name != "strictLiBlock" {
			return true
		}

		found = true

		return true
	})

	if !found {
		t.Fatalf("no call to strictLiBlock in %s; if the strict LI decode moved, move this guard "+
			"with it rather than deleting it — the property it holds is that a refused LI block "+
			"never stops the network function", file)
	}

	// The call must be the right-hand side of an assignment to liBlockErr, and nothing else. An
	// `if err := strictLiBlock(...); err != nil { return err }` is the shape that stops the
	// network function, and it is an assignment too — so the guard checks the target, not merely
	// that an assignment happened.
	ast.Inspect(parsed, func(n ast.Node) bool {
		assign, isAssign := n.(*ast.AssignStmt)
		if !isAssign || len(assign.Rhs) != 1 {
			return true
		}

		call, isCall := assign.Rhs[0].(*ast.CallExpr)
		if !isCall {
			return true
		}

		ident, isIdent := call.Fun.(*ast.Ident)
		if !isIdent || ident.Name != "strictLiBlock" {
			return true
		}

		for _, lhs := range assign.Lhs {
			if target, ok := lhs.(*ast.Ident); ok && target.Name == "liBlockErr" {
				recorded = true
			}
		}

		return true
	})

	if !recorded {
		t.Errorf("%s: strictLiBlock's verdict is not recorded in liBlockErr. If it is returned "+
			"from InitConfigFactory instead, a single mistyped key in the optional `li` block "+
			"stops this whole network function — an outage, and the loudest way to disclose that "+
			"this element is LI-provisioned. Record it and let the LI subsystem refuse "+
			"interception on it, where the ADMF can be told.", file)
	}

	// The same outage, one decode earlier. If the lenient decode of the whole file reads the
	// `li` block too, a value of the wrong type inside it (`keepaliveDisabled: [true]`) fails
	// nfconfig.LoadYAML before strictLiBlock ever runs, and InitConfigFactory returns it.
	const configFile = "config.go"
	parsedConfig, err := parser.ParseFile(fset, configFile, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", configFile, err)
	}

	var tag string
	ast.Inspect(parsedConfig, func(n ast.Node) bool {
		spec, isSpec := n.(*ast.TypeSpec)
		if !isSpec || spec.Name.Name != "Configuration" {
			return true
		}
		fields, isStruct := spec.Type.(*ast.StructType)
		if !isStruct {
			return false
		}
		for _, field := range fields.Fields.List {
			for _, name := range field.Names {
				if name.Name == "Li" && field.Tag != nil {
					tag = field.Tag.Value
				}
			}
		}

		return false
	})

	if tag != "`yaml:\"-\"`" {
		t.Errorf("%s: Configuration.Li is tagged %s, want `yaml:\"-\"`. The lenient decode of the "+
			"whole configuration must not read the li block: a type error inside it would fail "+
			"the configuration load, which stops the network function. strictLiBlock is the "+
			"block's only decode.", configFile, tag)
	}
}

// TestTheStrictLiDecodeIsStillStrict guards the other direction. The fix above is a narrow one —
// who acts on the refusal — and it must not be read, or implemented, as backing out the strictness
// that produced it. A mistyped LI key must still be refused; it simply must not take the network
// function down.
func TestTheStrictLiDecodeIsStillStrict(t *testing.T) {
	const body = `info:
  version: 1.0.0
configuration:
  li:
    x1Listen: ":8443"
    neId: smf-1
    keepaliveTimeut: 30s
`

	if _, err := strictLiBlock([]byte(body)); err == nil {
		t.Error("a misspelled LI key was accepted by the strict decode; the containment fix is " +
			"about who acts on the refusal, not about whether there is one")
	}
}

// An alias inside the block may name an anchor outside it, and a merge key may pull the
// whole block from one. Both are valid YAML that the lenient decode of the rest of the file
// accepts, so the strict decode must resolve them in the context of the whole document and
// not of the block alone; refusing them leaves interception off on a correct configuration.
// The misspelled key under a merge must still be refused.
func TestTheStrictLiDecodeResolvesAnchorsOutsideTheBlock(t *testing.T) {
	const aliased = `info:
  version: 1.0.0
  description: &ne smf-1
configuration:
  li:
    x1Listen: ":8443"
    neId: *ne
`
	li, err := strictLiBlock([]byte(aliased))
	if err != nil {
		t.Fatalf("an alias to an anchor outside the block was refused: %v", err)
	}
	if li.NEID != "smf-1" {
		t.Errorf("the aliased neId decoded as %q, want smf-1", li.NEID)
	}

	const merged = `info:
  version: 1.0.0
common: &li
  x1Listen: ":8443"
  neId: smf-2
configuration:
  li:
    <<: *li
`
	li, err = strictLiBlock([]byte(merged))
	if err != nil {
		t.Fatalf("a block merged from an anchor outside it was refused: %v", err)
	}
	if li.NEID != "smf-2" || li.X1Listen != ":8443" {
		t.Errorf("the merged block decoded as neId %q, x1Listen %q", li.NEID, li.X1Listen)
	}

	const mergedTypo = `info:
  version: 1.0.0
common: &li
  x1Listen: ":8443"
  keepaliveTimeut: 30s
configuration:
  li:
    <<: *li
`
	if _, err := strictLiBlock([]byte(mergedTypo)); err == nil {
		t.Error("a misspelled key reaching the block through a merge was accepted")
	}
}
