// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"fmt"

	"go.yaml.in/yaml/v4"
)

// liBlockErr records why the `li` block was refused, if it was. Package-level because
// InitConfigFactory has no other channel to the LI subsystem, and it is reset on every load so a
// reload that fixes the block clears it.
var liBlockErr error

// LiBlockError reports why the `li` block was refused, or nil. The LI subsystem consults it at
// start-up: interception does not start on a refusal, and the refusal is reported to the ADMF.
//
// **The caller must not log this, and must not fail the network function on it.** The text names
// LI configuration keys, so it belongs on the X1 fault channel and nowhere else.
func LiBlockError() error { return liBlockErr }

// strictLiBlock decodes the `li` block on its own, refusing a key this element does not model or
// a value it cannot read. It is the only decode of the block: Configuration.Li is excluded from
// the lenient decode of the whole file, so that a mistake inside the block reaches the LI
// subsystem as a refusal instead of failing the configuration load.
//
// **A misspelled LI key is silently dropped, and the defaults it lands on are the dangerous
// ones.** A typo'd `keepaliveRetainTasking` or `keepaliveTimeout` leaves the X1 keepalive
// procedure on timers or a purge policy the operator did not choose, while the element looks
// healthy. A typo'd `admfUrl` leaves the fault channel a no-op, so every condition this element
// is required to report goes nowhere — including the report that would have said the
// configuration was wrong. In both cases the operator wrote the setting, the element ignored it,
// and nothing anywhere says so.
//
// **Scoped to the `li` block, deliberately.** Decoding the whole configuration strictly would
// refuse every key this version does not model, which is a different and much larger change: a
// deployment carrying a key from a later release would stop starting. The
// property to hold is narrow — a mistyped LI key must not reach a default — and so is the check.
//
// The block is isolated first and decoded strictly second, because strictness lives on the decode
// and a decode covers everything it is given. The lenient first pass models nothing but the path
// to the block, so no key outside it is visible to be refused.
//
// The returned *Li is nil only when the configuration has no `li` key or a null one. Whenever the
// key is present it is non-nil, refused or not: the LI subsystem starts on a non-nil block, and it
// is the LI subsystem that declines to intercept on the error and reports it to the ADMF. A nil
// block on a refusal would turn interception off with nothing reported.
func strictLiBlock(content []byte) (*Li, error) {
	// Only the path to the block. This struct must not grow: modelling anything else here would
	// make it a second, diverging definition of the configuration.
	var outer struct {
		Configuration struct {
			Li yaml.Node `yaml:"li"`
		} `yaml:"configuration"`
	}
	if err := yaml.Unmarshal(content, &outer); err != nil {
		// Anything that makes the file undecodable is the real decode's to report, with its own
		// message. This check has nothing to add about it.
		return nil, nil
	}

	block := &outer.Configuration.Li
	if block.Kind == 0 || (block.Kind == yaml.ScalarNode && block.ShortTag() == "!!null") {
		// No `li` block at all: interception is off, and there is nothing to be strict about.
		return nil, nil
	}

	li := &Li{}

	// The node is decoded in place, so the strict pass sees the block and only the block while
	// an alias or merge in it still resolves to its anchor elsewhere in the document. Marshalling
	// the node out and decoding the text would keep the alias and drop the anchor.
	//
	// A decode error leaves whatever was decoded before it in li; the error is what the LI
	// subsystem acts on, so a partial block is never used to intercept.
	if err := block.Load(li, yaml.WithKnownFields()); err != nil {
		return li, fmt.Errorf("configuration.li: %w — a key this element does not recognise, or a "+
			"value it cannot read, is a setting that never reaches it, and the defaults it leaves in "+
			"place are the unsafe ones: an unread keepalive setting leaves the X1 keepalive procedure "+
			"on terms the operator did not choose, and an unread admfUrl leaves "+
			"this element with no channel to report that on", err)
	}

	return li, nil
}
