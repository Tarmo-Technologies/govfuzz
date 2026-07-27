// SPDX-License-Identifier: Apache-2.0
// Fixture for the Go `--force` path: both targets here are UNDRIVABLE by the
// type-directed generator and must be skipped cleanly without --force.
//   * Feed is a method, so it needs a receiver value.
//   * Render takes a map, for which there is no byte decoder.
// Each carries a planted out-of-bounds read (CWE-125) reachable from the input
// bytes alone, so a forced build that really executes the target produces a
// finding rather than an empty pass.
package forcelib

// Option is an exported type used only to make Render's map parameter name a
// TARGET-package type, which the forced driver has to qualify as `tgt.Option`.
type Option struct {
	Name string
}

// Decoder is the method receiver. Its zero value is usable, so a forced harness
// can call Feed without a constructor.
type Decoder struct {
	Limit int
}

// Feed reads a length-prefixed body. Planted bug: on tag 'M' it indexes past the
// slice without checking the length.
func (d *Decoder) Feed(data []byte) int {
	if len(data) == 0 {
		return d.Limit
	}
	if data[0] == 'M' {
		return int(data[1]) + int(data[2]) + int(data[3]) + int(data[4])
	}
	return len(data)
}

// Render takes an undrivable map parameter alongside the fuzz bytes. Planted bug:
// on tag 'R' it indexes past the slice.
func Render(data []byte, opts map[string]Option) int {
	if len(data) == 0 {
		return len(opts)
	}
	if data[0] == 'R' {
		return int(data[1]) + int(data[2]) + int(data[3]) + int(data[4])
	}
	return len(data) + len(opts)
}
