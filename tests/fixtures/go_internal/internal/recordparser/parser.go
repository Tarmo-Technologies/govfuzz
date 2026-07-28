// SPDX-License-Identifier: Apache-2.0
// The same tiny parser as the `go_lane` fixture, but living under `internal/` —
// where a great deal of real Go code lives. Go decides "outside the internal
// tree" from the IMPORT PATH, so a harness module named `govfuzzharness` was
// outside every project and could not import this at all: `use of internal
// package ... not allowed`, which reported as a failed BUILD rather than as the
// naming problem it was.
package recordparser

// ParseRecord parses a length-prefixed record. A planted bug: on tag 'A' it reads
// past the slice bounds without checking length (CWE-125).
func ParseRecord(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	tag := data[0]
	if tag == 'A' {
		return int(data[1]) + int(data[2]) + int(data[3]) + int(data[4]) + int(data[5])
	}
	return len(data)
}
