// SPDX-License-Identifier: Apache-2.0
// A tiny untrusted-input parser fixture for the govfuzz Go lane. ParseRecord is
// the fuzzable entry point; a crafted first byte drives an out-of-bounds slice
// access (CWE-125), a real panic reachable purely from the input bytes.
package recordparser

// ParseRecord parses a length-prefixed record. A planted bug: on tag 'A' it reads
// past the slice bounds without checking length.
func ParseRecord(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	tag := data[0]
	if tag == 'A' {
		// Bug: assumes at least 5 bytes follow the tag; panics (index out of range)
		// on a short input.
		return int(data[1]) + int(data[2]) + int(data[3]) + int(data[4]) + int(data[5])
	}
	return len(data)
}
