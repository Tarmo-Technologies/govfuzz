// SPDX-License-Identifier: Apache-2.0
// Uncontrolled allocation size (GF-436, CWE-789): a tainted length drives a
// slice allocation. A constant size is not tainted and is not flagged.
package corpus

import "strconv"

func grow(userInput string) []byte {
	// Idiomatic Go tuple assignment must propagate taint to `n` (not just `_`).
	n, _ := strconv.Atoi(userInput)
	return make([]byte, n) // EXPECT GF-436
}

func fixedAlloc() []byte {
	return make([]byte, 64) // constant size: not tainted, no finding
}
