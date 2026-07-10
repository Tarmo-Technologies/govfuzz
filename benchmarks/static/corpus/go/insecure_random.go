// SPDX-License-Identifier: Apache-2.0
// GF-428 (CWE-338): a non-crypto PRNG produces a secret; a plain index does not.
package guards

import "math/rand"

func makeNonce() int {
	nonce := rand.Intn(1 << 30) // EXPECT GF-428
	return nonce
}

func pickIndex(n int) int {
	return rand.Intn(n) // safe: no security context
}
