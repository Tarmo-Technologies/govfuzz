// Feature gaps closed: insecure TLS (CWE-295, GF-426) and SSRF (CWE-918, GF-427).
package p

import (
	"crypto/tls"
	"net/http"
)

func vulnTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} // EXPECT GF-426
}

func vulnSSRF(userInput string) {
	http.Get(userInput) // EXPECT GF-427
}

func safeReq() {
	http.Get("https://api.example.com") // safe: literal URL
}
