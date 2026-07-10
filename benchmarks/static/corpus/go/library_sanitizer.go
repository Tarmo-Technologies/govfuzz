// SPDX-License-Identifier: Apache-2.0
// Library-summary sanitizer: an attacker value reaching a command sink is a taint
// finding, but the same value URL-encoded first carries no shell metacharacter
// and is not.
package guards

import (
	"net/url"
	"os/exec"
)

func vuln(userInput string) {
	exec.Command(userInput).Run() // EXPECT GF-304
}

func safe(userInput string) {
	clean := url.QueryEscape(userInput)
	exec.Command(clean).Run() // sanitized: no finding
}
