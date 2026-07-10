// SPDX-License-Identifier: Apache-2.0
// Field-sensitive taint: a source stored in a struct FIELD flows to a sink through
// that field (previously the field write was dropped and the flow missed); a
// sibling field assigned a literal is not tainted.
package guards

import "os/exec"

type Cmd struct {
	name string
	safe string
}

func handler(userInput string) {
	var c Cmd
	c.name = userInput
	c.safe = "ls"
	exec.Command(c.name).Run() // EXPECT GF-304
	exec.Command(c.safe).Run() // sibling field, literal: not tainted
}
