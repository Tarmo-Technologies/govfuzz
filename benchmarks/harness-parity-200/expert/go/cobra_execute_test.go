// SPDX-License-Identifier: Apache-2.0

package cobra

import (
	"io"
	"strings"
	"testing"
)

func FuzzCobraExecute(f *testing.F) {
	f.Add([]byte("help"))
	f.Fuzz(func(t *testing.T, data []byte) {
		cmd := &Command{Use: "root", SilenceErrors: true, SilenceUsage: true}
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(strings.Split(string(data), "\x00"))
		cmd.Run = func(*Command, []string) {}
		_ = cmd.Execute()
	})
}
