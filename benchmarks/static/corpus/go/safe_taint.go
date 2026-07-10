// Hard negatives: every function here takes a tainted input and reaches a sink,
// yet NONE is a real vulnerability. A precise scanner must stay silent on all of
// them — each exercises a different precision lever (list-form exec, parameterized
// query, literal path, sanitizer, guard). No EXPECT annotations: any finding here
// is a false positive that breaks the precision gate.
package p

import (
	"database/sql"
	"os"
	"os/exec"
)

// A tainted ARGUMENT to a fixed program is not command injection.
func argExec(userInput string) {
	exec.Command("ls", "-l", userInput)
}

// A parameterized query with a tainted BOUND argument is safe.
func paramQuery(userQuery string, db *sql.DB) {
	db.Query("SELECT * FROM t WHERE x=?", userQuery)
}

// A literal path is not attacker-controlled.
func literalPath() {
	os.Open("/etc/hosts")
}

// Sanitized before the sink.
func sanitized(userInput string) {
	clean := sanitize(userInput)
	exec.Command(clean)
}

// Validated by a recognized guard.
func guarded(userInput string) {
	if validate(userInput) {
		exec.Command(userInput)
	}
}
