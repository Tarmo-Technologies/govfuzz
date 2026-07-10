package p
import ("os/exec"; "os"; "crypto/sha256")
const secretToken = "<secret>" // placeholder, not a credential
func h() {
    exec.Command("ls", "-l")      // safe: no shell
    os.ReadFile("/etc/hosts")     // literal path
    sha256.New()                  // strong
}
