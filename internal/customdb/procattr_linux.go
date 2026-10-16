package customdb

import (
	"os/exec"
	"syscall"
)

// setProcAttr makes the kernel kill the runner if zeroauthy dies, so no
// runner outlives the server. (Pdeathsig fires when the starting OS thread
// exits; Go keeps its threads unless one is locked, so this holds here.)
func setProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
