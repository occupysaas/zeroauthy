//go:build linux

package script

import (
	"os/exec"
	"syscall"
)

// setProcAttr kills the runner if zeroauthy dies.
func setProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
