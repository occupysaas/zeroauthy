//go:build !linux

package script

import "os/exec"

func setProcAttr(*exec.Cmd) {}
