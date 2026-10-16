//go:build !linux

package customdb

import "os/exec"

// setProcAttr has no portable parent-death signal outside Linux; runners
// there exit when their stdin closes with the server.
func setProcAttr(*exec.Cmd) {}
