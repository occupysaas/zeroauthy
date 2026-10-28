package noderunner

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Runtime describes a Node.js executable.
type Runtime struct {
	Version  string // "v22.13.0"
	AllowNet bool   // --allow-net exists (Node 25+): needed for network under --permission
}

// CheckNodeVersion accepts "vMAJOR.MINOR.PATCH" of Node 22.13 or later. The
// error wraps ErrUnavailable.
func CheckNodeVersion(v string) error {
	parts := strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3)
	if len(parts) < 2 {
		return fmt.Errorf("%w: unrecognised node version %q", ErrUnavailable, v)
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return fmt.Errorf("%w: unrecognised node version %q", ErrUnavailable, v)
	}
	if major > 22 || (major == 22 && minor >= 13) {
		return nil
	}
	return fmt.Errorf("%w: node %s is too old; 22.13 or later is required", ErrUnavailable, v)
}

// Detect checks that node is a usable Node.js and whether it has
// --allow-net. It runs node with an empty environment. The error wraps
// ErrUnavailable.
func Detect(node string) (Runtime, error) {
	return detect(node, os.TempDir())
}

func detect(node, dir string) (Runtime, error) {
	cmd := exec.Command(node, "--version")
	cmd.Env = []string{}
	out, err := cmd.Output()
	if err != nil {
		return Runtime{}, fmt.Errorf("%w: running %s --version: %v", ErrUnavailable, node, err)
	}
	rt := Runtime{Version: strings.TrimSpace(string(out))}
	if err := CheckNodeVersion(rt.Version); err != nil {
		return Runtime{}, err
	}
	net := exec.Command(node, "--permission", "--allow-net", "-e", "0")
	net.Env = []string{}
	net.Dir = dir
	rt.AllowNet = net.Run() == nil
	return rt, nil
}
