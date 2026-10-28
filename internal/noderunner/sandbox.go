package noderunner

import "os/exec"

// Sandbox confines a node command to Node's permission model (D-0022, spec
// §2): it clears the environment, and inserts --permission with file reads
// limited to reads and writes limited to writes right after the node
// executable in cmd.Args. It grants no child processes, workers, addons or
// WASI. allowNet passes --allow-net, which Node 25+ needs for any network
// access under --permission (Detect reports whether the flag exists; Node 22
// lacks it and leaves the network open). On Linux the process is also
// killed if the server dies. Empty entries in reads and writes are skipped.
//
// cmd.Args[0] must be the node executable; the script and its arguments
// follow. cmd.Dir is left to the caller.
func Sandbox(cmd *exec.Cmd, reads, writes []string, allowNet bool) {
	flags := []string{"--permission"}
	for _, d := range reads {
		if d != "" {
			flags = append(flags, "--allow-fs-read="+d)
		}
	}
	for _, d := range writes {
		if d != "" {
			flags = append(flags, "--allow-fs-write="+d)
		}
	}
	if allowNet {
		flags = append(flags, "--allow-net", "--disable-warning=ExperimentalWarning")
	}
	args := make([]string, 0, len(cmd.Args)+len(flags))
	args = append(args, cmd.Args[0])
	args = append(args, flags...)
	cmd.Args = append(args, cmd.Args[1:]...)
	cmd.Env = []string{} // never inherit the server's environment
	setProcAttr(cmd)
}
