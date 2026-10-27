package build

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/noderunner"
)

// bundledNPM returns the npm-cli.js installed with node
// (<prefix>/bin/node beside <prefix>/lib/node_modules/npm).
func bundledNPM(node string) (string, error) {
	p, err := exec.LookPath(node)
	if err != nil {
		return "", err
	}
	if p, err = filepath.EvalSymlinks(p); err != nil {
		return "", err
	}
	return npmCLI(filepath.Join(filepath.Dir(p), "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"))
}

// npmCLI resolves cli's symlinks and checks it is a regular file.
func npmCLI(cli string) (string, error) {
	cli, err := filepath.EvalSymlinks(cli)
	if err != nil {
		return "", err
	}
	if fi, err := os.Stat(cli); err != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a file", cli)
	}
	return filepath.Clean(cli), nil
}

// resolverJS prints {name: version} for the registry's "latest" dist-tag of
// each name in argv (after the registry URL). It runs sandboxed like npm.
var resolverJS = `
const [registry, ...names] = process.argv.slice(2);
(async () => {
  const out = {};
  await Promise.all(names.map(async (name) => {
    const res = await fetch(registry + name.replace("/", "%2f"), {
      headers: { accept: "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8" },
    });
    if (!res.ok) throw new Error(name + ": registry answered " + res.status);
    const doc = await res.json();
    const v = doc && doc["dist-tags"] && doc["dist-tags"].latest;
    if (typeof v !== "string" || !doc.versions || !doc.versions[v]) throw new Error(name + ": registry has no latest version");
    out[name] = v;
  }));
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { process.stderr.write(String((e && e.message) || e)); process.exit(1); });
`

const maxOutput = 1 << 20 // bytes of a sandboxed process's stdout kept

// tailBuffer keeps the last max bytes written.
type tailBuffer struct {
	b   []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return strings.TrimSpace(string(t.b)) }

// headBuffer keeps the first max bytes written and records overflow.
type headBuffer struct {
	bytes.Buffer
	max      int
	overflow bool
}

func (h *headBuffer) Write(p []byte) (int, error) {
	if room := h.max - h.Len(); room < len(p) {
		h.overflow = true
		if room > 0 {
			h.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return h.Buffer.Write(p)
}

// workDir makes a private 0700 directory for one build or resolution under
// <CacheDir>/.builds, which no tenant's runner can read.
func (m *Manager) workDir(prefix string) (string, error) {
	base := filepath.Join(m.cacheDir, buildsDir)
	if err := mkdirPrivate(m.cacheDir); err != nil {
		return "", err
	}
	if err := mkdirPrivate(base); err != nil {
		return "", err
	}
	return os.MkdirTemp(base, prefix)
}

// sandboxed runs node with script args in the build sandbox: empty
// environment except a private HOME in dir, file reads only in reads and
// dir, writes only in dir, no child processes, workers, addons or WASI.
func (m *Manager) sandboxed(ctx context.Context, dir string, reads []string, stdout *headBuffer, args ...string) (stderr string, err error) {
	rt, err := m.runtime()
	if err != nil {
		return "", err
	}
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, m.cfg.Node, args...)
	noderunner.Sandbox(cmd, append(reads, dir), []string{dir}, rt.AllowNet)
	cmd.Env = []string{"HOME=" + home} // private; nothing from the server
	cmd.Dir = dir
	cmd.WaitDelay = 5 * time.Second
	errTail := &tailBuffer{max: 2048}
	cmd.Stdout, cmd.Stderr = stdout, errTail
	err = cmd.Run()
	return errTail.String(), err
}

// runResolver resolves the "latest" version of each name, sandboxed.
func (m *Manager) runResolver(ctx context.Context, names []string) (map[string]string, error) {
	dir, err := m.workDir("resolve-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	script := filepath.Join(dir, "resolve.cjs")
	if err := os.WriteFile(script, []byte(resolverJS), 0o600); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, m.cfg.BuildTimeout)
	defer cancel()
	out := &headBuffer{max: maxOutput}
	stderr, err := m.sandboxed(ctx, dir, nil, out, append([]string{script, m.registry}, names...)...)
	if ctx.Err() != nil {
		return nil, fmt.Errorf("resolving dependency versions timed out after %s", m.cfg.BuildTimeout)
	}
	if err != nil {
		return nil, fmt.Errorf("resolving dependency versions failed: %s", firstNonEmpty(stderr, err.Error()))
	}
	var resolved map[string]string
	if out.overflow || json.Unmarshal(out.Bytes(), &resolved) != nil {
		return nil, errors.New("resolving dependency versions failed: unreadable resolver output")
	}
	return resolved, nil
}

// runNPM installs dir/package.json's dependencies with npm's CLI under the
// sandbox, within the build timeout and the installed-size cap.
func (m *Manager) runNPM(ctx context.Context, dir string) error {
	cli, npmDir, err := m.npm()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeoutCause(ctx, m.cfg.BuildTimeout, errTimedOut)
	defer cancel()
	ctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	go watchSize(ctx, dir, 2*m.maxBytes, stop) // the tree plus npm's cache of it
	userrc, globalrc := filepath.Join(dir, "npmrc-user"), filepath.Join(dir, "npmrc-global")
	for _, rc := range []string{userrc, globalrc} {
		if err := os.WriteFile(rc, nil, 0o600); err != nil {
			return err
		}
	}
	stderr, err := m.sandboxed(ctx, dir, []string{npmDir}, &headBuffer{max: 0}, cli, "install",
		"--ignore-scripts", "--no-bin-links", "--package-lock=false", "--no-audit", "--no-fund",
		"--no-update-notifier", "--no-progress", "--loglevel=error",
		"--registry="+m.registry,
		"--cache="+filepath.Join(dir, "cache"),
		"--userconfig="+userrc, "--globalconfig="+globalrc)
	switch cause := context.Cause(ctx); {
	case errors.Is(cause, errTimedOut):
		return fmt.Errorf("dependency build timed out after %s", m.cfg.BuildTimeout)
	case errors.Is(cause, errTooLarge):
		return fmt.Errorf("the dependency tree exceeds the %d MB artifact size limit", m.cfg.MaxArtifactMB)
	case cause != nil:
		return cause
	}
	if err != nil {
		return fmt.Errorf("npm install failed: %s", firstNonEmpty(stderr, err.Error()))
	}
	return nil
}

var errTimedOut = errors.New("build timed out")

// watchSize stops the build when dir grows past max bytes.
func watchSize(ctx context.Context, dir string, max int64, stop context.CancelCauseFunc) {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var total int64
		_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				if fi, err := d.Info(); err == nil {
					total += fi.Size()
				}
			}
			return nil
		})
		if total > max {
			stop(errTooLarge)
			return
		}
	}
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
