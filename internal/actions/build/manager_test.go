package build

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/noderunner"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// requireNode returns the node on PATH with its bundled npm, skipping when
// either is missing unless ZA_REQUIRE_NODE=1, which makes it a failure.
func requireNode(t *testing.T) string {
	t.Helper()
	reason := ""
	node, err := exec.LookPath("node")
	if err != nil {
		reason = "node not found on PATH"
	} else if rt, err := noderunner.Detect(node); err != nil {
		reason = err.Error()
	} else if _, err := bundledNPM(node); err != nil {
		reason = fmt.Sprintf("node %s has no bundled npm: %v", rt.Version, err)
	}
	if reason == "" {
		return node
	}
	if os.Getenv("ZA_REQUIRE_NODE") == "1" {
		t.Fatalf("ZA_REQUIRE_NODE=1 but %s", reason)
	}
	t.Skip(reason)
	return ""
}

// recordingActions records every build status written, in order.
type recordingActions struct {
	store.Actions
	mu       sync.Mutex
	statuses map[string][]store.BuildStatus
	gets     int
	// staleGet, when set, delays the result of the nth GetBuild (counting
	// from 1) after it was read, so the caller acts on a stale record.
	staleGet func(n int) time.Duration
}

func (r *recordingActions) GetBuild(ctx context.Context, tenantID, id string) (*store.Build, error) {
	b, err := r.Actions.GetBuild(ctx, tenantID, id)
	r.mu.Lock()
	r.gets++
	n, stale := r.gets, r.staleGet
	r.mu.Unlock()
	if stale != nil {
		time.Sleep(stale(n))
	}
	return b, err
}

func (r *recordingActions) PutBuild(ctx context.Context, b *store.Build) error {
	r.mu.Lock()
	r.statuses[b.ID] = append(r.statuses[b.ID], b.Status)
	r.mu.Unlock()
	return r.Actions.PutBuild(ctx, b)
}

func (r *recordingActions) history(id string) []store.BuildStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.statuses[id])
}

type recordingStore struct {
	*memory.Store
	rec *recordingActions
}

func (s recordingStore) Actions() store.Actions { return s.rec }

func newStore(t *testing.T, tenants ...string) recordingStore {
	t.Helper()
	st := memory.New()
	for _, id := range tenants {
		if err := st.Tenants().Create(context.Background(), &store.Tenant{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	return recordingStore{Store: st, rec: &recordingActions{Actions: st.Actions(), statuses: map[string][]store.BuildStatus{}}}
}

func testConfig(t *testing.T, node string, reg *registry) config.Actions {
	return config.Actions{
		Node: node, Registry: reg.URL + "/", CacheDir: t.TempDir(),
		MaxMemoryMB: 256, IdleTimeout: time.Minute, BuildTimeout: time.Minute,
		MaxArtifactMB: 50, MaxConcurrentBuilds: 2,
	}
}

func newManager(t *testing.T, cfg config.Actions, st store.Store) *Manager {
	t.Helper()
	m, err := New(cfg, st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

// waitBuild polls until the build is built or failed.
func waitBuild(t *testing.T, st store.Store, tenantID, id string) *store.Build {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		b, err := st.Actions().GetBuild(context.Background(), tenantID, id)
		if err != nil {
			t.Fatalf("GetBuild: %v", err)
		}
		if b.Status == store.BuildBuilt || b.Status == store.BuildFailed {
			return b
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("build %s did not finish", id)
	return nil
}

func queue(t *testing.T, m *Manager, tenantID string, deps ...store.Dependency) string {
	t.Helper()
	id, err := m.Queue(context.Background(), tenantID, deps, actionsrules.Runtime)
	if err != nil {
		t.Fatalf("Queue: %v", err)
	}
	return id
}

func installedVersionT(t *testing.T, root, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "node_modules", filepath.FromSlash(name), "package.json"))
	if err != nil {
		t.Fatalf("%s not installed: %v", name, err)
	}
	var pj struct{ Version string }
	if err := json.Unmarshal(b, &pj); err != nil {
		t.Fatal(err)
	}
	return pj.Version
}

func TestBuildResolvesAndPacks(t *testing.T) {
	node := requireNode(t)
	reg := fixtureRegistry(t, filepath.Join(t.TempDir(), "marker"))
	st := newStore(t, "ta")
	m := newManager(t, testConfig(t, node, reg), st)
	ctx := context.Background()

	id := queue(t, m, "ta",
		store.Dependency{Name: "za-pad", Version: ""},
		store.Dependency{Name: "@za/scoped", Version: "latest"},
		store.Dependency{Name: "za-left", Version: "1.0.0"})
	b := waitBuild(t, st, "ta", id)
	if b.Status != store.BuildBuilt {
		t.Fatalf("status = %s, errors = %v", b.Status, b.Errors)
	}
	want := []store.Dependency{{Name: "@za/scoped", Version: "2.0.0"}, {Name: "za-left", Version: "1.0.0"}, {Name: "za-pad", Version: "1.1.0"}}
	if !slices.Equal(b.Resolved, want) {
		t.Errorf("resolved = %v, want %v", b.Resolved, want)
	}
	if len(b.Requested) != 3 || b.BuiltAt.IsZero() {
		t.Errorf("build = %+v", b)
	}
	if id != ID(actionsrules.Runtime, want) || len(id) != 64 {
		t.Errorf("build ID %s is not the content address of the resolved set", id)
	}
	if h := st.rec.history(id); !slices.Equal(h, []store.BuildStatus{store.BuildPending, store.BuildBuilding, store.BuildBuilt}) {
		t.Errorf("status transitions = %v", h)
	}
	art, err := st.Actions().GetArtifact(ctx, "ta", id)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(art)
	if hex.EncodeToString(sum[:]) != b.ArtifactSHA256 {
		t.Error("artifact SHA-256 does not match the build record")
	}

	root, err := m.Ensure(ctx, "ta", id)
	if err != nil {
		t.Fatal(err)
	}
	if root != filepath.Join(m.cacheDir, "ta", id) {
		t.Errorf("root = %s", root)
	}
	for name, v := range map[string]string{"za-pad": "1.1.0", "@za/scoped": "2.0.0", "za-left": "1.0.0"} {
		if got := installedVersionT(t, root, name); got != v {
			t.Errorf("%s installed %s, want %s", name, got, v)
		}
	}
	for _, dir := range []string{m.cacheDir, filepath.Join(m.cacheDir, "ta"), root, filepath.Join(root, "node_modules")} {
		if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode = %v (%v), want 0700", dir, fi.Mode().Perm(), err)
		}
	}

	// The same resolved set, asked for exactly, is the same content-addressed
	// build and is not rebuilt.
	again := queue(t, m, "ta",
		store.Dependency{Name: "za-left", Version: "1.0.0"},
		store.Dependency{Name: "za-pad", Version: "1.1.0"},
		store.Dependency{Name: "@za/scoped", Version: "2.0.0"})
	if again != id {
		t.Errorf("exact request built %s, want shared %s", again, id)
	}
	if h := st.rec.history(id); len(h) != 3 {
		t.Errorf("built set rebuilt: %v", h)
	}

	// No dependencies is a build too, without npm.
	empty := queue(t, m, "ta")
	if b := waitBuild(t, st, "ta", empty); b.Status != store.BuildBuilt || len(b.Resolved) != 0 {
		t.Errorf("empty build = %+v", b)
	}
	if _, err := m.Ensure(ctx, "ta", empty); err != nil {
		t.Errorf("Ensure(empty): %v", err)
	}
}

func TestBuildRefuses(t *testing.T) {
	node := requireNode(t)
	reg := fixtureRegistry(t, filepath.Join(t.TempDir(), "marker"))
	st := newStore(t, "ta")
	m := newManager(t, testConfig(t, node, reg), st)

	bad := map[string]store.Dependency{
		"caret range":      {Name: "za-pad", Version: "^1.0.0"},
		"tilde range":      {Name: "za-pad", Version: "~1.0.0"},
		"x range":          {Name: "za-pad", Version: "1.x"},
		"comparator":       {Name: "za-pad", Version: ">=1.0.0"},
		"tag":              {Name: "za-pad", Version: "next"},
		"git":              {Name: "za-pad", Version: "git+https://example.test/za-pad.git"},
		"github":           {Name: "za-pad", Version: "github:example/za-pad"},
		"file":             {Name: "za-pad", Version: "file:../za-pad"},
		"url":              {Name: "za-pad", Version: "https://example.test/za-pad-1.0.0.tgz"},
		"alias":            {Name: "za-pad", Version: "npm:za-left@1.0.0"},
		"registry_url":     {Name: "za-pad", Version: reg.URL + "/za-pad/-/za-pad-1.0.0.tgz"},
		"registry in name": {Name: "--registry=" + reg.URL, Version: "1.0.0"},
		"url name":         {Name: reg.URL + "/za-pad", Version: "1.0.0"},
	}
	for label, dep := range bad {
		t.Run(label, func(t *testing.T) {
			before := reg.hits.Load()
			if _, err := m.Queue(context.Background(), "ta", []store.Dependency{dep}, actionsrules.Runtime); !errors.Is(err, ErrInvalid) {
				t.Errorf("Queue(%+v) err = %v, want ErrInvalid", dep, err)
			}
			if reg.hits.Load() != before {
				t.Error("a refused dependency reached the registry")
			}
		})
	}
	if _, err := m.Queue(context.Background(), "ta", nil, "node18"); !errors.Is(err, ErrInvalid) {
		t.Errorf("runtime node18: err = %v", err)
	}
	for _, tenant := range []string{"", ".", "..", "a/b", "../ta", ".builds"} {
		if _, err := m.Queue(context.Background(), tenant, nil, actionsrules.Runtime); !errors.Is(err, ErrInvalid) {
			t.Errorf("tenant %q: err = %v", tenant, err)
		}
	}

	t.Run("size cap", func(t *testing.T) {
		cfg := testConfig(t, node, reg)
		cfg.MaxArtifactMB = 1
		st := newStore(t, "ta")
		m := newManager(t, cfg, st)
		id := queue(t, m, "ta", store.Dependency{Name: "za-big", Version: "1.0.0"})
		b := waitBuild(t, st, "ta", id)
		if b.Status != store.BuildFailed || !strings.Contains(strings.Join(b.Errors, " "), "exceeds") {
			t.Fatalf("build = %s %v, want failed for size", b.Status, b.Errors)
		}
		if _, err := st.Actions().GetArtifact(context.Background(), "ta", id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("oversized artifact stored: %v", err)
		}
		if _, err := m.Ensure(context.Background(), "ta", id); !errors.Is(err, ErrNotBuilt) {
			t.Errorf("Ensure(failed) err = %v, want ErrNotBuilt", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		cfg := testConfig(t, node, reg)
		cfg.BuildTimeout = 2 * time.Second
		st := newStore(t, "ta")
		m := newManager(t, cfg, st)
		start := time.Now()
		id := queue(t, m, "ta", store.Dependency{Name: "za-slow", Version: "1.0.0"})
		b := waitBuild(t, st, "ta", id)
		if b.Status != store.BuildFailed || !strings.Contains(strings.Join(b.Errors, " "), "timed out") {
			t.Fatalf("build = %s %v, want failed for timeout", b.Status, b.Errors)
		}
		if d := time.Since(start); d > 20*time.Second {
			t.Errorf("timeout took %s", d)
		}
	})
}

func TestBuildIgnoresScripts(t *testing.T) {
	node := requireNode(t)
	marker := filepath.Join(t.TempDir(), "marker")
	reg := fixtureRegistry(t, marker)
	st := newStore(t, "ta")
	m := newManager(t, testConfig(t, node, reg), st)
	id := queue(t, m, "ta", store.Dependency{Name: "za-post", Version: "1.0.0"})
	if b := waitBuild(t, st, "ta", id); b.Status != store.BuildBuilt {
		t.Fatalf("status = %s, errors = %v", b.Status, b.Errors)
	}
	root, err := m.Ensure(context.Background(), "ta", id)
	if err != nil {
		t.Fatal(err)
	}
	if installedVersionT(t, root, "za-post") != "1.0.0" {
		t.Error("za-post not installed")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an install script ran: marker %v", err)
	}
}

// probeJS reads every source of the server's secrets it can name. Each entry
// is "denied:<code>" when the read throws. PROBE_FILES is replaced in-test.
const probeJS = `
const fs = require("fs");
const out = { env: JSON.stringify(process.env) };
const files = ["/proc/self/environ", "/proc/" + process.ppid + "/environ", "/proc/1/environ"].concat(PROBE_FILES);
const key = (f) => (f === "/proc/" + process.ppid + "/environ" ? "/proc/<ppid>/environ" : f);
for (const f of files) {
  try { out[key(f)] = "read:" + fs.readFileSync(f, "utf8"); } catch (e) { out[key(f)] = "denied:" + e.code; }
}
try { out.realEnv = JSON.stringify(fs.constructor.constructor("return process")().env); } catch (e) { out.realEnv = "denied"; }
`

// checkProbe fails when the probe saw a canary, a non-private environment or
// any of files.
func checkProbe(t *testing.T, label string, out map[string]string, buildDirPrefix string, files []string) {
	t.Helper()
	raw, _ := json.Marshal(out)
	t.Logf("%s probe: %s", label, raw)
	if bytes.Contains(raw, []byte("s3cr3t-canary")) || bytes.Contains(raw, []byte("config-canary")) || bytes.Contains(raw, []byte("tenant-b-secret")) {
		t.Fatalf("%s: server secret visible: %s", label, raw)
	}
	for _, key := range []string{"env", "realEnv"} {
		v := out[key]
		if key == "realEnv" && v == "denied" {
			continue
		}
		var env map[string]string
		if err := json.Unmarshal([]byte(v), &env); err != nil {
			t.Fatalf("%s: %s = %q", label, key, v)
		}
		for k, val := range env {
			if k != "HOME" || !strings.HasPrefix(val, buildDirPrefix) {
				t.Errorf("%s: %s has %s=%s; only a private HOME is allowed", label, key, k, val)
			}
		}
	}
	for _, f := range append([]string{"/proc/self/environ", "/proc/<ppid>/environ", "/proc/1/environ"}, files...) {
		if out[f] != "denied:ERR_ACCESS_DENIED" {
			t.Errorf("%s: %s = %q, want denied:ERR_ACCESS_DENIED", label, f, out[f])
		}
	}
}

// TestBuildNoServerEnvironment proves the dependency build cannot read the
// server's environment or files (spec §2): npm's CLI is replaced by a probe
// that runs exactly where and how npm would, and the resolver runs the probe
// in its own sandbox.
func TestBuildNoServerEnvironment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the /proc environment probes need Linux")
	}
	node := requireNode(t)
	t.Setenv("ZEROAUTHY_CANARY", "s3cr3t-canary")
	cfgFile := filepath.Join(t.TempDir(), "zeroauthy.yaml")
	if err := os.WriteFile(cfgFile, []byte("master_key: config-canary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := fixtureRegistry(t, filepath.Join(t.TempDir(), "marker"))
	cfg := testConfig(t, node, reg)
	st := newStore(t, "ta", "tb")

	// Tenant B already has a build root with a secret in it.
	other := filepath.Join(cfg.CacheDir, "tb", strings.Repeat("b", 64), "node_modules", "secret.txt")
	if err := os.MkdirAll(filepath.Dir(other), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("tenant-b-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := []string{cfgFile, other}
	fileList, _ := json.Marshal(files)
	probe := strings.ReplaceAll(probeJS, "PROBE_FILES", string(fileList))

	t.Run("npm", func(t *testing.T) {
		// A fake npm installation whose CLI writes the probe result as an
		// installed package, so it travels back in the artifact.
		npmDir := filepath.Join(t.TempDir(), "npm")
		if err := os.MkdirAll(filepath.Join(npmDir, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		cli := probe + `
const path = require("path");
const dir = path.join(process.cwd(), "node_modules", "za-probe");
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "za-probe", version: "1.0.0" }));
fs.writeFileSync(path.join(dir, "probe.json"), JSON.stringify(out));
`
		if err := os.WriteFile(filepath.Join(npmDir, "bin", "npm-cli.js"), []byte(cli), 0o644); err != nil {
			t.Fatal(err)
		}
		c := cfg
		c.NPMCLI = filepath.Join(npmDir, "bin", "npm-cli.js")
		m := newManager(t, c, st)
		id := queue(t, m, "ta", store.Dependency{Name: "za-probe", Version: "1.0.0"})
		if b := waitBuild(t, st, "ta", id); b.Status != store.BuildBuilt {
			t.Fatalf("status = %s, errors = %v", b.Status, b.Errors)
		}
		root, err := m.Ensure(context.Background(), "ta", id)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(root, "node_modules", "za-probe", "probe.json"))
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]string
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		checkProbe(t, "npm build", out, filepath.Join(cfg.CacheDir, buildsDir), files)
	})

	t.Run("resolver", func(t *testing.T) {
		m := newManager(t, cfg, st)
		saved := resolverJS
		resolverJS = probe + `process.stdout.write(JSON.stringify(out));`
		t.Cleanup(func() { resolverJS = saved })
		out, err := m.runResolver(context.Background(), []string{"za-pad"})
		if err != nil {
			t.Fatal(err)
		}
		checkProbe(t, "resolver", out, filepath.Join(cfg.CacheDir, buildsDir), files)
	})
}

func TestEnsureExtractsOnFreshNode(t *testing.T) {
	node := requireNode(t)
	reg := fixtureRegistry(t, filepath.Join(t.TempDir(), "marker"))
	st := newStore(t, "ta")
	ctx := context.Background()
	m1 := newManager(t, testConfig(t, node, reg), st)
	id := queue(t, m1, "ta", store.Dependency{Name: "za-pad", Version: "1.0.0"})
	if b := waitBuild(t, st, "ta", id); b.Status != store.BuildBuilt {
		t.Fatalf("status = %s, errors = %v", b.Status, b.Errors)
	}

	// A second node: same store, empty cache dir, no registry needed.
	cfg2 := testConfig(t, node, reg)
	cfg2.Registry = "http://127.0.0.1:1/"
	m2 := newManager(t, cfg2, st)
	root, err := m2.Ensure(ctx, "ta", id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(root, cfg2.CacheDir) || installedVersionT(t, root, "za-pad") != "1.0.0" {
		t.Errorf("fresh node root %s not extracted", root)
	}
	if again, err := m2.Ensure(ctx, "ta", id); err != nil || again != root {
		t.Errorf("second Ensure = %s, %v", again, err)
	}

	// A corrupt artifact fails closed on a third node and leaves no root.
	art, err := st.Actions().GetArtifact(ctx, "ta", id)
	if err != nil {
		t.Fatal(err)
	}
	art[len(art)/2] ^= 0xff
	if err := st.Actions().PutArtifact(ctx, "ta", id, art); err != nil {
		t.Fatal(err)
	}
	cfg3 := testConfig(t, node, reg)
	m3 := newManager(t, cfg3, st)
	if _, err := m3.Ensure(ctx, "ta", id); !errors.Is(err, ErrCorruptArtifact) {
		t.Errorf("corrupt artifact: err = %v, want ErrCorruptArtifact", err)
	}
	if _, err := os.Stat(filepath.Join(cfg3.CacheDir, "ta", id)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("corrupt artifact left a root: %v", err)
	}
	// Unknown builds and bad IDs fail closed too.
	if _, err := m3.Ensure(ctx, "ta", strings.Repeat("0", 64)); !errors.Is(err, ErrNotBuilt) {
		t.Errorf("unknown build: err = %v", err)
	}
	for _, bad := range [][2]string{{"ta", "../ta"}, {"../x", id}, {"ta", "ABC"}} {
		if _, err := m3.Ensure(ctx, bad[0], bad[1]); !errors.Is(err, ErrInvalid) {
			t.Errorf("Ensure(%q, %q) err = %v, want ErrInvalid", bad[0], bad[1], err)
		}
	}
}

// TestEnsureRejectsEscapes stores artifacts whose entries leave the root and
// checks extraction refuses each, even with a matching SHA-256.
func TestEnsureRejectsEscapes(t *testing.T) {
	ctx := context.Background()
	outside := t.TempDir()
	cases := map[string]tar.Header{
		"dotdot":        {Name: "node_modules/../../" + filepath.Base(outside) + "/x", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1},
		"absolute":      {Name: filepath.Join(outside, "x"), Typeflag: tar.TypeReg, Mode: 0o644, Size: 1},
		"symlink":       {Name: "node_modules/link", Typeflag: tar.TypeSymlink, Linkname: outside},
		"relative link": {Name: "node_modules/link", Typeflag: tar.TypeSymlink, Linkname: "../../.."},
		"hardlink":      {Name: "node_modules/hard", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"},
		"device":        {Name: "node_modules/dev", Typeflag: tar.TypeChar},
	}
	for label, hdr := range cases {
		t.Run(label, func(t *testing.T) {
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			if err := tw.WriteHeader(&hdr); err != nil {
				t.Fatal(err)
			}
			if hdr.Size > 0 {
				_, _ = tw.Write(bytes.Repeat([]byte("x"), int(hdr.Size)))
			}
			_ = tw.Close()
			st := newStore(t, "ta")
			id := strings.Repeat("a", 64)
			sum := sha256.Sum256(buf.Bytes())
			if err := st.Actions().PutBuild(ctx, &store.Build{TenantID: "ta", ID: id, Status: store.BuildBuilt, ArtifactSHA256: hex.EncodeToString(sum[:])}); err != nil {
				t.Fatal(err)
			}
			if err := st.Actions().PutArtifact(ctx, "ta", id, buf.Bytes()); err != nil {
				t.Fatal(err)
			}
			cfg := config.Actions{Node: "node", Registry: "http://127.0.0.1:1/", CacheDir: t.TempDir(), BuildTimeout: time.Minute, MaxArtifactMB: 1, MaxConcurrentBuilds: 1}
			m := newManager(t, cfg, st)
			if _, err := m.Ensure(ctx, "ta", id); !errors.Is(err, ErrCorruptArtifact) {
				t.Errorf("err = %v, want ErrCorruptArtifact", err)
			}
			if entries, _ := os.ReadDir(outside); len(entries) != 0 {
				t.Errorf("extraction wrote outside the root: %v", entries)
			}
			if _, err := os.Stat(filepath.Join(cfg.CacheDir, "ta", id)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("rejected artifact left a root: %v", err)
			}
		})
	}
}

func TestBuildTenantRoots(t *testing.T) {
	node := requireNode(t)
	reg := fixtureRegistry(t, filepath.Join(t.TempDir(), "marker"))
	st := newStore(t, "ta", "tb")
	m := newManager(t, testConfig(t, node, reg), st)
	ctx := context.Background()
	idA := queue(t, m, "ta", store.Dependency{Name: "za-pad", Version: "1.0.0"})
	idB := queue(t, m, "tb", store.Dependency{Name: "za-pad", Version: "1.0.0"})
	if idA != idB {
		t.Fatalf("same set, different IDs: %s %s", idA, idB)
	}
	for _, tn := range []string{"ta", "tb"} {
		if b := waitBuild(t, st, tn, idA); b.Status != store.BuildBuilt {
			t.Fatalf("%s: status = %s, errors = %v", tn, b.Status, b.Errors)
		}
	}
	rootA, err := m.Ensure(ctx, "ta", idA)
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := m.Ensure(ctx, "tb", idB)
	if err != nil {
		t.Fatal(err)
	}
	if rootA == rootB {
		t.Fatal("tenants share a build root")
	}
	dirA, err := m.TenantRoot("ta")
	if err != nil || !strings.HasPrefix(rootA, dirA+string(filepath.Separator)) || strings.HasPrefix(rootB, dirA+string(filepath.Separator)) {
		t.Fatalf("TenantRoot(ta) = %s, %v", dirA, err)
	}

	// Tenant A's runner process reads only tenant A's directory.
	rt, err := noderunner.Detect(node)
	if err != nil {
		t.Fatal(err)
	}
	script := `
const fs = require("fs");
const read = (f) => { try { fs.readFileSync(f, "utf8"); return "read"; } catch (e) { return "denied:" + e.code; } };
process.stdout.write(JSON.stringify({ own: read(process.argv[1]), other: read(process.argv[2]) }));`
	cmd := exec.Command(node, "-e", script,
		filepath.Join(rootA, "node_modules", "za-pad", "index.js"),
		filepath.Join(rootB, "node_modules", "za-pad", "index.js"))
	noderunner.Sandbox(cmd, []string{dirA}, nil, rt.AllowNet)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if string(out) != `{"own":"read","other":"denied:ERR_ACCESS_DENIED"}` {
		t.Errorf("tenant A's process: %s", out)
	}
}

func TestPrewarm(t *testing.T) {
	node := requireNode(t)
	reg := fixtureRegistry(t, filepath.Join(t.TempDir(), "marker"))
	st := newStore(t, "ta")
	ctx := context.Background()
	m1 := newManager(t, testConfig(t, node, reg), st)

	// Nothing deployed: prewarm has nothing to do.
	if err := m1.Prewarm(ctx); err != nil {
		t.Fatalf("Prewarm(empty): %v", err)
	}

	id := queue(t, m1, "ta", store.Dependency{Name: "za-pad", Version: "1.0.0"})
	if b := waitBuild(t, st, "ta", id); b.Status != store.BuildBuilt {
		t.Fatalf("status = %s, errors = %v", b.Status, b.Errors)
	}
	a := &store.Action{TenantID: "ta", ID: "act_1", Name: "a", Trigger: "post-login", Runtime: actionsrules.Runtime,
		Code: "exports.onExecutePostLogin = async () => {};", Dependencies: []store.Dependency{{Name: "za-pad", Version: "1.0.0"}}, DraftBuildID: id}
	if err := st.Actions().CreateAction(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Actions().Deploy(ctx, "ta", "act_1", ""); err != nil {
		t.Fatal(err)
	}

	cfg2 := testConfig(t, node, reg)
	m2 := newManager(t, cfg2, st)
	if err := m2.Prewarm(ctx); err != nil {
		t.Fatal(err)
	}
	if installedVersionT(t, filepath.Join(cfg2.CacheDir, "ta", id), "za-pad") != "1.0.0" {
		t.Error("prewarm did not extract the deployed build")
	}

	// PrewarmBuild extracts in the background.
	cfg3 := testConfig(t, node, reg)
	m3 := newManager(t, cfg3, st)
	m3.PrewarmBuild("ta", id)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(cfg3.CacheDir, "ta", id, "node_modules", "za-pad")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("PrewarmBuild did not extract")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestResolveBoundedAndTimesOut(t *testing.T) {
	node := requireNode(t)
	reg := fixtureRegistry(t, filepath.Join(t.TempDir(), "marker"))
	cfg := testConfig(t, node, reg)
	cfg.MaxConcurrentBuilds = 2
	st := newStore(t, "ta")
	m := newManager(t, cfg, st)

	// Six concurrent saves needing resolution run at most two resolvers.
	const n = 6
	ids := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids[i], errs[i] = m.Queue(context.Background(), "ta", []store.Dependency{{Name: "za-slowmeta", Version: "latest"}}, actionsrules.Runtime)
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil || ids[i] != ids[0] {
			t.Fatalf("Queue %d = %s, %v", i, ids[i], errs[i])
		}
	}
	if peak := reg.slowPeak.Load(); peak < 1 || peak > int64(cfg.MaxConcurrentBuilds) {
		t.Errorf("peak concurrent resolvers = %d, want 1..%d", peak, cfg.MaxConcurrentBuilds)
	}
	if b := waitBuild(t, st, "ta", ids[0]); b.Status != store.BuildBuilt {
		t.Errorf("status = %s, errors = %v", b.Status, b.Errors)
	}

	saved := resolveTimeout
	resolveTimeout = time.Second
	t.Cleanup(func() { resolveTimeout = saved })
	hang := []store.Dependency{{Name: "za-hangmeta", Version: ""}}
	start := time.Now()
	if _, err := m.Queue(context.Background(), "ta", hang, actionsrules.Runtime); !errors.Is(err, ErrResolveTimeout) {
		t.Errorf("hung registry: err = %v, want ErrResolveTimeout", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("resolve timeout took %s", d)
	}

	// A caller that gives up gets its own context error, not a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := m.Queue(ctx, "ta", hang, actionsrules.Runtime); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrResolveTimeout) {
		t.Errorf("cancelled caller: err = %v, want context.DeadlineExceeded", err)
	}
	cancelled, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, err := m.Queue(cancelled, "ta", hang, actionsrules.Runtime); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled caller: err = %v, want context.Canceled", err)
	}
}

// TestInterruptedBuildsResume simulates a server stopped mid-build: a fresh
// Manager over the same store rebuilds a record left building, through
// Queue of the same set and through Recover.
func TestInterruptedBuildsResume(t *testing.T) {
	node := requireNode(t)
	reg := fixtureRegistry(t, filepath.Join(t.TempDir(), "marker"))
	ctx := context.Background()
	deps := []store.Dependency{{Name: "za-pad", Version: "1.0.0"}}
	id := ID(actionsrules.Runtime, deps)
	for _, via := range []string{"queue", "recover"} {
		t.Run(via, func(t *testing.T) {
			st := newStore(t, "ta")
			if err := st.Actions().PutBuild(ctx, &store.Build{TenantID: "ta", ID: id, Status: store.BuildBuilding, Requested: deps, Resolved: deps}); err != nil {
				t.Fatal(err)
			}
			m := newManager(t, testConfig(t, node, reg), st)
			if via == "queue" {
				if got := queue(t, m, "ta", deps...); got != id {
					t.Fatalf("Queue = %s, want %s", got, id)
				}
			} else if err := m.Recover(ctx, "ta", id); err != nil {
				t.Fatal(err)
			}
			if b := waitBuild(t, st, "ta", id); b.Status != store.BuildBuilt {
				t.Fatalf("status = %s, errors = %v", b.Status, b.Errors)
			}
			if _, err := m.Ensure(ctx, "ta", id); err != nil {
				t.Fatal(err)
			}
			// Recover leaves built builds alone.
			n := len(st.rec.history(id))
			if err := m.Recover(ctx, "ta", id); err != nil || len(st.rec.history(id)) != n {
				t.Errorf("Recover(built) = %v, history %v", err, st.rec.history(id))
			}
		})
	}
}

// TestQueueNeverDowngradesBuilt queues an empty set twice concurrently, with
// the first Queue's (stale) store read held back until the second Queue's
// build has finished:
// once built, the record is never written pending again.
func TestQueueNeverDowngradesBuilt(t *testing.T) {
	st := newStore(t, "ta")
	st.rec.staleGet = func(n int) time.Duration {
		if n == 1 {
			return 200 * time.Millisecond
		}
		return 0
	}
	cfg := config.Actions{Node: "node", Registry: "http://127.0.0.1:1/", CacheDir: t.TempDir(), BuildTimeout: time.Minute, MaxArtifactMB: 1, MaxConcurrentBuilds: 2}
	m := newManager(t, cfg, st)
	id := ID(actionsrules.Runtime, nil)
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 20 * time.Millisecond)
			if _, err := m.Queue(context.Background(), "ta", nil, actionsrules.Runtime); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	waitBuild(t, st, "ta", id)
	h := st.rec.history(id)
	if i := slices.Index(h, store.BuildBuilt); i < 0 || slices.Contains(h[i:], store.BuildPending) {
		t.Errorf("status history %v: a built record was downgraded", h)
	}
}

// TestMissingDefaultCacheDir: a server that cannot name a default cache dir
// still starts; the Manager fails only when it needs the directory.
func TestMissingDefaultCacheDir(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("os.UserCacheDir's environment differs off Linux")
	}
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", "")
	st := newStore(t, "ta")
	m := newManager(t, config.Actions{}, st)
	ctx := context.Background()
	if err := m.Prewarm(ctx); err != nil {
		t.Errorf("Prewarm with nothing deployed: %v", err)
	}
	if _, err := m.Queue(ctx, "ta", nil, actionsrules.Runtime); err == nil || !strings.Contains(err.Error(), "actions.cache_dir") {
		t.Errorf("Queue err = %v, want a cache_dir error", err)
	}
	if _, err := m.Ensure(ctx, "ta", strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "actions.cache_dir") {
		t.Errorf("Ensure err = %v, want a cache_dir error", err)
	}
}
