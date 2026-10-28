// Package build builds Actions' npm dependencies in a sandbox and shares
// the packed result through the store (spec §5).
//
// A build installs the resolved dependency set with npm's own CLI run as
// `node --permission`: an empty environment except a private HOME, file
// reads limited to the npm installation and the build directory, writes
// limited to the build directory, no child processes, workers, addons or
// WASI, --ignore-scripts, a time limit and a size cap (spec §2). Resolving
// empty/"latest" versions runs in the same sandbox. The tree is packed into
// a tar artifact stored with its SHA-256, so every node extracts the same
// bytes into <CacheDir>/<tenantID>/<buildID>/.
package build

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/noderunner"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	// ErrInvalid reports a refused build request: an unsupported runtime,
	// a dependency rule violation or an unusable tenant or build ID.
	ErrInvalid = errors.New("build: invalid build request")
	// ErrNotBuilt reports a build that is unknown, pending or failed.
	ErrNotBuilt = errors.New("build: dependencies are not built")
	// ErrCorruptArtifact reports a missing, altered or unsafe artifact.
	ErrCorruptArtifact = errors.New("build: dependency artifact is missing or corrupt")
	// ErrResolveTimeout reports that resolving empty/"latest" versions took
	// longer than ResolveTimeout.
	ErrResolveTimeout = errors.New("build: resolving dependency versions timed out")
)

// ResolveTimeout bounds the synchronous resolution in Queue.
const ResolveTimeout = 15 * time.Second

// resolveTimeout is ResolveTimeout; tests shorten it.
var resolveTimeout = ResolveTimeout

// buildsDir under the cache dir holds private work directories. Tenant IDs
// cannot start with a dot, so it never collides with a tenant's directory.
const buildsDir = ".builds"

var (
	tenantIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	buildIDRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Manager queues builds and extracts their artifacts.
type Manager struct {
	cfg      config.Actions
	st       store.Store
	log      *slog.Logger
	cacheDir string
	registry string
	maxBytes int64         // installed and packed size cap
	sem      chan struct{} // running builds
	resSem   chan struct{} // running resolver processes
	dirErr   error         // no usable default cache dir; reported on first use

	ctx    context.Context // the Manager's lifetime; builds outlive requests
	cancel context.CancelFunc
	wg     sync.WaitGroup

	rtOnce sync.Once
	rt     noderunner.Runtime
	rtErr  error

	npmOnce sync.Once
	npmPath string
	npmDir  string
	npmErr  error

	mu       sync.Mutex
	inflight map[string]bool     // tenant/build queued or running here
	locks    map[string]*keyLock // per tenant/build extraction
}

type keyLock struct {
	sync.Mutex
	refs int
}

// New returns a Manager. Zero fields of cfg take config's defaults; an empty
// CacheDir is <user cache dir>/zeroauthy/actions-cache, created 0700 on
// first use. Node and npm are looked up on the first build, so a server
// without them still starts and its builds fail.
func New(cfg config.Actions, st store.Store, log *slog.Logger) (*Manager, error) {
	if cfg.Node == "" {
		cfg.Node = "node"
	}
	if cfg.Registry == "" {
		cfg.Registry = "https://registry.npmjs.org/"
	}
	if cfg.BuildTimeout <= 0 {
		cfg.BuildTimeout = 2 * time.Minute
	}
	if cfg.MaxConcurrentBuilds <= 0 {
		cfg.MaxConcurrentBuilds = 2
	}
	limit := int64(actionsrules.Inventory().Limits["artifact_bytes_max"])
	maxBytes := limit
	if cfg.MaxArtifactMB > 0 && int64(cfg.MaxArtifactMB)*1_000_000 < limit {
		maxBytes = int64(cfg.MaxArtifactMB) * 1_000_000
	}
	if cfg.MaxArtifactMB <= 0 {
		cfg.MaxArtifactMB = int(limit / 1_000_000)
	}
	if log == nil {
		log = slog.Default()
	}
	dir := cfg.CacheDir
	var dirErr error
	if dir == "" {
		// Servers that never use Actions must still start: the error is
		// returned when the Manager first needs the directory.
		if base, err := os.UserCacheDir(); err != nil {
			dirErr = fmt.Errorf("build: no default Actions cache dir (set actions.cache_dir): %w", err)
			log.Warn("actions: builds unavailable until actions.cache_dir is set", "err", err)
		} else {
			dir = filepath.Join(base, "zeroauthy", "actions-cache")
		}
	}
	if dirErr == nil && !filepath.IsAbs(dir) {
		return nil, errors.New("build: actions.cache_dir must be an absolute path")
	}
	if dirErr == nil {
		dir = filepath.Clean(dir) // created 0700 on first use
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		cfg: cfg, st: st, log: log, cacheDir: dir,
		registry: strings.TrimSuffix(cfg.Registry, "/") + "/",
		maxBytes: maxBytes, dirErr: dirErr,
		sem: make(chan struct{}, cfg.MaxConcurrentBuilds), resSem: make(chan struct{}, cfg.MaxConcurrentBuilds),
		ctx: ctx, cancel: cancel,
		inflight: map[string]bool{}, locks: map[string]*keyLock{},
	}, nil
}

// Close stops queued and running builds and waits for them. A build stopped
// this way stays pending or building in the store and is rebuilt by the
// next Queue of its set or by Recover.
func (m *Manager) Close() {
	m.mu.Lock()
	m.cancel()
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *Manager) runtime() (noderunner.Runtime, error) {
	m.rtOnce.Do(func() { m.rt, m.rtErr = noderunner.Detect(m.cfg.Node) })
	return m.rt, m.rtErr
}

// npm returns npm-cli.js and the npm installation directory it reads.
func (m *Manager) npm() (cli, dir string, err error) {
	m.npmOnce.Do(func() {
		if m.cfg.NPMCLI != "" {
			m.npmPath, m.npmErr = npmCLI(m.cfg.NPMCLI)
		} else {
			m.npmPath, m.npmErr = bundledNPM(m.cfg.Node)
		}
		if m.npmErr != nil {
			m.npmErr = fmt.Errorf("npm is unavailable: %v", m.npmErr)
			return
		}
		m.npmDir = filepath.Dir(filepath.Dir(m.npmPath)) // <npm>/bin/npm-cli.js
	})
	return m.npmPath, m.npmDir, m.npmErr
}

// TenantRoot returns the tenant's cache directory, the only one its runner
// process may read; it holds one directory per build.
func (m *Manager) TenantRoot(tenantID string) (string, error) {
	if !tenantIDRE.MatchString(tenantID) {
		return "", fmt.Errorf("%w: tenant ID %q", ErrInvalid, tenantID)
	}
	if m.dirErr != nil {
		return "", m.dirErr
	}
	if err := mkdirPrivate(m.cacheDir); err != nil {
		return "", err
	}
	dir := filepath.Join(m.cacheDir, tenantID)
	return dir, mkdirPrivate(dir)
}

// Queue validates deps, resolves empty/"latest" versions synchronously
// (sandboxed, at most MaxConcurrentBuilds resolutions at once, bounded by
// ResolveTimeout) and queues the build of the resolved set, returning its
// content-addressed ID before the build runs; the record goes pending →
// building → built or failed. A set already built for the tenant is not
// rebuilt. A resolution timeout returns ErrResolveTimeout and a cancelled
// ctx its error; any other resolution failure is recorded as a failed build
// of the requested set.
func (m *Manager) Queue(ctx context.Context, tenantID string, deps []store.Dependency, runtime string) (string, error) {
	if !tenantIDRE.MatchString(tenantID) {
		return "", fmt.Errorf("%w: tenant ID %q", ErrInvalid, tenantID)
	}
	if runtime != actionsrules.Runtime {
		return "", fmt.Errorf("%w: runtime must be %q", ErrInvalid, actionsrules.Runtime)
	}
	if errs := actionsrules.ValidateDependencies(deps); len(errs) > 0 {
		return "", fmt.Errorf("%w: %w", ErrInvalid, errors.Join(errs...))
	}
	if m.dirErr != nil {
		return "", m.dirErr
	}
	requested := slices.Clone(deps)
	b := &store.Build{TenantID: tenantID, Status: store.BuildPending, Requested: requested}
	resolved, rerr := m.resolve(ctx, requested)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if errors.Is(rerr, ErrResolveTimeout) {
		return "", rerr
	}
	if rerr != nil {
		b.ID = unresolvedID(runtime, requested)
		b.Status, b.Errors = store.BuildFailed, []string{rerr.Error()}
		if err := m.st.Actions().PutBuild(ctx, b); err != nil {
			return "", err
		}
		return b.ID, nil
	}
	b.ID, b.Resolved = ID(runtime, resolved), resolved
	if err := m.start(ctx, b); err != nil {
		return "", err
	}
	return b.ID, nil
}

// Recover restarts a known build left pending or building by a stopped
// server (one not in flight on this node), from its recorded resolved set.
// Built, failed and in-flight builds are left alone.
func (m *Manager) Recover(ctx context.Context, tenantID, buildID string) error {
	if !tenantIDRE.MatchString(tenantID) || !buildIDRE.MatchString(buildID) {
		return fmt.Errorf("%w: tenant %q build %q", ErrInvalid, tenantID, buildID)
	}
	if m.dirErr != nil {
		return m.dirErr
	}
	b, err := m.st.Actions().GetBuild(ctx, tenantID, buildID)
	if err != nil {
		return err
	}
	if b.Status != store.BuildPending && b.Status != store.BuildBuilding {
		return nil
	}
	return m.start(ctx, &store.Build{TenantID: tenantID, ID: buildID, Status: store.BuildPending, Requested: b.Requested, Resolved: b.Resolved})
}

// start records b pending and runs it, unless this node is already building
// it or the store has it built. A record that is pending or building but not
// in flight here was left by a stopped server (or is being built by another
// node) and is rebuilt: builds are content-addressed and packing is
// deterministic, so duplicate builds across nodes store identical artifacts.
// The per-key lock and the re-read make the check and the write atomic on
// this node, so a built record is never downgraded to pending.
func (m *Manager) start(ctx context.Context, b *store.Build) error {
	key := b.TenantID + "/" + b.ID
	unlock := m.lock("queue:" + key)
	defer unlock()
	m.mu.Lock()
	busy, closed := m.inflight[key], m.ctx.Err() != nil
	m.mu.Unlock()
	switch {
	case busy:
		return nil
	case closed:
		return errors.New("build: manager is closed")
	}
	old, err := m.st.Actions().GetBuild(ctx, b.TenantID, b.ID)
	switch {
	case err == nil && old.Status == store.BuildBuilt:
		return nil
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return err
	}
	if err := m.st.Actions().PutBuild(ctx, b); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return nil // closing: the pending record is recovered later
	}
	m.inflight[key] = true
	m.wg.Add(1)
	go m.run(key, b)
	return nil
}

// resolve returns deps with empty/"latest" versions replaced by the
// registry's latest version, sorted by name.
func (m *Manager) resolve(ctx context.Context, deps []store.Dependency) ([]store.Dependency, error) {
	var names []string
	for _, d := range deps {
		if d.Version == "" || d.Version == "latest" {
			names = append(names, d.Name)
		}
	}
	out := slices.Clone(deps)
	if len(names) > 0 {
		latest, err := m.runResolver(ctx, names)
		if err != nil {
			return nil, err
		}
		for i, d := range out {
			if d.Version != "" && d.Version != "latest" {
				continue
			}
			v := latest[d.Name]
			if v == "" || v == "latest" || len(actionsrules.ValidateDependencies([]store.Dependency{{Name: d.Name, Version: v}})) > 0 {
				return nil, fmt.Errorf("the registry's latest version of %q is not exact semver", d.Name)
			}
			out[i].Version = v
		}
	}
	slices.SortFunc(out, func(a, b store.Dependency) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// unresolvedID addresses a failed resolution of a requested set; it never
// equals a resolved build's ID.
func unresolvedID(runtime string, requested []store.Dependency) string {
	return ID("unresolved\x00"+runtime, requested)
}

// run builds b within the concurrency bound and records the outcome.
func (m *Manager) run(key string, b *store.Build) {
	defer m.wg.Done()
	defer func() {
		m.mu.Lock()
		delete(m.inflight, key)
		m.mu.Unlock()
	}()
	select {
	case m.sem <- struct{}{}:
	case <-m.ctx.Done():
		return
	}
	defer func() { <-m.sem }()
	ctx, acts := m.ctx, m.st.Actions()
	b.Status = store.BuildBuilding
	if err := acts.PutBuild(ctx, b); err != nil {
		m.log.Warn("actions build: recording status failed", "tenant", b.TenantID, "build", b.ID, "err", err)
	}
	art, err := m.build(ctx, b)
	if err == nil {
		err = acts.PutArtifact(ctx, b.TenantID, b.ID, art)
	}
	if err == nil {
		b.Status, b.ArtifactSHA256, b.BuiltAt, b.Errors = store.BuildBuilt, sha256Hex(art), time.Now().UTC(), nil
		err = acts.PutBuild(ctx, b)
	}
	if ctx.Err() != nil {
		return // shutting down: the record stays building and is re-queued later
	}
	if err != nil {
		m.log.Info("actions build failed", "tenant", b.TenantID, "build", b.ID, "err", err)
		b.Status, b.ArtifactSHA256, b.BuiltAt, b.Errors = store.BuildFailed, "", time.Time{}, []string{err.Error()}
		if err := acts.PutBuild(ctx, b); err != nil {
			m.log.Warn("actions build: recording failure failed", "tenant", b.TenantID, "build", b.ID, "err", err)
		}
		return
	}
	unlock := m.lock(key)
	defer unlock()
	if _, err := m.install(b.TenantID, b.ID, art, b.ArtifactSHA256); err != nil {
		m.log.Warn("actions build: extracting artifact failed", "tenant", b.TenantID, "build", b.ID, "err", err)
	}
}

// build installs b.Resolved in a private work dir and packs the tree.
func (m *Manager) build(ctx context.Context, b *store.Build) ([]byte, error) {
	dir, err := m.workDir("build-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if len(b.Resolved) > 0 {
		deps := map[string]string{}
		for _, d := range b.Resolved {
			deps[d.Name] = d.Version
		}
		pj, _ := json.Marshal(map[string]any{"name": "zeroauthy-action-deps", "version": "1.0.0", "private": true, "dependencies": deps})
		if err := os.WriteFile(filepath.Join(dir, "package.json"), pj, 0o600); err != nil {
			return nil, err
		}
		if err := m.runNPM(ctx, dir); err != nil {
			return nil, err
		}
		for _, d := range b.Resolved {
			if got := installedVersion(dir, d.Name); stripBuild(got) != stripBuild(d.Version) {
				return nil, fmt.Errorf("npm installed %s@%q, want %s", d.Name, got, d.Version)
			}
		}
	}
	art, err := pack(dir, m.maxBytes)
	if errors.Is(err, errTooLarge) {
		return nil, fmt.Errorf("the dependency tree exceeds the %d MB artifact size limit", m.cfg.MaxArtifactMB)
	}
	return art, err
}

func installedVersion(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, "node_modules", filepath.FromSlash(name), "package.json"))
	if err != nil {
		return ""
	}
	var pj struct{ Version string }
	_ = json.Unmarshal(b, &pj)
	return pj.Version
}

func stripBuild(v string) string {
	v, _, _ = strings.Cut(v, "+")
	return v
}

// Ensure returns the extracted root of a built build, extracting it from
// the store when this node lacks it after checking the artifact's SHA-256.
// It fails closed: ErrNotBuilt for an unknown or unfinished build,
// ErrCorruptArtifact for a missing, altered or unsafe artifact.
func (m *Manager) Ensure(ctx context.Context, tenantID, buildID string) (string, error) {
	if !tenantIDRE.MatchString(tenantID) || !buildIDRE.MatchString(buildID) {
		return "", fmt.Errorf("%w: tenant %q build %q", ErrInvalid, tenantID, buildID)
	}
	if m.dirErr != nil {
		return "", m.dirErr
	}
	root := filepath.Join(m.cacheDir, tenantID, buildID)
	if isDir(root) {
		return root, nil
	}
	unlock := m.lock(tenantID + "/" + buildID)
	defer unlock()
	if isDir(root) {
		return root, nil
	}
	b, err := m.st.Actions().GetBuild(ctx, tenantID, buildID)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrNotBuilt
	}
	if err != nil {
		return "", err
	}
	if b.Status != store.BuildBuilt || b.ArtifactSHA256 == "" {
		return "", ErrNotBuilt
	}
	art, err := m.st.Actions().GetArtifact(ctx, tenantID, buildID)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrCorruptArtifact
	}
	if err != nil {
		return "", err
	}
	return m.install(tenantID, buildID, art, b.ArtifactSHA256)
}

// install verifies art against sum and extracts it atomically into the
// build's root. The caller holds the build's lock.
func (m *Manager) install(tenantID, buildID string, art []byte, sum string) (string, error) {
	root := filepath.Join(m.cacheDir, tenantID, buildID)
	if isDir(root) {
		return root, nil
	}
	limit := int64(actionsrules.Inventory().Limits["artifact_bytes_max"])
	if int64(len(art)) > limit || sha256Hex(art) != sum {
		return "", ErrCorruptArtifact
	}
	tdir, err := m.TenantRoot(tenantID)
	if err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(tdir, ".extract-")
	if err != nil {
		return "", err
	}
	if err := extract(art, tmp, limit); err != nil {
		_ = os.RemoveAll(tmp)
		return "", fmt.Errorf("%w: %v", ErrCorruptArtifact, err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "node_modules"), 0o700); err != nil {
		_ = os.RemoveAll(tmp)
		return "", err
	}
	if err := os.Rename(tmp, root); err != nil {
		_ = os.RemoveAll(tmp)
		if isDir(root) {
			return root, nil
		}
		return "", err
	}
	return root, nil
}

// lock serialises work on one tenant/build key.
func (m *Manager) lock(key string) (unlock func()) {
	m.mu.Lock()
	l := m.locks[key]
	if l == nil {
		l = &keyLock{}
		m.locks[key] = l
	}
	l.refs++
	m.mu.Unlock()
	l.Lock()
	return func() {
		l.Unlock()
		m.mu.Lock()
		if l.refs--; l.refs == 0 {
			delete(m.locks, key)
		}
		m.mu.Unlock()
	}
}

// Prewarm extracts every tenant's deployed builds that this node lacks. It
// runs at startup; extraction failures are returned joined and also fail
// the affected flows closed later.
func (m *Manager) Prewarm(ctx context.Context) error {
	tenants, err := m.st.Tenants().List(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range tenants {
		if !tenantIDRE.MatchString(t.ID) {
			continue
		}
		for page := 0; ; page++ {
			p, err := m.st.Actions().ListActions(ctx, t.ID, store.ActionFilter{PageRequest: store.PageRequest{Page: page, PerPage: store.MaxPerPage}})
			if errors.Is(err, store.ErrActionsUnavailable) {
				return nil
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("tenant %s: %w", t.ID, err))
				break
			}
			for _, a := range p.Items {
				if a.DeployedVersionID == "" {
					continue
				}
				v, err := m.st.Actions().GetVersion(ctx, t.ID, a.ID, a.DeployedVersionID)
				if err == nil {
					_, err = m.Ensure(ctx, t.ID, v.BuildID)
				}
				if err != nil {
					errs = append(errs, fmt.Errorf("tenant %s action %s: %w", t.ID, a.ID, err))
				}
			}
			if len(p.Items) == 0 || (page+1)*store.MaxPerPage >= p.Total {
				break
			}
		}
	}
	return errors.Join(errs...)
}

// PrewarmBuild extracts one build in the background, e.g. after a deploy.
func (m *Manager) PrewarmBuild(tenantID, buildID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if _, err := m.Ensure(m.ctx, tenantID, buildID); err != nil && m.ctx.Err() == nil {
			m.log.Warn("actions: pre-extracting build failed", "tenant", tenantID, "build", buildID, "err", err)
		}
	}()
}

func isDir(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.IsDir()
}

// mkdirPrivate creates dir (and parents) and makes dir itself 0700.
func mkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}
