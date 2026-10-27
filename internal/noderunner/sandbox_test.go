package noderunner_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/noderunner"
)

// fixtureRegistry serves one package, za-pad@1.0.0, the way the npm registry
// does: a packument at /za-pad and its tarball.
func fixtureRegistry(t *testing.T) *httptest.Server {
	t.Helper()
	var tgz bytes.Buffer
	gz := gzip.NewWriter(&tgz)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{
		"package/package.json": `{"name":"za-pad","version":"1.0.0","main":"index.js"}`,
		"package/index.js":     `module.exports = (s) => "[" + s + "]";`,
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	tarball := tgz.Bytes()
	s1 := sha1.Sum(tarball)
	s512 := sha512.Sum512(tarball)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/za-pad":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name": "za-pad", "dist-tags": map[string]string{"latest": "1.0.0"},
				"versions": map[string]any{"1.0.0": map[string]any{
					"name": "za-pad", "version": "1.0.0", "main": "index.js",
					"dist": map[string]string{
						"tarball":   srv.URL + "/za-pad/-/za-pad-1.0.0.tgz",
						"shasum":    hex.EncodeToString(s1[:]),
						"integrity": "sha512-" + base64.StdEncoding.EncodeToString(s512[:]),
					},
				}},
			})
		case "/za-pad/-/za-pad-1.0.0.tgz":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(tarball)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testNodes is the node on PATH plus any listed in ZA_TEST_NODES
// (colon-separated), so the gate can run on several Node versions.
func testNodes(t *testing.T) []string {
	nodes := []string{requireNode(t)}
	for _, n := range filepath.SplitList(os.Getenv("ZA_TEST_NODES")) {
		if n != "" {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// TestSandboxNPMFeasibility proves npm's own CLI can install a registry
// package under the build sandbox: reads limited to the npm installation and
// the build dir, writes to the build dir, no child processes, empty
// environment (spec §5).
func TestSandboxNPMFeasibility(t *testing.T) {
	reg := fixtureRegistry(t)
	for _, node := range testNodes(t) {
		rt, err := noderunner.Detect(node)
		if err != nil {
			t.Fatalf("%s: %v", node, err)
		}
		t.Run(rt.Version, func(t *testing.T) {
			npmDir, err := filepath.EvalSymlinks(filepath.Join(filepath.Dir(node), "..", "lib", "node_modules", "npm"))
			if err != nil {
				t.Skipf("no bundled npm next to %s: %v", node, err)
			}
			build := t.TempDir()
			if err := os.WriteFile(filepath.Join(build, "package.json"),
				[]byte(`{"name":"build","version":"1.0.0","private":true,"dependencies":{"za-pad":"1.0.0"}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), noderunner.DefaultBudget*3)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, filepath.Join(npmDir, "bin", "npm-cli.js"), "install",
				"--ignore-scripts", "--no-audit", "--no-fund", "--no-update-notifier",
				"--registry="+reg.URL+"/",
				"--cache="+filepath.Join(build, ".npm-cache"),
				"--userconfig="+filepath.Join(build, ".npmrc"))
			noderunner.Sandbox(cmd, []string{npmDir, build}, []string{build}, rt.AllowNet)
			cmd.Dir = build
			out, err := cmd.CombinedOutput()
			t.Logf("node %s (allow-net %v): %s", rt.Version, rt.AllowNet, out)
			if err != nil {
				t.Fatalf("sandboxed npm install failed: %v\n%s", err, out)
			}
			if b, err := os.ReadFile(filepath.Join(build, "node_modules", "za-pad", "index.js")); err != nil || !strings.Contains(string(b), "module.exports") {
				t.Fatalf("za-pad not installed: %v", err)
			}
			for _, a := range cmd.Args {
				if strings.HasPrefix(a, "--allow-child-process") || strings.HasPrefix(a, "--allow-worker") ||
					strings.HasPrefix(a, "--allow-addons") || strings.HasPrefix(a, "--allow-wasi") {
					t.Errorf("sandbox grants %s", a)
				}
			}
			if len(cmd.Env) != 0 {
				t.Errorf("env = %v, want empty", cmd.Env)
			}
		})
	}
}

// envProbe reads every source of the server's secrets it can name; each
// entry is "denied:<code>" when the read throws.
const envProbe = `
  const fs = require("fs");
  const out = { env: JSON.stringify(process.env) };
  const files = ["/proc/self/environ", "/proc/" + process.ppid + "/environ", "/proc/1/environ", OTHER, CONFIG];
  for (const f of files) {
    try { out[f] = "read:" + fs.readFileSync(f, "utf8"); } catch (e) { out[f] = "denied:" + e.code; }
  }
  try { out.realEnv = JSON.stringify(fs.constructor.constructor("return process")().env); } catch (e) { out.realEnv = "denied"; }
`

func checkNoServerEnvironment(t *testing.T, label string, raw []byte, files []string) {
	t.Helper()
	t.Logf("%s probe: %s", label, raw)
	if bytes.Contains(raw, []byte("s3cr3t-canary")) || bytes.Contains(raw, []byte("config-canary")) {
		t.Fatalf("%s: server secret visible: %s", label, raw)
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: %v (%s)", label, err, raw)
	}
	if out["env"] != "{}" {
		t.Errorf("%s: process.env = %s, want {}", label, out["env"])
	}
	if v := out["realEnv"]; v != "{}" && v != "denied" {
		t.Errorf("%s: escaped process.env = %s", label, v)
	}
	for _, f := range files {
		if out[f] != "denied:ERR_ACCESS_DENIED" {
			t.Errorf("%s: %s = %q, want denied:ERR_ACCESS_DENIED", label, f, out[f])
		}
	}
}

// TestSandboxNoServerEnvironment proves neither Action code nor custom
// database scripts can read the server's environment or files (spec §2).
func TestSandboxNoServerEnvironment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the /proc environment probes need Linux")
	}
	t.Setenv("ZEROAUTHY_CANARY", "s3cr3t-canary")
	root := t.TempDir()
	for _, tenant := range []string{"t1", "t2"} {
		if err := os.MkdirAll(filepath.Join(root, tenant), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, tenant, "secret.txt"), []byte("tenant "+tenant), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfgFile := filepath.Join(t.TempDir(), "zeroauthy.yaml")
	if err := os.WriteFile(cfgFile, []byte("master_key: config-canary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "t2", "secret.txt")
	files := []string{"/proc/self/environ", "/proc/<ppid>/environ", "/proc/1/environ", other, cfgFile}
	probe := strings.NewReplacer("OTHER", fmt.Sprintf("%q", other), "CONFIG", fmt.Sprintf("%q", cfgFile)).Replace(envProbe)
	normalise := func(raw []byte) []byte {
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			return raw
		}
		for k, v := range out {
			if strings.HasPrefix(k, "/proc/") && strings.HasSuffix(k, "/environ") && k != "/proc/self/environ" && k != "/proc/1/environ" {
				delete(out, k)
				out["/proc/<ppid>/environ"] = v
			}
		}
		b, _ := json.Marshal(out)
		return b
	}

	t.Run("action", func(t *testing.T) {
		p := actionsPool(t, root)
		resp := callAction(t, p, "t1", actionRequest{VersionKey: "v1",
			Code: `exports.onExecutePostLogin = async (event, api) => {` + probe + `
			  out.own = fs.readFileSync(` + fmt.Sprintf("%q", filepath.Join(root, "t1", "secret.txt")) + `, "utf8");
			  api.accessToken.setCustomClaim("probe", out);
			};`})
		raw := claim(t, resp, "probe")
		checkNoServerEnvironment(t, "action", normalise(raw), files)
		if !bytes.Contains(raw, []byte(`"own":"tenant t1"`)) {
			t.Errorf("own build root unreadable: %s", raw)
		}
	})

	t.Run("customdb", func(t *testing.T) {
		requireNode(t)
		r, err := customdb.NewNodeRunner(config.CustomDB{ModulesDir: filepath.Join(root, "t1")}, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close() })
		res, err := r.Execute(context.Background(), customdb.Request{TenantID: "t1", ConnectionID: "c1", Script: "login",
			Args: []any{"e", "p"}, Source: `function login(e, p, cb) {` + probe + ` cb(null, out); }`})
		if err != nil {
			t.Fatal(err)
		}
		checkNoServerEnvironment(t, "customdb", normalise(res), files)
	})
}
