package customdb

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestProcessMasksCredentialConfigurationOverlap(t *testing.T) {
	for _, tt := range []struct{ name, configured, credential, text, want string }{
		{"config_inside_credential", "middle", "prefix-middle-suffix", "prefix-middle-suffix middle", logscrub.Marker + " " + Mask},
		{"credential_inside_config", "prefix-middle-suffix", "middle", "prefix-middle-suffix", Mask},
		{"partial_overlap", "middle-suffix", "prefix-middle", "prefix-middle-suffix", logscrub.Marker},
		{"one_rune_config", "b", "abc", "abc", logscrub.Marker},
		{"one_rune_credential", "abc", "b", "abc", Mask},
		{"same_value", "abc", "abc", "abc", Mask},
		{"truncated_credential", "middle", "prefix-middle-suffix", strings.Repeat("x", 2030) + "prefix-middle-suff", strings.Repeat("x", 2030) + logscrub.Marker},
		{"escaped_json", "middle", "prefix-middle-suffix", `{"\u0070refix-middle-suffix":"\u0070refix-middle-suffix"}`, `{"` + logscrub.Marker + `":"` + logscrub.Marker + `"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := newMaskTestProcess(256, 64<<10)
			p.registerMasks(logscrub.WithCredentials(context.Background(), tt.credential), Request{Config: map[string]string{"K": tt.configured}})
			got := p.capture([]string{tt.text})
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("capture=%q want=%q", got, tt.want)
			}
		})
	}
}

func TestRunnerMasksCredentialConfigurationOverlap(t *testing.T) {
	var sink syncBuffer
	r := newRunnerLog(t, config.CustomDB{}, slog.New(slog.NewJSONHandler(&sink, nil)))
	var lines []string
	req := Request{TenantID: "overlap", ConnectionID: "c", Script: store.ScriptLogin, Config: map[string]string{"K": "middle"}, Args: []any{"a", "prefix-middle-suffix"}, OnLogs: func(v []string) { lines = v }, Source: `function login(e,p,cb){console.log("overlap",p);console.log(configuration.K);console.log(JSON.stringify({[p]:p}));console.log("x".repeat(2030)+p);cb(null,{name:p});setTimeout(()=>console.log("late-overlap",p),30);}`}
	raw, err := r.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"name":"prefix-middle-suffix"}` {
		t.Fatalf("business result changed: %s", raw)
	}
	if len(lines) != 4 || lines[0] != "overlap "+logscrub.Marker || lines[1] != Mask {
		t.Fatalf("captured=%q", lines)
	}
	for _, line := range lines {
		if strings.Contains(line, "prefix") || strings.Contains(line, "suff") {
			t.Fatalf("captured credential fragments: %q", line)
		}
	}
	waitLog(t, &sink, "late-overlap")
	if out := sink.String(); strings.Contains(out, "prefix") || strings.Contains(out, "suff") {
		t.Fatalf("stderr credential fragments: %s", out)
	}
}

type overlapConsoleExecutor struct{ lines []string }

func (e overlapConsoleExecutor) Execute(_ context.Context, req Request) (json.RawMessage, error) {
	req.OnLogs(append([]string(nil), e.lines...))
	return json.RawMessage(`{"ok":true}`), nil
}
func (overlapConsoleExecutor) Close() error { return nil }

func TestClientTryMasksCredentialConfigurationOverlap(t *testing.T) {
	wrapper := testWrapper(t)
	conn := &store.Connection{TenantID: "t", ID: "c", CustomScripts: map[string]string{store.ScriptLogin: "source"}}
	var err error
	conn.ConfigurationSealed, err = keys.SealConnectionConfig(wrapper, "t", "c", map[string]string{"K": "middle"})
	if err != nil {
		t.Fatal(err)
	}
	input := []string{"prefix-middle-suffix middle", strings.Repeat("x", 2030) + "prefix-middle-suff", `{"\u0070refix-middle-suffix":"\u0070refix-middle-suffix"}`}
	client := Client{Exec: overlapConsoleExecutor{lines: input}, Wrapper: wrapper}
	var got []string
	raw, err := client.Try(context.Background(), conn, store.ScriptLogin, []any{"a", "prefix-middle-suffix"}, func(lines []string) { got = lines })
	if err != nil || string(raw) != `{"ok":true}` {
		t.Fatalf("raw=%s err=%v", raw, err)
	}
	want := []string{logscrub.Marker + " " + Mask, strings.Repeat("x", 2030) + logscrub.Marker, `{"` + logscrub.Marker + `":"` + logscrub.Marker + `"}`}
	if len(got) != len(want) {
		t.Fatalf("lines=%q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d=%q want=%q", i, got[i], want[i])
		}
	}
}

func TestProcessMasksOverlapUnknownAndUnstructuredOutput(t *testing.T) {
	p, _ := newMaskTestProcess(256, 64<<10)
	p.registerMasks(logscrub.WithCredentials(context.Background(), "prefix-middle-suffix"), Request{Config: map[string]string{"K": "middle"}})
	var sink syncBuffer
	r := &NodeRunner{log: slog.New(slog.NewJSONHandler(&sink, nil))}
	r.logLine(p, []byte("raw prefix-middle-suffix middle"))
	r.logLine(p, []byte(`{"conn":"unknown","level":"info","msg":"{\"\\u0070refix-middle-suffix\":\"\\u0070refix-middle-suffix\"}"}`))
	if out := sink.String(); strings.Contains(out, "prefix") || strings.Contains(out, "suff") || strings.Count(out, `"output":`) != 2 {
		t.Fatalf("unsafe/missing diagnostic output: %s", out)
	}
}
