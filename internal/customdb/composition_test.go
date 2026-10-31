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

func TestRunnerConsolePrivacyBeforeFormatting(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"warn_object", `console.warn({password:'unregistered-private-value'});`},
		{"error_nested", `console.error({normal:[{nested:{'API.-KEY':'unregistered-private-value'}}]});`},
		{"oversized_object", `console.log({password:'unregistered-private-value',padding:'x'.repeat(3000)});`},
		{"encoded_nested", `console.debug('prefix',JSON.stringify({normal:JSON.stringify([{password:'unregistered-private-value'}])}));`},
		{"immutable", `const v={password:'unregistered-private-value'};console.warn(v);if(v.password!=='unregistered-private-value')throw Error('console mutated script data');`},
		{"cycle", `const v={password:'unregistered-private-value'};v.self=v;console.warn(v);`},
		{"deep", `let v={password:'unregistered-private-value'};for(let i=0;i<100;i++)v={normal:v};console.warn(v);`},
		{"toJSON", `console.warn({password:'unregistered-private-value',toJSON(){return this.password}});`},
		{"key_policy", `console.warn(Object.fromEntries(['Password','pre-PASSWD-post','p.w.d','client-secret','refresh_token','Authorization','API.-KEY','private_key','Credential','OTP','recovery-code','prİvatekey'].map(k=>[k,'unregistered-private-value'])));`},
		{"wide", `console.warn(Object.fromEntries(Array.from({length:9000},(_,i)=>['key'+i,{password:'unregistered-private-value'}])));`},
		{"sparse_array", `const v=[];v[1000000]={password:'unregistered-private-value'};console.warn(v);`},
		{"accessor", `console.warn({get value(){return 'unregistered-private-value'}});`},
		{"escaped_cut", `console.log('x'.repeat(2035)+JSON.stringify(p));`},
		{"escaped_prefix", `console.error('prefix',JSON.stringify(p));`},
		{"escaped_configuration_cut", `console.warn('x'.repeat(2035)+JSON.stringify(configuration.K));`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sink syncBuffer
			r := newRunnerLog(t, config.CustomDB{}, slog.New(slog.NewJSONHandler(&sink, nil)))
			password := "line\nbreak\"value"
			var lines []string
			var configuration map[string]string
			if tc.name == "escaped_configuration_cut" {
				configuration = map[string]string{"K": password}
			}
			raw, err := r.Execute(context.Background(), Request{TenantID: "privacy", ConnectionID: "c", Script: store.ScriptLogin, Config: configuration, Args: []any{"a", password}, OnLogs: func(v []string) { lines = v }, Source: `function login(e,p,cb){` + tc.body + `cb(null,{name:p});setTimeout(()=>{` + tc.body + `console.log('late-safe-marker')},10);}`})
			want, _ := json.Marshal(map[string]string{"name": password})
			if err != nil || string(raw) != string(want) {
				t.Fatalf("business result=%s err=%v", raw, err)
			}
			if len(lines) != 1 {
				t.Fatalf("logs=%q", lines)
			}
			check := func(where, text string) {
				t.Helper()
				for _, secret := range []string{"unregistered-private-value", "line", `line\n`, "break", password} {
					if strings.Contains(text, secret) {
						t.Errorf("%s leaked %q: %q", where, secret, text)
					}
				}
			}
			check("captured", strings.Join(lines, "\n"))
			if !strings.Contains(lines[0], logscrub.Marker) && !strings.Contains(lines[0], Mask) {
				t.Errorf("missing redaction: %q", lines)
			}
			waitLog(t, &sink, "late-safe-marker")
			check("stderr including late output", sink.String())
		})
	}
}

func TestRunnerConsoleRawJSONCredentials(t *testing.T) {
	for _, password := range []string{`{ "value" : "json-secret" }`, `"\u0071uoted-secret"`, `{ "password" : "hidden", "value":"json-secret" }`} {
		t.Run(password, func(t *testing.T) {
			var sink syncBuffer
			r := newRunnerLog(t, config.CustomDB{}, slog.New(slog.NewJSONHandler(&sink, nil)))
			var lines []string
			raw, err := r.Execute(context.Background(), Request{TenantID: "privacy", ConnectionID: "c", Script: store.ScriptLogin, Args: []any{"a", password}, OnLogs: func(v []string) { lines = v }, Source: `function login(e,p,cb){console.log(p);console.warn(JSON.stringify(p));cb(null,{name:p});setTimeout(()=>{console.error(p);console.log('raw-json-safe-marker')},10)}`})
			want, _ := json.Marshal(map[string]string{"name": password})
			if err != nil || string(raw) != string(want) {
				t.Fatalf("business result=%s err=%v", raw, err)
			}
			if len(lines) != 2 {
				t.Fatalf("captured=%q", lines)
			}
			waitLog(t, &sink, "raw-json-safe-marker")
			for _, out := range append(lines, sink.String()) {
				if strings.Contains(out, "json-secret") || strings.Contains(out, "quoted-secret") || !strings.Contains(out, logscrub.Marker) {
					t.Errorf("unsafe/missing redaction: %s", out)
				}
			}
		})
	}
}
