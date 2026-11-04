package config

//go:generate go run ./gendoc -src . -out ../../docs/configuration.md

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ReferencePath is docs/configuration.md relative to this package.
const ReferencePath = "../../docs/configuration.md"

// Reference renders docs/configuration.md: every leaf key of Config with
// its environment variable, type, default and description. Descriptions
// come from the doc or trailing comments in the package source under
// srcDir, which reflection cannot see.
func Reference(srcDir string) ([]byte, error) {
	docs, err := parseComments(srcDir)
	if err != nil {
		return nil, err
	}
	r := &refWriter{docs: docs}
	r.header()
	root := reflect.ValueOf(*defaults())
	r.section(root, "", "", 3)
	if len(r.missing) > 0 {
		return nil, fmt.Errorf("config reference: no description for %s; add a doc comment in internal/config", strings.Join(r.missing, ", "))
	}
	return r.buf.Bytes(), nil
}

// refDocs holds the comments of the package's struct types and fields.
type refDocs struct {
	types  map[string]string            // type name -> doc
	fields map[string]map[string]string // type name -> field name -> doc or trailing comment
}

func parseComments(dir string) (*refDocs, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	d := &refDocs{types: map[string]string{}, fields: map[string]map[string]string{}}
	fset := token.NewFileSet()
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				ts := spec.(*ast.TypeSpec)
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				doc := ts.Doc
				if doc == nil && len(gen.Specs) == 1 {
					doc = gen.Doc
				}
				d.types[ts.Name.Name] = commentText(doc)
				fields := map[string]string{}
				for _, fld := range st.Fields.List {
					text := commentText(fld.Doc)
					if text == "" {
						text = commentText(fld.Comment)
					}
					for _, n := range fld.Names {
						fields[n.Name] = text
					}
				}
				d.fields[ts.Name.Name] = fields
			}
		}
	}
	return d, nil
}

// commentText joins a comment group into one line.
func commentText(g *ast.CommentGroup) string {
	if g == nil {
		return ""
	}
	return strings.Join(strings.Fields(g.Text()), " ")
}

type refWriter struct {
	buf     bytes.Buffer
	docs    *refDocs
	missing []string
}

type refRow struct {
	key, env, typ, def, desc string
}

var durationType = reflect.TypeOf(time.Duration(0))

// section writes the leaves of struct v (at path prefix) as one table,
// then each nested struct as its own subsection.
func (r *refWriter) section(v reflect.Value, prefix, intro string, level int) {
	t := v.Type()
	var rows []refRow
	type child struct {
		v           reflect.Value
		path, intro string
	}
	var children []child
	for i := range t.NumField() {
		f := t.Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("koanf"), ",")
		if !f.IsExported() || key == "" || key == "-" {
			continue
		}
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		doc := r.docs.fields[t.Name()][f.Name]
		fv := v.Field(i)
		if f.Type.Kind() == reflect.Struct && f.Type != durationType {
			intro := r.prose(doc, t, prefix, "")
			if doc == "" {
				intro = r.prose(r.docs.types[f.Type.Name()], f.Type, path, f.Type.Name())
			}
			children = append(children, child{v: fv, path: path, intro: intro})
			continue
		}
		if doc == "" {
			r.missing = append(r.missing, path)
		}
		secret := isSecretKey(key)
		rows = append(rows, refRow{
			key:  path,
			env:  envName(path),
			typ:  typeName(f.Type, secret),
			def:  defaultText(fv, secret),
			desc: r.prose(doc, t, prefix, ""),
		})
	}
	if prefix != "" {
		fmt.Fprintf(&r.buf, "%s `%s`\n\n", strings.Repeat("#", level), prefix)
		if intro != "" {
			fmt.Fprintf(&r.buf, "%s\n\n", intro)
		}
	} else if len(rows) > 0 {
		fmt.Fprintf(&r.buf, "%s Top-level keys\n\n", strings.Repeat("#", level))
	}
	if len(rows) > 0 {
		r.buf.WriteString("| Key | Environment variable | Type | Default | Description |\n")
		r.buf.WriteString("| --- | --- | --- | --- | --- |\n")
		for _, row := range rows {
			fmt.Fprintf(&r.buf, "| `%s` | `%s` | %s | %s | %s |\n", row.key, row.env, row.typ, row.def, row.desc)
		}
		r.buf.WriteString("\n")
	}
	next := level + 1
	if prefix == "" {
		next = level
	}
	for _, c := range children {
		r.section(c.v, c.path, c.intro, next)
	}
}

// envName is the ZEROAUTHY_ variable for a key path.
func envName(path string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(path, ".", "__"))
}

// isSecretKey reports whether a key holds a secret value itself (not the
// path of a file holding one).
func isSecretKey(key string) bool {
	if strings.HasSuffix(key, "_file") {
		return false
	}
	switch key {
	case "master_key", "password", "dsn":
		return true
	}
	return strings.HasSuffix(key, "token") || strings.HasSuffix(key, "secret")
}

func typeName(t reflect.Type, secret bool) string {
	var s string
	switch {
	case t == durationType:
		s = "duration"
	case t.Kind() == reflect.Slice:
		s = "list of " + typeName(t.Elem(), false)
	case t.Kind() == reflect.Map:
		s = "map of " + typeName(t.Key(), false) + " to " + typeName(t.Elem(), false)
	case t.Kind() >= reflect.Int && t.Kind() <= reflect.Uint64:
		s = "integer"
	case t.Kind() == reflect.Float32 || t.Kind() == reflect.Float64:
		s = "number"
	default:
		s = t.Kind().String()
	}
	if secret {
		s += ", **secret**"
	}
	return s
}

func defaultText(v reflect.Value, secret bool) string {
	switch v.Kind() {
	case reflect.String, reflect.Slice, reflect.Map:
		if v.Len() == 0 {
			return "—"
		}
	}
	if secret {
		return "(hidden)"
	}
	switch {
	case v.Type() == durationType:
		return durationText(time.Duration(v.Int()))
	case v.Kind() == reflect.String:
		return "`" + v.String() + "`"
	case v.Kind() == reflect.Bool:
		return "`" + strconv.FormatBool(v.Bool()) + "`"
	case v.CanInt():
		return "`" + strconv.FormatInt(v.Int(), 10) + "`"
	case v.CanUint():
		return "`" + strconv.FormatUint(v.Uint(), 10) + "`"
	case v.CanFloat():
		return "`" + strconv.FormatFloat(v.Float(), 'g', -1, 64) + "`"
	case v.Kind() == reflect.Slice:
		parts := make([]string, v.Len())
		for i := range parts {
			parts[i] = defaultText(v.Index(i), false)
		}
		return strings.Join(parts, ", ")
	case v.Kind() == reflect.Map:
		keys := v.MapKeys()
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("`%v: %v`", k, v.MapIndex(k)))
		}
		sort.Strings(parts)
		return strings.Join(parts, ", ")
	}
	return fmt.Sprintf("`%v`", v.Interface())
}

// durationText writes d the way the loader accepts it ("5m", "720h"),
// adding days when that is easier to read.
func durationText(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	s = "`" + s + "`"
	if day := 24 * time.Hour; d >= day && d%day == 0 {
		n := d / day
		unit := "days"
		if n == 1 {
			unit = "day"
		}
		s += fmt.Sprintf(" (%d %s)", n, unit)
	}
	return s
}

var (
	mdEscaper = strings.NewReplacer("|", `\|`, "<", "&lt;", ">", "&gt;", "*", `\*`, "`", "")
	wordRE    = regexp.MustCompile(`[A-Za-z][A-Za-z0-9]*(\.[a-z]+)?`)
)

// prose prepares a comment for a table cell: Markdown escaped, and the Go
// field names of owner rewritten as their configuration keys (under
// ownerPath). A field name that is a single capitalized word (Enabled,
// Workers) is rewritten only where it starts the comment, the Go doc
// convention, so ordinary words elsewhere stay as written. self, when set,
// is the type a type doc describes; it becomes ownerPath.
func (r *refWriter) prose(text string, owner reflect.Type, ownerPath, self string) string {
	if text == "" {
		return ""
	}
	keys := map[string]string{}
	if self != "" {
		keys[self] = ownerPath // a type doc names the type: the section itself
	}
	for i := range owner.NumField() {
		f := owner.Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("koanf"), ",")
		if key == "" || key == "-" {
			continue
		}
		if ownerPath != "" {
			key = ownerPath + "." + key
		}
		keys[f.Name] = key
	}
	text = mdEscaper.Replace(text)
	first := true
	return wordRE.ReplaceAllStringFunc(text, func(w string) string {
		atStart := first
		first = false
		if strings.Contains(w, ".") { // Node.js, file.ext: not a field name
			return w
		}
		key, ok := keys[w]
		if !ok || (!atStart && !multiHump(w)) {
			return w
		}
		return "`" + key + "`"
	})
}

// multiHump reports whether an identifier is more than one capitalized
// word (BaseDomain, DSN), so it cannot be an ordinary English word.
func multiHump(w string) bool {
	upper := 0
	for _, c := range w {
		if c >= 'A' && c <= 'Z' {
			upper++
		}
	}
	return upper >= 2
}

func (r *refWriter) header() {
	r.buf.WriteString(`<!-- Code generated by "go generate ./internal/config"; DO NOT EDIT. -->
<!-- Source: the Config struct and its comments in internal/config. -->

# Configuration reference

Every zeroauthy setting, generated from the configuration code, so this page
always matches the server. For a worked production file see
[examples/zeroauthy.yaml](../examples/zeroauthy.yaml); for the steps around it
see [deployment](deployment.md).

## How settings are read

- **Sources and precedence.** Built-in defaults, then the YAML file, then
  ` + "`ZEROAUTHY_*`" + ` environment variables. An environment variable overrides the
  same key in the file.
- **The file** is named by ` + "`--config`" + ` (` + "`-c`" + `) or by the ` + "`ZEROAUTHY_CONFIG`" + ` variable.
  Without either, only defaults and environment variables apply.
- **Environment variable names** are ` + "`ZEROAUTHY_`" + ` plus the key path in upper
  case, with ` + "`__`" + ` (two underscores) between levels: ` + "`storage.dsn`" + ` is
  ` + "`ZEROAUTHY_STORAGE__DSN`" + `, ` + "`security.rate_limit.token.burst`" + ` is
  ` + "`ZEROAUTHY_SECURITY__RATE_LIMIT__TOKEN__BURST`" + `. Single underscores are part
  of a key name.
- **Strict keys.** An unknown key in the file, or any unknown variable starting
  with ` + "`ZEROAUTHY_`" + ` (other than ` + "`ZEROAUTHY_CONFIG`" + `), stops the server at startup.
- **Values in environment variables** are text converted to the key's type:
  booleans ` + "`true`" + `/` + "`false`" + ` (or ` + "`1`" + `/` + "`0`" + `), integers and numbers in decimal, and
  durations in Go syntax (` + "`90s`" + `, ` + "`5m`" + `, ` + "`720h`" + `; there is no ` + "`d`" + ` unit).
- **Lists.** In YAML write a normal list. An environment variable sets a list
  with exactly one entry; its value is not split on commas or spaces. The
  exception is ` + "`server.trusted_proxy_cidrs`" + `, which itself accepts
  comma-separated entries (` + "`ZEROAUTHY_SERVER__TRUSTED_PROXY_CIDRS=10.0.0.0/8,192.168.0.0/16`" + `).
  For several entries of any other list, use the file.
- **Secrets.** Keys marked **secret** hold credentials; their defaults are never
  shown here. Prefer the ` + "`_file`" + ` variant where one exists
  (` + "`security.master_key_file`" + `) and keep passwords out of the YAML file, for
  example in ` + "`ZEROAUTHY_STORAGE__DSN`" + ` or ` + "`ZEROAUTHY_EMAIL__SMTP__PASSWORD`" + `.

## Minimal container start

The Docker image already sets ` + "`ZEROAUTHY_SERVER__LISTEN=:8080`" + `,
` + "`ZEROAUTHY_STORAGE__DSN=sqlite:///data/zeroauthy.db`" + ` (SQLite in the ` + "`/data`" + `
volume) and ` + "`ZEROAUTHY_STORAGE__AUTO_MIGRATE=true`" + `. On top of that you must set:

- ` + "`ZEROAUTHY_SERVER__SYSTEM_HOST`" + ` (the console's host, for example
  ` + "`system.localhost:8443`" + `), or ` + "`ZEROAUTHY_SERVER__BASE_DOMAIN`" + `, which makes it
  default to ` + "`system.<base_domain>`" + `.
- ` + "`ZEROAUTHY_SECURITY__MASTER_KEY`" + ` (base64 of 32 random bytes:
  ` + "`openssl rand -base64 32`" + `) or ` + "`ZEROAUTHY_SECURITY__MASTER_KEY_FILE`" + ` (a path to a
  file holding it). It is required with persistent storage; back it up, as the
  database is unreadable without it.

Without ` + "`server.tls_cert_file`" + ` and ` + "`server.tls_key_file`" + ` (or ` + "`server.acme`" + `) the
server speaks plain HTTP, so put a TLS-terminating proxy in front of it or
mount a certificate. The [quickstart](quickstart.md) shows a full ` + "`docker run`" + `.

## Settings

`)
}
