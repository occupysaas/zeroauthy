package liquid

import (
	"context"
	"errors"
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	ErrRenderLimit    = errors.New("email render limit exceeded")
	ErrRenderSyntax   = errors.New("unsupported or invalid email template syntax")
	ErrRenderCapacity = errors.New("email renderer at capacity")
)

const (
	maxRequestBytes = 256 << 10
	maxBodyBytes    = 128 << 10
	maxSubjectBytes = 1 << 10
	maxFromBytes    = 1 << 10
	maxURLBytes     = 4 << 10
	maxContextBytes = 64 << 10
	maxDepth        = 32
	maxIterations   = 10_000
	maxSteps        = 100_000
	maxOutputBytes  = 256 << 10
	maxRenderTime   = 100 * time.Millisecond
	maxConcurrent   = 8
)

const ContextByteLimit = maxContextBytes
const EmailOutputByteLimit = maxOutputBytes

// ProjectVariables copies the supported value types and omits sensitive keys.
func ProjectVariables(value any, depth int) (any, int, error) { return projectVariables(value, depth) }

type RenderInput struct {
	Fields    map[string]string
	Variables map[string]any
}

type Rendered struct {
	From      string `json:"from"`
	Subject   string `json:"subject"`
	Text      string `json:"text"`
	HTML      string `json:"html"`
	ResultURL string `json:"resultUrl"`
}

type Renderer interface {
	Render(context.Context, RenderInput) (Rendered, error)
}

type boundedRenderer struct{}

var activeRenders atomic.Int32

// SlotsInUse reports the shared renderer capacity currently held.
func SlotsInUse() int32 { return activeRenders.Load() }

func NewRenderer() (Renderer, error) { return boundedRenderer{}, nil }

func (boundedRenderer) Render(parent context.Context, input RenderInput) (Rendered, error) {
	if activeRenders.Add(1) > maxConcurrent {
		activeRenders.Add(-1)
		return Rendered{}, ErrRenderCapacity
	}
	defer activeRenders.Add(-1)
	ctx, cancel := context.WithTimeout(parent, maxRenderTime)
	defer cancel()
	inputBytes := 0
	for name, source := range input.Fields {
		if name != "from" && name != "subject" && name != "body" && name != "html" && name != "resultUrl" {
			return Rendered{}, ErrRenderSyntax
		}
		inputBytes += len(name) + len(source)
		limit := maxBodyBytes
		switch name {
		case "from":
			limit = maxFromBytes
		case "subject":
			limit = maxSubjectBytes
		case "resultUrl":
			limit = maxURLBytes
		case "body", "html":
			limit = maxBodyBytes
		}
		if !utf8String(source) || len(source) > limit {
			return Rendered{}, ErrRenderLimit
		}
	}
	if inputBytes > maxRequestBytes {
		return Rendered{}, ErrRenderLimit
	}
	vars, size, err := projectVariables(input.Variables, 0)
	if err != nil {
		return Rendered{}, err
	}
	if size > maxContextBytes {
		return Rendered{}, ErrRenderLimit
	}
	varMap, ok := vars.(map[string]any)
	if !ok {
		return Rendered{}, ErrRenderSyntax
	}
	var total int
	state := renderState{ctx: ctx, deadline: time.Now().Add(maxRenderTime)}
	renderField := func(key string) (string, error) {
		source := input.Fields[key]
		if source == "" {
			return "", nil
		}
		state.vars = cloneMap(varMap)
		nodes, _, err := state.parse(source, 0)
		if err != nil {
			return "", err
		}
		var out strings.Builder
		if err := state.renderNodes(&out, nodes); err != nil {
			return "", err
		}
		total += out.Len()
		if total > maxOutputBytes {
			return "", ErrRenderLimit
		}
		return out.String(), nil
	}
	var out Rendered
	var e error
	if out.From, e = renderField("from"); e != nil {
		return Rendered{}, e
	}
	if out.Subject, e = renderField("subject"); e != nil {
		return Rendered{}, e
	}
	if out.Text, e = renderField("body"); e != nil {
		return Rendered{}, e
	}
	if out.HTML, e = renderField("html"); e != nil {
		return Rendered{}, e
	}
	if out.ResultURL, e = renderField("resultUrl"); e != nil {
		return Rendered{}, e
	}
	return out, nil
}

func utf8String(s string) bool { return strings.ToValidUTF8(s, "\uFFFD") == s }

func projectVariables(value any, depth int) (any, int, error) {
	if depth > maxDepth {
		return nil, 0, ErrRenderLimit
	}
	switch v := value.(type) {
	case nil, bool, string, float64, float32, int, int64, int32:
		s, ok := v.(string)
		if ok {
			return s, len(s), nil
		}
		return v, 8, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		size := 0
		for k, value := range v {
			if sensitiveKey(k) {
				continue
			}
			pv, n, err := projectVariables(value, depth+1)
			if err != nil {
				return nil, 0, err
			}
			out[k], size = pv, size+len(k)+n
			if size > maxContextBytes {
				return nil, size, ErrRenderLimit
			}
		}
		return out, size, nil
	case []any:
		out := make([]any, len(v))
		size := 0
		for i, value := range v {
			pv, n, err := projectVariables(value, depth+1)
			if err != nil {
				return nil, 0, err
			}
			out[i], size = pv, size+n
			if size > maxContextBytes {
				return nil, size, ErrRenderLimit
			}
		}
		return out, size, nil
	default:
		return nil, 0, ErrRenderSyntax
	}
}

func sensitiveKey(k string) bool {
	k = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, "-", ""), "_", ""))
	for _, part := range []string{"password", "secret", "token", "credential", "authorization", "privatekey", "hash", "ticket", "otp", "code"} {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

type renderState struct {
	ctx                      context.Context
	vars                     map[string]any
	steps, iterations, depth int
	deadline                 time.Time
	maxOutput                int
	maxSource                int
	escapeVariables          bool
}

type templateNode interface {
	render(*renderState, *strings.Builder) error
}
type textNode string
type valueNode string

// escapedValue records an explicit escape filter in auto-escaped hosted output.
// Email always retains plain string results.
type escapedValue string
type assignNode struct{ name, expr string }
type forNode struct {
	name, expr string
	body       []templateNode
}
type ifNode struct {
	branches  []ifBranch
	otherwise []templateNode
}
type ifBranch struct {
	expr string
	body []templateNode
}

func (n textNode) render(s *renderState, b *strings.Builder) error {
	if err := s.step(); err != nil {
		return err
	}
	b.WriteString(string(n))
	return s.output(b)
}
func (n valueNode) render(s *renderState, b *strings.Builder) error {
	if err := s.step(); err != nil {
		return err
	}
	v, err := s.eval(string(n))
	if err != nil {
		return err
	}
	output := stringify(v)
	if s.escapeVariables {
		if _, escaped := v.(escapedValue); !escaped {
			output = html.EscapeString(output)
		}
	}
	b.WriteString(output)
	return s.output(b)
}
func (n assignNode) render(s *renderState, _ *strings.Builder) error {
	if err := s.step(); err != nil {
		return err
	}
	v, err := s.eval(n.expr)
	if err != nil {
		return err
	}
	s.vars[n.name] = v
	return nil
}
func (n forNode) render(s *renderState, b *strings.Builder) error {
	if err := s.step(); err != nil {
		return err
	}
	v, err := s.eval(n.expr)
	if err != nil {
		return err
	}
	items := toSlice(v)
	for i, item := range items {
		s.iterations++
		if s.iterations > maxIterations {
			return ErrRenderLimit
		}
		if err := s.step(); err != nil {
			return err
		}
		old, had := s.vars[n.name]
		s.vars[n.name] = item
		s.vars["forloop"] = map[string]any{"index": i + 1, "index0": i, "first": i == 0, "last": i == len(items)-1}
		if err := s.renderNodes(b, n.body); err != nil {
			return err
		}
		if had {
			s.vars[n.name] = old
		} else {
			delete(s.vars, n.name)
		}
	}
	return nil
}
func (n ifNode) render(s *renderState, b *strings.Builder) error {
	if err := s.step(); err != nil {
		return err
	}
	for _, br := range n.branches {
		v, e := s.eval(br.expr)
		if e != nil {
			return e
		}
		if truthy(v) {
			return s.renderNodes(b, br.body)
		}
	}
	return s.renderNodes(b, n.otherwise)
}

func (s *renderState) step() error {
	s.steps++
	if s.steps > maxSteps {
		return ErrRenderLimit
	}
	if s.steps&63 == 0 {
		return s.checkContext()
	}
	return nil
}
func (s *renderState) checkContext() error {
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	default:
	}
	if time.Now().After(s.deadline) {
		return context.DeadlineExceeded
	}
	return nil
}
func (s *renderState) outputBudget() int {
	if s.maxOutput > 0 {
		return s.maxOutput
	}
	return maxOutputBytes
}

func (s *renderState) output(b *strings.Builder) error {
	if b.Len() > s.outputBudget() {
		return ErrRenderLimit
	}
	return nil
}

// RenderLiquid evaluates one source with the same bounded parser as email.
// Hosted pages supply a larger output cap; email's existing limits stay fixed.
func RenderLiquid(parent context.Context, source string, variables map[string]any, outputLimit int) (string, error) {
	return renderLiquid(parent, source, variables, outputLimit, false)
}

func renderLiquid(parent context.Context, source string, variables map[string]any, outputLimit int, escapeVariables bool) (string, error) {
	if activeRenders.Add(1) > maxConcurrent {
		activeRenders.Add(-1)
		return "", ErrRenderCapacity
	}
	defer activeRenders.Add(-1)
	ctx, cancel := context.WithTimeout(parent, maxRenderTime)
	defer cancel()
	projected, size, err := projectVariables(variables, 0)
	if err != nil {
		return "", err
	}
	if size > maxContextBytes {
		return "", ErrRenderLimit
	}
	varMap, ok := projected.(map[string]any)
	if !ok {
		return "", ErrRenderSyntax
	}
	state := renderState{ctx: ctx, deadline: time.Now().Add(maxRenderTime), vars: cloneMap(varMap), maxOutput: outputLimit, maxSource: len(source), escapeVariables: escapeVariables}
	nodes, _, err := state.parse(source, 0)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	if err := state.renderNodes(&out, nodes); err != nil {
		return "", err
	}
	return out.String(), nil
}
func (s *renderState) renderNodes(b *strings.Builder, nodes []templateNode) error {
	for _, n := range nodes {
		if err := n.render(s, b); err != nil {
			return err
		}
	}
	return nil
}

var tokenPattern = regexp.MustCompile(`(?s)(\{\{.*?\}\}|\{%.*?%\})`)

type lexToken struct {
	text   string
	output bool
	tag    bool
}

func lex(source string) []lexToken {
	locations := tokenPattern.FindAllStringIndex(source, -1)
	tokens := make([]lexToken, 0, len(locations)*2+1)
	offset := 0
	for _, loc := range locations {
		if loc[0] > offset {
			tokens = append(tokens, lexToken{text: source[offset:loc[0]]})
		}
		tok := source[loc[0]:loc[1]]
		if strings.HasPrefix(tok, "{{") {
			tokens = append(tokens, lexToken{text: strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(tok, "{{"), "}}")), output: true})
		} else {
			tokens = append(tokens, lexToken{text: strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(tok, "{%"), "%}")), tag: true})
		}
		offset = loc[1]
	}
	if offset < len(source) {
		tokens = append(tokens, lexToken{text: source[offset:]})
	}
	return tokens
}

func (s *renderState) parse(source string, depth int) ([]templateNode, string, error) {
	if depth > maxDepth {
		return nil, "", ErrRenderLimit
	}
	if err := s.ctx.Err(); err != nil {
		return nil, "", err
	}
	limit := s.maxSource
	if limit == 0 {
		limit = maxBodyBytes
	}
	if len(source) > limit {
		return nil, "", ErrRenderLimit
	}
	if strings.Count(source, "{{") != strings.Count(source, "}}") || strings.Count(source, "{%") != strings.Count(source, "%}") {
		return nil, "", ErrRenderSyntax
	}
	for i := 0; i < len(source); i += 256 {
		if err := s.checkContext(); err != nil {
			return nil, "", err
		}
	}
	tokens, pos := lex(source), 0
	nodes, stop, _, err := s.parseSequence(tokens, &pos, depth)
	if err != nil {
		return nil, "", err
	}
	if stop != "" {
		return nil, "", ErrRenderSyntax
	}
	return nodes, "", nil
}

func (s *renderState) parseSequence(tokens []lexToken, pos *int, depth int) ([]templateNode, string, string, error) {
	if depth > maxDepth {
		return nil, "", "", ErrRenderLimit
	}
	nodes := []templateNode{}
	for *pos < len(tokens) {
		if err := s.step(); err != nil {
			return nil, "", "", err
		}
		t := tokens[*pos]
		*pos++
		if t.output {
			if t.text == "" {
				return nil, "", "", ErrRenderSyntax
			}
			nodes = append(nodes, valueNode(t.text))
			continue
		}
		if !t.tag {
			nodes = append(nodes, textNode(t.text))
			continue
		}
		parts := strings.Fields(t.text)
		if len(parts) == 0 {
			return nil, "", "", ErrRenderSyntax
		}
		name := parts[0]
		arg := strings.TrimSpace(strings.TrimPrefix(t.text, name))
		switch name {
		case "assign":
			pair := strings.SplitN(arg, "=", 2)
			if len(pair) != 2 {
				return nil, "", "", ErrRenderSyntax
			}
			key := strings.TrimSpace(pair[0])
			if !validName(key) {
				return nil, "", "", ErrRenderSyntax
			}
			nodes = append(nodes, assignNode{key, strings.TrimSpace(pair[1])})
		case "if", "unless":
			firstExpr := arg
			if name == "unless" {
				firstExpr = "not (" + arg + ")"
			}
			body, stop, stopArg, err := s.parseSequence(tokens, pos, depth+1)
			if err != nil {
				return nil, "", "", err
			}
			branches := []ifBranch{{expr: firstExpr, body: body}}
			otherwise := []templateNode{}
			for stop == "elsif" {
				body, stop, stopArg, err = s.parseSequence(tokens, pos, depth+1)
				if err != nil {
					return nil, "", "", err
				}
				branches = append(branches, ifBranch{expr: stopArg, body: body})
			}
			if stop == "else" {
				otherwise, stop, _, err = s.parseSequence(tokens, pos, depth+1)
				if err != nil {
					return nil, "", "", err
				}
			}
			if stop != "endif" {
				return nil, "", "", ErrRenderSyntax
			}
			nodes = append(nodes, ifNode{branches, otherwise})
		case "for":
			pair := strings.SplitN(arg, " in ", 2)
			if len(pair) != 2 || !validName(strings.TrimSpace(pair[0])) {
				return nil, "", "", ErrRenderSyntax
			}
			body, stop, _, err := s.parseSequence(tokens, pos, depth+1)
			if err != nil {
				return nil, "", "", err
			}
			if stop != "endfor" {
				return nil, "", "", ErrRenderSyntax
			}
			nodes = append(nodes, forNode{strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1]), body})
		case "else", "elsif", "endif", "endfor":
			return nodes, name, arg, nil
		case "comment":
			closed := false
			for *pos < len(tokens) {
				x := tokens[*pos]
				*pos++
				if strings.TrimSpace(x.text) == "endcomment" {
					closed = true
					break
				}
			}
			if !closed {
				return nil, "", "", ErrRenderSyntax
			}
		default:
			return nil, "", "", ErrRenderSyntax
		}
	}
	return nodes, "", "", nil
}
func validName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func (s *renderState) eval(expr string) (any, error) {
	if err := s.step(); err != nil {
		return nil, err
	}
	expr = strings.TrimSpace(expr)
	parts := splitTop(expr, '|')
	if len(parts) > 1 {
		v, e := s.eval(parts[0])
		if e != nil {
			return nil, e
		}
		for _, f := range parts[1:] {
			if err := s.step(); err != nil {
				return nil, err
			}
			v, e = applyFilter(s, v, strings.TrimSpace(f))
			if e != nil {
				return nil, e
			}
		}
		return v, nil
	}
	for _, op := range []string{" or ", " and ", " == ", " != ", " >= ", " <= ", " > ", " < ", " contains "} {
		if i := indexTopOperator(expr, op); i > 0 {
			a, e := s.eval(expr[:i])
			if e != nil {
				return nil, e
			}
			b, e := s.eval(expr[i+len(op):])
			if e != nil {
				return nil, e
			}
			switch strings.TrimSpace(op) {
			case "or":
				return truthy(a) || truthy(b), nil
			case "and":
				return truthy(a) && truthy(b), nil
			case "==":
				return stringify(a) == stringify(b), nil
			case "!=":
				return stringify(a) != stringify(b), nil
			case "contains":
				return strings.Contains(stringify(a), stringify(b)), nil
			default:
				cmp := strings.Compare(stringify(a), stringify(b))
				return map[string]bool{">": cmp > 0, "<": cmp < 0, ">=": cmp >= 0, "<=": cmp <= 0}[strings.TrimSpace(op)], nil
			}
		}
	}
	if strings.HasPrefix(expr, "not ") {
		v, e := s.eval(strings.TrimSpace(strings.TrimPrefix(expr, "not ")))
		return !truthy(v), e
	}
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		inner := strings.TrimSpace(expr[1 : len(expr)-1])
		if strings.Contains(inner, "..") {
			p := strings.SplitN(inner, "..", 2)
			a, e := s.eval(p[0])
			if e != nil {
				return nil, e
			}
			b, e := s.eval(p[1])
			if e != nil {
				return nil, e
			}
			start, ok1 := number(a)
			end, ok2 := number(b)
			if !ok1 || !ok2 || end < start || end-start > maxIterations {
				return nil, ErrRenderLimit
			}
			items := make([]any, 0, int(end-start+1))
			for i := start; i <= end; i++ {
				items = append(items, i)
			}
			return items, nil
		}
		return s.eval(inner)
	}
	if len(expr) >= 2 && (expr[0] == '\'' || expr[0] == '"') && expr[len(expr)-1] == expr[0] {
		return expr[1 : len(expr)-1], nil
	}
	switch expr {
	case "true":
		return true, nil
	case "false", "nil", "null":
		return nil, nil
	}
	if n, e := strconv.ParseFloat(expr, 64); e == nil {
		return n, nil
	}
	path := strings.Split(expr, ".")
	var v any = s.vars
	for _, part := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return "", nil
		}
		v = m[part]
	}
	return v, nil
}

func splitTop(s string, sep rune) []string {
	out := []string{}
	start, depth := 0, 0
	var quote rune
	for i, r := range s {
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '(' || r == '[' {
			depth++
		}
		if r == ')' || r == ']' {
			depth--
		}
		if r == sep && depth == 0 {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// Operators inside quoted literals or parenthesized subexpressions are data.
func indexTopOperator(source, operator string) int {
	var quote rune
	depth := 0
	for i, r := range source {
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '(' || r == '[' {
			depth++
			continue
		}
		if r == ')' || r == ']' {
			depth--
			continue
		}
		if depth == 0 && strings.HasPrefix(source[i:], operator) {
			return i
		}
	}
	return -1
}

func (s *renderState) escaped(value string) any {
	if s.escapeVariables {
		return escapedValue(value)
	}
	return value
}

func applyFilter(state *renderState, value any, spec string) (any, error) {
	p := splitTop(spec, ':')
	name := strings.TrimSpace(p[0])
	arg := any("")
	args := []any{}
	if len(p) > 1 {
		for _, x := range splitTop(p[1], ',') {
			v, err := state.eval(strings.TrimSpace(x))
			if err != nil {
				return nil, err
			}
			args = append(args, v)
		}
		if len(args) > 0 {
			arg = args[0]
		}
	}
	s := stringify(value)
	a := stringify(arg)
	switch name {
	case "escape":
		if escapedSize(s) > state.outputBudget() {
			return nil, ErrRenderLimit
		}
		return state.escaped(html.EscapeString(s)), nil
	case "escape_once":
		decoded := html.UnescapeString(s)
		if escapedSize(decoded) > state.outputBudget() {
			return nil, ErrRenderLimit
		}
		return state.escaped(html.EscapeString(decoded)), nil
	case "upcase":
		return strings.ToUpper(s), nil
	case "downcase":
		return strings.ToLower(s), nil
	case "capitalize":
		if s == "" {
			return s, nil
		}
		return strings.ToUpper(s[:1]) + strings.ToLower(s[1:]), nil
	case "strip":
		return strings.TrimSpace(s), nil
	case "lstrip":
		return strings.TrimLeft(s, " \t\r\n"), nil
	case "rstrip":
		return strings.TrimRight(s, " \t\r\n"), nil
	case "append":
		return boundedConcat(s, a, state.outputBudget())
	case "prepend":
		return boundedConcat(a, s, state.outputBudget())
	case "replace", "replace_first", "remove", "remove_first":
		if len(p) < 2 {
			return nil, ErrRenderSyntax
		}
		if len(args) < 1 {
			return nil, ErrRenderSyntax
		}
		old := stringify(args[0])
		rep := ""
		if len(args) > 1 {
			rep = stringify(args[1])
		}
		if name == "remove" || name == "remove_first" {
			rep = ""
		}
		count := -1
		if name == "replace_first" || name == "remove_first" {
			count = 1
		}
		if old == "" {
			return s, nil
		}
		if count < 0 && projectedReplacementSize(s, old, rep) > state.outputBudget() {
			return nil, ErrRenderLimit
		}
		out := strings.Replace(s, old, rep, count)
		if len(out) > state.outputBudget() {
			return nil, ErrRenderLimit
		}
		return out, nil
	case "truncate", "truncatewords":
		limit := 50
		if n, e := strconv.Atoi(a); e == nil {
			limit = n
		}
		if limit < 0 {
			return nil, ErrRenderSyntax
		}
		if name == "truncate" && len(s) > limit {
			return s[:limit] + "…", nil
		}
		if name == "truncatewords" {
			words := strings.Fields(s)
			if len(words) > limit {
				return strings.Join(words[:limit], " ") + "…", nil
			}
		}
		return s, nil
	case "default":
		if !truthy(value) {
			return arg, nil
		}
		return value, nil
	case "size":
		switch v := value.(type) {
		case string:
			return len(v), nil
		case escapedValue:
			return len(v), nil
		case []any:
			return len(v), nil
		case map[string]any:
			return len(v), nil
		}
		return 0, nil
	case "first", "last":
		switch v := value.(type) {
		case []any:
			if len(v) == 0 {
				return "", nil
			}
			if name == "first" {
				return v[0], nil
			}
			return v[len(v)-1], nil
		case string:
			if v == "" {
				return "", nil
			}
			if name == "first" {
				return v[:1], nil
			}
			return v[len(v)-1:], nil
		}
		return "", nil
	case "join":
		if arr, ok := value.([]any); ok {
			sep := a
			items := make([]string, len(arr))
			estimated := len(sep) * maxInt(0, len(arr)-1)
			for i, v := range arr {
				items[i] = stringify(v)
				estimated += len(items[i])
				if estimated > state.outputBudget() {
					return nil, ErrRenderLimit
				}
			}
			return strings.Join(items, sep), nil
		}
		return s, nil
	case "date":
		return formatDate(value, a)
	default:
		return nil, ErrRenderSyntax
	}
}
func boundedConcat(a, b string, limit int) (string, error) {
	if len(a)+len(b) > limit {
		return "", ErrRenderLimit
	}
	return a + b, nil
}

func escapedSize(s string) int {
	size := len(s)
	for _, r := range s {
		switch r {
		case '&':
			size += 4
		case '<', '>':
			size += 3
		case '"', '\'':
			size += 5
		}
	}
	return size
}

func formatDate(value any, format string) (string, error) {
	if format == "" {
		return stringify(value), nil
	}
	layout := format
	for _, pair := range [][2]string{{"%Y", "2006"}, {"%y", "06"}, {"%m", "01"}, {"%-m", "1"}, {"%d", "02"}, {"%-d", "2"}, {"%H", "15"}, {"%M", "04"}, {"%S", "05"}, {"%b", "Jan"}, {"%B", "January"}, {"%a", "Mon"}, {"%A", "Monday"}, {"%%", "%"}} {
		layout = strings.ReplaceAll(layout, pair[0], pair[1])
	}
	var parsed time.Time
	var err error
	for _, sourceLayout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02", "Jan 2, 2006"} {
		parsed, err = time.Parse(sourceLayout, stringify(value))
		if err == nil {
			break
		}
	}
	if err != nil {
		return "", ErrRenderSyntax
	}
	return parsed.Format(layout), nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func projectedReplacementSize(source, old, replacement string) int {
	return len(source) + strings.Count(source, old)*(len(replacement)-len(old))
}
func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') {
		return s[1 : len(s)-1]
	}
	return s
}
func stringify(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case escapedValue:
		return string(x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	case []any:
		parts := make([]string, len(x))
		for i, v := range x {
			parts[i] = stringify(v)
		}
		return strings.Join(parts, " ")
	default:
		return fmt.Sprint(v)
	}
}
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case escapedValue:
		return x != ""
	case float64:
		return x != 0
	}
	return true
}
func number(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	}
	return 0, false
}
func toSlice(v any) []any {
	if x, ok := v.([]any); ok {
		return x
	}
	return nil
}
