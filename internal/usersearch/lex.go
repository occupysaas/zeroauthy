package usersearch

import (
	"strings"
	"unicode"
)

// scanner reads the query on demand; the parser drives it because what a
// character means depends on where it is (a bare word, a value after a
// colon, a range bound).
type scanner struct {
	r    []rune
	pos  int
	stop string // extra characters that end a bare value (range brackets)
}

// val is a scanned value. plain is the unescaped text; text is the same as
// a glob (a literal * written \*); wild is true when an unescaped * is
// present; quoted values never are wild.
type val struct {
	plain, text string
	wild        bool
	quoted      bool
}

func (s *scanner) eof() bool { return s.pos >= len(s.r) }

func (s *scanner) peek() rune {
	if s.eof() {
		return 0
	}
	return s.r[s.pos]
}

func (s *scanner) skipSpace() {
	for !s.eof() && unicode.IsSpace(s.r[s.pos]) {
		s.pos++
	}
}

// atBoundary reports whether the scanner is at the end of a word.
func (s *scanner) atBoundary() bool {
	if s.eof() {
		return true
	}
	c := s.r[s.pos]
	return unicode.IsSpace(c) || c == '(' || c == ')' || strings.ContainsRune(s.stop, c)
}

// keyword consumes AND, OR or NOT when it is next as a whole word.
func (s *scanner) keyword(kw string) bool {
	n := len(kw)
	if s.pos+n > len(s.r) || string(s.r[s.pos:s.pos+n]) != kw {
		return false
	}
	save := s.pos
	s.pos += n
	if s.atBoundary() {
		return true
	}
	s.pos = save
	return false
}

func isFieldRune(c rune) bool {
	return c == '_' || c == '.' || c == '-' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// fieldPrefix returns the field name when the next word starts "field:", and
// the position after the colon.
func (s *scanner) fieldPrefix() (string, int, bool) {
	i := s.pos
	for i < len(s.r) && isFieldRune(s.r[i]) {
		i++
	}
	if i > s.pos && i < len(s.r) && s.r[i] == ':' {
		return string(s.r[s.pos:i]), i + 1, true
	}
	return "", 0, false
}

// quoted reads a "..." value; the scanner is on the opening quote.
func (s *scanner) quoted() (val, bool) {
	s.pos++
	var b strings.Builder
	for !s.eof() {
		c := s.r[s.pos]
		s.pos++
		switch c {
		case '"':
			t := b.String()
			return val{plain: t, text: strings.ReplaceAll(t, "*", `\*`), quoted: true}, true
		case '\\':
			if s.eof() {
				return val{}, false
			}
			b.WriteRune(s.r[s.pos])
			s.pos++
		default:
			b.WriteRune(c)
		}
	}
	return val{}, false
}

// bare reads an unquoted value up to whitespace or a parenthesis. A quote
// inside it is an error.
func (s *scanner) bare() (val, bool) {
	var plain, text strings.Builder
	var v val
	for !s.atBoundary() {
		c := s.r[s.pos]
		s.pos++
		switch c {
		case '"':
			return val{}, false
		case '\\':
			if s.eof() {
				plain.WriteRune('\\')
				text.WriteRune('\\')
				continue
			}
			n := s.r[s.pos]
			s.pos++
			plain.WriteRune(n)
			if n == '*' {
				text.WriteString(`\*`)
			} else {
				text.WriteRune(n)
			}
		case '*':
			v.wild = true
			plain.WriteRune('*')
			text.WriteRune('*')
		default:
			plain.WriteRune(c)
			text.WriteRune(c)
		}
	}
	v.plain, v.text = plain.String(), text.String()
	return v, v.plain != ""
}

// value reads a quoted or bare value.
func (s *scanner) value() (val, bool) {
	if s.peek() == '"' {
		return s.quoted()
	}
	return s.bare()
}
