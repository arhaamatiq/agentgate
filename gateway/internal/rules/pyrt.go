package rules

// Python runtime semantics the rule engine depends on. Each helper mirrors a
// specific CPython 3.12 behavior so the Go engine makes the same decision as
// the Python reference implementation on the same input.

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Character classes equivalent to Python's Unicode-aware \s, \S and \w for
// str patterns. RE2's \s is ASCII-only and would let "DROP\vTABLE" through.
const (
	pyWS    = `\t\n\v\f\r\x{1c}-\x{1f} \x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}`
	reS     = `[` + pyWS + `]`
	reNotS  = `[^` + pyWS + `]`
	reW     = `[\p{L}\p{N}_]`
	reDigit = `\p{Nd}`
	// Python's "$" (no MULTILINE) also matches just before a final newline.
	reEnd = `\n?\z`
)

func mustRe(p string) *regexp.Regexp { return regexp.MustCompile(p) }

// isPySpace reports str.isspace() for a single code point.
func isPySpace(r rune) bool {
	switch {
	case r >= 0x09 && r <= 0x0d, r >= 0x1c && r <= 0x20, r == 0x85, r == 0xa0:
		return true
	case r < 0x80:
		return false
	}
	return unicode.Is(unicode.Zs, r) || r == 0x2028 || r == 0x2029
}

func isPyWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// pyStrip is str.strip() with no arguments.
func pyStrip(s string) string { return strings.TrimFunc(s, isPySpace) }

// pySplit is str.split() with no arguments.
func pySplit(s string) []string { return strings.FieldsFunc(s, isPySpace) }

// stripChars is str.strip(chars).
func stripChars(s, chars string) string { return strings.Trim(s, chars) }

// pyLower is str.lower(). Go's simple case mapping takes U+0130 (İ) to "i";
// Python's full mapping gives "i" + U+0307, the one unconditional
// multi-rune lowercase in Unicode, so it is applied first.
func pyLower(s string) string { return strings.ToLower(strings.ReplaceAll(s, "İ", "i̇")) }
func pyUpper(s string) string { return strings.ToUpper(s) }

// runePrefix returns s[:n] measured in code points, like Python slicing.
func runePrefix(s string, n int) string {
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

func nfkc(s string) string { return norm.NFKC.String(s) }

// decodeUTF8Replace is bytes.decode("utf-8", errors="replace"): each maximal
// ill-formed subsequence becomes one U+FFFD (Unicode Table 3-7 rules).
func decodeUTF8Replace(b []byte) string {
	var out strings.Builder
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			out.WriteByte(c)
			i++
			continue
		}
		r, size := utf8.DecodeRune(b[i:])
		if r != utf8.RuneError || size > 1 {
			out.WriteRune(r)
			i += size
			continue
		}
		// Ill-formed: consume the longest prefix of a valid sequence.
		var need int
		lo, hi := byte(0x80), byte(0xbf)
		switch {
		case c >= 0xc2 && c <= 0xdf:
			need = 1
		case c == 0xe0:
			need, lo = 2, 0xa0
		case c >= 0xe1 && c <= 0xec, c == 0xee, c == 0xef:
			need = 2
		case c == 0xed:
			need, hi = 2, 0x9f
		case c == 0xf0:
			need, lo = 3, 0x90
		case c >= 0xf1 && c <= 0xf3:
			need = 3
		case c == 0xf4:
			need, hi = 3, 0x8f
		}
		j := i + 1
		for k := 0; k < need && j < len(b); k++ {
			if b[j] < lo || b[j] > hi {
				break
			}
			lo, hi = 0x80, 0xbf
			j++
		}
		out.WriteRune(utf8.RuneError)
		i = j
	}
	return out.String()
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// unquoteToBytes is urllib.parse.unquote_to_bytes.
func unquoteToBytes(s []byte) []byte {
	if len(s) == 0 {
		return nil
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			h, ok1 := hexVal(s[i+1])
			l, ok2 := hexVal(s[i+2])
			if ok1 && ok2 {
				out = append(out, h<<4|l)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}

// pyUnquote is urllib.parse.unquote(s) (utf-8, errors="replace"). Only ASCII
// runs are percent-decoded; non-ASCII text passes through untouched.
func pyUnquote(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var out strings.Builder
	i := 0
	for i < len(s) {
		j := i
		for j < len(s) && s[j] < 0x80 {
			j++
		}
		if j > i {
			out.WriteString(decodeUTF8Replace(unquoteToBytes([]byte(s[i:j]))))
		}
		k := j
		for k < len(s) && s[k] >= 0x80 {
			k++
		}
		out.WriteString(s[j:k])
		i = k
	}
	return out.String()
}

// pyIntHex2 is int(pair, 16) for a two-character string, including Python's
// tolerance of surrounding whitespace and a sign. ok=false on ValueError.
func pyIntHex2(pair string) (int, bool) {
	p := strings.TrimFunc(pair, isPySpace)
	neg := false
	if strings.HasPrefix(p, "+") || strings.HasPrefix(p, "-") {
		neg = p[0] == '-'
		p = p[1:]
	}
	if p == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(p); i++ {
		v, ok := hexVal(p[i])
		if !ok {
			return 0, false
		}
		n = n*16 + int(v)
	}
	if neg {
		n = -n
	}
	return n, true
}

// posixNormpath is posixpath.normpath.
func posixNormpath(p string) string {
	if p == "" {
		return "."
	}
	initial := 0
	if strings.HasPrefix(p, "/") {
		initial = 1
		if strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///") {
			initial = 2
		}
	}
	var comps []string
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." {
			continue
		}
		if c != ".." || (initial == 0 && len(comps) == 0) || (len(comps) > 0 && comps[len(comps)-1] == "..") {
			comps = append(comps, c)
		} else if len(comps) > 0 {
			comps = comps[:len(comps)-1]
		}
	}
	out := strings.Repeat("/", initial) + strings.Join(comps, "/")
	if out == "" {
		return "."
	}
	return out
}

// posixBasename is posixpath.basename.
func posixBasename(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// posixSplitextExt returns the extension part of posixpath.splitext.
func posixSplitextExt(p string) string {
	sep := strings.LastIndexByte(p, '/')
	dot := strings.LastIndexByte(p, '.')
	if dot > sep {
		// Skip all leading dots of the filename.
		filenameIndex := sep + 1
		for filenameIndex < dot {
			if p[filenameIndex] != '.' {
				return p[dot:]
			}
			filenameIndex++
		}
	}
	return ""
}

func isPyDigitString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) && !unicode.Is(unicode.No, r) {
			return false
		}
	}
	return true
}
