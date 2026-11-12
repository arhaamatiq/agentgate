// Package pyjson parses JSON into an order-preserving tree and re-serializes it
// exactly as Python's json.dumps / str() / repr() would.
//
// The rule engine is a port of the Python reference implementation, and many
// of its regexes run over json.dumps(arguments). Byte-identical serialization
// is what lets the Go and Python engines agree on every decision.
package pyjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Kind uint8

const (
	Null Kind = iota
	Bool
	Int
	Float
	String
	Array
	Object
)

// Value is a JSON value. Ints keep their literal digits (Python ints are
// arbitrary precision); objects keep insertion order like a Python dict.
type Value struct {
	Kind Kind
	B    bool
	S    string // String content, or the decimal digits of an Int
	F    float64
	A    []Value
	O    *Obj
}

// Obj is an insertion-ordered map. A duplicate key keeps its first position
// and takes the last value, matching dict semantics in json.loads.
type Obj struct {
	keys []string
	vals []Value
	idx  map[string]int
}

func NewObj() *Obj { return &Obj{idx: map[string]int{}} }

func (o *Obj) Set(k string, v Value) {
	if i, ok := o.idx[k]; ok {
		o.vals[i] = v
		return
	}
	o.idx[k] = len(o.keys)
	o.keys = append(o.keys, k)
	o.vals = append(o.vals, v)
}

func (o *Obj) Get(k string) (Value, bool) {
	if o == nil {
		return Value{}, false
	}
	i, ok := o.idx[k]
	if !ok {
		return Value{}, false
	}
	return o.vals[i], true
}

func (o *Obj) Has(k string) bool {
	if o == nil {
		return false
	}
	_, ok := o.idx[k]
	return ok
}

func (o *Obj) Len() int {
	if o == nil {
		return 0
	}
	return len(o.keys)
}

func (o *Obj) Keys() []string {
	if o == nil {
		return nil
	}
	return o.keys
}

// Str returns str(value) for key k, or def when k is absent.
func (o *Obj) Str(k, def string) string {
	v, ok := o.Get(k)
	if !ok {
		return def
	}
	return v.PyStr()
}

// Truthy reports Python truthiness.
func (v Value) Truthy() bool {
	switch v.Kind {
	case Null:
		return false
	case Bool:
		return v.B
	case Int:
		return strings.TrimLeft(strings.TrimPrefix(v.S, "-"), "0") != ""
	case Float:
		return v.F != 0
	case String:
		return v.S != ""
	case Array:
		return len(v.A) > 0
	case Object:
		return v.O.Len() > 0
	}
	return false
}

func Str(s string) Value { return Value{Kind: String, S: s} }

// ParseObject parses a JSON object. Anything else is an error.
func ParseObject(data []byte) (*Obj, error) {
	v, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if v.Kind != Object {
		return nil, errors.New("arguments must be a JSON object")
	}
	return v.O, nil
}

func Parse(data []byte) (Value, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return Value{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return Value{}, errors.New("trailing data after JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (Value, error) {
	tok, err := dec.Token()
	if err != nil {
		return Value{}, err
	}
	return fromToken(dec, tok)
}

func fromToken(dec *json.Decoder, tok json.Token) (Value, error) {
	switch t := tok.(type) {
	case nil:
		return Value{Kind: Null}, nil
	case bool:
		return Value{Kind: Bool, B: t}, nil
	case string:
		return Value{Kind: String, S: t}, nil
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			f, err := strconv.ParseFloat(s, 64)
			if err != nil && !errors.Is(err, strconv.ErrRange) {
				return Value{}, err
			}
			return Value{Kind: Float, F: f}, nil
		}
		neg := strings.HasPrefix(s, "-")
		digits := strings.TrimLeft(strings.TrimPrefix(s, "-"), "0")
		if digits == "" {
			return Value{Kind: Int, S: "0"}, nil
		}
		if neg {
			digits = "-" + digits
		}
		return Value{Kind: Int, S: digits}, nil
	case json.Delim:
		switch t {
		case '[':
			arr := []Value{}
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return Value{}, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil {
				return Value{}, err
			}
			return Value{Kind: Array, A: arr}, nil
		case '{':
			obj := NewObj()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return Value{}, err
				}
				k, ok := kt.(string)
				if !ok {
					return Value{}, errors.New("object key must be a string")
				}
				v, err := parseValue(dec)
				if err != nil {
					return Value{}, err
				}
				obj.Set(k, v)
			}
			if _, err := dec.Token(); err != nil {
				return Value{}, err
			}
			return Value{Kind: Object, O: obj}, nil
		}
	}
	return Value{}, fmt.Errorf("unexpected token %v", tok)
}

// Dumps returns json.dumps(value) with Python's defaults:
// ensure_ascii=True, separators (", ", ": ").
func Dumps(v Value) string {
	var b strings.Builder
	dump(&b, v)
	return b.String()
}

// DumpsObj is Dumps for an object.
func DumpsObj(o *Obj) string {
	if o == nil {
		return "{}"
	}
	return Dumps(Value{Kind: Object, O: o})
}

func dump(b *strings.Builder, v Value) {
	switch v.Kind {
	case Null:
		b.WriteString("null")
	case Bool:
		if v.B {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case Int:
		b.WriteString(v.S)
	case Float:
		switch {
		case math.IsNaN(v.F):
			b.WriteString("NaN")
		case math.IsInf(v.F, 1):
			b.WriteString("Infinity")
		case math.IsInf(v.F, -1):
			b.WriteString("-Infinity")
		default:
			b.WriteString(FloatRepr(v.F))
		}
	case String:
		dumpString(b, v.S)
	case Array:
		b.WriteByte('[')
		for i, e := range v.A {
			if i > 0 {
				b.WriteString(", ")
			}
			dump(b, e)
		}
		b.WriteByte(']')
	case Object:
		b.WriteByte('{')
		for i, k := range v.O.keys {
			if i > 0 {
				b.WriteString(", ")
			}
			dumpString(b, k)
			b.WriteString(": ")
			dump(b, v.O.vals[i])
		}
		b.WriteByte('}')
	}
}

const hexdigits = "0123456789abcdef"

func dumpString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 || r > 0x7e {
				if r > 0xffff {
					r -= 0x10000
					writeU(b, 0xd800|((r>>10)&0x3ff))
					writeU(b, 0xdc00|(r&0x3ff))
				} else {
					writeU(b, r)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func writeU(b *strings.Builder, r rune) {
	b.WriteString(`\u`)
	b.WriteByte(hexdigits[(r>>12)&0xf])
	b.WriteByte(hexdigits[(r>>8)&0xf])
	b.WriteByte(hexdigits[(r>>4)&0xf])
	b.WriteByte(hexdigits[r&0xf])
}

// FloatRepr returns Python's repr(float).
func FloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	sign := ""
	if math.Signbit(f) {
		sign = "-"
		f = -f
	}
	if f == 0 {
		return sign + "0.0"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	mant, expStr, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mant, ".", "", 1)
	decpt := exp + 1
	if decpt <= -4 || decpt > 16 {
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		es := "+"
		if exp < 0 {
			es = "-"
			exp = -exp
		}
		return fmt.Sprintf("%s%se%s%02d", sign, m, es, exp)
	}
	var out string
	switch {
	case decpt <= 0:
		out = "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		out = digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	default:
		out = digits[:decpt] + "." + digits[decpt:]
	}
	return sign + out
}

// PyStr returns str(value) as Python would print the parsed JSON value.
func (v Value) PyStr() string {
	switch v.Kind {
	case String:
		return v.S
	default:
		return v.PyRepr()
	}
}

// PyRepr returns repr(value).
func (v Value) PyRepr() string {
	switch v.Kind {
	case Null:
		return "None"
	case Bool:
		if v.B {
			return "True"
		}
		return "False"
	case Int:
		return v.S
	case Float:
		return FloatRepr(v.F)
	case String:
		return Repr(v.S)
	case Array:
		parts := make([]string, len(v.A))
		for i, e := range v.A {
			parts[i] = e.PyRepr()
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case Object:
		parts := make([]string, len(v.O.keys))
		for i, k := range v.O.keys {
			parts[i] = Repr(k) + ": " + v.O.vals[i].PyRepr()
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return ""
}

// Repr returns Python's repr() of a str.
func Repr(s string) string {
	quote := byte('\'')
	if strings.IndexByte(s, '\'') >= 0 && strings.IndexByte(s, '"') < 0 {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f:
			b.WriteRune(r)
		case !unicode.IsPrint(r):
			switch {
			case r <= 0xff:
				fmt.Fprintf(&b, `\x%02x`, r)
			case r <= 0xffff:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				fmt.Fprintf(&b, `\U%08x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// ReprList returns repr(list_of_str).
func ReprList(items []string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = Repr(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
