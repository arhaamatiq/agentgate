package rules

// A Go emulation of the parts of sqlparse 0.5 the SQL analyzer relies on:
// the lexer (SQL_REGEX, in priority order), the statement splitter, and
// Statement.get_type(). RE2 has no lookaround or backreferences, so the rules
// that need them are implemented by hand, including the backtracking
// behavior of the number rules.

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type tokType uint8

const (
	tkError tokType = iota
	tkWS
	tkNewline
	tkCommentSingle
	tkCommentSingleHint
	tkCommentMulti
	tkCommentMultiHint
	tkKeyword
	tkDML
	tkDDL
	tkDCL
	tkCTE
	tkOrder
	tkTZCast
	tkName
	tkBuiltin
	tkPlaceholder
	tkPunct
	tkString
	tkLiteral
	tkNumber
	tkOperator
	tkComparison
	tkWildcard
	tkCommand
	tkAssignment
)

func (t tokType) isKeywordFamily() bool {
	switch t {
	case tkKeyword, tkDML, tkDDL, tkDCL, tkCTE, tkOrder, tkTZCast:
		return true
	}
	return false
}

func (t tokType) isWhitespace() bool { return t == tkWS || t == tkNewline }

func (t tokType) isComment() bool {
	switch t {
	case tkCommentSingle, tkCommentSingleHint, tkCommentMulti, tkCommentMultiHint:
		return true
	}
	return false
}

type sqlToken struct {
	typ tokType
	val string
}

const nameStart = `(?i:[A-ZÀ-Ü])`

var (
	lxHintSingle  = mustRe(`\A(?:--|# )\+.*?(?:\r\n|\r|\n|\z)`)
	lxHintMulti   = mustRe(`\A/\*\+(?s:.)*?\*/`)
	lxSingle      = mustRe(`\A(?:--|# ).*?(?:\r\n|\r|\n|\z)`)
	lxMulti       = mustRe(`\A/\*(?s:.)*?\*/`)
	lxNewline     = mustRe(`\A(?:\r\n|\r|\n)`)
	lxWS          = mustRe(`\A` + reS)
	lxBacktick    = mustRe("\\A`(?:``|[^`])*`")
	lxAcute       = mustRe(`\A´(?:´´|[^´])*´`)
	lxDollarTag   = mustRe(`\A\$(?:(?:_|` + nameStart + `)` + reW + `*)?\$`)
	lxPctPlace    = mustRe(`\A%(?:\(` + reW + `+\))?s`)
	lxColonPlace  = mustRe(`\A[$:?]` + reW + `+`)
	lxCommand     = mustRe(`\A\\` + reW + `+`)
	lxKwSpecial   = mustRe(`(?i)\A(?:CASE|IN|VALUES|USING|FROM|AS)`)
	lxAtName      = mustRe(`\A(?:@|##|#)` + nameStart + reW + `+`)
	lxNameWord    = mustRe(`\A` + nameStart + reW + `*`)
	lxHex         = mustRe(`(?i)\A-?0x[` + reDigit + `A-F]+`)
	lxFloatExp    = mustRe(`(?i)\A-?` + reDigit + `+(?:\.` + reDigit + `+)?E-?` + reDigit + `+`)
	lxString      = mustRe(`\A'(?:''|\\'|[^'])*'`)
	lxSymbol      = mustRe(`\A"(?:""|\\"|[^"])*"`)
	lxSymbol2     = mustRe(`\A(?:""|".*?[^\\]")`)
	lxBracketName = mustRe(`\A\[[^\]\[]+\]`)
	lxJoin        = mustRe(`(?i)\A(?:(?:LEFT` + reS + `+|RIGHT` + reS + `+|FULL` + reS + `+)?(?:INNER` + reS + `+|OUTER` + reS + `+|STRAIGHT` + reS + `+)?|(?:CROSS` + reS + `+|NATURAL` + reS + `+)?)?JOIN`)
	lxTZCast      = mustRe(`(?i)\A(?:AT|WITH')` + reS + `+TIME` + reS + `+ZONE` + reS + `+'[^']+'`)
	lxWord        = mustRe(`\A` + reW + `[$#\p{L}\p{N}_]*`)
	lxPunct       = mustRe(`\A[;:()\[\],\.]`)
	lxJSONOp      = mustRe(`\A(?:->>?|#>>?|@>|<@|\?\|?|\?&|-|#-)`)
	lxCompare     = mustRe(`\A[<>=~!]+`)
	lxOperator    = mustRe(`\A[+/@#%^&|^-]+`)
)

// Keyword rules that end in \b, as alternatives in Python's backtracking
// order. The first alternative whose end is a Unicode word boundary wins.
type kwRule struct {
	alts []*regexp.Regexp
	typ  tokType
}

func kwAlts(typ tokType, alts ...string) kwRule {
	r := kwRule{typ: typ}
	for _, a := range alts {
		a = strings.ReplaceAll(a, `\s`, reS)
		r.alts = append(r.alts, mustRe(`(?i)\A`+a))
	}
	return r
}

var lxKwRulesA = []kwRule{
	kwAlts(tkKeyword, `END\s+IF`, `END\s+LOOP`, `END\s+WHILE`, `END`),
	kwAlts(tkKeyword, `IF\s+NOT\s+EXISTS`, `IF\s+EXISTS`),
	kwAlts(tkKeyword, `NOT\s+NULL`),
	kwAlts(tkOrder, `(?:ASC|DESC)\s+NULLS\s+(?:FIRST|LAST)`, `(?:ASC|DESC)`),
	kwAlts(tkOrder, `NULLS\s+(?:FIRST|LAST)`),
	kwAlts(tkKeyword, `UNION\s+ALL`),
	kwAlts(tkDDL, `CREATE\s+OR\s+REPLACE`, `CREATE`),
	kwAlts(tkBuiltin, `DOUBLE\s+PRECISION`),
	kwAlts(tkKeyword, `GROUP\s+BY`),
	kwAlts(tkKeyword, `ORDER\s+BY`),
	kwAlts(tkKeyword, `PRIMARY\s+KEY`),
	kwAlts(tkKeyword, `HANDLER\s+FOR`),
	kwAlts(tkKeyword, `GO[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]`+reDigit+`+`),
	kwAlts(tkKeyword, `LATERAL\s+VIEW\s+(?:EXPLODE|INLINE|PARSE_URL_TUPLE|POSEXPLODE|STACK)`),
}

var lxKwRulesB = []kwRule{
	kwAlts(tkComparison, `NOT\s+(?:LIKE|ILIKE|RLIKE)`, `(?:LIKE|ILIKE|RLIKE)`),
	kwAlts(tkComparison, `NOT\s+REGEXP\s+BINARY`, `NOT\s+REGEXP`, `REGEXP\s+BINARY`, `REGEXP`),
}

func runeAt(s string, i int) (rune, bool) {
	if i >= len(s) {
		return 0, false
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return r, true
}

func runeBefore(s string, i int) (rune, bool) {
	if i <= 0 {
		return 0, false
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return r, true
}

// wordBoundaryAt reports Python's \b at byte offset i, given that the char
// before i is a word char (true for every keyword rule here).
func wordEndsAt(s string, i int) bool {
	r, ok := runeAt(s, i)
	return !ok || !isPyWordRune(r)
}

// isNameStartRune is (?i)[A-ZÀ-Ü] for one rune: true when any member of the
// rune's simple case-fold orbit falls in A-Z or U+00C0-U+00DC.
func isNameStartRune(r rune) bool {
	f := r
	for {
		if (f >= 'A' && f <= 'Z') || (f >= 0xC0 && f <= 0xDC) {
			return true
		}
		f = unicode.SimpleFold(f)
		if f == r {
			return false
		}
	}
}

func (k kwRule) match(s string) int {
	for _, re := range k.alts {
		if loc := re.FindStringIndex(s); loc != nil && wordEndsAt(s, loc[1]) {
			return loc[1]
		}
	}
	return -1
}

func isDigitRune(r rune) bool { return unicode.Is(unicode.Nd, r) }

// matchFloat emulates (?![_A-ZÀ-Ü])-?(\d+(\.\d*)|\.\d+)(?![_A-ZÀ-Ü]) with
// Python's backtracking order over the trailing negative lookahead.
func matchFloat(s string) int {
	j := 0
	if strings.HasPrefix(s, "-") {
		j = 1
	}
	digitsEnd := func(i int) int {
		for i < len(s) {
			r, sz := utf8.DecodeRuneInString(s[i:])
			if !isDigitRune(r) {
				break
			}
			i += sz
		}
		return i
	}
	notNameAt := func(i int) bool {
		r, ok := runeAt(s, i)
		return !ok || !(r == '_' || isNameStartRune(r))
	}
	tryEnds := func(minEnd, maxEnd int) int {
		for e := maxEnd; e >= minEnd; {
			if notNameAt(e) {
				return e
			}
			if e == minEnd {
				break
			}
			_, sz := utf8.DecodeLastRuneInString(s[:e])
			e -= sz
		}
		return -1
	}
	if r, ok := runeAt(s, j); ok && isDigitRune(r) {
		k := digitsEnd(j)
		if k < len(s) && s[k] == '.' {
			return tryEnds(k+1, digitsEnd(k+1))
		}
		return -1
	}
	if j < len(s) && s[j] == '.' {
		m := digitsEnd(j + 1)
		if m == j+1 {
			return -1
		}
		_, sz := utf8.DecodeRuneInString(s[j+1:])
		return tryEnds(j+1+sz, m)
	}
	return -1
}

// matchInt emulates (?![_A-ZÀ-Ü])-?\d+(?![_A-ZÀ-Ü]).
func matchInt(s string) int {
	j := 0
	if strings.HasPrefix(s, "-") {
		j = 1
	}
	start := j
	var ends []int
	for j < len(s) {
		r, sz := utf8.DecodeRuneInString(s[j:])
		if !isDigitRune(r) {
			break
		}
		j += sz
		ends = append(ends, j)
	}
	for i := len(ends) - 1; i >= 0; i-- {
		e := ends[i]
		r, ok := runeAt(s, e)
		if !ok || !(r == '_' || isNameStartRune(r)) {
			return e
		}
	}
	_ = start
	return -1
}

func lexSQL(text string) []sqlToken {
	var toks []sqlToken
	pos := 0
	emit := func(t tokType, n int) {
		toks = append(toks, sqlToken{t, text[pos : pos+n]})
		pos += n
	}
	for pos < len(text) {
		s := text[pos:]
		prev, hasPrev := runeBefore(text, pos)
		if loc := lxHintSingle.FindStringIndex(s); loc != nil {
			emit(tkCommentSingleHint, loc[1])
			continue
		}
		if loc := lxHintMulti.FindStringIndex(s); loc != nil {
			emit(tkCommentMultiHint, loc[1])
			continue
		}
		if loc := lxSingle.FindStringIndex(s); loc != nil {
			emit(tkCommentSingle, loc[1])
			continue
		}
		if loc := lxMulti.FindStringIndex(s); loc != nil {
			emit(tkCommentMulti, loc[1])
			continue
		}
		if loc := lxNewline.FindStringIndex(s); loc != nil {
			emit(tkNewline, loc[1])
			continue
		}
		if loc := lxWS.FindStringIndex(s); loc != nil {
			emit(tkWS, loc[1])
			continue
		}
		if strings.HasPrefix(s, ":=") {
			emit(tkAssignment, 2)
			continue
		}
		if strings.HasPrefix(s, "::") {
			emit(tkPunct, 2)
			continue
		}
		if s[0] == '*' {
			emit(tkWildcard, 1)
			continue
		}
		if loc := lxBacktick.FindStringIndex(s); loc != nil {
			emit(tkName, loc[1])
			continue
		}
		if loc := lxAcute.FindStringIndex(s); loc != nil {
			emit(tkName, loc[1])
			continue
		}
		if s[0] == '$' && !(hasPrev && (isPyWordRune(prev) || prev == '"' || prev == '$')) {
			if loc := lxDollarTag.FindStringIndex(s); loc != nil {
				tag := s[:loc[1]]
				if k := strings.Index(s[loc[1]:], tag); k >= 0 {
					emit(tkLiteral, loc[1]+k+len(tag))
					continue
				}
			}
		}
		if s[0] == '?' {
			emit(tkPlaceholder, 1)
			continue
		}
		if loc := lxPctPlace.FindStringIndex(s); loc != nil {
			emit(tkPlaceholder, loc[1])
			continue
		}
		if !(hasPrev && isPyWordRune(prev)) {
			if loc := lxColonPlace.FindStringIndex(s); loc != nil {
				emit(tkPlaceholder, loc[1])
				continue
			}
		}
		if loc := lxCommand.FindStringIndex(s); loc != nil {
			emit(tkCommand, loc[1])
			continue
		}
		if loc := lxKwSpecial.FindStringIndex(s); loc != nil && wordEndsAt(s, loc[1]) {
			emit(tkKeyword, loc[1])
			continue
		}
		if loc := lxAtName.FindStringIndex(s); loc != nil {
			emit(tkName, loc[1])
			continue
		}
		if loc := lxNameWord.FindStringIndex(s); loc != nil {
			// [A-ZÀ-Ü]\w*(?=\s*\.)
			rest := strings.TrimLeftFunc(s[loc[1]:], isPySpace)
			if strings.HasPrefix(rest, ".") {
				emit(tkName, loc[1])
				continue
			}
			// (?<=\.)[A-ZÀ-Ü]\w*
			if hasPrev && prev == '.' {
				emit(tkName, loc[1])
				continue
			}
			// [A-ZÀ-Ü]\w*(?=\()
			if strings.HasPrefix(s[loc[1]:], "(") {
				emit(tkName, loc[1])
				continue
			}
		}
		if loc := lxHex.FindStringIndex(s); loc != nil {
			emit(tkNumber, loc[1])
			continue
		}
		if loc := lxFloatExp.FindStringIndex(s); loc != nil {
			emit(tkNumber, loc[1])
			continue
		}
		if n := matchFloat(s); n > 0 {
			emit(tkNumber, n)
			continue
		}
		if n := matchInt(s); n > 0 {
			emit(tkNumber, n)
			continue
		}
		if loc := lxString.FindStringIndex(s); loc != nil {
			emit(tkString, loc[1])
			continue
		}
		if loc := lxSymbol.FindStringIndex(s); loc != nil {
			emit(tkString, loc[1])
			continue
		}
		if loc := lxSymbol2.FindStringIndex(s); loc != nil {
			emit(tkString, loc[1])
			continue
		}
		if !(hasPrev && (isPyWordRune(prev) || prev == ']' || prev == ')')) {
			if loc := lxBracketName.FindStringIndex(s); loc != nil {
				emit(tkName, loc[1])
				continue
			}
		}
		if loc := lxJoin.FindStringIndex(s); loc != nil && wordEndsAt(s, loc[1]) {
			emit(tkKeyword, loc[1])
			continue
		}
		matched := false
		for _, k := range lxKwRulesA {
			if n := k.match(s); n > 0 {
				emit(k.typ, n)
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		if loc := lxTZCast.FindStringIndex(s); loc != nil {
			emit(tkTZCast, loc[1])
			continue
		}
		for _, k := range lxKwRulesB {
			if n := k.match(s); n > 0 {
				emit(k.typ, n)
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		if loc := lxWord.FindStringIndex(s); loc != nil {
			word := s[:loc[1]]
			t, ok := sqlKeywords[pyUpper(word)]
			if !ok {
				t = tkName
			}
			emit(t, loc[1])
			continue
		}
		if loc := lxPunct.FindStringIndex(s); loc != nil {
			emit(tkPunct, loc[1])
			continue
		}
		if loc := lxJSONOp.FindStringIndex(s); loc != nil {
			emit(tkOperator, loc[1])
			continue
		}
		if loc := lxCompare.FindStringIndex(s); loc != nil {
			emit(tkComparison, loc[1])
			continue
		}
		if loc := lxOperator.FindStringIndex(s); loc != nil {
			emit(tkOperator, loc[1])
			continue
		}
		_, sz := utf8.DecodeRuneInString(s)
		emit(tkError, sz)
	}
	return toks
}

// splitStatements emulates sqlparse.engine.StatementSplitter.
func splitStatements(toks []sqlToken) [][]sqlToken {
	var out [][]sqlToken
	var cur []sqlToken
	var (
		inDeclare, inCase, isCreate, seenBegin bool
		beginDepth, level                      int
		consumeWS                              bool
	)
	reset := func() {
		inDeclare, inCase, isCreate, seenBegin = false, false, false, false
		beginDepth, level = 0, 0
		consumeWS = false
		cur = nil
	}
	_ = inDeclare
	change := func(t sqlToken) int {
		if t.typ == tkPunct && t.val == "(" {
			return 1
		}
		if t.typ == tkPunct && t.val == ")" {
			return -1
		}
		if !t.typ.isKeywordFamily() {
			return 0
		}
		u := pyUpper(t.val)
		if t.typ == tkDDL && strings.HasPrefix(u, "CREATE") {
			isCreate = true
			return 0
		}
		if u == "DECLARE" && isCreate && beginDepth == 0 {
			inDeclare = true
			return 1
		}
		if u == "BEGIN" {
			beginDepth++
			seenBegin = true
			if isCreate {
				return 1
			}
			return 0
		}
		if seenBegin && (t.typ == tkKeyword || t.typ == tkName) {
			switch u {
			case "TRANSACTION", "WORK", "TRAN", "DISTRIBUTED", "DEFERRED", "IMMEDIATE", "EXCLUSIVE":
				if beginDepth > 0 {
					beginDepth--
				}
				seenBegin = false
				return 0
			}
		}
		if u == "END" {
			if !inCase {
				if beginDepth > 0 {
					beginDepth--
				}
			} else {
				inCase = false
			}
			return -1
		}
		if (u == "IF" || u == "FOR" || u == "WHILE" || u == "CASE") && isCreate && beginDepth > 0 {
			if u == "CASE" {
				inCase = true
			}
			return 1
		}
		if u == "END IF" || u == "END FOR" || u == "END WHILE" {
			return -1
		}
		return 0
	}
	for _, t := range toks {
		// The seenBegin transaction check above only fires for exact Keyword
		// or Name; it is evaluated on every token, so mirror that ordering.
		if consumeWS && t.typ != tkWS && t.typ != tkCommentSingle {
			out = append(out, cur)
			reset()
		}
		level += change(t)
		cur = append(cur, t)
		switch {
		case t.typ == tkPunct && t.val == ";":
			if seenBegin && beginDepth > 0 {
				beginDepth--
			}
			seenBegin = false
			if level <= 0 && beginDepth == 0 {
				consumeWS = true
			}
		case t.typ == tkKeyword && firstField(t.val) == "GO":
			consumeWS = true
		case !(t.typ == tkWS || t.typ == tkNewline || t.typ == tkCommentSingle || t.typ == tkCommentMulti) &&
			!(t.typ == tkKeyword && pyUpper(t.val) == "BEGIN"):
			seenBegin = false
		}
	}
	if len(cur) > 0 {
		allWS := true
		for _, t := range cur {
			if !t.typ.isWhitespace() {
				allWS = false
				break
			}
		}
		if !allWS {
			out = append(out, cur)
		}
	}
	return out
}

func firstField(s string) string {
	f := pySplit(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// statementType emulates Statement.get_type().
func statementType(stmt []sqlToken) string {
	first := -1
	for i, t := range stmt {
		if t.typ.isWhitespace() || t.typ.isComment() {
			continue
		}
		first = i
		break
	}
	if first < 0 {
		return "UNKNOWN"
	}
	t := stmt[first]
	if t.typ == tkDML || t.typ == tkDDL {
		return pyUpper(t.val)
	}
	if t.typ == tkCTE {
		// sqlparse walks the grouped statement after WITH and returns the
		// first DML keyword that directly follows an Identifier or
		// IdentifierList group. align_comments folds a trailing comment
		// into the group before it, so comments are transparent here.
		// Without porting all of sqlparse's grouping, a token ends such a
		// group when it is a name or quoted symbol, the ")" of a matched
		// parenthesis, or the alias word in "AS <word>". Unmatched
		// parentheses are not groups in sqlparse, so they don't nest here.
		rest := stmt[first+1:]
		match := matchParens(rest)
		depth := 0
		var prev, prevPrev *sqlToken
		for i := range rest {
			tk := &rest[i]
			if tk.typ.isWhitespace() || tk.typ.isComment() {
				continue
			}
			if depth == 0 && tk.typ == tkDML && prev != nil && endsIdentifier(prev, prevPrev) {
				return pyUpper(tk.val)
			}
			if tk.typ == tkPunct && tk.val == "(" && match[i] {
				depth++
			} else if tk.typ == tkPunct && tk.val == ")" && match[i] {
				depth--
			}
			prevPrev, prev = prev, tk
		}
	}
	return "UNKNOWN"
}

// matchParens marks parentheses that have a partner.
func matchParens(toks []sqlToken) map[int]bool {
	m := map[int]bool{}
	var stack []int
	for i, t := range toks {
		if t.typ != tkPunct {
			continue
		}
		switch t.val {
		case "(":
			stack = append(stack, i)
		case ")":
			if len(stack) > 0 {
				m[stack[len(stack)-1]] = true
				m[i] = true
				stack = stack[:len(stack)-1]
			}
		}
	}
	return m
}

func endsIdentifier(prev, prevPrev *sqlToken) bool {
	switch {
	case prev.typ == tkName:
		return true
	case prev.typ == tkString && strings.HasPrefix(prev.val, `"`):
		return true
	case prev.typ == tkPunct && prev.val == ")":
		return true
	case prevPrev != nil && prevPrev.typ == tkKeyword && pyUpper(prevPrev.val) == "AS" &&
		prev.typ != tkDML && prev.typ != tkDDL && prev.typ != tkCTE && prev.typ != tkPunct:
		return true
	}
	return false
}
