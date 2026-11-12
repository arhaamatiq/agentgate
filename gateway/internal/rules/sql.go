package rules

// Port of agentgate/analyzers/sql.py.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type analysis struct {
	verdict   Verdict
	severity  Severity
	reasoning string
}

var (
	sqlDestructiveKW = map[string]bool{"DROP": true, "TRUNCATE": true, "DELETE": true, "ALTER": true, "GRANT": true, "REVOKE": true}
	sqlWriteKW       = map[string]bool{"INSERT": true, "UPDATE": true, "CREATE": true, "MERGE": true, "UPSERT": true, "REPLACE": true, "REFRESH": true}
	sqlSafeKW        = map[string]bool{"SELECT": true, "SHOW": true, "DESCRIBE": true, "EXPLAIN": true, "WITH": true}

	sqlFastDestructive = mustRe(`(?i)\b(DROP|TRUNCATE|DELETE` + reS + `+FROM|ALTER` + reS + `+TABLE|GRANT|REVOKE)\b`)
	sqlComment         = mustRe(`(?s)/\*.*?\*/`)
	sqlStringLiteral   = mustRe(`'[^']*'`)
	sqlHexEscape       = mustRe(`\\x([0-9a-fA-F]{2})`)

	sqlStarters = map[string]bool{}
)

func init() {
	for _, w := range strings.Fields(`SELECT INSERT UPDATE DELETE CREATE DROP ALTER WITH EXPLAIN SHOW DESCRIBE
		TRUNCATE GRANT REVOKE SET BEGIN COMMIT ROLLBACK SAVEPOINT MERGE CALL EXEC EXECUTE USE DECLARE IF
		WHILE REPLACE UPSERT VALUES TABLE INDEX VIEW REFRESH`) {
		sqlStarters[w] = true
	}
}

type sqlPattern struct {
	re     *regexp.Regexp
	desc   string
	sev    Severity
	leadB  bool // pattern starts with \b
	trailB bool // pattern ends with \b
}

func sp(re string, desc string, sev Severity) sqlPattern {
	return sqlPattern{
		re: mustRe(re), desc: desc, sev: sev,
		leadB:  strings.HasPrefix(strings.TrimPrefix(re, "(?i)"), `\b`),
		trailB: strings.HasSuffix(re, `\b`),
	}
}

var sqlInjectionPatterns = []sqlPattern{
	sp(`(?i)\bUNION`+reS+`+(?:ALL`+reS+`+)?SELECT\b`, "UNION SELECT exfiltration", SevHigh),
	sp(`(?i)\bEXEC`+reS+`*\(`, "Dynamic SQL execution (EXEC())", SevCritical),
	sp(`(?i)\bEXEC`+reS+`+`+reW+`+`, "Stored procedure execution (EXEC)", SevHigh),
	sp(`(?i)\bEXECUTE`+reS+`+`, "SQL execution (EXECUTE)", SevCritical),
	sp(`(?i)\bxp_cmdshell\b`, "OS command execution (xp_cmdshell)", SevCritical),
	sp(`(?i)\bsp_executesql\b`, "Dynamic SQL execution (sp_executesql)", SevCritical),
	sp(`(?i)\bxp_`+reW+`+\b`, "Extended stored procedure (xp_)", SevCritical),
	sp(`(?i)\bDECLARE`+reS+`+@`, "Variable declaration injection (DECLARE @)", SevHigh),
	sp(`(?i)\bLOAD_FILE`+reS+`*\(`, "SQL file read (LOAD_FILE)", SevCritical),
	sp(`(?i)\bINTO`+reS+`+OUTFILE\b`, "SQL file write (INTO OUTFILE)", SevCritical),
	sp(`(?i)\bINTO`+reS+`+DUMPFILE\b`, "SQL file write (INTO DUMPFILE)", SevCritical),
	sp(`(?i);`+reS+`*(?:DROP|DELETE|TRUNCATE|ALTER|EXEC|EXECUTE|DECLARE|GRANT|REVOKE|CREATE)\b`, "Stacked query with dangerous operation", SevCritical),
	sp(`\A`+reS+`*0x[0-9a-fA-F]{16,}`, "Hex-encoded payload", SevHigh),
}

var sqlPostASTIndicators = []sqlPattern{
	sp(`(?i)\bUNION\b`, "UNION keyword", SevHigh),
	sp(`@`+reW+`+`+reS+`*=`, "@variable assignment", SevHigh),
	sp(`@@`+reW+`+`, "@@system variable access", SevHigh),
	sp(`(?i)\bDECLARE\b`, "DECLARE keyword", SevHigh),
	sp(`(?i)\binformation_schema\b`, "information_schema access", SevHigh),
	sp(`(?i)\bsyscolumns\b`, "syscolumns system table", SevHigh),
	sp(`(?i)\bsysobjects\b`, "sysobjects system table", SevHigh),
	sp(`(?i)\bsys\.`+reW+`+`, "sys.* system catalog", SevHigh),
	sp(`(?i)\bmysql\.`+reW+`+`, "mysql.* system catalog", SevHigh),
	sp(`(?i)\bLOAD_FILE\b`, "LOAD_FILE function", SevHigh),
	sp(`(?i)\bINTO`+reS+`+(?:OUT|DUMP)FILE\b`, "INTO OUTFILE/DUMPFILE", SevHigh),
	sp(`(?i)\bINTO`+reS+`+TEMP\b`, "INTO TEMP table", SevHigh),
	sp(`(?i)\bEXEC[`+pyWS+`(]`, "EXEC keyword", SevHigh),
}

// pySearch finds the first match of re in s that also satisfies Python's
// Unicode \b at the pattern's ends. RE2's \b is ASCII-only, so it accepts
// boundaries next to non-ASCII letters that Python rejects.
func pySearch(re *regexp.Regexp, s string, leadB, trailB bool) []int {
	if !leadB && !trailB {
		return re.FindStringSubmatchIndex(s)
	}
	for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
		if leadB {
			if r, ok := runeBefore(s, m[0]); ok && isPyWordRune(r) {
				continue
			}
		}
		if trailB {
			if r, ok := runeAt(s, m[1]); ok && isPyWordRune(r) {
				continue
			}
		}
		return m
	}
	return nil
}

func (p sqlPattern) search(s string) []int { return pySearch(p.re, s, p.leadB, p.trailB) }

func sqlPreprocess(sql string) string {
	d := pyUnquote(pyUnquote(sql))
	d = sqlHexEscape.ReplaceAllStringFunc(d, func(m string) string {
		n, _ := strconv.ParseUint(m[2:], 16, 8)
		return string(rune(n))
	})
	return strings.ReplaceAll(d, "\x00", "")
}

func analyzeSQL(sql string) analysis {
	if pyStrip(sql) == "" {
		return analysis{Allow, SevLow, "Empty SQL statement"}
	}
	sql = sqlPreprocess(sql)
	if a, ok := sqlFastPass(sql); ok {
		return a
	}
	return sqlASTPass(sql)
}

func sqlFastPass(sql string) (analysis, bool) {
	stripped := sqlComment.ReplaceAllString(sql, "")
	noLiterals := sqlStringLiteral.ReplaceAllString(stripped, "''")
	if m := pySearch(sqlFastDestructive, noLiterals, true, true); m != nil {
		keyword := pyUpper(firstField(noLiterals[m[2]:m[3]]))
		sev := SevHigh
		if keyword == "DROP" || keyword == "TRUNCATE" {
			sev = SevCritical
		}
		return analysis{Block, sev, "Destructive SQL operation detected: " + keyword}, true
	}
	for _, p := range sqlInjectionPatterns {
		if p.search(stripped) != nil {
			return analysis{Block, p.sev, "Injection pattern detected: " + p.desc}, true
		}
	}
	return analysis{}, false
}

var sqlAllKnown = func() map[string]bool {
	m := map[string]bool{}
	for _, s := range []map[string]bool{sqlDestructiveKW, sqlWriteKW, sqlSafeKW} {
		for k := range s {
			m[k] = true
		}
	}
	return m
}()

func classifyStatement(stmt []sqlToken) string {
	st := pyUpper(statementType(stmt))
	if sqlAllKnown[st] {
		return st
	}
	for _, t := range stmt {
		if t.typ == tkDML || t.typ == tkDDL || t.typ == tkKeyword {
			v := pyStrip(pyUpper(t.val))
			if sqlAllKnown[v] {
				return v
			}
		}
	}
	return ""
}

// statementCandidates returns the classifications sqlparse could assign to a
// statement, the emulated get_type() result first. For WITH statements the
// emulation of sqlparse's identifier grouping is approximate, so every
// top-level DML after WITH and the flatten() fallback are candidates too.
func statementCandidates(stmt []sqlToken) []string {
	primary := classifyStatement(stmt)
	out := []string{primary}
	first := -1
	for i, t := range stmt {
		if !t.typ.isWhitespace() && !t.typ.isComment() {
			first = i
			break
		}
	}
	if first < 0 || stmt[first].typ != tkCTE {
		return out
	}
	seen := map[string]bool{primary: true}
	add := func(v string) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	rest := stmt[first+1:]
	match := matchParens(rest)
	depth := 0
	for i, tk := range rest {
		switch {
		case tk.typ == tkPunct && tk.val == "(" && match[i]:
			depth++
		case tk.typ == tkPunct && tk.val == ")" && match[i]:
			depth--
		case depth == 0 && tk.typ == tkDML && sqlAllKnown[pyUpper(tk.val)]:
			add(pyUpper(tk.val))
		}
	}
	for _, t := range stmt {
		if t.typ == tkDML || t.typ == tkDDL || t.typ == tkKeyword {
			if v := pyStrip(pyUpper(t.val)); sqlAllKnown[v] {
				add(v)
				break
			}
		}
	}
	return out
}

var verdictRank = map[Verdict]int{Allow: 0, Escalate: 1, Block: 2}

// sqlASTPass evaluates every combination of statement classifications and
// keeps the most restrictive outcome (the emulated get_type() combination
// wins ties). For all non-WITH SQL there is exactly one combination.
func sqlASTPass(sql string) analysis {
	var choices [][]string
	for _, stmt := range splitStatements(lexSQL(sql)) {
		choices = append(choices, statementCandidates(stmt))
	}
	idx := make([]int, len(choices))
	var best analysis
	bestRank := -1
	for combos := 0; combos < 256; combos++ {
		var types []string
		for i, c := range choices {
			if c[idx[i]] != "" {
				types = append(types, c[idx[i]])
			}
		}
		if a := aggregateSQL(types, sql); verdictRank[a.verdict] > bestRank {
			best, bestRank = a, verdictRank[a.verdict]
		}
		// advance the odometer
		i := len(idx) - 1
		for ; i >= 0; i-- {
			idx[i]++
			if idx[i] < len(choices[i]) {
				break
			}
			idx[i] = 0
		}
		if i < 0 {
			break
		}
	}
	return best
}

func aggregateSQL(types []string, sql string) analysis {
	maxSev := SevLow
	block := false
	for _, st := range types {
		if sqlDestructiveKW[st] {
			block = true
			if st == "DROP" || st == "TRUNCATE" {
				maxSev = SevCritical
			} else {
				maxSev = SevHigh
			}
		} else if sqlWriteKW[st] && maxSev == SevLow {
			maxSev = SevMedium
		}
	}
	tl := pyReprStrList(types)
	if block {
		return analysis{Block, maxSev, "AST analysis detected destructive operations: " + tl}
	}
	if len(types) == 0 {
		return analysis{Escalate, SevMedium, "Could not determine SQL statement type — escalating to Tier 2"}
	}
	onlySafe := true
	for _, t := range types {
		if !sqlSafeKW[t] {
			onlySafe = false
			break
		}
	}
	if onlySafe {
		if ind := sqlIndicatorScan(sql); ind != "" {
			return analysis{Block, SevHigh, "Injection indicator in statement classified as safe: " + ind}
		}
		return analysis{Allow, SevLow, "Read-only SQL operations: " + tl}
	}
	return analysis{Escalate, maxSev, "Write operations detected, escalating for review: " + tl}
}

func sqlIndicatorScan(sql string) string {
	var found []string
	for _, p := range sqlPostASTIndicators {
		if p.search(sql) != nil {
			found = append(found, p.desc)
		}
	}
	if len(found) > 0 {
		for _, f := range found {
			if f != "information_schema access" {
				return found[0]
			}
		}
		return ""
	}
	return sqlLooksLikeFragment(sql)
}

var (
	sqlFirstWord      = mustRe(`\A(` + reW + `+)`)
	sqlNumericStacked = mustRe(`\A` + reDigit + `+` + reS + `*;`)
)

func sqlLooksLikeFragment(sql string) string {
	stripped := pyStrip(sql)
	if stripped == "" {
		return ""
	}
	if m := sqlFirstWord.FindStringSubmatch(stripped); m != nil {
		fw := pyUpper(m[1])
		if !sqlStarters[fw] {
			return fmt.Sprintf("Does not start with SQL keyword (starts with '%s')", fw)
		}
	} else {
		r, _ := runeAt(stripped, 0)
		return "Starts with non-keyword character: " + reprStr(string(r))
	}
	if len(pySplit(stripped)) <= 1 {
		return "Bare SQL keyword without query structure"
	}
	if sqlNumericStacked.MatchString(stripped) {
		return "Numeric prefix with stacked query"
	}
	return ""
}

var (
	sqlTableFromJoin = mustRe(`(?i)\b(?:FROM|JOIN)` + reS + "+`?(" + reW + "+)`?(?:" + reS + `*\.` + reS + "*`?(" + reW + "+)`?)?")
	sqlTableInto     = mustRe(`(?i)\bINTO` + reS + "+`?(" + reW + "+)`?(?:" + reS + `*\.` + reS + "*`?(" + reW + "+)`?)?")
	sqlTableUpdate   = mustRe(`(?i)\bUPDATE` + reS + "+`?(" + reW + "+)`?(?:" + reS + `*\.` + reS + "*`?(" + reW + "+)`?)?")
	sqlCTEName       = mustRe(`(?i)\bWITH` + reS + `+(?:RECURSIVE` + reS + `+)?(` + reW + `+)` + reS + `+AS` + reS + `*\(`)
	sqlCTECont       = mustRe(`(?i)\)` + reS + `*,` + reS + `*(` + reW + `+)` + reS + `+AS` + reS + `*\(`)
	sqlNonTableWords = map[string]bool{"SELECT": true, "WHERE": true, "SET": true, "VALUES": true, "DUAL": true,
		"OUTFILE": true, "DUMPFILE": true, "TEMP": true, "TEMPORARY": true, "LOCAL": true, "TABLE": true}
)

// pyFindAllSub is re.finditer restricted to matches that satisfy a leading
// Unicode \b.
func pyFindAllSub(re *regexp.Regexp, s string) [][]int {
	var out [][]int
	for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
		if r, ok := runeBefore(s, m[0]); ok && isPyWordRune(r) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// extractTables mirrors SQLAnalyzer.extract_tables.
func extractTables(sql string) []string {
	if pyStrip(sql) == "" {
		return nil
	}
	cleaned := sqlComment.ReplaceAllString(sql, "")
	cleaned = sqlStringLiteral.ReplaceAllString(cleaned, "''")

	cte := map[string]bool{}
	for _, m := range pyFindAllSub(sqlCTEName, cleaned) {
		cte[pyLower(cleaned[m[2]:m[3]])] = true
	}
	for _, m := range sqlCTECont.FindAllStringSubmatchIndex(cleaned, -1) {
		cte[pyLower(cleaned[m[2]:m[3]])] = true
	}
	set := map[string]bool{}
	for _, re := range []*regexp.Regexp{sqlTableFromJoin, sqlTableInto, sqlTableUpdate} {
		for _, m := range pyFindAllSub(re, cleaned) {
			table := cleaned[m[2]:m[3]]
			if m[4] >= 0 {
				table = cleaned[m[4]:m[5]]
			}
			tl := pyLower(table)
			if !sqlNonTableWords[pyUpper(table)] && !cte[tl] {
				set[tl] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
