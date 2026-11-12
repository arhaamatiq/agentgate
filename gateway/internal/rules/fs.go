package rules

// Port of agentgate/analyzers/filesystem.py.
//
// Location heuristics (Unix system directories, log-file names, the broad
// path patterns) only escalate, instead of blocking, when the path lies
// inside a resource the scope explicitly grants; see coveringGrant.
//
// One intentional difference: the Python analyzer's symlink check calls
// os.path.islink() on the *firewall host*. A gateway does not share the
// tool's filesystem, so that check is host-dependent noise (on macOS it flags
// a bare "/etc" because /etc -> /private/etc) and is omitted here.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

var fsOverlong = []struct{ old, new []byte }{
	{[]byte("\xc0\xae"), []byte(".")},
	{[]byte("\xc0\xaf"), []byte("/")},
	{[]byte("\xc1\x9c"), []byte("\\")},
	{[]byte("\xc0\x2e"), []byte(".")},
	{[]byte("\xe0\x80\xae"), []byte(".")},
	{[]byte("\xe0\x80\xaf"), []byte("/")},
	{[]byte("\xf0\x80\x80\xae"), []byte(".")},
	{[]byte("\xf0\x80\x80\xaf"), []byte("/")},
}

type namedRe struct {
	src string // the Python pattern source, quoted in reasoning strings
	re  *regexp.Regexp
}

func reMatcher(goPattern string) *regexp.Regexp { return mustRe(goPattern) }

var fsTraversal = []namedRe{
	{`\.\./`, reMatcher(`\.\./`)},
	{`\.\.$`, reMatcher(`\.\.` + reEnd)},
	{`\.\.\\`, reMatcher(`\.\.\\`)},
	{`%2e%2e[/\\%]`, reMatcher(`(?i)%2e%2e[/\\%]`)},
	{`\.%2e[/\\%]`, reMatcher(`(?i)\.%2e[/\\%]`)},
	{`%2e\.[/\\%]`, reMatcher(`(?i)%2e\.[/\\%]`)},
	{`%252e%252e`, reMatcher(`(?i)%252e%252e`)},
	{`\.\.2[fF]`, reMatcher(`\.\.2[fF]`)},
	{`2[fF]\.\.`, reMatcher(`2[fF]\.\.`)},
	{`\.\.%5[cC]`, reMatcher(`(?i)\.\.%5[cC]`)},
	{`%5[cC]\.\.`, reMatcher(`(?i)%5[cC]\.\.`)},
}

var fsSystemDirsUnix = []string{
	"/etc/", "/proc/", "/sys/", "/dev/", "/boot/",
	"/root/", "/var/log/", "/var/run/", "/var/www/",
	"/usr/sbin/", "/sbin/",
	"/usr/local/", "/usr/lib/", "/usr/etc/",
	"/usr/ports/", "/usr/pkgsrc/",
	"/apache/", "/apache2/",
	"/nginx/",
	"/srv/www/", "/srv/http/",
	"/opt/lampp/", "/opt/xampp/", "/opt/bitnami/",
	"/var/log",
	"/private/etc/",
	"/postgresql/",
}

var fsSystemDirsWindows = []string{
	"c:/windows/", "c:/system32/", "c:/program files/",
	"c:/program files (x86)/", "c:/programdata/",
	"c:/inetpub/", "c:/xampp/", "c:/wamp/", "c:/wamp64/",
	"c:/appserv/",
	"d:/program files/", "d:/appserv/",
}

var fsWindowsDrive = mustRe(`[a-zA-Z]:[/\\]|\A[a-zA-Z]:[a-zA-Z]`)

// Matched as substrings of the lower-cased path. Mixed-case entries (e.g.
// ".git/HEAD") can therefore never match; that mirrors the reference.
var fsSensitiveFiles = []string{
	"/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group",
	"/etc/master.passwd", "/etc/security/passwd", "/etc/gshadow",
	".env", ".ssh/", "id_rsa", "id_ed25519", "id_dsa",
	".aws/credentials", ".git/config", ".git/HEAD",
	".kube/config", ".docker/config.json",
	"authorized_keys", "known_hosts",

	"access.log", "access_log", "accesslog",
	"error.log", "error_log", "errorlog",
	"auth.log", "syslog", "messages",
	"debug.log", "mail.log", "daemon.log",
	"pure-ftpd.log", "pureftpd.log",
	"pgadmin.log", "mysql.log", "postgresql.log",
	"catalina.out",

	"php.ini", "httpd.conf", "apache2.conf", "nginx.conf",
	"my.cnf", "my.ini", "postgresql.conf", "pg_hba.conf",
	".htaccess", ".htpasswd",
	"lighttpd.conf", "squid.conf",
	"proftpd.conf", "vsftpd.conf", "pure-ftpd.conf", "pureftpd.conf",
	"smb.conf", "sshd_config", "ssh_config",
	"resolv.conf", "fstab", "crontab",
	"named.conf",
	"pureftpd.pdb", "pureftpd.passwd",

	".bash_history", ".bashrc", ".bash_profile", ".bash_logout",
	".zsh_history", ".zshrc", ".zprofile", ".zlogin", ".zlogout",
	".profile", ".netrc", ".wgetrc", ".curlrc",
	".pgpass", ".mysql_history", ".viminfo", ".vimrc",
	".cshrc", ".tcshrc", ".logout", ".login", ".forward",
	".rhosts", ".shosts", ".exrc",

	"wp-config.php", "configuration.php", "config.php",
	"config.inc.php", "LocalSettings.php", "local_settings.py",
	"database.yml", "database.php",
	"settings.php", "parameters.yml", "parameters.ini",
	"web.config", "machine.config", "app.config",
	"connectionstrings.config",

	"global.asa", "global.asax",

	"boot.ini", "win.ini", "system.ini",
	"autoexec.bat", "config.sys",
	"sam", "ntuser.dat",

	"web.xml", "server.xml", "context.xml",
	".DS_Store",

	"config.asp", "config.aspx", "config.js",
	"database.asp", "database.aspx", "database.js",
	"install.php", "setup.php", "phpinfo.php",

	"master.passwd", "pass.dat", "passwd.dat",
	"mkuser.default",
}

// Entries of fsSensitiveFiles listed as log-poisoning targets rather than for
// what they contain: location heuristics, not credential files.
var fsLogFiles = map[string]bool{
	"access.log": true, "access_log": true, "accesslog": true,
	"error.log": true, "error_log": true, "errorlog": true,
	"auth.log": true, "syslog": true, "messages": true,
	"debug.log": true, "mail.log": true, "daemon.log": true,
	"pure-ftpd.log": true, "pureftpd.log": true,
	"pgadmin.log": true, "mysql.log": true, "postgresql.log": true,
	"catalina.out": true,
}

var fsSensitiveBasenames = map[string]bool{
	"passwd": true, "shadow": true, "master.passwd": true, "group": true,
	".passwd": true, ".pass": true, ".passw": true, ".password": true,
	"pass.dat": true, "passwd.dat": true, "password.dat": true,
	"db.php": true, "data.php": true, "users.db": true, "users.db.php": true,
	"mkuser.default": true, "htpasswd": true, ".htpasswd": true,
	".pgpass": true, ".my.cnf": true,
}

type descRe struct {
	desc string
	m    func(string) bool
}

func dr(desc, pattern string) descRe {
	re := mustRe(pattern)
	return descRe{desc, re.MatchString}
}

var fsBasenamePatterns = []descRe{
	dr("Cryptographic key file", `(?i)\.(?:key|pem|p12|pfx|jks|keystore)`+reEnd),
	dr("Certificate file", `(?i)\.(?:crt|cer|der)`+reEnd),
	dr("Credential/secret file", `(?i)(?:credential|secret|private[_-]?key|signing[_-]?key|api[_-]?key|master[_-]?key|keystore)`),
}

var fsPathPatterns = []descRe{
	dr("Configuration file", `(?i)\.conf`+reEnd),
	dr("Configuration file", `(?i)\.cfg`+reEnd),
	dr("Config file (config.*)", `(?i)(?:\A|[/\\])config\.`+reW+`+`+reEnd),
	dr("Database config (database.*)", `(?i)(?:\A|[/\\])database\.`+reW+`+`+reEnd),
	dr("ASP global config", `(?i)(?:\A|[/\\])global\.asa[x]?`+reEnd),
	dr("Admin/install script", `(?i)(?:\A|[/\\])(?:install|setup)\.`+reW+`+`+reEnd),
	dr("PHP info exposure", `(?i)(?:\A|[/\\])phpinfo\.`+reW+`+`+reEnd),
	dr("Backup directory", `(?i)(?:\A|/)backups?(?:/|`+reEnd+`)`),
}

var fsBase64 = mustRe(`\A[A-Za-z0-9+/]{12,}={0,3}` + reEnd)

// rawPercentDecode mirrors _raw_percent_decode: bytes viewed as latin-1, and
// int(pair, 16) quirks (whitespace, signs) preserved.
func rawPercentDecode(data []byte) []byte {
	out := make([]byte, 0, len(data))
	n := len(data)
	for i := 0; i < n; {
		if data[i] == '%' && i+2 < n {
			pair := string([]rune{rune(data[i+1]), rune(data[i+2])})
			if v, ok := pyIntHex2(pair); ok && v >= 0 && v <= 255 {
				out = append(out, byte(v))
				i += 3
				continue
			}
		}
		out = append(out, data[i])
		i++
	}
	return out
}

func fsDecodePath(path string) string {
	raw := unquoteToBytes([]byte(path))
	raw = rawPercentDecode(raw)
	for _, o := range fsOverlong {
		raw = bytes.ReplaceAll(raw, o.old, o.new)
	}
	raw = bytes.ReplaceAll(raw, []byte{0}, nil)
	decoded := nfkc(decodeUTF8Replace(raw))
	decoded = strings.ReplaceAll(decoded, "\ufffd", "")
	return strings.ReplaceAll(decoded, "\x00", "")
}

func fsCheckTraversal(path string) string {
	for _, p := range fsTraversal {
		if p.re.MatchString(path) {
			return "Path traversal detected: " + p.src
		}
	}
	if n := posixNormpath(path); n != path && strings.Contains(path, "..") {
		return fmt.Sprintf("Path normalization reveals traversal: %s -> %s", path, n)
	}
	return ""
}

// fsUnixSystemDir returns the Unix system-directory entry the path falls under.
func fsUnixSystemDir(path string) string {
	pl := strings.ReplaceAll(pyLower(path), "\\", "/")
	if !strings.HasPrefix(pl, "/") {
		pl = "/" + pl
	}
	for _, d := range fsSystemDirsUnix {
		if strings.HasPrefix(pl, d) || pl == strings.TrimRight(d, "/") {
			return d
		}
	}
	return ""
}

func fsCheckSystemDirs(path string) string {
	pl := strings.ReplaceAll(pyLower(path), "\\", "/")
	if !strings.HasPrefix(pl, "/") {
		pl = "/" + pl
	}
	if d := fsUnixSystemDir(path); d != "" {
		return "System directory access: " + d
	}
	for _, check := range []string{pl, pl[1:]} {
		for _, d := range fsSystemDirsWindows {
			if strings.HasPrefix(check, d) {
				return "Windows system directory: " + d
			}
		}
	}
	return ""
}

func fsCheckSensitiveFiles(path string) string { return fsCheckSensitiveFilesSkip(path, nil) }

func fsCheckSensitiveFilesSkip(path string, skip map[string]bool) string {
	pl := strings.ReplaceAll(pyLower(path), "\\", "/")
	for _, s := range fsSensitiveFiles {
		if strings.Contains(pl, s) && !skip[s] {
			return "Sensitive file access: " + s
		}
	}
	return ""
}

func fsCheckSensitiveBasenames(path string) string {
	base := pyLower(posixBasename(strings.ReplaceAll(path, "\\", "/")))
	if base == "" {
		return ""
	}
	if fsSensitiveBasenames[base] {
		return "Sensitive basename: " + base
	}
	for _, p := range fsBasenamePatterns {
		if p.m(base) {
			return "Sensitive basename pattern: " + p.desc
		}
	}
	return ""
}

func fsIsAppPath(path string) bool {
	l := pyLower(path)
	return strings.HasPrefix(l, "/app/") || strings.HasPrefix(l, "app/") || strings.HasPrefix(l, "./app/")
}

func fsCheckSensitivePatterns(path string) string {
	pn := strings.ReplaceAll(path, "\\", "/")
	for _, p := range fsPathPatterns {
		if p.m(pn) {
			return "Sensitive pattern match: " + p.desc
		}
	}
	return ""
}

// pyB64Decode mirrors base64.b64decode on input already known to match
// [A-Za-z0-9+/]{12,}={0,3}.
func pyB64Decode(s string) ([]byte, bool) {
	data := strings.TrimRight(s, "=")
	pad := len(s) - len(data)
	switch len(data) % 4 {
	case 1:
		return nil, false
	case 2:
		if pad < 2 {
			return nil, false
		}
	case 3:
		if pad < 1 {
			return nil, false
		}
	}
	out, err := base64.RawStdEncoding.DecodeString(data)
	if err != nil {
		return nil, false
	}
	return out, true
}

func fsCheckBase64(path string) string {
	stripped := pyStrip(path)
	if !fsBase64.MatchString(stripped) {
		return ""
	}
	raw, ok := pyB64Decode(strings.TrimSuffix(stripped, "\n"))
	if !ok || !utf8.Valid(raw) {
		return ""
	}
	decoded := string(raw)
	if !strings.ContainsAny(decoded, "/\\") {
		return ""
	}
	normalized := posixNormpath(decoded)
	if fsCheckSystemDirs(normalized) != "" {
		return "Base64-encoded path to system directory: " + decoded
	}
	if fsCheckSensitiveFiles(normalized) != "" {
		return "Base64-encoded sensitive file: " + decoded
	}
	if fsCheckTraversal(decoded) != "" {
		return "Base64-encoded path traversal: " + decoded
	}
	return ""
}

// absParts returns the components of an absolute POSIX path, or nil (ok
// false) if it is relative or climbs with "..".
func absParts(path string) ([]string, bool) {
	if !strings.HasPrefix(path, "/") {
		return nil, false
	}
	var parts []string
	for _, p := range strings.Split(path, "/") {
		switch p {
		case "", ".":
		case "..":
			return nil, false
		default:
			parts = append(parts, p)
		}
	}
	return parts, true
}

// coveringGrant returns the granted resource that contains path, by whole
// components and case-sensitively. The grant must be absolute and not the
// root, and deeper than the system directory the path is in, if any.
func coveringGrant(path string, granted []string, systemDir string) (string, bool) {
	parts, ok := absParts(path)
	if !ok {
		return "", false
	}
	minDepth := 1
	if systemDir != "" {
		minDepth = len(strings.FieldsFunc(systemDir, func(r rune) bool { return r == '/' })) + 1
	}
	for _, g := range granted {
		gp, ok := absParts(g)
		if !ok || len(gp) == 0 || len(gp) < minDepth || len(gp) > len(parts) {
			continue
		}
		match := true
		for i := range gp {
			if gp[i] != parts[i] {
				match = false
				break
			}
		}
		if match {
			return g, true
		}
	}
	return "", false
}

func analyzeFilesystem(path, operation string, granted []string) analysis {
	if pyStrip(path) == "" {
		return analysis{Allow, SevLow, "Empty path"}
	}
	hasNull := strings.Contains(path, "\x00") || strings.Contains(pyLower(path), "%00")
	decoded := fsDecodePath(path)

	var threats []string
	maxSev := SevLow
	location := 0 // threats that are location heuristics only
	add := func(t string, sev Severity) {
		threats = append(threats, t)
		maxSev = maxSeverity(maxSev, sev)
	}
	if hasNull {
		add("Null byte injection detected", SevHigh)
	}
	tr := fsCheckTraversal(decoded)
	if tr == "" {
		tr = fsCheckTraversal(path)
	}
	if tr != "" {
		add(tr, SevCritical)
	}
	normalized := posixNormpath(decoded)
	unixSystemDir := fsUnixSystemDir(normalized)
	if t := fsCheckSystemDirs(normalized); t != "" {
		add(t, SevHigh)
		if unixSystemDir != "" {
			location++
		}
	}
	if fsWindowsDrive.MatchString(decoded) {
		add("Windows drive letter path detected", SevHigh)
	}
	if t := fsCheckSensitiveFiles(normalized); t != "" {
		add(t, SevHigh)
		if fsCheckSensitiveFilesSkip(normalized, fsLogFiles) == "" {
			location++
		}
	}
	if t := fsCheckSensitiveBasenames(normalized); t != "" {
		add(t, SevHigh)
	}
	if !fsIsAppPath(normalized) {
		if t := fsCheckSensitivePatterns(normalized); t != "" {
			add(t, SevHigh)
			location++
		}
	}
	if t := fsCheckBase64(path); t != "" {
		add(t, SevHigh)
	}
	if strings.Trim(decoded, "/") == "" && pyStrip(decoded) != "" {
		add("Root filesystem access", SevHigh)
	}

	switch {
	case operation == "delete":
		if strings.ContainsAny(decoded, "*?") {
			add("Wildcard deletion pattern — unknown blast radius", SevHigh)
		} else if strings.Trim(decoded, "/") != "" && posixSplitextExt(posixBasename(decoded)) == "" {
			add("Deletion target has no file extension — possible directory deletion", SevHigh)
		} else if len(threats) == 0 {
			maxSev = SevMedium
			threats = append(threats, "Potentially dangerous operation: delete")
		}
	case operation == "execute" && len(threats) == 0:
		maxSev = SevMedium
		threats = append(threats, "Potentially dangerous operation: execute")
	}

	if len(threats) == 0 {
		return analysis{Allow, SevLow, "Path appears safe"}
	}
	v := Escalate
	if maxSev == SevCritical || maxSev == SevHigh {
		v = Block
	}
	reasoning := "Filesystem threats detected: " + strings.Join(threats, "; ")
	if v == Block && location == len(threats) && decoded == path {
		if g, ok := coveringGrant(path, granted, unixSystemDir); ok {
			v = Escalate
			reasoning += " — inside granted resource '" + g + "', escalating to Tier 2"
		}
	}
	return analysis{v, maxSev, reasoning}
}
