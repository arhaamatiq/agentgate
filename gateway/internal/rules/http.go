package rules

// Port of agentgate/analyzers/http.py, including the CPython 3.12 urlsplit
// and ipaddress semantics it depends on.

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"unicode"
)

// ---------------------------------------------------------------- urlsplit

type pyURL struct{ scheme, netloc string }

var errURL = errors.New("invalid URL")

func isSchemeChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'
}

func pyURLSplit(url string) (pyURL, error) {
	url = strings.TrimLeftFunc(url, func(r rune) bool { return r <= 0x20 })
	url = strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(url)
	var u pyURL
	if i := strings.IndexByte(url, ':'); i > 0 && (url[0] >= 'a' && url[0] <= 'z' || url[0] >= 'A' && url[0] <= 'Z') {
		ok := true
		for j := 0; j < i; j++ {
			if !isSchemeChar(url[j]) {
				ok = false
				break
			}
		}
		if ok {
			u.scheme, url = strings.ToLower(url[:i]), url[i+1:]
		}
	}
	if strings.HasPrefix(url, "//") {
		delim := len(url)
		for _, c := range "/?#" {
			if w := strings.IndexRune(url[2:], c); w >= 0 && w+2 < delim {
				delim = w + 2
			}
		}
		u.netloc = url[2:delim]
		open, close := strings.Contains(u.netloc, "["), strings.Contains(u.netloc, "]")
		if open != close {
			return u, errURL
		}
		if open && close {
			if err := checkBracketedNetloc(u.netloc); err != nil {
				return u, err
			}
		}
	}
	if err := checkNetlocNFKC(u.netloc); err != nil {
		return u, err
	}
	return u, nil
}

var ipvFuture = mustRe(`\Av[a-fA-F0-9]+\.(?s:.)+\z`)

func checkBracketedNetloc(netloc string) error {
	hp := netloc[strings.LastIndexByte(netloc, '@')+1:]
	var hostname string
	if before, bracketed, ok := strings.Cut(hp, "["); ok {
		if before != "" {
			return errURL
		}
		h, port, _ := strings.Cut(bracketed, "]")
		if port != "" && !strings.HasPrefix(port, ":") {
			return errURL
		}
		hostname = h
	} else {
		hostname, _, _ = strings.Cut(hp, ":")
	}
	if strings.HasPrefix(hostname, "v") {
		if !ipvFuture.MatchString(hostname) {
			return errURL
		}
		return nil
	}
	a, ok := pyIPAddress(hostname)
	if !ok || a.Is4() {
		return errURL
	}
	return nil
}

func checkNetlocNFKC(netloc string) error {
	ascii := true
	for i := 0; i < len(netloc); i++ {
		if netloc[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if netloc == "" || ascii {
		return nil
	}
	n := strings.NewReplacer("@", "", ":", "", "#", "", "?", "").Replace(netloc)
	n2 := nfkc(n)
	if n == n2 {
		return nil
	}
	if strings.ContainsAny(n2, "/?#@:") {
		return errURL
	}
	return nil
}

// hostname mirrors SplitResult.hostname ("" for None).
func (u pyURL) hostname() string {
	hostinfo := u.netloc[strings.LastIndexByte(u.netloc, '@')+1:]
	var h string
	if _, bracketed, ok := strings.Cut(hostinfo, "["); ok {
		h, _, _ = strings.Cut(bracketed, "]")
	} else {
		h, _, _ = strings.Cut(hostinfo, ":")
	}
	if h == "" {
		return ""
	}
	host, zone, hasZone := strings.Cut(h, "%")
	if hasZone {
		return pyLower(host) + "%" + zone
	}
	return pyLower(host)
}

// ---------------------------------------------------------------- ipaddress

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

var (
	v4Private = []netip.Prefix{pfx("0.0.0.0/8"), pfx("10.0.0.0/8"), pfx("127.0.0.0/8"), pfx("169.254.0.0/16"),
		pfx("172.16.0.0/12"), pfx("192.0.0.0/24"), pfx("192.0.0.170/31"), pfx("192.0.2.0/24"), pfx("192.168.0.0/16"),
		pfx("198.18.0.0/15"), pfx("198.51.100.0/24"), pfx("203.0.113.0/24"), pfx("240.0.0.0/4"), pfx("255.255.255.255/32")}
	v4PrivateExc = []netip.Prefix{pfx("192.0.0.9/32"), pfx("192.0.0.10/32")}
	v6Private    = []netip.Prefix{pfx("::1/128"), pfx("::/128"), pfx("::ffff:0.0.0.0/96"), pfx("64:ff9b:1::/48"),
		pfx("100::/64"), pfx("2001::/23"), pfx("2001:db8::/32"), pfx("2002::/16"), pfx("3fff::/20"), pfx("fc00::/7"), pfx("fe80::/10")}
	v6PrivateExc = []netip.Prefix{pfx("2001:1::1/128"), pfx("2001:1::2/128"), pfx("2001:3::/32"), pfx("2001:4:112::/48"),
		pfx("2001:20::/28"), pfx("2001:30::/28")}
	v6Reserved = []netip.Prefix{pfx("::/8"), pfx("100::/8"), pfx("200::/7"), pfx("400::/6"), pfx("800::/5"), pfx("1000::/4"),
		pfx("4000::/3"), pfx("6000::/3"), pfx("8000::/3"), pfx("a000::/3"), pfx("c000::/3"), pfx("e000::/4"),
		pfx("f000::/5"), pfx("f800::/6"), pfx("fe00::/9")}
	awsEC2V6 = pfx("fd00:ec2::/32")

	metadataEndpoints = []string{"169.254.169.254", "metadata.google.internal", "metadata.goog",
		"100.100.100.200", "fd00:ec2::254", "169.254.170.2"}
	metadataIPs = func() map[netip.Addr]bool {
		m := map[netip.Addr]bool{}
		for _, e := range metadataEndpoints {
			if a, err := netip.ParseAddr(e); err == nil {
				m[a] = true
			}
		}
		return m
	}()
)

// pyIPAddress is ipaddress.ip_address(str). Python never accepts the
// "::ffff:1.2.3.4" form as IPv4, so 4-in-6 addresses stay IPv6.
func pyIPAddress(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	if a.Is6() {
		if host, zone, ok := strings.Cut(s, "%"); ok && (zone == "" || strings.Contains(zone, "%") || host == "") {
			return netip.Addr{}, false
		}
	}
	return a, true
}

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	a = a.WithZone("")
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// v4mapped returns the IPv4 address of an IPv4-mapped IPv6 address.
func v4mapped(a netip.Addr) (netip.Addr, bool) {
	if a.Is4In6() {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

func ipIsPrivate(a netip.Addr) bool {
	if m, ok := v4mapped(a); ok {
		a = m
	}
	if a.Is4() {
		return inAny(a, v4Private) && !inAny(a, v4PrivateExc)
	}
	return inAny(a, v6Private) && !inAny(a, v6PrivateExc)
}

func ipIsLoopback(a netip.Addr) bool {
	if m, ok := v4mapped(a); ok {
		a = m
	}
	if a.Is4() {
		return inAny(a, []netip.Prefix{pfx("127.0.0.0/8")})
	}
	return a.WithZone("") == netip.IPv6Loopback()
}

func ipIsLinkLocal(a netip.Addr) bool {
	if m, ok := v4mapped(a); ok {
		a = m
	}
	if a.Is4() {
		return inAny(a, []netip.Prefix{pfx("169.254.0.0/16")})
	}
	return inAny(a, []netip.Prefix{pfx("fe80::/10")})
}

func ipIsReserved(a netip.Addr) bool {
	if m, ok := v4mapped(a); ok {
		a = m
	}
	if a.Is4() {
		return inAny(a, []netip.Prefix{pfx("240.0.0.0/4")})
	}
	return inAny(a, v6Reserved)
}

func ipIsUnspecified(a netip.Addr) bool {
	if m, ok := v4mapped(a); ok {
		a = m
	}
	return a.WithZone("").IsUnspecified()
}

// pyIPString is str(IPv4Address | IPv6Address).
func pyIPString(a netip.Addr) string {
	if a.Is4In6() {
		// Python prints ::ffff:a.b.c.d mapped addresses in pure hex form.
		b := a.As16()
		z := a.Zone()
		s := fmt.Sprintf("::ffff:%x:%x", uint16(b[12])<<8|uint16(b[13]), uint16(b[14])<<8|uint16(b[15]))
		if z != "" {
			s += "%" + z
		}
		return s
	}
	return a.String()
}

func ipv4FromInt(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// pyInt mirrors int(s, base) for bases 8, 10 and 16. big=true means the
// value overflowed int64 (Python would return a large int).
func pyInt(s string, base int) (v int64, big bool, ok bool) {
	s = strings.TrimFunc(s, isPySpace)
	neg := false
	if strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") {
		neg = s[0] == '-'
		s = s[1:]
	}
	lower := strings.ToLower(s)
	switch {
	case base == 16 && strings.HasPrefix(lower, "0x"):
		s = s[2:]
		s = strings.TrimPrefix(s, "_")
	case base == 8 && strings.HasPrefix(lower, "0o"):
		s = s[2:]
		s = strings.TrimPrefix(s, "_")
	}
	if s == "" || strings.HasPrefix(s, "_") || strings.HasSuffix(s, "_") || strings.Contains(s, "__") {
		return 0, false, false
	}
	var acc uint64
	for _, r := range s {
		if r == '_' {
			continue
		}
		var d int
		switch {
		case unicode.Is(unicode.Nd, r):
			d = int(digitValue(r))
		case r >= 'a' && r <= 'z':
			d = int(r-'a') + 10
		case r >= 'A' && r <= 'Z':
			d = int(r-'A') + 10
		default:
			return 0, false, false
		}
		if d >= base {
			return 0, false, false
		}
		if !big {
			if acc > (math.MaxInt64-uint64(d))/uint64(base) {
				big = true
			} else {
				acc = acc*uint64(base) + uint64(d)
			}
		}
	}
	if big {
		return 0, true, true
	}
	v = int64(acc)
	if neg {
		v = -v
	}
	return v, false, true
}

// digitValue returns the decimal value of an Nd rune. Every contiguous run
// of Nd code points starts at a zero digit, so the value is the offset from
// the start of the run modulo 10.
func digitValue(r rune) rune {
	z := r
	for unicode.Is(unicode.Nd, z-1) {
		z--
	}
	return (r - z) % 10
}

const outOfRange = int64(math.MaxInt64)

// parseIPOctet mirrors _parse_ip_octet. ok=false is Python's None.
func parseIPOctet(part string) (int64, bool) {
	p := pyStrip(part)
	if p == "" {
		return 0, false
	}
	low := strings.ToLower(p)
	conv := func(s string, base int) (int64, bool) {
		v, big, ok := pyInt(s, base)
		if !ok {
			return 0, false
		}
		if big {
			return outOfRange, true
		}
		return v, true
	}
	rs := []rune(p)
	switch {
	case strings.HasPrefix(low, "0x"):
		return conv(p, 16)
	case strings.HasPrefix(low, "0o") && len(rs) > 2 && isPyDigitString(string(rs[2:])):
		return conv(string(rs[2:]), 8)
	case strings.ContainsRune("oOqQ", rs[0]) && len(rs) > 1 && isPyDigitString(string(rs[1:])):
		return conv(string(rs[1:]), 8)
	case len(rs) > 1 && rs[0] == '0' && isPyDigitString(p):
		return conv(p, 8)
	}
	return conv(p, 10)
}

func expandIPParts(parts []int64) (netip.Addr, bool) {
	in := func(v, hi int64) bool { return v >= 0 && v <= hi }
	switch len(parts) {
	case 4:
		for _, o := range parts {
			if !in(o, 255) {
				return netip.Addr{}, false
			}
		}
		return netip.AddrFrom4([4]byte{byte(parts[0]), byte(parts[1]), byte(parts[2]), byte(parts[3])}), true
	case 3:
		if in(parts[0], 255) && in(parts[1], 255) && in(parts[2], 65535) {
			return ipv4FromInt(uint32(parts[0]<<24 | parts[1]<<16 | parts[2])), true
		}
	case 2:
		if in(parts[0], 255) && in(parts[1], 16777215) {
			return ipv4FromInt(uint32(parts[0]<<24 | parts[1])), true
		}
	}
	return netip.Addr{}, false
}

func resolveObfuscatedIP(hostname string) (netip.Addr, bool) {
	clean := pyStrip(strings.Trim(hostname, "[]"))
	if clean == "" {
		return netip.Addr{}, false
	}
	if a, ok := pyIPAddress(clean); ok {
		if m, ok := v4mapped(a); ok && a.Is6() {
			return m, true
		}
		return a, true
	}
	if isPyDigitString(clean) {
		if v, big, ok := pyInt(clean, 10); ok && !big && v >= 0 && v <= 0xFFFFFFFF {
			return ipv4FromInt(uint32(v)), true
		}
	}
	if strings.HasPrefix(strings.ToLower(clean), "0x") && !strings.Contains(clean, ".") {
		if v, big, ok := pyInt(clean, 16); ok && !big && v >= 0 && v <= 0xFFFFFFFF {
			return ipv4FromInt(uint32(v)), true
		}
	}
	if strings.Contains(clean, ".") {
		parts := strings.Split(clean, ".")
		if len(parts) >= 2 && len(parts) <= 4 {
			vals := make([]int64, len(parts))
			for i, p := range parts {
				v, ok := parseIPOctet(p)
				if !ok {
					return netip.Addr{}, false
				}
				vals[i] = v
			}
			return expandIPParts(vals)
		}
	}
	return netip.Addr{}, false
}

// ---------------------------------------------------------------- analyzer

var (
	criticalSchemes = map[string]bool{"file": true, "gopher": true, "dict": true, "ldap": true, "ldaps": true,
		"jar": true, "netdoc": true, "php": true, "phar": true, "expect": true, "glob": true, "data": true,
		"vbscript": true, "javascript": true}

	metadataHostPatterns = []*namedHost{
		nh(`(?i)\Ametadata\.google\.internal` + reEnd),
		nh(`(?i)\Ametadata\.goog` + reEnd),
		nh(`(?i)\Ametadata` + reEnd),
		nh(`(?i)\Ainstance-data` + reEnd),
		nh(`(?i)\Akubernetes\.default`),
	}
	localhostPatterns = []*namedHost{
		nh(`(?i)\Alocalhost` + reEnd),
		nh(`(?i)\Aip6-localhost` + reEnd),
		nh(`(?i)\Aip6-loopback` + reEnd),
		nh(`\A127\.` + reDigit + `{1,3}\.` + reDigit + `{1,3}\.` + reDigit + `{1,3}` + reEnd),
		nh(`\A0\.0\.0\.0` + reEnd),
		nh(`\A\[?::1\]?` + reEnd),
		nh(`\A\[?0:0:0:0:0:0:0:1\]?` + reEnd),
		nh(`(?i)\A0x7f`),
		nh(`\A2130706433` + reEnd),
		nh(`\A017700000001` + reEnd),
		nh(`\A0177\.0+\.0+\.0*1` + reEnd),
	}
	privateRanges = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"}
	rebindDomains = []*namedHost{}
	templateVar   = mustRe(`(?i)\$\{[^}]+\}|\$[A-Z_]` + reW + `*`)
)

type namedHost struct{ m func(string) bool }

func nh(p string) *namedHost {
	re := mustRe(p)
	return &namedHost{re.MatchString}
}

func init() {
	for _, d := range []string{"nip.io", "xip.io", "sslip.io", "localtest.me", "lvh.me", "vcap.me",
		"lacolhost.com", "burpcollaborator.net", "oastify.com", "interact.sh", "requestbin.net",
		"ngrok.io", "ngrok-free.app", "serveo.net", "r3dir.me"} {
		rebindDomains = append(rebindDomains, nh(`(?i)\.`+strings.ReplaceAll(d, ".", `\.`)+reEnd))
	}
}

func checkDangerousScheme(scheme string) string {
	if scheme == "" {
		return ""
	}
	s := strings.ToLower(scheme)
	if s == "http" || s == "https" {
		return ""
	}
	if criticalSchemes[s] {
		return "Critical protocol handler: " + s + "://"
	}
	return "Non-HTTP scheme: " + s + "://"
}

func checkMetadataEndpoint(hostname string) string {
	hl := strings.Trim(pyLower(hostname), "[]")
	for _, e := range metadataEndpoints {
		if hl == e {
			return "Cloud metadata endpoint: " + e
		}
	}
	for _, p := range metadataHostPatterns {
		if p.m(hl) {
			return "Cloud metadata hostname: " + hostname
		}
	}
	return ""
}

func checkPrivateIP(hostname string) string {
	a, ok := pyIPAddress(strings.Trim(hostname, "[]"))
	if !ok {
		return ""
	}
	if a.Is6() {
		if v4, ok := v4mapped(a); ok {
			if ipIsPrivate(v4) || ipIsLoopback(v4) || ipIsLinkLocal(v4) || metadataIPs[v4] {
				return fmt.Sprintf("IPv4-mapped IPv6 to internal IP: %s → %s", hostname, v4)
			}
		}
		if awsEC2V6.Contains(a.WithZone("")) {
			return "AWS EC2 IPv6 metadata range: " + hostname
		}
	}
	if ipIsPrivate(a) || ipIsLoopback(a) || ipIsLinkLocal(a) {
		return "Private/internal IP: " + hostname
	}
	for _, c := range privateRanges {
		p := pfx(c)
		if p.Addr().Is4() == a.Is4() && p.Contains(a.WithZone("")) {
			return fmt.Sprintf("IP in private range %s: %s", c, hostname)
		}
	}
	return ""
}

func checkIPObfuscation(hostname string) string {
	r, ok := resolveObfuscatedIP(hostname)
	if !ok {
		return ""
	}
	rs := pyIPString(r)
	switch {
	case ipIsLoopback(r):
		return fmt.Sprintf("Obfuscated loopback IP: %s → %s", hostname, rs)
	case ipIsPrivate(r):
		return fmt.Sprintf("Obfuscated private IP: %s → %s", hostname, rs)
	case ipIsLinkLocal(r):
		return fmt.Sprintf("Obfuscated link-local IP: %s → %s", hostname, rs)
	case ipIsReserved(r):
		return fmt.Sprintf("Obfuscated reserved IP: %s → %s", hostname, rs)
	case metadataIPs[r]: // Python compares scope IDs too
		return fmt.Sprintf("Obfuscated metadata IP: %s → %s", hostname, rs)
	case ipIsUnspecified(r):
		return fmt.Sprintf("Obfuscated unspecified IP: %s → %s", hostname, rs)
	}
	return ""
}

func analyzeHTTP(url string) analysis {
	if pyStrip(url) == "" {
		return analysis{Allow, SevLow, "Empty URL"}
	}
	parsed, err := pyURLSplit(url)
	if err != nil {
		return analysis{Escalate, SevMedium, "URL could not be parsed — escalating to Tier 2"}
	}
	hostname := parsed.hostname()
	schemeThreat := checkDangerousScheme(parsed.scheme)
	schemeSev := SevHigh
	if criticalSchemes[strings.ToLower(parsed.scheme)] {
		schemeSev = SevCritical
	}
	if schemeThreat != "" && hostname == "" {
		return analysis{Block, schemeSev, "SSRF threats detected: " + schemeThreat}
	}
	if hostname == "" {
		return analysis{Escalate, SevMedium, "No hostname in URL"}
	}
	hostname = pyLower(nfkc(hostname))

	var threats []string
	maxSev := SevLow
	add := func(t string, s Severity) {
		if t != "" {
			threats = append(threats, t)
			maxSev = maxSeverity(maxSev, s)
		}
	}
	if templateVar.MatchString(hostname) {
		add("Template variable in hostname: "+hostname, SevHigh)
	}
	add(schemeThreat, schemeSev)
	add(checkMetadataEndpoint(hostname), SevCritical)
	for _, p := range localhostPatterns {
		if p.m(hostname) {
			add("Localhost variant detected: "+hostname, SevCritical)
			break
		}
	}
	add(checkPrivateIP(hostname), SevHigh)
	add(checkIPObfuscation(hostname), SevCritical)
	for _, p := range rebindDomains {
		if p.m(hostname) {
			add("DNS rebinding domain: "+hostname, SevHigh)
			break
		}
	}
	switch {
	case strings.Count(url, "@") > 1:
		add("Multiple @ signs — URL parser confusion", SevHigh)
	case strings.Contains(parsed.netloc, "\\"):
		add("Backslash in netloc — parser confusion", SevHigh)
	}
	if len(threats) == 0 {
		return analysis{Allow, SevLow, "URL appears safe"}
	}
	return analysis{Block, maxSev, "SSRF threats detected: " + strings.Join(threats, "; ")}
}
