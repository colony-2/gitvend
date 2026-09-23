// Package policy implements the versioned, bounded JWT permission language.
package policy

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxRules   = 128
	MaxPattern = 1024
	MaxStates  = 8192
)

type Repository struct {
	Host, Path string
	FoldCase   bool
}
type Rule struct {
	Text, Host, Actions string
	Deny, Scoped        bool
	path, pathFold, ref *regexp.Regexp
	refExpr             string
}
type Policy struct{ Rules []Rule }
type Decision struct {
	Allowed bool     `json:"allowed"`
	Allows  []string `json:"allows"`
	Denies  []string `json:"denies"`
}

func Compile(lines []string) (*Policy, error) {
	if len(lines) == 0 || len(lines) > MaxRules {
		return nil, fmt.Errorf("permissions must contain 1..%d rules", MaxRules)
	}
	p := &Policy{}
	for i, line := range lines {
		r, err := parse(line)
		if err != nil {
			return nil, fmt.Errorf("permission %d: %w", i, err)
		}
		p.Rules = append(p.Rules, r)
	}
	return p, nil
}
func ValidHost(s string) bool {
	if len(s) == 0 || len(s) > 259 || s != strings.ToLower(s) {
		return false
	}
	host := s
	if strings.Contains(s, ":") {
		var port string
		var err error
		host, port, err = net.SplitHostPort(s)
		if err != nil {
			return false
		}
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return false
		}
	}
	if len(host) > 253 {
		return false
	}
	for _, part := range strings.Split(host, ".") {
		if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func splitAt(s string, delim byte) (int, error) {
	pos := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			if i == len(s) {
				return -1, fmt.Errorf("trailing escape")
			}
			continue
		}
		if s[i] == delim {
			if pos >= 0 {
				return -1, fmt.Errorf("multiple %q delimiters", delim)
			}
			pos = i
		}
	}
	return pos, nil
}
func parse(text string) (Rule, error) {
	r := Rule{Text: text}
	s := text
	if len(s) > MaxPattern || !utf8.ValidString(s) {
		return r, fmt.Errorf("invalid or oversized pattern")
	}
	if strings.HasPrefix(s, "!") {
		r.Deny = true
		s = s[1:]
	}
	slash := strings.IndexByte(s, '/')
	if slash < 1 {
		return r, fmt.Errorf("expected host/repository")
	}
	r.Host = s[:slash]
	if !ValidHost(r.Host) {
		return r, fmt.Errorf("host must be an exact lowercase authority")
	}
	s = s[slash+1:]
	colon, err := splitAt(s, ':')
	if err != nil || colon < 0 {
		return r, fmt.Errorf("expected one action delimiter")
	}
	r.Actions = s[colon+1:]
	s = s[:colon]
	seen := map[rune]bool{}
	for _, a := range r.Actions {
		if !strings.ContainsRune("rwdc", a) || seen[a] {
			return r, fmt.Errorf("invalid or duplicate action")
		}
		seen[a] = true
	}
	if len(seen) == 0 {
		return r, fmt.Errorf("empty actions")
	}
	hash, err := splitAt(s, '#')
	if err != nil {
		return r, err
	}
	ref := ""
	if hash >= 0 {
		r.Scoped = true
		ref = s[hash+1:]
		s = s[:hash]
		if ref == "" || seen['c'] {
			return r, fmt.Errorf("empty selector or branch-scoped creation")
		}
	}
	if s == "" || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") || strings.Contains(s, "//") {
		return r, fmt.Errorf("invalid repository path")
	}
	var pathExpr string
	if s == "*" || s == "**" {
		pathExpr = `[^/]+(?:/[^/]+)+`
	} else {
		parts := strings.Split(s, "/")
		if len(parts) < 2 {
			return r, fmt.Errorf("repository needs a namespace")
		}
		var out strings.Builder
		for i, part := range parts {
			if part == "." || part == ".." {
				return r, fmt.Errorf("invalid path segment")
			}
			if part == "**" {
				if i == len(parts)-1 {
					out.WriteString(`(?:[^/]+(?:/[^/]+)*)?`)
				} else {
					out.WriteString(`(?:[^/]+/)*`)
				}
				continue
			}
			expr, e := glob(part, false)
			if e != nil {
				return r, e
			}
			out.WriteString(expr)
			if i < len(parts)-1 {
				out.WriteByte('/')
			}
		}
		pathExpr = out.String()
	}
	r.path = regexp.MustCompile(`\A(?:` + pathExpr + `)\z`)
	r.pathFold = regexp.MustCompile(`\A(?i:` + pathExpr + `)\z`)
	if !r.Scoped {
		r.refExpr = `refs/(?:heads|tags)/.+`
	} else {
		prefix := "refs/heads/"
		if strings.HasPrefix(ref, "refs/") {
			switch {
			case strings.HasPrefix(ref, "refs/heads/"):
				ref = strings.TrimPrefix(ref, "refs/heads/")
			case strings.HasPrefix(ref, "refs/tags/"):
				prefix = "refs/tags/"
				ref = strings.TrimPrefix(ref, "refs/tags/")
			default:
				return r, fmt.Errorf("unsupported ref namespace")
			}
		}
		if ref == "" {
			return r, fmt.Errorf("empty ref pattern")
		}
		expr, e := glob(ref, true)
		if e != nil {
			return r, e
		}
		r.refExpr = regexp.QuoteMeta(prefix) + expr
	}
	r.ref = regexp.MustCompile(`\A(?:` + r.refExpr + `)\z`)
	return r, nil
}

// glob emits only quoted literals and controlled RE2 operators. User regex is never interpreted.
func glob(s string, slash bool) (string, error) {
	var b strings.Builder
	group := false
	groups := 0
	content := false
	for i := 0; i < len(s); {
		c, n := utf8.DecodeRuneInString(s[i:])
		i += n
		switch c {
		case '\\':
			if i == len(s) {
				return "", fmt.Errorf("trailing escape")
			}
			c, n = utf8.DecodeRuneInString(s[i:])
			i += n
			if !strings.ContainsRune(`()|#:!\*?[]`, c) {
				return "", fmt.Errorf("invalid escape")
			}
			b.WriteString(regexp.QuoteMeta(string(c)))
			content = true
		case '*':
			if i < len(s) && s[i] == '*' {
				return "", fmt.Errorf("** must be a repository path segment")
			}
			if slash {
				b.WriteString(`.*`)
			} else {
				b.WriteString(`[^/]*`)
			}
			content = true
		case '(':
			if group {
				return "", fmt.Errorf("nested alternatives")
			}
			groups++
			if groups > 16 {
				return "", fmt.Errorf("too many groups")
			}
			group = true
			content = false
			b.WriteString(`(?:`)
		case '|':
			if !group || !content {
				return "", fmt.Errorf("empty or ungrouped alternative")
			}
			content = false
			b.WriteByte('|')
		case ')':
			if !group || !content {
				return "", fmt.Errorf("unmatched or empty group")
			}
			group = false
			b.WriteByte(')')
			content = true
		case '?', '[', ']', '#', ':':
			return "", fmt.Errorf("unsupported unescaped pattern character")
		default:
			if c < 33 || c == 127 || (!slash && c == '/') {
				return "", fmt.Errorf("invalid pattern character")
			}
			b.WriteString(regexp.QuoteMeta(string(c)))
			content = true
		}
	}
	if group {
		return "", fmt.Errorf("unclosed group")
	}
	return b.String(), nil
}
func (r Rule) MatchesRepository(repo Repository) bool {
	if repo.Host != r.Host {
		return false
	}
	if repo.FoldCase {
		return r.pathFold.MatchString(repo.Path)
	}
	return r.path.MatchString(repo.Path)
}
func (p *Policy) Explain(repo Repository, ref, action string) Decision {
	d := Decision{Allows: []string{}, Denies: []string{}}
	for _, r := range p.Rules {
		if !r.MatchesRepository(repo) {
			continue
		}
		var match bool
		switch action {
		case "repo.read":
			match = strings.Contains(r.Actions, "r") && (!r.Deny || !r.Scoped)
		case "repo.create":
			match = strings.Contains(r.Actions, "c")
		case "ref.discover":
			match = strings.Contains(r.Actions, "r") && r.ref.MatchString(ref)
		case "ref.create", "ref.update":
			match = strings.Contains(r.Actions, "w") && r.ref.MatchString(ref)
		case "ref.delete":
			match = strings.Contains(r.Actions, "d") && r.ref.MatchString(ref)
		}
		if match {
			if r.Deny {
				d.Denies = append(d.Denies, r.Text)
			} else {
				d.Allows = append(d.Allows, r.Text)
			}
		}
	}
	d.Allowed = len(d.Allows) > 0 && len(d.Denies) == 0
	return d
}
func (p *Policy) Allows(repo Repository, ref, action string) bool {
	return p.Explain(repo, ref, action).Allowed
}
func (p *Policy) Read(repo Repository) bool { return p.Allows(repo, "", "repo.read") }
func (p *Policy) Discover(repo Repository, ref string) bool {
	return ValidRef(ref) && p.Read(repo) && p.Allows(repo, ref, "ref.discover")
}
func (p *Policy) Write(repo Repository, ref, action string) bool {
	return p.Discover(repo, ref) && p.Allows(repo, ref, action)
}

func ValidRef(ref string) bool {
	if !utf8.ValidString(ref) || len(ref) > 1024 || !(strings.HasPrefix(ref, "refs/heads/") || strings.HasPrefix(ref, "refs/tags/")) {
		return false
	}
	if strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.HasSuffix(ref, ".") {
		return false
	}
	for _, c := range ref {
		if c <= 32 || c == 127 || strings.ContainsRune(`~^:?*[\`, c) {
			return false
		}
	}
	for _, part := range strings.Split(ref, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}
