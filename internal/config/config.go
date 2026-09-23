package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/colony-2/gitgate/internal/auth"
	"github.com/colony-2/gitgate/internal/jsonutil"
	"github.com/colony-2/gitgate/internal/policy"
)

type Credential struct {
	Kind      string `json:"kind"`
	SecretRef string `json:"secret_ref"`
}
type Provider struct {
	Alias         string      `json:"alias"`
	Host          string      `json:"host"`
	Kind          string      `json:"kind"`
	GitBaseURL    string      `json:"git_base_url"`
	APIBaseURL    string      `json:"api_base_url"`
	AllowedOwners []string    `json:"allowed_owners"`
	Credential    Credential  `json:"credential"`
	APICredential *Credential `json:"api_credential,omitempty"`
	AllowCreation bool        `json:"allow_creation"`
}
type SigningKey struct {
	ID            string              `json:"id"`
	Issuer        string              `json:"issuer"`
	PublicKeyFile string              `json:"public_key_file"`
	Owners        map[string][]string `json:"owners"`
}
type Config struct {
	Listen                  string       `json:"listen"`
	TLSCert                 string       `json:"tls_cert"`
	TLSKey                  string       `json:"tls_key"`
	AllowHTTP               bool         `json:"allow_http"`
	AllowHTTPUpstream       bool         `json:"allow_http_upstream"`
	StateFile               string       `json:"state_file"`
	Audience                string       `json:"audience"`
	Revision                string       `json:"revision"`
	Keys                    []SigningKey `json:"keys"`
	Providers               []Provider   `json:"providers"`
	Denies                  []string     `json:"denies"`
	MaxTokenBytes           int          `json:"max_token_bytes"`
	MaxTokenLifetimeSeconds int          `json:"max_token_lifetime_seconds"`
	ClockSkewSeconds        int          `json:"clock_skew_seconds"`
	MaxControlBytes         int64        `json:"max_control_bytes"`
	MaxPackBytes            int64        `json:"max_pack_bytes"`
	MaxConcurrent           int          `json:"max_concurrent"`
	RequestTimeoutSeconds   int          `json:"request_timeout_seconds"`
	CreatesPerSubjectPerDay int          `json:"creates_per_subject_per_day"`
	CreatesPerOwnerPerDay   int          `json:"creates_per_owner_per_day"`
}

func Defaults() Config {
	return Config{Listen: "127.0.0.1:8443", StateFile: "var/gitgate.db", Audience: "gitgate", MaxTokenBytes: 4096, MaxTokenLifetimeSeconds: 900, ClockSkewSeconds: 30, MaxControlBytes: 4 << 20, MaxPackBytes: 1 << 30, MaxConcurrent: 64, RequestTimeoutSeconds: 1800, CreatesPerSubjectPerDay: 100, CreatesPerOwnerPerDay: 1000}
}

var aliasRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var nameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func ValidName(s string) bool {
	return len(s) > 0 && len(s) <= 100 && s != "." && s != ".." && nameRE.MatchString(s)
}
func Load(path string) (Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Config{}, e
	}
	if len(b) > 1<<20 {
		return Config{}, fmt.Errorf("config too large")
	}
	c := Defaults()
	if e = jsonutil.Decode(b, &c); e != nil {
		return c, e
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.Audience == "" || c.StateFile == "" || len(c.Keys) == 0 || len(c.Providers) == 0 {
		return fmt.Errorf("audience, state_file, keys and providers are required")
	}
	if _, _, e := net.SplitHostPort(c.Listen); e != nil {
		return fmt.Errorf("invalid listen address")
	}
	if !c.AllowHTTP && (c.TLSCert == "" || c.TLSKey == "") {
		return fmt.Errorf("TLS cert/key required unless allow_http is explicit")
	}
	if c.MaxTokenBytes < 512 || c.MaxTokenBytes > 32768 || c.MaxTokenLifetimeSeconds < 1 || c.MaxTokenLifetimeSeconds > 86400 || c.ClockSkewSeconds < 0 || c.ClockSkewSeconds > 30 || c.MaxControlBytes < 1024 || c.MaxControlBytes > 64<<20 || c.MaxPackBytes < 1024 || c.MaxConcurrent < 1 || c.MaxConcurrent > 10000 || c.RequestTimeoutSeconds < 1 || c.CreatesPerSubjectPerDay < 1 || c.CreatesPerOwnerPerDay < 1 {
		return fmt.Errorf("invalid resource limit")
	}
	seen := map[string]bool{}
	routes := map[string]bool{}
	for _, p := range c.Providers {
		if !aliasRE.MatchString(p.Alias) || seen[p.Alias] {
			return fmt.Errorf("invalid or duplicate provider alias")
		}
		seen[p.Alias] = true
		if !policy.ValidHost(p.Host) || p.Kind != "github" || len(p.AllowedOwners) == 0 {
			return fmt.Errorf("provider requires exact host, github kind and allowed owners")
		}
		for _, u := range []string{p.GitBaseURL, p.APIBaseURL} {
			if e := validURL(u, c.AllowHTTPUpstream); e != nil {
				return e
			}
		}
		for _, owner := range p.AllowedOwners {
			if !ValidName(owner) || owner != strings.ToLower(owner) {
				return fmt.Errorf("owners must be canonical lowercase names")
			}
			route := p.Host + "/" + owner
			if routes[route] {
				return fmt.Errorf("ambiguous provider owner route")
			}
			routes[route] = true
		}
		if _, e := Secret(p.Credential); e != nil {
			return e
		}
		if p.APICredential != nil {
			if _, e := Secret(*p.APICredential); e != nil {
				return e
			}
		}
	}
	ids := map[string]bool{}
	for _, k := range c.Keys {
		if k.ID == "" || len(k.ID) > 128 || ids[k.ID] || k.Issuer == "" || len(k.Owners) == 0 {
			return fmt.Errorf("invalid signing key configuration")
		}
		ids[k.ID] = true
		for h, owners := range k.Owners {
			if !policy.ValidHost(h) || len(owners) == 0 {
				return fmt.Errorf("invalid issuer ceiling")
			}
			for _, o := range owners {
				if !routes[h+"/"+o] {
					return fmt.Errorf("issuer ceiling references an unconfigured owner")
				}
			}
		}
	}
	if len(c.Denies) > 0 {
		p, e := policy.Compile(c.Denies)
		if e != nil {
			return e
		}
		for _, r := range p.Rules {
			if !r.Deny {
				return fmt.Errorf("gateway constraints must be deny rules")
			}
		}
	}
	_, e := c.Verifier()
	return e
}
func validURL(s string, allowHTTP bool) error {
	u, e := url.Parse(s)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.Contains(u.Path, "..") {
		return fmt.Errorf("invalid upstream base URL")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return fmt.Errorf("upstream requires HTTPS")
	}
	return nil
}
func Secret(c Credential) (string, error) {
	if c.Kind != "token" {
		return "", fmt.Errorf("only token credentials supported")
	}
	var s string
	switch {
	case strings.HasPrefix(c.SecretRef, "env:"):
		s = os.Getenv(strings.TrimPrefix(c.SecretRef, "env:"))
	case strings.HasPrefix(c.SecretRef, "file:"):
		b, e := os.ReadFile(strings.TrimPrefix(c.SecretRef, "file:"))
		if e != nil {
			return "", fmt.Errorf("cannot read credential file")
		}
		s = strings.TrimSpace(string(b))
	default:
		return "", fmt.Errorf("credential requires env: or file: secret reference")
	}
	if s == "" || len(s) > 65536 || strings.ContainsAny(s, "\r\n\x00") {
		return "", fmt.Errorf("missing or invalid upstream credential")
	}
	return s, nil
}
func (c Config) Verifier() (*auth.Verifier, error) {
	v := &auth.Verifier{Audience: c.Audience, Keys: map[string]auth.Key{}, MaxBytes: c.MaxTokenBytes, MaxLifetime: time.Duration(c.MaxTokenLifetimeSeconds) * time.Second, Leeway: time.Duration(c.ClockSkewSeconds) * time.Second, Denies: c.Denies}
	for _, k := range c.Keys {
		b, e := os.ReadFile(k.PublicKeyFile)
		if e != nil {
			return nil, e
		}
		pub, e := auth.ParsePublic(b)
		if e != nil {
			return nil, e
		}
		v.Keys[k.ID] = auth.Key{Issuer: k.Issuer, Public: pub, Owners: k.Owners}
	}
	return v, nil
}
