package jobdbprovider

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/colony-2/gitvend/internal/auth"
	"github.com/colony-2/gitvend/internal/jsonutil"
	"github.com/colony-2/gitvend/internal/policy"
)

type config struct {
	Issuer               string                  `json:"issuer"`
	Audience             string                  `json:"audience"`
	KeyID                string                  `json:"key_id"`
	SigningKeyFile       string                  `json:"signing_key_file"`
	PolicyRevision       string                  `json:"policy_revision"`
	MaxTokenBytes        int                     `json:"max_token_bytes"`
	MaxLifetimeSeconds   int                     `json:"max_lifetime_seconds"`
	GatewayLeewaySeconds int                     `json:"gateway_leeway_seconds"`
	ClockMarginSeconds   int                     `json:"clock_margin_seconds"`
	CellMetadataField    string                  `json:"cell_metadata_field"`
	Tenants              map[string]tenantConfig `json:"tenants"`
}

type tenantConfig struct {
	ReadPermissions       []string `json:"read_permissions"`
	CellWriteRepositories []string `json:"cell_write_repositories"`
	// Omitted means any verified principal (including absent) in this tenant.
	Principals []string `json:"principals,omitempty"`
}

type tenantPolicy struct {
	reads      []string
	writes     *policy.Policy
	principals map[string]bool
}

// Provider is an immutable, concurrent-safe issuer created by Load.
type Provider struct {
	config  config
	key     ed25519.PrivateKey
	tenants map[string]tenantPolicy
	now     func() time.Time
}

func defaults() config {
	return config{Audience: "gitvend", MaxTokenBytes: 4096, MaxLifetimeSeconds: 900,
		GatewayLeewaySeconds: 30, ClockMarginSeconds: 1, CellMetadataField: "repo"}
}

// Load reads and validates an issuer configuration and its Ed25519 signing key.
// Relative key paths resolve from the configuration file's directory.
// Returned errors may include file or configuration details; do not expose them
// to secret-resolution callers or log them without redaction.
func Load(path string) (*Provider, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := defaults()
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("configuration too large")
	}
	if err := jsonutil.Decode(b, &c); err != nil {
		return nil, err
	}
	if c.SigningKeyFile == "" {
		return nil, fmt.Errorf("signing key file required")
	}
	keyPath := c.SigningKeyFile
	if !filepath.IsAbs(keyPath) {
		keyPath = filepath.Join(filepath.Dir(path), keyPath)
	}
	b, err = os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := auth.ParsePrivate(b)
	if err != nil {
		return nil, err
	}
	return newProvider(c, key, time.Now)
}

func newProvider(c config, key ed25519.PrivateKey, now func() time.Time) (*Provider, error) {
	if c.Issuer == "" || c.Audience == "" || c.KeyID == "" || len(c.KeyID) > 128 ||
		c.CellMetadataField == "" || len(c.Tenants) == 0 || len(key) != ed25519.PrivateKeySize || now == nil {
		return nil, fmt.Errorf("issuer, audience, key, metadata field and tenants required")
	}
	if c.MaxTokenBytes < 512 || c.MaxTokenBytes > 32768 || c.MaxLifetimeSeconds < 1 || c.MaxLifetimeSeconds > 86400 ||
		c.GatewayLeewaySeconds < 0 || c.GatewayLeewaySeconds > 30 || c.ClockMarginSeconds < 0 || c.ClockMarginSeconds > 3600 {
		return nil, fmt.Errorf("invalid token limits")
	}
	p := &Provider{config: c, key: append(ed25519.PrivateKey(nil), key...), tenants: map[string]tenantPolicy{}, now: now}
	// Compile and copy policy once. Calls never retain caller-owned maps or slices.
	p.config.Tenants = nil
	for id, t := range c.Tenants {
		if id == "" {
			return nil, fmt.Errorf("empty tenant")
		}
		reads, err := policy.Compile(t.ReadPermissions)
		if err != nil {
			return nil, fmt.Errorf("invalid tenant read permissions")
		}
		for _, rule := range reads.Rules {
			if rule.Actions != "r" {
				return nil, fmt.Errorf("tenant read permissions may only contain r")
			}
		}
		tp := tenantPolicy{reads: append([]string(nil), t.ReadPermissions...), principals: map[string]bool{}}
		for _, principal := range t.Principals {
			if principal == "" {
				return nil, fmt.Errorf("empty principal")
			}
			tp.principals[principal] = true
		}
		if len(t.CellWriteRepositories) > 0 {
			patterns := make([]string, 0, len(t.CellWriteRepositories))
			for _, pattern := range t.CellWriteRepositories {
				if strings.HasPrefix(pattern, "!") || strings.Contains(pattern, "#") || strings.HasSuffix(pattern, ".git") {
					return nil, fmt.Errorf("expected cell repository pattern without actions, ref or .git suffix")
				}
				patterns = append(patterns, pattern+":r")
			}
			tp.writes, err = policy.Compile(patterns)
			if err != nil || len(t.ReadPermissions) >= policy.MaxRules {
				return nil, fmt.Errorf("invalid cell repository patterns or too many read permissions")
			}
		}
		p.tenants[id] = tp
	}
	return p, nil
}
