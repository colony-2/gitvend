package jobdbprovider

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/colony-2/gitvend/internal/auth"
	"github.com/colony-2/gitvend/internal/configutil"
	"github.com/colony-2/gitvend/internal/policy"
)

type config struct {
	Issuer               string                  `json:"issuer" yaml:"issuer"`
	Audience             string                  `json:"audience" yaml:"audience"`
	KeyID                string                  `json:"key_id" yaml:"key_id"`
	SigningKeyFile       string                  `json:"signing_key_file" yaml:"signing_key_file"`
	PolicyRevision       string                  `json:"policy_revision" yaml:"policy_revision"`
	MaxTokenBytes        int                     `json:"max_token_bytes" yaml:"max_token_bytes"`
	MaxLifetimeSeconds   int                     `json:"max_lifetime_seconds" yaml:"max_lifetime_seconds"`
	GatewayLeewaySeconds int                     `json:"gateway_leeway_seconds" yaml:"gateway_leeway_seconds"`
	ClockMarginSeconds   int                     `json:"clock_margin_seconds" yaml:"clock_margin_seconds"`
	CellMetadataField    string                  `json:"cell_metadata_field" yaml:"cell_metadata_field"`
	Tenants              map[string]tenantConfig `json:"tenants" yaml:"tenants"`
}

type tenantConfig struct {
	BasePermissions   []string `json:"base_permissions" yaml:"base_permissions"`
	TargetPermissions []string `json:"target_permissions" yaml:"target_permissions"`
	// Omitted means any verified principal (including absent) in this tenant.
	Principals []string `json:"principals,omitempty" yaml:"principals,omitempty"`
}

type tenantPolicy struct {
	base       []string
	target     *policy.Policy
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
	if err := configutil.Decode(b, &c); err != nil {
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
		if len(t.BasePermissions)+len(t.TargetPermissions) == 0 || len(t.BasePermissions)+len(t.TargetPermissions) > policy.MaxRules {
			return nil, fmt.Errorf("tenant requires 1..%d permission rules", policy.MaxRules)
		}
		if len(t.BasePermissions) > 0 {
			if _, err := policy.Compile(t.BasePermissions); err != nil {
				return nil, fmt.Errorf("invalid tenant base permissions")
			}
		}
		tp := tenantPolicy{base: append([]string(nil), t.BasePermissions...), principals: map[string]bool{}}
		for _, principal := range t.Principals {
			if principal == "" {
				return nil, fmt.Errorf("empty principal")
			}
			tp.principals[principal] = true
		}
		if len(t.TargetPermissions) > 0 {
			var err error
			tp.target, err = policy.Compile(t.TargetPermissions)
			if err != nil {
				return nil, fmt.Errorf("invalid tenant target permissions")
			}
		}
		p.tenants[id] = tp
	}
	return p, nil
}
