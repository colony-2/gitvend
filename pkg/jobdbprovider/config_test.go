package jobdbprovider

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/colony-2/jobdb/pkg/jobdb"
)

func writeConfig(t *testing.T, p *Provider) string {
	t.Helper()
	dir := t.TempDir()
	der, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signing.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	c := testConfig()
	c.SigningKeyFile = "signing.key"
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "issuer.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAndConfigurationValidation(t *testing.T) {
	p, _, _ := testProvider(t)
	path := writeConfig(t, p)
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*config){
		func(c *config) { c.Issuer = "" },
		func(c *config) { c.Audience = "" },
		func(c *config) { c.KeyID = "" },
		func(c *config) { c.CellMetadataField = "" },
		func(c *config) { c.MaxTokenBytes = 32769 },
		func(c *config) { c.MaxLifetimeSeconds = 86401 },
		func(c *config) { c.GatewayLeewaySeconds = -1 },
		func(c *config) { c.ClockMarginSeconds = -1 },
		func(c *config) { c.Tenants = nil },
		func(c *config) { c.Tenants["alpha"] = tenantConfig{ReadPermissions: []string{"github.com/*:rw"}} },
		func(c *config) {
			c.Tenants["alpha"] = tenantConfig{ReadPermissions: []string{"github.com/*:r"}, CellWriteRepositories: []string{"github.com/acme/*#main"}}
		},
		func(c *config) {
			c.Tenants["alpha"] = tenantConfig{ReadPermissions: []string{"github.com/*:r"}, CellWriteRepositories: []string{"!github.com/acme/*"}}
		},
		func(c *config) {
			c.Tenants["alpha"] = tenantConfig{ReadPermissions: []string{"github.com/*:r"}, CellWriteRepositories: []string{"github.com/acme/*:rw"}}
		},
	} {
		c := testConfig()
		mutate(&c)
		if _, err := newProvider(c, p.key, p.now); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, err := newProvider(testConfig(), nil, p.now); err == nil {
		t.Fatal("invalid key accepted")
	}
	for _, data := range []string{
		`{"issuer":"one","issuer":"two"}`, `{"unknown":true}`, `{} {}`, strings.Repeat(" ", (1<<20)+1),
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("invalid configuration file accepted")
		}
	}
}

func TestCustomMetadataFieldAndReadDenies(t *testing.T) {
	p, v, r := testProvider(t)
	c := testConfig()
	c.CellMetadataField = "target_cell"
	c.Tenants["alpha"] = tenantConfig{
		ReadPermissions:       []string{"github.com/*:r", "!github.com/acme/alpha-one:r"},
		CellWriteRepositories: []string{"github.com/acme/alpha-*"},
	}
	p, err := newProvider(c, p.key, p.now)
	if err != nil {
		t.Fatal(err)
	}
	// Changing source configuration after initialization must not change authority.
	c.Tenants["alpha"].ReadPermissions[1] = "github.com/*:rw"
	r.AppMetadata = json.RawMessage(`{"target_cell":"github.com/acme/alpha-one"}`)
	out := resolve(t, p, r)
	cell := verify(t, v, out.Secrets[CellSecretName])
	repo, ok := cellRepository(r.AppMetadata, "target_cell")
	if !ok || cell.Policy.Read(repo) || cell.Policy.Write(repo, "refs/heads/main", "ref.update") {
		t.Fatal("cell grant overrode tenant deny")
	}
}

func TestOversizedTokenFailsEntireResolution(t *testing.T) {
	p, _, r := testProvider(t)
	c := testConfig()
	c.MaxTokenBytes = 512
	p, err := newProvider(c, p.key, p.now)
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.ResolveSecrets(t.Context(), r)
	if err != jobdb.ErrSecretResolutionFailed || len(out.Secrets) != 0 {
		t.Fatal("oversized token must fail without partial credentials")
	}
}
