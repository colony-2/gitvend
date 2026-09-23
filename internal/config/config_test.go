package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func validConfig(t *testing.T) Config {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	path := filepath.Join(t.TempDir(), "key.pub")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600)
	t.Setenv("TEST_CONFIG_TOKEN", "secret")
	c := Defaults()
	c.AllowHTTP = true
	c.Keys = []SigningKey{{ID: "one", Issuer: "issuer", PublicKeyFile: path, Owners: map[string][]string{"github.com": {"org"}}}}
	c.Providers = []Provider{{Alias: "github", Host: "github.com", Kind: "github", GitBaseURL: "https://github.com", APIBaseURL: "https://api.github.com", AllowedOwners: []string{"org"}, Credential: Credential{Kind: "token", SecretRef: "env:TEST_CONFIG_TOKEN"}}}
	return c
}
func TestLoadAndValidation(t *testing.T) {
	c := validConfig(t)
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	b, _ := json.Marshal(c)
	os.WriteFile(path, b, 0600)
	loaded, e := Load(path)
	if e != nil || loaded.MaxTokenBytes != 4096 {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.MaxTokenBytes = 100000 }, func(c *Config) { c.Providers[0].GitBaseURL = "http://github.com" }, func(c *Config) { c.Providers[0].APIBaseURL = "https://user:secret@github.com" }, func(c *Config) { c.Providers[0].APIBaseURL = "https://api.github.com?url=else" }, func(c *Config) { c.Providers = append(c.Providers, c.Providers[0]) }, func(c *Config) { c.Keys[0].Owners["github.com"] = []string{"other"} }, func(c *Config) { c.Denies = []string{"github.com/*:rw"} }, func(c *Config) { c.AllowHTTP = false }, func(c *Config) { c.Providers[0].Credential.Kind = "ssh" }} {
		cc := validConfig(t)
		mutate(&cc)
		if e := cc.Validate(); e == nil {
			t.Fatal("invalid config accepted")
		}
	}
	os.WriteFile(path, []byte(`{"audience":"one","audience":"two"}`), 0600)
	if _, e = Load(path); e == nil {
		t.Fatal("duplicate config field")
	}
}
func TestSecrets(t *testing.T) {
	t.Setenv("EMPTY_CONFIG_TOKEN", "")
	for _, c := range []Credential{{Kind: "token", SecretRef: "literal-secret"}, {Kind: "token", SecretRef: "env:EMPTY_CONFIG_TOKEN"}, {Kind: "token", SecretRef: "file:/not/a/file"}} {
		if _, e := Secret(c); e == nil {
			t.Fatal(c.Kind)
		}
	}
	path := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(path, []byte("first\n"), 0600)
	c := Credential{Kind: "token", SecretRef: "file:" + path}
	s, e := Secret(c)
	if e != nil || s != "first" {
		t.Fatal(e)
	}
	os.WriteFile(path, []byte("replacement"), 0600)
	s, e = Secret(c)
	if e != nil || s != "replacement" {
		t.Fatal(e)
	}
}

func TestRemovedStateSettingsAreRejected(t *testing.T) {
	c := validConfig(t)
	b, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "config.json")
	for _, key := range []string{"state_file", "creates_per_subject_per_day", "creates_per_owner_per_day"} {
		var fields map[string]any
		json.Unmarshal(b, &fields)
		fields[key] = "removed"
		modified, _ := json.Marshal(fields)
		os.WriteFile(path, modified, 0600)
		if _, err := Load(path); err == nil {
			t.Fatalf("silently accepted obsolete configuration %s", key)
		}
	}
}
