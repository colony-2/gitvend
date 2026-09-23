package main

import (
	"bytes"
	"encoding/json"
	"gitgate/internal/auth"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKeygenSignAndExplain(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "key"), filepath.Join(dir, "pub")
	var out, errout bytes.Buffer
	if e := run([]string{"keygen", "-private", priv, "-public", pub}, nil, &out, &errout); e != nil {
		t.Fatal(e)
	}
	if e := run([]string{"keygen", "-private", priv, "-public", pub}, nil, &out, &errout); e == nil {
		t.Fatal("overwrote keys")
	}
	tokenPath := filepath.Join(dir, "token")
	args := []string{"sign", "-key", priv, "-kid", "one", "-issuer", "issuer", "-subject", "agent", "-output", tokenPath, "-permission", "github.com/org/repo#main:rw"}
	if e := run(args, nil, &out, &errout); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(tokenPath)
	pb, _ := os.ReadFile(pub)
	pk, e := auth.ParsePublic(pb)
	if e != nil {
		t.Fatal(e)
	}
	v := auth.Verifier{Audience: "gitgate", Keys: map[string]auth.Key{"one": {Issuer: "issuer", Public: pk}}, MaxBytes: 4096, MaxLifetime: 15 * time.Minute}
	if _, e = v.Verify(strings.TrimSpace(string(raw))); e != nil {
		t.Fatal(e)
	}
	info, _ := os.Stat(tokenPath)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	out.Reset()
	if e = run([]string{"explain", "-repo", "github.com/org/repo", "-ref", "refs/heads/main", "-permission", "github.com/org/repo#main:rw"}, nil, &out, &errout); e != nil {
		t.Fatal(e)
	}
	var decision struct {
		Allowed bool `json:"allowed"`
	}
	if e = json.Unmarshal(out.Bytes(), &decision); e != nil || !decision.Allowed {
		t.Fatal(out.String(), e)
	}
}
func TestCredentialHelper(t *testing.T) {
	t.Setenv("TEST_HELPER_JWT", "test.jwt.token")
	for _, tt := range []struct {
		input   string
		allowed bool
	}{{"protocol=https\nhost=proxy.example\n\n", true}, {"protocol=https\nhost=github.com\n\n", false}, {"protocol=http\nhost=proxy.example\n\n", false}, {"protocol=https\nhost=proxy.example:8443\n\n", false}} {
		var out bytes.Buffer
		e := run([]string{"credential", "-host", "proxy.example", "-token-env", "TEST_HELPER_JWT", "get"}, strings.NewReader(tt.input), &out, &out)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(out.String(), "password=") != tt.allowed {
			t.Fatal(tt, out.String())
		}
	}
	var out bytes.Buffer
	if e := run([]string{"credential", "-host", "proxy.example", "-token-env", "TEST_HELPER_JWT", "get"}, strings.NewReader("host=proxy.example\nhost=other\n\n"), &out, &out); e == nil {
		t.Fatal("duplicate fields")
	}
	if e := run([]string{"credential", "-host", "proxy.example", "-token-env", "TEST_HELPER_JWT", "store"}, nil, &out, &out); e != nil {
		t.Fatal(e)
	}
}
