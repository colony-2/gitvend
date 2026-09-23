package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"github.com/colony-2/gitvend/internal/policy"
	"strings"
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v := Verifier{Audience: "gitvend", Keys: map[string]Key{"one": {Issuer: "issuer", Public: pub, Owners: map[string][]string{"github.com": {"org"}}}}, MaxBytes: 4096, MaxLifetime: 15 * time.Minute, Leeway: 30 * time.Second}
	c := NewClaims("issuer", "agent", "gitvend", time.Minute, Grant{Version: 1, Permissions: []string{"github.com/org/*:r"}})
	raw, e := Sign(c, priv, "one", 4096)
	if e != nil {
		t.Fatal(e)
	}
	id, e := v.Verify(raw)
	if e != nil {
		t.Fatal(e)
	}
	if !id.Access(policy.Repository{Host: "github.com", Path: "org/r"}) || id.Access(policy.Repository{Host: "github.com", Path: "other/r"}) {
		t.Fatal("key ceiling")
	}
	parts := strings.Split(raw, ".")
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(body), ":r", ":rw", 1)))
	if _, e = v.Verify(strings.Join(parts, ".")); e == nil {
		t.Fatal("tampering accepted")
	}
	for _, kind := range []string{"issuer", "audience", "lifetime", "expired", "version"} {
		bad := *c
		switch kind {
		case "issuer":
			bad.Issuer = "other"
		case "audience":
			bad.Audience = []string{"else"}
		case "lifetime":
			bad.ExpiresAt = NewClaims("i", "s", "a", time.Hour, Grant{}).ExpiresAt
		case "expired":
			v.Now = func() time.Time { return time.Now().Add(time.Hour) }
		case "version":
			bad.Grant.Version = 2
		}
		s, _ := Sign(&bad, priv, "one", 4096)
		if _, e = v.Verify(s); e == nil {
			t.Errorf("accepted %s", kind)
		}
		v.Now = nil
	}
}
func TestDuplicateClaims(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"gitvend+jwt","kid":"k"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"a","sub":"b"}`))
	input := head + "." + body
	token := input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(input)))
	v := Verifier{MaxBytes: 4096, Keys: map[string]Key{"k": {Public: pub}}}
	if _, e := v.Verify(token); e == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestStrictProfile(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v := Verifier{Audience: "gitvend", Keys: map[string]Key{"one": {Issuer: "issuer", Public: pub}}, MaxBytes: 4096, MaxLifetime: 15 * time.Minute, Leeway: 0}
	fresh := func() *Claims {
		return NewClaims("issuer", "agent", "gitvend", time.Minute, Grant{Version: 1, Permissions: []string{"github.com/org/*:r"}})
	}
	for _, change := range []func(*Claims){func(c *Claims) { c.ID = "" }, func(c *Claims) { c.Subject = "" }, func(c *Claims) { c.IssuedAt = nil }, func(c *Claims) { c.NotBefore = nil }, func(c *Claims) { c.ExpiresAt = nil }, func(c *Claims) { c.Audience = []string{"gitvend", "other"} }, func(c *Claims) { c.Grant.Version = 9 }, func(c *Claims) { c.Grant.Bindings = map[string]string{"github.com/org/*": "1"} }} {
		c := fresh()
		change(c)
		s, e := Sign(c, priv, "one", 4096)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = v.Verify(s); e == nil {
			t.Fatal("invalid claims accepted")
		}
	}
	c := fresh()
	s, _ := Sign(c, priv, "unknown", 4096)
	if _, e := v.Verify(s); e == nil {
		t.Fatal("unknown key")
	}
	s, _ = Sign(c, priv, "one", 4096)
	v.MaxBytes = 10
	if _, e := v.Verify(s); e == nil {
		t.Fatal("token size")
	}
	if _, e := Sign(c, priv, "one", 10); e == nil {
		t.Fatal("issuer size")
	}
	for _, bad := range []string{"garbage", "a.b.c", "a.b"} {
		if _, e := v.Verify(bad); e == nil {
			t.Fatal(bad)
		}
	}
}
