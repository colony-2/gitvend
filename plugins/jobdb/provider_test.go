package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/colony-2/gitvend/internal/auth"
	"github.com/colony-2/gitvend/internal/policy"
	"github.com/colony-2/jobdb/pkg/jobdb"
)

func testConfig() config {
	c := defaults()
	c.Issuer, c.KeyID, c.PolicyRevision = "jobdb", "jobdb-key", "policy-1"
	c.Tenants = map[string]tenantConfig{
		"alpha": {ReadPermissions: []string{"github.com/*:r"}, CellWriteRepositories: []string{"github.com/acme/alpha-*"}},
		"beta":  {ReadPermissions: []string{"github.com/acme/beta-*:r"}, CellWriteRepositories: []string{"github.com/acme/beta-*"}},
	}
	return c
}

func testProvider(t *testing.T) (*provider, *auth.Verifier, jobdb.SecretResolveRequest) {
	t.Helper()
	now := time.Date(2026, 10, 23, 12, 0, 0, 999999999, time.UTC)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := newProvider(testConfig(), key, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	v := &auth.Verifier{Audience: "gitvend", MaxBytes: 4096, MaxLifetime: 15 * time.Minute, Leeway: 30 * time.Second,
		Now: func() time.Time { return now }, Keys: map[string]auth.Key{"jobdb-key": {Issuer: "jobdb", Public: pub, Owners: map[string][]string{"github.com": {"*"}}}}}
	r := jobdb.SecretResolveRequest{TenantID: "alpha", JobID: "job-1", Names: []string{readSecret, cellSecret, "unrelated"},
		AppMetadata: json.RawMessage(`{"cell_id":"123","cell_name":"alpha-one","repo":"https://github.com/Acme/Alpha-one.git","git_ref":"main","v":1}`),
		Lease:       jobdb.SecretLeaseContext{LeaseID: "lease-1", WorkerID: "worker-1", LeaseExpiresAt: now.Add(10 * time.Minute), AuthorizedNotAfter: now.Add(5 * time.Minute)}}
	return p, v, r
}

func resolve(t *testing.T, p *provider, r jobdb.SecretResolveRequest) jobdb.SecretResolveResult {
	t.Helper()
	out, err := p.ResolveSecrets(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func verify(t *testing.T, v *auth.Verifier, value jobdb.SecretValue) *auth.Identity {
	t.Helper()
	id, err := v.Verify(value.Value)
	if err != nil {
		t.Fatal(err)
	}
	if !value.LeaseBound || value.ExpiresAt == nil || !id.Claims.ExpiresAt.Time.Equal(*value.ExpiresAt) {
		t.Fatal("expiry metadata does not match signed credential")
	}
	return id
}

func TestRequestedTokensEnforceReadAndExactCellGrants(t *testing.T) {
	p, v, r := testProvider(t)
	out := resolve(t, p, r)
	if len(out.Secrets) != 2 {
		t.Fatalf("got %d secrets", len(out.Secrets))
	}
	read := verify(t, v, out.Secrets[readSecret])
	cell := verify(t, v, out.Secrets[cellSecret])
	for _, path := range []string{"acme/alpha-one", "acme/alpha-two", "acme/beta-one", "public/project"} {
		repo := policy.Repository{Host: "github.com", Path: path, FoldCase: true}
		for _, id := range []*auth.Identity{read, cell} {
			if !id.Policy.Read(repo) || !id.Policy.Discover(repo, "refs/heads/main") {
				t.Errorf("read denied for %s", path)
			}
			if id.Policy.Allows(repo, "", "repo.create") || id.Policy.Write(repo, "refs/heads/main", "ref.delete") {
				t.Errorf("unexpected creation/deletion grant for %s", path)
			}
		}
		if read.Policy.Write(repo, "refs/heads/main", "ref.update") || cell.Policy.Write(repo, "refs/heads/main", "ref.update") != (path == "acme/alpha-one") {
			t.Errorf("wrong write grant for %s", path)
		}
	}
	if read.Claims.ID == cell.Claims.ID || read.Claims.PolicyRevision != "policy-1" {
		t.Fatal("token ID or policy revision not preserved")
	}
	// A read-only request needs no cell metadata and must never return a cell credential.
	r.Names, r.AppMetadata = []string{readSecret}, nil
	if out := resolve(t, p, r); len(out.Secrets) != 1 || out.Secrets[readSecret].Value == "" {
		t.Fatal("read-only resolution failed")
	}
}

func TestTenantAndPrincipalAuthorization(t *testing.T) {
	p, v, r := testProvider(t)
	r.TenantID = "unknown"
	if len(resolve(t, p, r).Secrets) != 0 {
		t.Fatal("unknown tenant authorized")
	}
	r.TenantID = "beta"
	out := resolve(t, p, r)
	if len(out.Secrets) != 1 {
		t.Fatal("cross-tenant cell authorized")
	}
	id := verify(t, v, out.Secrets[readSecret])
	if id.Policy.Read(policy.Repository{Host: "github.com", Path: "acme/alpha-one"}) {
		t.Fatal("tenant read policy leaked")
	}
	c := testConfig()
	c.Tenants["alpha"] = tenantConfig{ReadPermissions: []string{"github.com/*:r"}, Principals: []string{"trusted"}}
	p, err := newProvider(c, p.key, p.now)
	if err != nil {
		t.Fatal(err)
	}
	r.TenantID = "alpha"
	untrusted, trusted := "untrusted", "trusted"
	for _, principal := range []*string{nil, &untrusted, &trusted} {
		r.Principal = principal
		got := len(resolve(t, p, r).Secrets)
		want := 0
		if principal != nil && *principal == "trusted" {
			want = 1
		}
		if got != want {
			t.Fatalf("principal authorization got %d, want %d", got, want)
		}
	}
}

func TestUntrustedCellMetadata(t *testing.T) {
	p, _, r := testProvider(t)
	for _, metadata := range []string{
		`{}`, `null`, `[]`, `{"repo":null}`, `{"repo":123}`, `{"repo":`,
		`{"repo":"github.com/acme/alpha-one","repo":"github.com/acme/beta-one"}`,
		`{"repo":"github.com/acme/alpha-one"} {}`,
		`{"repo":"github.com/acme/*"}`, `{"repo":"github.com/acme/alpha-one:rw"}`,
		`{"repo":"github.com/acme/alpha-one#main"}`, `{"repo":"github.com/acme/../alpha-one"}`,
		`{"repo":"https://github.com/acme/alpha-one?x=1"}`, `{"repo":"https://github.com/acme/alpha-one?"}`,
		`{"repo":"https://github.com/acme/alpha-one#"}`, `{"repo":"https://github.com/acme/alpha-one#main"}`,
		`{"repo":"https://user@github.com/acme/alpha-one"}`, `{"repo":"https://github.com/acme/alpha%2Done"}`,
		`{"repo":"https://evil.example/acme/alpha-one"}`, `{"repo":"http://github.com/acme/alpha-one"}`,
		`{"repo":"github.com/acme/beta-one","tenant":"beta","permissions":["github.com/*:rw"]}`,
	} {
		t.Run(metadata, func(t *testing.T) {
			r.AppMetadata = json.RawMessage(metadata)
			out := resolve(t, p, r)
			if len(out.Secrets) != 1 || out.Secrets[readSecret].Value == "" {
				t.Fatal("invalid cell should omit only the cell token")
			}
		})
	}
}

func TestLeaseExpiryIncludesVerifierLeewayAndRenewal(t *testing.T) {
	p, v, r := testProvider(t)
	r.Names = []string{readSecret}
	old := resolve(t, p, r).Secrets[readSecret]
	id := verify(t, v, old)
	if id.Expiry.After(r.Lease.AuthorizedNotAfter.Add(-time.Second)) {
		t.Fatal("gateway acceptance extends past authority margin")
	}
	// Renewing the backend lease must not extend an old presenting capability.
	r.Lease.LeaseExpiresAt = r.Lease.LeaseExpiresAt.Add(time.Hour)
	if !resolve(t, p, r).Secrets[readSecret].ExpiresAt.Equal(*old.ExpiresAt) {
		t.Fatal("backend renewal extended old capability")
	}
	deadline := r.Lease.AuthorizedNotAfter
	v.Now = func() time.Time { return deadline }
	if _, err := v.Verify(old.Value); err == nil {
		t.Fatal("JWT accepted at presenting authority deadline")
	}
	r.Lease.AuthorizedNotAfter = r.Lease.LeaseExpiresAt
	newToken := resolve(t, p, r).Secrets[readSecret]
	v.Now = p.now
	newID := verify(t, v, newToken)
	if !newToken.ExpiresAt.After(*old.ExpiresAt) || newID.Claims.ExpiresAt.Sub(newID.Claims.IssuedAt.Time) > 15*time.Minute {
		t.Fatal("renewed credential lifetime incorrect")
	}
	// The backend lease remains an independent ceiling even if the request is inconsistent.
	r.Lease.LeaseExpiresAt = p.now().Add(2 * time.Minute)
	short := verify(t, v, resolve(t, p, r).Secrets[readSecret])
	if short.Expiry.After(r.Lease.LeaseExpiresAt) {
		t.Fatal("backend lease ceiling ignored")
	}
}

func TestMissingExpiredAndCanceledAuthority(t *testing.T) {
	p, _, original := testProvider(t)
	for _, mutate := range []func(*jobdb.SecretResolveRequest){
		func(r *jobdb.SecretResolveRequest) { r.JobID = "" },
		func(r *jobdb.SecretResolveRequest) { r.Lease.LeaseID = "" },
		func(r *jobdb.SecretResolveRequest) { r.Lease.WorkerID = "" },
		func(r *jobdb.SecretResolveRequest) { r.Lease.AuthorizedNotAfter = time.Time{} },
		func(r *jobdb.SecretResolveRequest) { r.Lease.LeaseExpiresAt = time.Time{} },
	} {
		r := original
		mutate(&r)
		out, err := p.ResolveSecrets(context.Background(), r)
		if !errors.Is(err, jobdb.ErrSecretResolutionFailed) || len(out.Secrets) != 0 {
			t.Fatal("missing identity/authority not rejected")
		}
	}
	for _, remaining := range []time.Duration{-time.Second, 0, 30 * time.Second, 31 * time.Second} {
		r := original
		r.Lease.AuthorizedNotAfter = p.now().Add(remaining)
		if _, err := p.ResolveSecrets(context.Background(), r); !errors.Is(err, jobdb.ErrSecretsUnavailable) {
			t.Fatal("insufficient lifetime not rejected")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.ResolveSecrets(ctx, original); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	r := jobdb.SecretResolveRequest{TenantID: "alpha", Names: []string{"unrelated"}}
	if len(resolve(t, p, r).Secrets) != 0 {
		t.Fatal("unknown name returned")
	}
}

func TestConcurrentFreshCredentialsAndOwnedResults(t *testing.T) {
	p, v, r := testProvider(t)
	r.Names = []string{readSecret, readSecret}
	var wg sync.WaitGroup
	ids := make(chan string, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := p.ResolveSecrets(context.Background(), r)
			if err != nil {
				t.Error(err)
				return
			}
			id, err := v.Verify(out.Secrets[readSecret].Value)
			if err != nil {
				t.Error(err)
				return
			}
			ids <- id.Claims.ID
			delete(out.Secrets, readSecret)
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[string]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatal("token reused")
		}
		seen[id] = true
	}
	if len(seen) != 20 {
		t.Fatal("missing resolutions")
	}
}
