package jobdbprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/colony-2/gitvend/internal/auth"
	"github.com/colony-2/gitvend/internal/policy"
	"github.com/colony-2/jobdb/pkg/jobdb"
	"gopkg.in/yaml.v3"
)

func eventually(t *testing.T, check func() bool) {
	t.Helper()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for !check() {
		select {
		case <-timeout.C:
			t.Fatal("timed out waiting for configuration reload")
		case <-tick.C:
		}
	}
}

func replaceFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	f, err := os.CreateTemp(filepath.Dir(path), ".reload-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	if _, err := f.Write(contents); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		t.Fatal(err)
	}
}

func replaceConfig(t *testing.T, path string, c config) {
	t.Helper()
	b, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	replaceFile(t, path, b)
}

func watchFixture(t *testing.T) (*ReloadingProvider, *auth.Verifier, jobdb.SecretResolveRequest, chan string) {
	t.Helper()
	p, v, request := testProvider(t)
	path := writeConfig(t, p)
	logs := make(chan string, 128)
	r, err := WatchConfig(path, func(message string) { logs <- message })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	v.Now = time.Now
	request.Lease.LeaseExpiresAt = time.Now().Add(10 * time.Minute)
	request.Lease.AuthorizedNotAfter = time.Now().Add(5 * time.Minute)
	return r, v, request, logs
}

func awaitFailure(t *testing.T, logs <-chan string) {
	t.Helper()
	eventually(t, func() bool {
		select {
		case message := <-logs:
			return message == "configuration reload failed; retaining last valid configuration and retrying"
		default:
			return false
		}
	})
}

func TestReloadWritesAndAtomicReplacementsRemoveTenantAccess(t *testing.T) {
	r, v, request, _ := watchFixture(t)
	c := testConfig()
	c.SigningKeyFile = "signing.key"
	c.PolicyRevision = "direct-write"
	b, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.path, b, 0600); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return r.current.Load().config.PolicyRevision == c.PolicyRevision })
	for _, revision := range []string{"replace-one", "replace-two"} {
		c.PolicyRevision = revision
		replaceConfig(t, r.path, c)
		eventually(t, func() bool { return r.current.Load().config.PolicyRevision == revision })
		out, err := r.ResolveSecrets(t.Context(), request)
		if err != nil || len(out.Secrets) != 2 {
			t.Fatalf("resolution after replacement: %v", err)
		}
		for _, value := range out.Secrets {
			if verify(t, v, value).Claims.PolicyRevision != revision {
				t.Fatal("request used old policy")
			}
		}
	}
	c.Tenants["alpha"] = tenantConfig{BasePermissions: []string{"github.com/acme/shared:r"}}
	c.PolicyRevision = "permissions-removed"
	replaceConfig(t, r.path, c)
	eventually(t, func() bool { return r.current.Load().config.PolicyRevision == c.PolicyRevision })
	out, err := r.ResolveSecrets(t.Context(), request)
	if err != nil || len(out.Secrets) != 1 {
		t.Fatal("removed cell write permission retained authorization")
	}
	id := verify(t, v, out.Secrets[BaseSecretName])
	if id.Policy.Read(policy.Repository{Host: "github.com", Path: "acme/alpha-one"}) ||
		!id.Policy.Read(policy.Repository{Host: "github.com", Path: "acme/shared"}) {
		t.Fatal("read permissions were merged instead of replaced")
	}
	delete(c.Tenants, "alpha")
	c.PolicyRevision = "tenant-removed"
	replaceConfig(t, r.path, c)
	eventually(t, func() bool { return r.current.Load().config.PolicyRevision == c.PolicyRevision })
	out, err = r.ResolveSecrets(t.Context(), request)
	if err != nil || len(out.Secrets) != 0 {
		t.Fatal("removed tenant retained authorization")
	}
}

func TestReloadTargetCreationAndBranchRules(t *testing.T) {
	r, v, request, _ := watchFixture(t)
	c := testConfig()
	c.SigningKeyFile, c.PolicyRevision = "signing.key", "target-creation"
	c.Tenants["alpha"] = tenantConfig{
		BasePermissions:   []string{"github.com/*:r"},
		TargetPermissions: []string{"github.com/acme/*:c", "github.com/acme/*#work/*:rw"},
	}
	replaceConfig(t, r.path, c)
	eventually(t, func() bool { return r.current.Load().config.PolicyRevision == c.PolicyRevision })
	out, err := r.ResolveSecrets(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	cell := verify(t, v, out.Secrets[CellSecretName])
	repo := policy.Repository{Host: "github.com", Path: "acme/alpha-one"}
	if !cell.Policy.Allows(repo, "", "repo.create") || !cell.Policy.Write(repo, "refs/heads/work/a", "ref.update") || cell.Policy.Write(repo, "refs/heads/main", "ref.update") {
		t.Fatal("reloaded target policy lost actions or branch scope")
	}
	c.PolicyRevision = "creation-denied"
	tenant := c.Tenants["alpha"]
	tenant.TargetPermissions = append(tenant.TargetPermissions, "!github.com/acme/*:c")
	c.Tenants["alpha"] = tenant
	replaceConfig(t, r.path, c)
	eventually(t, func() bool { return r.current.Load().config.PolicyRevision == c.PolicyRevision })
	out, err = r.ResolveSecrets(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if verify(t, v, out.Secrets[CellSecretName]).Policy.Allows(repo, "", "repo.create") {
		t.Fatal("reloaded deny did not revoke creation in fresh tokens")
	}
}

func TestInvalidReloadRetainsSnapshotAndRecovers(t *testing.T) {
	for _, target := range []string{"config", "key"} {
		t.Run(target, func(t *testing.T) {
			r, v, request, logs := watchFixture(t)
			before := r.current.Load()
			path := r.path
			if target == "key" {
				path = signingKeyPath(r.path, before)
			}
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			replaceFile(t, path, []byte("malformed-secret-bearing-input"))
			awaitFailure(t, logs)
			if r.current.Load() != before {
				t.Fatal("invalid reload replaced valid snapshot")
			}
			out, err := r.ResolveSecrets(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			verify(t, v, out.Secrets[BaseSecretName])
			replaceFile(t, path, original)
			eventually(t, func() bool { return r.current.Load() != before })
		})
	}
}

func TestReloadRetriesMissingNewKeyAndWatchesNewDirectory(t *testing.T) {
	r, v, request, logs := watchFixture(t)
	before := r.current.Load()
	c := testConfig()
	c.PolicyRevision, c.KeyID = "rotated", "rotated-key"
	c.SigningKeyFile = filepath.Join("new-keys", "rotated.key")
	replaceConfig(t, r.path, c)
	awaitFailure(t, logs)
	if r.current.Load() != before {
		t.Fatal("missing key replaced valid snapshot")
	}
	// This directory was absent at reload time. Creating the key must recover
	// without requiring another write to the configuration file.
	keyPath := filepath.Join(filepath.Dir(r.path), c.SigningKeyFile)
	if err := os.Mkdir(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatal(err)
	}
	pub := replaceSigningKey(t, keyPath)
	eventually(t, func() bool { return r.current.Load().config.PolicyRevision == "rotated" })
	v.Keys = map[string]auth.Key{"rotated-key": {Issuer: "jobdb", Public: pub}}
	out, err := r.ResolveSecrets(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range out.Secrets {
		if verify(t, v, value).Kid != "rotated-key" {
			t.Fatal("new signing key ID not applied")
		}
	}
	// A subsequent key-only replacement exercises the newly installed watch.
	pub = replaceSigningKey(t, keyPath)
	eventually(t, func() bool {
		return bytes.Equal(r.current.Load().key.Public().(ed25519.PublicKey), pub)
	})
	v.Keys["rotated-key"] = auth.Key{Issuer: "jobdb", Public: pub}
	out, err = r.ResolveSecrets(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	verify(t, v, out.Secrets[BaseSecretName])
}

func replaceSigningKey(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	replaceFile(t, path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return pub
}

func replaceWatchedDirectory(t *testing.T, r *ReloadingProvider, dir string, logs <-chan string, files ...string) {
	t.Helper()
	before := r.current.Load()
	// Keep the renamed files alive to exercise kqueue's retained child watches.
	// Recovery must watch the new files, not just load them once on a retry.
	backup := filepath.Join(t.TempDir(), "old")
	if err := os.Rename(dir, backup); err != nil {
		t.Fatal(err)
	}
	awaitFailure(t, logs)
	if r.current.Load() != before {
		t.Fatal("missing watched directory changed snapshot")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(backup, name))
		if err != nil {
			t.Fatal(err)
		}
		replaceFile(t, filepath.Join(dir, name), data)
	}
	eventually(t, func() bool { return r.current.Load() != before })
}

func TestReloadAfterConfigDirectoryReplacement(t *testing.T) {
	r, _, _, logs := watchFixture(t)
	c := testConfig()
	c.SigningKeyFile = "signing.key"
	for _, revision := range []string{"first-directory-replacement", "second-directory-replacement"} {
		replaceWatchedDirectory(t, r, filepath.Dir(r.path), logs, "issuer.yaml", "signing.key")
		c.PolicyRevision = revision
		replaceConfig(t, r.path, c)
		eventually(t, func() bool { return r.current.Load().config.PolicyRevision == revision })
		// Direct writes must also reach the new file's watch after an atomic edit.
		c.PolicyRevision = revision + "-direct-write"
		data, err := yaml.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(r.path, data, 0600); err != nil {
			t.Fatal(err)
		}
		eventually(t, func() bool { return r.current.Load().config.PolicyRevision == c.PolicyRevision })
	}
}

func TestReloadAfterSigningKeyDirectoryReplacement(t *testing.T) {
	p, _, _ := testProvider(t)
	path := writeConfig(t, p)
	c := testConfig()
	c.SigningKeyFile = filepath.Join(t.TempDir(), "signing.key")
	replaceSigningKey(t, c.SigningKeyFile)
	replaceConfig(t, path, c)
	logs := make(chan string, 128)
	r, err := WatchConfig(path, func(message string) { logs <- message })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	for range 2 {
		replaceWatchedDirectory(t, r, filepath.Dir(c.SigningKeyFile), logs, "signing.key")
		pub := replaceSigningKey(t, c.SigningKeyFile)
		eventually(t, func() bool {
			return bytes.Equal(r.current.Load().key.Public().(ed25519.PublicKey), pub)
		})
		// A subsequent in-place key rotation also needs the correct child watch.
		nextKey := filepath.Join(t.TempDir(), "next.key")
		pub = replaceSigningKey(t, nextKey)
		data, err := os.ReadFile(nextKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(c.SigningKeyFile, data, 0600); err != nil {
			t.Fatal(err)
		}
		eventually(t, func() bool {
			return bytes.Equal(r.current.Load().key.Public().(ed25519.PublicKey), pub)
		})
	}
}

func TestRequestUsesSingleSnapshotAcrossSwap(t *testing.T) {
	old, v, request := testProvider(t)
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	now := old.now()
	old.now = func() time.Time {
		once.Do(func() { close(entered); <-resume })
		return now
	}
	c := testConfig()
	c.PolicyRevision = "new-policy"
	next, err := newProvider(c, old.key, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	r := &ReloadingProvider{}
	r.current.Store(old)
	result := make(chan jobdb.SecretResolveResult, 1)
	errors := make(chan error, 1)
	go func() {
		out, err := r.ResolveSecrets(t.Context(), request)
		result <- out
		errors <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(resume)
		t.Fatal("request did not reach issuer")
	}
	r.current.Store(next)
	close(resume)
	out := <-result
	if err := <-errors; err != nil {
		t.Fatal(err)
	}
	for _, value := range out.Secrets {
		if verify(t, v, value).Claims.PolicyRevision != "policy-1" {
			t.Fatal("in-flight request mixed configuration snapshots")
		}
	}
	out, err = r.ResolveSecrets(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range out.Secrets {
		if verify(t, v, value).Claims.PolicyRevision != "new-policy" {
			t.Fatal("new request did not use replacement snapshot")
		}
	}
}

func TestConcurrentRequestsDuringFileReload(t *testing.T) {
	r, v, request, _ := watchFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); wg.Wait() })
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				out, err := r.ResolveSecrets(context.Background(), request)
				if err != nil || len(out.Secrets) != 2 {
					t.Errorf("resolution failed during reload: %v", err)
					return
				}
				read, err := v.Verify(out.Secrets[BaseSecretName].Value)
				if err != nil {
					t.Error(err)
					return
				}
				cell, err := v.Verify(out.Secrets[CellSecretName].Value)
				if err != nil || cell.Claims.PolicyRevision != read.Claims.PolicyRevision {
					t.Error("mixed or invalid credentials during reload")
					return
				}
			}
		}()
	}
	c := testConfig()
	c.SigningKeyFile = "signing.key"
	for _, revision := range []string{"concurrent-one", "concurrent-two", "concurrent-three"} {
		c.PolicyRevision = revision
		replaceConfig(t, r.path, c)
		eventually(t, func() bool { return r.current.Load().config.PolicyRevision == revision })
	}
}

func TestWatcherStartupAndClose(t *testing.T) {
	if _, err := WatchConfig("", nil); err == nil {
		t.Fatal("empty configuration path accepted")
	}
	if _, err := WatchConfig(filepath.Join(t.TempDir(), "missing.yaml"), nil); err == nil {
		t.Fatal("missing initial configuration accepted")
	}
	r, _, _, _ := watchFixture(t)
	c := testConfig()
	c.SigningKeyFile, c.PolicyRevision = "signing.key", "reload-before-close"
	replaceConfig(t, r.path, c)
	eventually(t, func() bool { return r.current.Load().config.PolicyRevision == c.PolicyRevision })
	r.Close()
	r.Close()
	if r.watcher.WatchList() != nil {
		t.Fatal("watcher resources not released")
	}
	select {
	case <-r.done:
	default:
		t.Fatal("watcher goroutine did not exit")
	}
}

func TestReloadDoesNotLogConfigurationContents(t *testing.T) {
	r, _, _, logs := watchFixture(t)
	replaceFile(t, r.path, []byte(`{"sensitive":"DO-NOT-LOG"}`))
	select {
	case message := <-logs:
		if strings.Contains(message, "DO-NOT-LOG") || !strings.Contains(message, "reload failed") {
			t.Fatal("reload error did not use safe diagnostics")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reload failure reported")
	}
}
