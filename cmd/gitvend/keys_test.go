package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/colony-2/gitvend/internal/auth"
	"github.com/colony-2/gitvend/internal/policy"
)

func TestPersistentSigningKeys(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "signing.key"), filepath.Join(dir, "signing.pub")
	init := func() error {
		return run([]string{"keygen", "-if-missing", "-private", private, "-public", public}, nil, io.Discard, io.Discard)
	}
	// Concurrent initializers must all settle on the same pair.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := init(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	before := readKey(t, private)
	publicBefore := readKey(t, public)
	for _, path := range []string{private, public} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unexpected key permissions: %v, %v", info, err)
		}
	}
	var out bytes.Buffer
	if err := run([]string{"sign", "-key", private, "-kid", "compose-1", "-issuer", "compose",
		"-subject", "agent", "-permission", "github.com/myorg/project#agents/*:rw"}, nil, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	// Simulate interruption after committing the private key but before the
	// public key, then a normal restart.
	if err := os.Remove(public); err != nil {
		t.Fatal(err)
	}
	if err := init(); err != nil {
		t.Fatal(err)
	}
	if err := init(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, readKey(t, private)) || !bytes.Equal(publicBefore, readKey(t, public)) {
		t.Fatal("initialization changed the signing identity")
	}
	pub, err := auth.ParsePublic(readKey(t, public))
	if err != nil {
		t.Fatal(err)
	}
	v := auth.Verifier{Audience: "gitvend", Keys: map[string]auth.Key{
		"compose-1": {Issuer: "compose", Public: pub, Owners: map[string][]string{"github.com": {"myorg"}}},
	}, MaxBytes: 4096, MaxLifetime: 15 * time.Minute}
	id, err := v.Verify(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatal("token issued before restart no longer verifies:", err)
	}
	repo := policy.Repository{Host: "github.com", Path: "myorg/project", FoldCase: true}
	if !id.Access(repo) || !id.Policy.Write(repo, "refs/heads/agents/task", "ref.update") {
		t.Fatal("assigned branch was denied")
	}
	if id.Policy.Write(repo, "refs/heads/main", "ref.update") {
		t.Fatal("unassigned branch was allowed")
	}
}

func TestPersistentKeysRejectInvalidState(t *testing.T) {
	for _, state := range []string{"public-only", "bad-private", "bad-public", "mismatch"} {
		t.Run(state, func(t *testing.T) {
			dir := t.TempDir()
			private, public := filepath.Join(dir, "key"), filepath.Join(dir, "pub")
			if err := ensureSigningKeys(private, public); err != nil {
				t.Fatal(err)
			}
			switch state {
			case "public-only":
				if err := os.Remove(private); err != nil {
					t.Fatal(err)
				}
			case "bad-private":
				writeKey(t, private, []byte("partial private key"))
			case "bad-public":
				writeKey(t, public, []byte("partial public key"))
			case "mismatch":
				otherPrivate, otherPublic := filepath.Join(dir, "other-key"), filepath.Join(dir, "other-pub")
				if err := ensureSigningKeys(otherPrivate, otherPublic); err != nil {
					t.Fatal(err)
				}
				writeKey(t, public, readKey(t, otherPublic))
			}
			privateBefore, _ := os.ReadFile(private)
			publicBefore := readKey(t, public)
			if err := ensureSigningKeys(private, public); err == nil {
				t.Fatal("accepted invalid state")
			}
			privateAfter, _ := os.ReadFile(private)
			if !bytes.Equal(privateBefore, privateAfter) || !bytes.Equal(publicBefore, readKey(t, public)) {
				t.Fatal("changed keys while rejecting invalid state")
			}
		})
	}
}

func TestPersistentKeysRejectSamePath(t *testing.T) {
	private := filepath.Join(t.TempDir(), "key")
	for _, public := range []string{private, private + ".lock"} {
		if err := ensureSigningKeys(private, public); err == nil {
			t.Fatal("accepted overlapping paths")
		}
	}
}

func readKey(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeKey(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
