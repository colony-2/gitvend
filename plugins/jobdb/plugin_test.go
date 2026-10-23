package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	secretplugin "github.com/colony-2/jobdb/pkg/jobdb/secrets/plugin"
)

func TestExecutableJobDBHandshake(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess build")
	}
	p, verifier, request := testProvider(t)
	configPath := writeConfig(t, p)
	binary := filepath.Join(t.TempDir(), "jobdb-gitvend-secret-provider")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	process, err := secretplugin.Start(ctx, secretplugin.ProcessConfig{Command: binary, Args: []string{"--config", configPath}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := process.Close(); err != nil {
			t.Error(err)
		}
	})
	now := time.Now()
	request.Lease.LeaseExpiresAt = now.Add(10 * time.Minute)
	request.Lease.AuthorizedNotAfter = now.Add(5 * time.Minute)
	verifier.Now = time.Now
	out, err := process.ResolveSecrets(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Secrets) != 2 {
		t.Fatalf("got %d secrets over plugin transport", len(out.Secrets))
	}
	for _, name := range []string{readSecret, cellSecret} {
		id := verify(t, verifier, out.Secrets[name])
		if id.Expiry.After(request.Lease.AuthorizedNotAfter) {
			t.Fatal("plugin token exceeds presenting lease authority")
		}
	}
	request.TenantID = "unknown"
	out, err = process.ResolveSecrets(ctx, request)
	if err != nil || len(out.Secrets) != 0 {
		t.Fatal("unauthorized request not omitted over plugin transport")
	}
}
