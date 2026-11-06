package jobdbprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/colony-2/gitvend/internal/policy"
	"github.com/colony-2/jobdb/pkg/jobdb"
	secretplugin "github.com/colony-2/jobdb/pkg/jobdb/secrets/plugin"
)

type pluginDiagnostics struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (d *pluginDiagnostics) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.b.Write(p)
}

func (d *pluginDiagnostics) String() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.b.String()
}

func TestExecutableJobDBHandshake(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess build")
	}
	p, verifier, request := testProvider(t)
	configPath := writeConfig(t, p)
	binary := filepath.Join(t.TempDir(), "jobdb-gitvend-secret-provider")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", binary, "github.com/colony-2/gitvend/cmd/jobdb-gitvend-secret-provider").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	var diagnostics pluginDiagnostics
	process, err := secretplugin.Start(ctx, secretplugin.ProcessConfig{Command: binary, Args: []string{"--config", configPath},
		Logger: slog.New(slog.NewTextHandler(&diagnostics, nil))})
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
	for _, name := range []string{BaseSecretName, CellSecretName} {
		id := verify(t, verifier, out.Secrets[name])
		if id.Expiry.After(request.Lease.AuthorizedNotAfter) {
			t.Fatal("plugin token exceeds presenting lease authority")
		}
	}
	// Both the cell context and the authority boundary must survive the subprocess wire.
	request.AppMetadata = json.RawMessage(`{"repo":"github.com/acme/alpha-two","cellRepo":"github.com/acme/alpha-two"}`)
	out, err = process.ResolveSecrets(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	cell := verify(t, verifier, out.Secrets[CellSecretName])
	for _, path := range []string{"acme/alpha-one", "acme/alpha-two"} {
		repo := policy.Repository{Host: "github.com", Path: path}
		if cell.Policy.Write(repo, "refs/heads/main", "ref.update") != (path == "acme/alpha-one") {
			t.Fatalf("plugin metadata overrode verified cell: %s", path)
		}
	}
	verifiedCell := request.Lease.Cell
	request.Lease.Cell = jobdb.ResolvedCell{}
	out, err = process.ResolveSecrets(ctx, request)
	if err != nil || len(out.Secrets) != 1 || out.Secrets[BaseSecretName].Value == "" {
		t.Fatalf("missing cell context must omit only the cell token: %v", err)
	}
	eventually(t, func() bool {
		return strings.Contains(diagnostics.String(), "gitvend_cell_token unavailable: verified Lease.Cell.CellID is missing")
	})
	request.Lease.Cell = verifiedCell
	request.TenantID = "unknown"
	out, err = process.ResolveSecrets(ctx, request)
	if err != nil || len(out.Secrets) != 0 {
		t.Fatal("unauthorized request not omitted over plugin transport")
	}
	// Update the running executable without restarting its JobDB process handle.
	request.TenantID = "alpha"
	c := testConfig()
	c.SigningKeyFile, c.PolicyRevision = "signing.key", "live-reload"
	replaceConfig(t, configPath, c)
	eventually(t, func() bool {
		out, err := process.ResolveSecrets(ctx, request)
		if err != nil || len(out.Secrets) != 2 {
			t.Fatalf("resolution during plugin reload: %v", err)
		}
		read := verify(t, verifier, out.Secrets[BaseSecretName])
		cell := verify(t, verifier, out.Secrets[CellSecretName])
		if read.Claims.PolicyRevision != cell.Claims.PolicyRevision {
			t.Fatal("plugin response mixed policy revisions")
		}
		return read.Claims.PolicyRevision == "live-reload"
	})
	delete(c.Tenants, "alpha")
	replaceConfig(t, configPath, c)
	eventually(t, func() bool {
		out, err := process.ResolveSecrets(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		return len(out.Secrets) == 0
	})
}
