package main

import (
	"bytes"
	"gopkg.in/yaml.v3"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/colony-2/gitvend/internal/config"
	"github.com/colony-2/gitvend/internal/gateway"
	"github.com/colony-2/gitvend/internal/gitwire"
)

func TestComposeDefaults(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "key"), filepath.Join(dir, "pub")
	if err := ensureSigningKeys(private, public); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../deploy/gitvend.default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c := config.Defaults()
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.Keys[0].PublicKeyFile = public
	t.Setenv("GITHUB_TOKEN", "")
	if err := c.Validate(); err == nil {
		t.Fatal("started without a GitHub token")
	}
	t.Setenv("GITHUB_TOKEN", "compose-test-token")
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, password, ok := r.BasicAuth()
		if !ok || password != "compose-test-token" {
			t.Error("GitHub token was not forwarded")
		}
		http.Error(w, "not accessible upstream", http.StatusNotFound)
	}))
	defer upstream.Close()
	c.AllowHTTPUpstream = true
	c.Providers[0].GitBaseURL = upstream.URL
	c.Providers[0].APIBaseURL = upstream.URL
	if c.Providers[0].AllowCreation {
		t.Fatal("repository creation enabled by default")
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	sign := func(permission string) string {
		t.Helper()
		var out bytes.Buffer
		if err := run([]string{"sign", "-key", private, "-kid", "compose-1",
			"-issuer", "compose", "-audience", "gitvend", "-subject", "test",
			"-permission", permission}, nil, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(out.String())
	}
	start := func(c config.Config) *gateway.Server {
		t.Helper()
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		s, err := gateway.New(c, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	s := start(c)
	token := sign("github.com/personal/project:rw")
	request := func(s *gateway.Server, token, owner string, push []byte) int {
		t.Helper()
		method, endpoint := "GET", "/info/refs?service=git-upload-pack"
		if push != nil {
			method, endpoint = "POST", "/git-receive-pack"
		}
		req := httptest.NewRequest(method, "/github/"+owner+"/project.git"+endpoint, bytes.NewReader(push))
		req.SetBasicAuth("git", token)
		if push == nil {
			req.Header.Set("Git-Protocol", "version=2")
		} else {
			req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w.Code
	}
	// An arbitrary owner is routed, but upstream access is still required.
	if status := request(s, token, "personal", nil); status != 404 || upstreamCalls.Load() != 1 {
		t.Fatalf("upstream authorization: status=%d, calls=%d", status, upstreamCalls.Load())
	}
	if status := request(s, token, "ungranted-org", nil); status != 403 || upstreamCalls.Load() != 1 {
		t.Fatal("wildcard owners bypassed JWT permissions", status, upstreamCalls.Load())
	}
	broad := sign("github.com/*:rwd")
	for _, owner := range []string{"personal", "another-org"} {
		for _, branch := range []string{"main", "master"} {
			push := append(gitwire.Line(strings.Repeat("1", 40)+" "+strings.Repeat("2", 40)+
				" refs/heads/"+branch+"\x00report-status\n"), []byte("0000")...)
			if status := request(s, broad, owner, push); status != 403 || upstreamCalls.Load() != 1 {
				t.Fatal("default branch protection bypassed", owner, branch, status)
			}
		}
	}
	// Restricting the issuer still works under a wildcard provider.
	c.Keys[0].Owners["github.com"] = []string{"personal"}
	if status := request(start(c), broad, "another-org", nil); status != 403 || upstreamCalls.Load() != 1 {
		t.Fatal("wildcard provider bypassed issuer ceiling", status)
	}
	// Explicit provider lists still reject owners outside their route.
	c.Providers[0].AllowedOwners = []string{"personal"}
	if status := request(start(c), broad, "another-org", nil); status != 404 || upstreamCalls.Load() != 1 {
		t.Fatal("explicit provider ceiling bypassed", status)
	}
}
