package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/colony-2/gitvend/internal/gitwire"
)

func TestIndependentReplicasCreateSameRepository(t *testing.T) {
	f := newFixture(t)
	other := f.replica()
	started, release := make(chan struct{}, 2), make(chan struct{})
	f.createStarted, f.createRelease = started, release
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	token := f.sign("github.com/org/race:c", "github.com/org/race#agents/a/*:rw")
	results := make(chan int, 2)
	for _, base := range []string{f.proxy.URL, other.URL} {
		go func() {
			req, _ := http.NewRequest("GET", base+"/github/org/race.git/info/refs?service=git-receive-pack", nil)
			req.SetBasicAuth("git", token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				results <- 0
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			results <- resp.StatusCode
		}()
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("both independent replicas must attempt creation")
		}
	}
	// Both saw 404 and reached POST independently; the forge accepts one and
	// returns a conflict to the other, which must reconcile by name.
	close(release)
	for range 2 {
		if code := <-results; code != 200 {
			t.Fatal("discovery failed", code)
		}
	}
	if f.creates.Load() != 2 || f.created.Load() != 1 {
		t.Fatal("forge did not coordinate concurrent creation", f.creates.Load(), f.created.Load())
	}
	created, reconciled := false, false
	for _, event := range f.events() {
		if event.Operation == "repo.create" {
			created = created || event.Outcome == "created"
			reconciled = reconciled || event.Outcome == "reconciled"
			if event.ParentID == "" {
				t.Fatal("creation event lacks request correlation")
			}
		}
	}
	if !created || !reconciled {
		t.Fatal("creation outcomes not logged")
	}
	// A third instance can perform the actual push without either instance's memory.
	fresh := f.replica()
	out, err := gitRun(f.work, token, "push", fresh.URL+"/github/org/race.git", "HEAD:refs/heads/agents/a/first")
	if err != nil || f.creates.Load() != 2 {
		t.Fatal("new replica could not push", err, out)
	}
}

func TestLostCreateResponseAndRestart(t *testing.T) {
	f := newFixture(t)
	f.lostCreateResponse = true
	token := f.sign("github.com/org/new*:c", "github.com/org/new*#agents/a/*:rw")
	out, err := gitRun(f.work, token, "push", f.proxy.URL+"/github/org/new-lost.git", "HEAD:refs/heads/agents/a/first")
	if err != nil {
		t.Fatal(err, out)
	}
	f.proxy.Close()
	f.server.Close()
	fresh := f.replica()
	out, err = gitRun(f.work, token, "ls-remote", fresh.URL+"/github/org/new-lost.git")
	if err != nil || !strings.Contains(out, "refs/heads/agents/a/first") || f.creates.Load() != 1 {
		t.Fatal("restart required local provisioning state", err, out)
	}
}

func TestOrdinaryGitNeedsNoRESTOrIdentityEnrollment(t *testing.T) {
	f := newFixture(t)
	f.lookupStatus = 503 // REST unavailable; normal Git still works.
	for i := range 2 {
		out, err := gitRun(f.root, f.token, "ls-remote", f.url)
		if err != nil || !strings.Contains(out, "refs/heads/main") {
			t.Fatal(err, out)
		}
		if i == 0 {
			// Recreate the Git repository itself, not just the API metadata.
			path := filepath.Join(f.root, "org/repo.git")
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			delete(f.repos, "org/repo")
			f.mu.Unlock()
			f.makeRepo("org/repo")
			git(t, f.work, "push", path, "main")
		}
	}
	out, err := gitRun(f.work, f.token, "push", f.url, "HEAD:refs/heads/agents/a/rest-offline")
	if err != nil || f.apiCalls.Load() != 0 {
		t.Fatal("ordinary Git used the REST API", err, out, f.apiCalls.Load())
	}
}

func TestCreationFailuresAndAdmission(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*fixture)
		want      int
		creates   int32
	}{
		{"lookup-unauthorized", func(f *fixture) { f.lookupStatus = 401 }, 502, 0},
		{"lookup-rate-limited", func(f *fixture) { f.lookupStatus = 429 }, 502, 0},
		{"lookup-unavailable", func(f *fixture) { f.lookupStatus = 503 }, 502, 0},
		{"creation-disabled", func(f *fixture) { f.server.Providers["github"].Config.AllowCreation = false }, 404, 0},
		{"public-create", func(f *fixture) { f.publicCreate = true }, 409, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			test.configure(f)
			token := f.sign("github.com/org/new:c", "github.com/org/new#agents/a/*:rw")
			resp := f.request("GET", "/github/org/new.git/info/refs?service=git-receive-pack", token, "", nil)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != test.want || f.creates.Load() != test.creates {
				t.Fatal(resp.StatusCode, f.creates.Load())
			}
		})
	}
	t.Run("expired-before-create", func(t *testing.T) {
		f := newFixture(t)
		token := f.sign("github.com/org/new:rcw")
		id, err := f.server.Verifier.Verify(token)
		if err != nil {
			t.Fatal(err)
		}
		id.Expiry = time.Now().Add(-time.Second)
		req := httptest.NewRequest("GET", "/github/org/new.git/info/refs?service=git-receive-pack", nil)
		rt, err := f.server.route(req)
		if err != nil {
			t.Fatal(err)
		}
		err = f.server.ensure(context.Background(), rt, id, true, "expired")
		var he *httpError
		if !errors.As(err, &he) || he.code != 401 || f.creates.Load() != 0 {
			t.Fatal("expired JWT created repository", err)
		}
	})
	t.Run("direct-post-does-not-create", func(t *testing.T) {
		f := newFixture(t)
		token := f.sign("github.com/org/new:rcw")
		body := append(gitwire.Line(strings.Repeat("0", 40)+" "+strings.Repeat("1", 40)+" refs/heads/main\x00report-status\n"), []byte("0000PACK")...)
		resp := f.request("POST", "/github/org/new.git/git-receive-pack", token, "", body)
		resp.Body.Close()
		if resp.StatusCode != 404 || f.apiCalls.Load() != 0 {
			t.Fatal("direct push attempted creation", resp.StatusCode, f.apiCalls.Load())
		}
	})
}

type failedLogWriter struct{}

func (failedLogWriter) Write([]byte) (int, error) { return 0, errors.New("collector unavailable") }

func TestAuditStreamAndUnavailableCollector(t *testing.T) {
	f := newFixture(t)
	out, err := gitRun(f.work, f.token, "push", f.url, "HEAD:refs/heads/agents/a/logged")
	if err != nil {
		t.Fatal(err, out)
	}
	admitted := map[string]bool{}
	completed := false
	for _, event := range f.events() {
		if event.Operation != "git-receive-pack" || event.Updates == nil {
			continue
		}
		if event.Outcome == "admitted" {
			admitted[event.ID] = true
		}
		if event.Outcome == "accepted" {
			if !admitted[event.ID] {
				t.Fatal("completion without prior admission")
			}
			completed = true
		}
	}
	if !completed {
		t.Fatal("missing final audit event")
	}
	for _, secret := range []string{f.token, "upstream-secret", "password", "Authorization"} {
		if bytes.Contains(f.logs.Bytes(), []byte(secret)) {
			t.Fatal("credential leaked to audit")
		}
	}
	// Logging is an output stream, not a transactional admission dependency.
	server, err := New(f.server.Config, slog.New(slog.NewJSONHandler(failedLogWriter{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	proxy := httptest.NewServer(server)
	defer proxy.Close()
	out, err = gitRun(f.work, f.token, "push", proxy.URL+"/github/org/repo.git", "HEAD:refs/heads/agents/a/collector-down")
	if err != nil {
		t.Fatal("logging failure blocked authorized push", err, out)
	}
}
