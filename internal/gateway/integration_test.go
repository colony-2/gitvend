package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitgate/internal/auth"
	"gitgate/internal/config"
	"gitgate/internal/gitwire"
	"gitgate/internal/state"
)

type fixture struct {
	t                                *testing.T
	root, work, url, token, secretID string
	server                           *Server
	proxy, upstream                  *httptest.Server
	store                            *state.Store
	key                              ed25519.PrivateKey
	mu                               sync.Mutex
	repos                            map[string]int64
	nextID                           int64
	pushes, creates                  atomic.Int32
	denyCreate                       bool
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, e := gitRun(dir, "", args...)
	if e != nil {
		t.Fatalf("git %v: %v\n%s", args, e, out)
	}
	return strings.TrimSpace(out)
}
func gitRun(dir, token string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.invalid", "GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.invalid", "TEST_JWT="+token)
	if token != "" {
		cmd.Args = append([]string{"git", "-c", "protocol.version=2", "-c", `credential.helper=!f() { printf 'username=git\npassword=%s\n' "$TEST_JWT"; }; f`}, args...)
	}
	out, e := cmd.CombinedOutput()
	return string(out), e
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	if _, e := exec.LookPath("git"); e != nil {
		t.Fatal("real Git required")
	}
	f := &fixture{t: t, root: t.TempDir(), repos: map[string]int64{}, nextID: 100}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	f.key = key
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	keyPath := filepath.Join(f.root, "public.pem")
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0600)
	tokenFile := filepath.Join(f.root, "token")
	os.WriteFile(tokenFile, []byte("upstream-secret"), 0600)
	f.makeRepo("org/repo")
	f.work = filepath.Join(f.root, "seed")
	os.MkdirAll(f.work, 0700)
	git(t, f.work, "init", "-b", "main")
	os.WriteFile(filepath.Join(f.work, "readme"), []byte("base"), 0600)
	git(t, f.work, "add", ".")
	git(t, f.work, "commit", "-m", "base")
	git(t, f.work, "push", filepath.Join(f.root, "org/repo.git"), "main")
	git(t, f.work, "checkout", "-b", "secret")
	os.WriteFile(filepath.Join(f.work, "secret"), []byte("hidden branch"), 0600)
	git(t, f.work, "add", ".")
	git(t, f.work, "commit", "-m", "secret")
	f.secretID = git(t, f.work, "rev-parse", "HEAD")
	git(t, f.work, "push", filepath.Join(f.root, "org/repo.git"), "secret")
	git(t, f.work, "checkout", "main")
	execPath := git(t, f.root, "--exec-path")
	backend := &cgi.Handler{Path: filepath.Join(execPath, "git-http-backend"), Env: []string{"GIT_PROJECT_ROOT=" + f.root, "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER=gitgate"}}
	f.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("Authorization") != "Bearer upstream-secret" {
				http.Error(w, "bad credential", 401)
				return
			}
			f.api(w, r)
			return
		}
		_, pw, ok := r.BasicAuth()
		if !ok || pw != "upstream-secret" {
			http.Error(w, "bad credential", 401)
			return
		}
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/git-receive-pack") {
			f.pushes.Add(1)
		}
		// CGI requires Content-Length. The test adapter materializes tiny test
		// bodies; the gateway itself still forwards packs as a stream.
		if r.ContentLength < 0 {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "test body read failed", 400)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(b))
			r.ContentLength = int64(len(b))
			r.TransferEncoding = nil
		}
		backend.ServeHTTP(w, r)
	}))
	c := config.Defaults()
	c.AllowHTTP = true
	c.AllowHTTPUpstream = true
	c.StateFile = filepath.Join(f.root, "state.db")
	c.Keys = []config.SigningKey{{ID: "test", Issuer: "test-issuer", PublicKeyFile: keyPath, Owners: map[string][]string{"github.com": {"org"}}}}
	c.Providers = []config.Provider{{Alias: "github", Host: "github.com", Kind: "github", GitBaseURL: f.upstream.URL, APIBaseURL: f.upstream.URL + "/api", AllowedOwners: []string{"org"}, Credential: config.Credential{Kind: "token", SecretRef: "file:" + tokenFile}, AllowCreation: true}}
	st, e := state.Open(c.StateFile)
	if e != nil {
		t.Fatal(e)
	}
	f.store = st
	f.server, e = New(c, st)
	if e != nil {
		t.Fatal(e)
	}
	f.proxy = httptest.NewServer(f.server)
	f.url = f.proxy.URL + "/github/org/repo.git"
	f.token = f.sign("github.com/org/repo#main:r", "github.com/org/repo#agents/a/*:rwd")
	t.Cleanup(func() { f.proxy.Close(); f.server.Close(); f.upstream.Close(); f.store.Close() })
	return f
}
func (f *fixture) sign(rules ...string) string {
	f.t.Helper()
	s, e := auth.Sign(auth.NewClaims("test-issuer", "agent-a", "gitgate", 15*time.Minute, auth.Grant{Version: 1, Permissions: rules}), f.key, "test", 4096)
	if e != nil {
		f.t.Fatal(e)
	}
	return s
}
func (f *fixture) makeRepo(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.repos[path] != 0 {
		return
	}
	repoPath := filepath.Join(f.root, path+".git")
	os.MkdirAll(filepath.Dir(repoPath), 0700)
	git(f.t, f.root, "init", "--bare", "--initial-branch=main", repoPath)
	git(f.t, f.root, "--git-dir="+repoPath, "config", "http.receivepack", "true")
	git(f.t, f.root, "--git-dir="+repoPath, "config", "uploadpack.allowFilter", "true")
	git(f.t, f.root, "--git-dir="+repoPath, "config", "uploadpack.allowAnySHA1InWant", "true")
	f.nextID++
	f.repos[path] = f.nextID
}
func (f *fixture) api(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "POST" && r.URL.Path == "/api/orgs/org/repos" {
		f.creates.Add(1)
		var input struct {
			Name     string `json:"name"`
			Private  bool   `json:"private"`
			AutoInit bool   `json:"auto_init"`
		}
		if e := json.NewDecoder(r.Body).Decode(&input); e != nil || !input.Private || input.AutoInit || f.denyCreate {
			http.Error(w, "rejected", 422)
			return
		}
		f.makeRepo("org/" + input.Name)
		f.mu.Lock()
		id := f.repos["org/"+input.Name]
		f.mu.Unlock()
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"id": id, "full_name": "org/" + input.Name, "private": true})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/repos/")
	f.mu.Lock()
	id := f.repos[path]
	f.mu.Unlock()
	if r.Method != "GET" || id == 0 {
		http.Error(w, "not found", 404)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"id": id, "full_name": path, "private": true})
}
func (f *fixture) request(method, path, token, protocol string, body []byte) *http.Response {
	f.t.Helper()
	req, _ := http.NewRequest(method, f.proxy.URL+path, bytes.NewReader(body))
	req.SetBasicAuth("git", token)
	if protocol != "" {
		req.Header.Set("Git-Protocol", protocol)
	}
	if method == "POST" {
		svc := path[strings.LastIndex(path, "/")+1:]
		req.Header.Set("Content-Type", "application/x-"+svc+"-request")
	}
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		f.t.Fatal(e)
	}
	return resp
}
func TestRealGitReadAndWrite(t *testing.T) {
	f := newFixture(t)
	out, e := gitRun(f.root, f.token, "ls-remote", f.url)
	if e != nil {
		t.Fatal(e, out)
	}
	if strings.Contains(out, "secret") || !strings.Contains(out, "refs/heads/main") {
		t.Fatal(out)
	}
	clone := filepath.Join(f.root, "clone")
	out, e = gitRun(f.root, f.token, "clone", "--branch", "main", f.url, clone)
	if e != nil {
		t.Fatal(e, out)
	}
	os.WriteFile(filepath.Join(clone, "change"), []byte("agent"), 0600)
	git(t, clone, "add", ".")
	git(t, clone, "commit", "-m", "agent change")
	out, e = gitRun(clone, f.token, "push", "origin", "HEAD:refs/heads/agents/a/task")
	if e != nil {
		events, _ := f.store.Events()
		for _, ev := range events {
			t.Logf("audit: %+v", ev)
		}
		t.Fatal(e, out)
	}
	if f.pushes.Load() != 1 {
		t.Fatal(f.pushes.Load())
	}
	before := f.pushes.Load()
	out, e = gitRun(clone, f.token, "push", "origin", "HEAD:refs/heads/main")
	if e == nil || f.pushes.Load() != before {
		t.Fatal("forbidden push reached upstream", e, out)
	}
	out, e = gitRun(clone, f.token, "push", "origin", "HEAD:refs/heads/agents/a/other", "HEAD:refs/heads/secret")
	if e == nil || f.pushes.Load() != before {
		t.Fatal("mixed push reached upstream", e, out)
	}
	out, e = gitRun(clone, f.token, "fetch", "origin", f.secretID)
	if e != nil {
		t.Fatal("known hash fetch", e, out)
	}
	out, e = gitRun(clone, f.token, "push", "origin", ":refs/heads/agents/a/task")
	if e != nil {
		t.Fatal("allowed delete", e, out)
	}
	events, e := f.store.Events()
	if e != nil {
		t.Fatal(e)
	}
	accepted := false
	denied := false
	for _, ev := range events {
		if ev.Operation == "git-receive-pack" && ev.Updates != nil {
			accepted = accepted || ev.Outcome == "accepted"
			denied = denied || ev.Outcome == "rejected"
		}
	}
	if !accepted || !denied {
		b, _ := json.Marshal(events)
		t.Fatal(string(b))
	}
}
func TestCreateFirstPushAndConcurrency(t *testing.T) {
	f := newFixture(t)
	token := f.sign("github.com/org/scratch-*:c", "github.com/org/scratch-*#agents/a/*:rw")
	url := f.proxy.URL + "/github/org/scratch-one.git"
	out, e := gitRun(f.work, token, "push", url, "HEAD:refs/heads/agents/a/first")
	if e != nil {
		t.Fatal(e, out)
	}
	if f.creates.Load() != 1 || f.pushes.Load() != 1 {
		t.Fatal(f.creates.Load(), f.pushes.Load())
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			resp := f.request("GET", "/github/org/scratch-two.git/info/refs?service=git-receive-pack", token, "", nil)
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				b, _ := io.ReadAll(resp.Body)
				t.Errorf("discovery %d %s", resp.StatusCode, b)
			}
		})
	}
	wg.Wait()
	if f.creates.Load() != 2 {
		t.Fatal("duplicate creation", f.creates.Load())
	}
	read := f.request("GET", "/github/org/scratch-three.git/info/refs?service=git-upload-pack", token, "version=2", nil)
	read.Body.Close()
	if read.StatusCode != 404 || f.creates.Load() != 2 {
		t.Fatal("fetch created repository")
	}
}
func TestDirectPushAndProtocolRejections(t *testing.T) {
	f := newFixture(t)
	zero := strings.Repeat("0", 40)
	id := strings.Repeat("1", 40)
	body := append(gitwire.Line(zero+" "+id+" refs/heads/main\x00report-status\n"), []byte("0000PACK")...)
	resp := f.request("POST", "/github/org/repo.git/git-receive-pack", f.token, "", body)
	resp.Body.Close()
	if resp.StatusCode != 403 || f.pushes.Load() != 0 {
		t.Fatal("direct unauthorized push")
	}
	for _, tt := range []struct {
		path, token, protocol string
		code                  int
	}{{"/github/org/repo.git/info/refs?service=git-upload-pack", f.token, "", 400}, {"/github/org/repo.git/info/refs?service=git-upload-pack", "bad", "version=2", 401}, {"/github/other/repo.git/info/refs?service=git-upload-pack", f.token, "version=2", 404}, {"/github/org/repo.git/info/refs?service=git-upload-pack&x=1", f.token, "version=2", 404}, {"/github/org/repo.git/objects/aa", f.token, "version=2", 404}} {
		resp := f.request("GET", tt.path, tt.token, tt.protocol, nil)
		resp.Body.Close()
		if resp.StatusCode != tt.code {
			t.Errorf("%+v got %d", tt, resp.StatusCode)
		}
	}
	denied := f.sign("github.com/org/repo#agents/a/*:rw", "!github.com/org/repo#agents/a/*:w", "github.com/org/new:c")
	resp = f.request("GET", "/github/org/new.git/info/refs?service=git-receive-pack", denied, "", nil)
	resp.Body.Close()
	if resp.StatusCode != 403 || f.creates.Load() != 0 {
		t.Fatal("denied create")
	}
}
func TestBindingAndAuditFailures(t *testing.T) {
	f := newFixture(t)
	resp := f.request("GET", "/github/org/repo.git/info/refs?service=git-upload-pack", f.token, "version=2", nil)
	resp.Body.Close()
	f.mu.Lock()
	f.repos["org/repo"]++
	f.mu.Unlock()
	resp = f.request("GET", "/github/org/repo.git/info/refs?service=git-upload-pack", f.token, "version=2", nil)
	resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Fatal("identity replacement", resp.StatusCode)
	}
	f.store.Close()
	resp = f.request("GET", "/github/org/repo.git/info/refs?service=git-upload-pack", f.token, "version=2", nil)
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatal("audit unavailable", resp.StatusCode)
	}
}
func TestProvisioningWaitCancellation(t *testing.T) {
	s := &Server{locks: map[string]*lock{}}
	release, e := s.acquire(context.Background(), "one")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = s.acquire(ctx, "one"); e == nil {
		t.Fatal("expected cancellation")
	}
	release()
	if len(s.locks) != 0 {
		t.Fatal(fmt.Sprint(s.locks))
	}
}

func TestRealGitPartialAtomicForceAndTags(t *testing.T) {
	f := newFixture(t)
	hook := filepath.Join(f.root, "org/repo.git/hooks/update")
	if e := os.WriteFile(hook, []byte("#!/bin/sh\ncase \"$1\" in *reject*) exit 1;; esac\nexit 0\n"), 0700); e != nil {
		t.Fatal(e)
	}
	out, e := gitRun(f.work, f.token, "push", f.url, "HEAD:refs/heads/agents/a/pass", "HEAD:refs/heads/agents/a/reject")
	if e == nil {
		t.Fatal("hook should reject one", out)
	}
	git(t, f.root, "--git-dir="+filepath.Join(f.root, "org/repo.git"), "rev-parse", "refs/heads/agents/a/pass")
	events, _ := f.store.Events()
	partial := false
	for _, ev := range events {
		if ev.Outcome == "partial" {
			partial = true
		}
	}
	if !partial {
		t.Fatal("partial push not audited")
	}
	out, e = gitRun(f.work, f.token, "push", "--atomic", f.url, "HEAD:refs/heads/agents/a/atomic-pass", "HEAD:refs/heads/agents/a/atomic-reject")
	if e == nil {
		t.Fatal("atomic push should reject", out)
	}
	if _, e = gitRun(f.root, "", "--git-dir="+filepath.Join(f.root, "org/repo.git"), "show-ref", "--verify", "refs/heads/agents/a/atomic-pass"); e == nil {
		t.Fatal("atomic push partly succeeded")
	}
	git(t, f.work, "checkout", "secret")
	out, e = gitRun(f.work, f.token, "push", f.url, "HEAD:refs/heads/agents/a/pass")
	if e != nil {
		t.Fatal(e, out)
	}
	git(t, f.work, "checkout", "main")
	out, e = gitRun(f.work, f.token, "push", "--force", f.url, "HEAD:refs/heads/agents/a/pass")
	if e != nil {
		t.Fatal("force update should be allowed", e, out)
	}
	before := f.pushes.Load()
	out, e = gitRun(f.work, f.token, "push", f.url, "HEAD:refs/tags/v1")
	if e == nil || f.pushes.Load() != before {
		t.Fatal("tag escaped branch scope", out)
	}
	tagToken := f.sign("github.com/org/repo#refs/tags/v*:rwd")
	out, e = gitRun(f.work, tagToken, "push", f.url, "HEAD:refs/tags/v1")
	if e != nil {
		t.Fatal(e, out)
	}
	out, e = gitRun(f.work, tagToken, "ls-remote", f.url)
	if e != nil || strings.Contains(out, "refs/heads/") || !strings.Contains(out, "refs/tags/v1") {
		t.Fatal(e, out)
	}
}
func TestRealGitShallowPartialAndDryRun(t *testing.T) {
	f := newFixture(t)
	for i, args := range [][]string{{"--depth", "1"}, {"--filter=blob:none"}} {
		clone := filepath.Join(f.root, fmt.Sprintf("clone-%d", i))
		all := append([]string{"clone", "--branch", "main"}, args...)
		all = append(all, f.url, clone)
		out, e := gitRun(f.root, f.token, all...)
		if e != nil {
			t.Fatal(e, out)
		}
	}
	token := f.sign("github.com/org/new*:rc", "github.com/org/new*#agents/a/*:rw")
	out, e := gitRun(f.work, token, "push", "--dry-run", f.proxy.URL+"/github/org/new-dry.git", "HEAD:refs/heads/agents/a/first")
	if e != nil {
		t.Fatal(e, out)
	}
	if f.creates.Load() != 1 || f.pushes.Load() != 0 {
		t.Fatal("dry run behavior", f.creates.Load(), f.pushes.Load())
	}
}
func TestCreationFailureAndRecovery(t *testing.T) {
	f := newFixture(t)
	f.denyCreate = true
	token := f.sign("github.com/org/new*:rc", "github.com/org/new*#agents/a/*:rw")
	resp := f.request("GET", "/github/org/new-one.git/info/refs?service=git-receive-pack", token, "", nil)
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatal(resp.StatusCode)
	}
	record, e := f.store.Repository("github.com/org/new-one")
	if e != nil || record.Status != "unknown" || !record.Reserved {
		t.Fatal(record, e)
	}
	f.denyCreate = false
	resp = f.request("GET", "/github/org/new-one.git/info/refs?service=git-receive-pack", token, "", nil)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	record, e = f.store.Repository("github.com/org/new-one")
	if e != nil || record.Status != "ready" {
		t.Fatal(record, e)
	}
}
