package gateway

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/colony-2/gitvend/internal/gitwire"
)

func TestRealGitShallowAndChunkedPush(t *testing.T) {
	type scenario struct {
		name                  string
		shallow, create       bool
		packBytes, postBuffer int
	}
	var scenarios []scenario
	for _, shallow := range []bool{false, true} {
		for _, create := range []bool{false, true} {
			for _, size := range []struct {
				name          string
				bytes, buffer int
			}{
				{"buffered", 0, 0},
				{"default buffer overflow", 2 << 20, 0},
				{"configured buffer overflow", 128 << 10, 1024},
			} {
				scenarios = append(scenarios, scenario{
					name:    fmt.Sprintf("shallow=%t/create=%t/%s", shallow, create, size.name),
					shallow: shallow, create: create, packBytes: size.bytes, postBuffer: size.buffer,
				})
			}
		}
	}
	for _, tt := range scenarios {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			token := f.sign("github.com/org/repo:rw")
			work := f.work
			if tt.shallow {
				git(t, f.work, "commit", "--allow-empty", "-m", "more history")
				git(t, f.work, "push", filepath.Join(f.root, "org/repo.git"), "main")
				work = filepath.Join(f.root, "shallow")
				if out, err := gitRun(f.root, token, "clone", "--depth=1", "--branch=main", f.url, work); err != nil {
					t.Fatalf("shallow clone failed: %v\n%s", err, out)
				}
				if git(t, work, "rev-parse", "--is-shallow-repository") != "true" {
					t.Fatal("test checkout is not shallow")
				}
			}
			data := []byte("small change")
			if tt.packBytes > 0 {
				// Incompressible data crosses the configured or default HTTP buffer.
				data = make([]byte, tt.packBytes)
				if _, err := rand.Read(data); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(work, "change.bin"), data, 0600); err != nil {
				t.Fatal(err)
			}
			git(t, work, "add", "change.bin")
			git(t, work, "commit", "-m", "push change")
			target := "refs/heads/main"
			if tt.create {
				target = "refs/heads/agents/a/first"
			}
			args := []string{"push", f.url, "HEAD:" + target}
			if tt.postBuffer != 0 {
				args = append([]string{"-c", fmt.Sprintf("http.postBuffer=%d", tt.postBuffer)}, args...)
			}
			// Discovery and probes may succeed, but they never authorize a later update.
			deniedToken := f.sign("github.com/org/repo:r", "github.com/org/repo#other/*:rw")
			if out, err := gitRun(work, deniedToken, args...); err == nil || f.pushes.Load() != 0 {
				t.Fatalf("unauthorized push reached upstream: %v\n%s", err, out)
			}
			denied := false
			for _, event := range f.events() {
				denied = denied || event.Outcome == "rejected" && event.Reason == "push denied for "+target
			}
			if !denied {
				t.Fatal("push failed before its ref authorization check")
			}
			out, err := gitRun(work, token, args...)
			if err != nil {
				for _, event := range f.events() {
					t.Logf("audit: %+v", event)
				}
				t.Fatalf("push failed: %v\n%s", err, out)
			}
			want := git(t, work, "rev-parse", "HEAD")
			got := git(t, f.root, "--git-dir="+filepath.Join(f.root, "org/repo.git"), "rev-parse", target)
			if got != want {
				t.Fatalf("remote %s = %s, want %s", target, got, want)
			}
			if f.pushes.Load() != 1 {
				t.Fatal("probe or denied update was forwarded upstream")
			}
			probes := 0
			for _, event := range f.events() {
				if event.Operation == "git-receive-pack-probe" && event.Outcome == "accepted" {
					probes++
				}
			}
			if (tt.packBytes > 0) != (probes > 0) {
				t.Fatalf("streaming scenario did not exercise expected probes: %d", probes)
			}
		})
	}
}

func TestPushProbeValidationAndAuthorization(t *testing.T) {
	f := newFixture(t)
	writer := f.sign("github.com/org/repo:rw")
	for _, tt := range []struct {
		name, token, repo, body string
		gzip, chunked           bool
		status                  int
	}{
		{name: "writer", token: writer, body: "0000", status: 200},
		{name: "branch scoped writer", token: f.token, body: "0000", status: 200},
		{name: "gzip", token: writer, body: "0000", gzip: true, status: 200},
		{name: "chunked", token: writer, body: "0000", chunked: true, status: 200},
		{name: "read only", token: f.sign("github.com/org/repo:r"), body: "0000", status: 403},
		{name: "write denied", token: f.sign("github.com/org/repo:rw", "!github.com/org/repo:w"), body: "0000", status: 403},
		{name: "no JWT", body: "0000", status: 401},
		{name: "wrong repository", token: f.sign("github.com/org/other:rw"), body: "0000", status: 403},
		{name: "missing repository is not created", token: f.sign("github.com/org/missing:rwc"), repo: "missing", body: "0000", status: 200},
		{name: "missing flush", token: writer, status: 400},
		{name: "extra flush", token: writer, body: "00000000", status: 400},
		{name: "trailing pack", token: writer, body: "0000PACKpayload", status: 400},
		{name: "gzip trailing pack", token: writer, body: "0000PACKpayload", gzip: true, status: 400},
		{name: "chunked trailing pack", token: writer, body: "0000PACKpayload", chunked: true, status: 400},
		{name: "trailing command", token: writer, body: "0000" + string(gitwire.Line(strings.Repeat("0", 40)+" "+strings.Repeat("1", 40)+" refs/heads/main\n")), status: 400},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader = strings.NewReader(tt.body)
			if tt.gzip {
				var compressed bytes.Buffer
				gz := gzip.NewWriter(&compressed)
				if _, err := gz.Write([]byte(tt.body)); err != nil {
					t.Fatal(err)
				}
				if err := gz.Close(); err != nil {
					t.Fatal(err)
				}
				body = &compressed
			}
			if tt.chunked {
				// Hide the length from net/http to exercise streamed request bodies.
				body = io.NopCloser(body)
			}
			repo := tt.repo
			if repo == "" {
				repo = "repo"
			}
			req, err := http.NewRequest("POST", f.proxy.URL+"/github/org/"+repo+".git/git-receive-pack", body)
			if err != nil {
				t.Fatal(err)
			}
			if tt.token != "" {
				req.SetBasicAuth("git", tt.token)
			}
			req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
			if tt.gzip {
				req.Header.Set("Content-Encoding", "gzip")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != tt.status {
				t.Fatalf("probe response = %d %q, %v; want %d", resp.StatusCode, data, err, tt.status)
			}
			if tt.status == 200 && (len(data) != 0 || resp.Header.Get("Content-Type") != "application/x-git-receive-pack-result") {
				t.Fatalf("invalid probe acknowledgement: %q, %v", data, resp.Header)
			}
			if f.pushes.Load() != 0 || f.apiCalls.Load() != 0 {
				t.Fatal("probe reached the upstream or repository provisioning API")
			}
		})
	}
}

func TestRealGitLargeFirstPushCreatesRepository(t *testing.T) {
	f := newFixture(t)
	data := make([]byte, 2<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.work, "large.bin"), data, 0600); err != nil {
		t.Fatal(err)
	}
	git(t, f.work, "add", "large.bin")
	git(t, f.work, "commit", "-m", "first large push")
	token := f.sign("github.com/org/large-first:rwc")
	url := f.proxy.URL + "/github/org/large-first.git"
	if out, err := gitRun(f.work, token, "push", url, "HEAD:refs/heads/main"); err != nil {
		t.Fatalf("first large push failed: %v\n%s", err, out)
	}
	want := git(t, f.work, "rev-parse", "HEAD")
	got := git(t, f.root, "--git-dir="+filepath.Join(f.root, "org/large-first.git"), "rev-parse", "refs/heads/main")
	if got != want || f.creates.Load() != 1 || f.pushes.Load() != 1 {
		t.Fatalf("first push did not create and populate exactly one repository: ref=%s creates=%d pushes=%d", got, f.creates.Load(), f.pushes.Load())
	}
}

func TestShallowPushPreservesUpstreamConnectivityRejection(t *testing.T) {
	f := newFixture(t)
	git(t, f.work, "commit", "--allow-empty", "-m", "more history")
	git(t, f.work, "push", filepath.Join(f.root, "org/repo.git"), "main")
	work := filepath.Join(f.root, "shallow")
	if out, err := gitRun(f.root, f.token, "clone", "--depth=1", "--branch=main", f.url, work); err != nil {
		t.Fatalf("shallow clone failed: %v\n%s", err, out)
	}
	git(t, work, "commit", "--allow-empty", "-m", "shallow child")
	f.makeRepo("org/empty")
	repo := filepath.Join(f.root, "org/empty.git")
	git(t, f.root, "--git-dir="+repo, "config", "receive.shallowUpdate", "false")
	token := f.sign("github.com/org/empty:rw")
	out, err := gitRun(work, token, "push", f.proxy.URL+"/github/org/empty.git", "HEAD:refs/heads/main")
	if err == nil || f.pushes.Load() != 1 || !strings.Contains(out, "shallow update not allowed") {
		t.Fatalf("expected upstream shallow-history refusal, got: %v\n%s", err, out)
	}
	if out := git(t, f.root, "--git-dir="+repo, "for-each-ref", "refs/heads/"); out != "" {
		t.Fatalf("ref was created despite missing history: %s", out)
	}
	for _, event := range f.events() {
		if event.Operation == "git-receive-pack" && event.Updates != nil && event.Outcome == "rejected" {
			return
		}
	}
	t.Fatal("upstream shallow-history refusal was not audited as a rejected push")
}
