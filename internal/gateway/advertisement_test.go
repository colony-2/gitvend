package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/colony-2/gitvend/internal/gitwire"
)

func TestRealGitCloneWithUploadPackServiceHeader(t *testing.T) {
	for _, header := range []string{"# service=git-upload-pack\n", "# service=git-upload-pack"} {
		t.Run(header, func(t *testing.T) {
			f := newFixture(t)
			f.proxy.Close()
			var advertisements atomic.Int32
			// Keep the real Git backend and add the service preamble reported by
			// GitHub. Local git-http-backend emits bare v2 advertisements.
			backend := f.upstream.Config.Handler
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Query().Get("service") != "git-upload-pack" {
					backend.ServeHTTP(w, r)
					return
				}
				recorded := httptest.NewRecorder()
				backend.ServeHTTP(recorded, r)
				if recorded.Code != http.StatusOK || !bytes.HasPrefix(recorded.Body.Bytes(), gitwire.Line("version 2\n")) {
					t.Error("test backend did not return a v2 advertisement")
					http.Error(w, "invalid test advertisement", http.StatusInternalServerError)
					return
				}
				for name, values := range recorded.Header() {
					w.Header()[name] = values
				}
				w.Header().Del("Content-Length")
				advertisements.Add(1)
				w.Write(gitwire.Line(header))
				w.Write([]byte("0000"))
				w.Write(recorded.Body.Bytes())
			}))
			defer upstream.Close()
			f.server.Providers["github"].Config.GitBaseURL = upstream.URL
			f.proxy = httptest.NewServer(f.server)
			url := f.proxy.URL + "/github/org/repo.git"
			out, err := gitRun(f.root, f.token, "ls-remote", url)
			if err != nil || !strings.Contains(out, "refs/heads/main") || strings.Contains(out, "refs/heads/secret") {
				t.Fatalf("discovery failed or exposed a hidden ref: %v\n%s", err, out)
			}
			clone := filepath.Join(f.root, "clone-with-service-header")
			if out, err := gitRun(f.root, f.token, "clone", "--branch", "main", url, clone); err != nil {
				t.Fatalf("clone failed: %v\n%s", err, out)
			}
			if contents, err := os.ReadFile(filepath.Join(clone, "readme")); err != nil || string(contents) != "base" {
				t.Fatalf("clone did not transfer repository contents: %q, %v", contents, err)
			}
			if out := git(t, clone, "branch", "-r"); strings.Contains(out, "secret") {
				t.Fatalf("clone exposed a hidden branch: %s", out)
			}
			if out, err := gitRun(clone, f.token, "fetch", "origin"); err != nil {
				t.Fatalf("fetch failed: %v\n%s", err, out)
			}
			if advertisements.Load() < 3 {
				t.Fatal("discovery, clone and fetch did not exercise service headers")
			}
			for _, event := range f.events() {
				// Git first makes an unauthenticated request to obtain the Basic
				// auth challenge. Only authenticated upload-pack failures matter.
				if event.Operation == "git-upload-pack" && event.Outcome == "rejected" {
					t.Fatalf("unexpected gateway rejection: %+v", event)
				}
			}
		})
	}
}
