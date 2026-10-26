package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/colony-2/gitvend/internal/config"
)

func TestCreationDefaultsBeforeFirstPush(t *testing.T) {
	for _, tt := range []struct {
		name                                      string
		public, existing, lostResponse, failPatch bool
	}{
		{name: "private"},
		{name: "public", public: true},
		{name: "lost create response", lostResponse: true},
		{name: "settings failure", failPatch: true},
		{name: "existing repository", existing: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			// Configure the stub before publishing the server to handler goroutines.
			f.proxy.Close()
			name := "new-defaults"
			if tt.existing {
				name = "repo"
			}
			var posts, patches atomic.Int32
			// Keep the real Git backend while substituting the GitHub API.
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer upstream-secret" {
					t.Error("wrong upstream API credential")
				}
				switch r.Method {
				case "POST":
					posts.Add(1)
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body["private"] != !tt.public || body["has_issues"] != false || body["auto_init"] != false {
						t.Errorf("wrong creation defaults: %v", body)
					}
					f.makeRepo("org/" + name)
					if tt.lostResponse {
						http.Error(w, "response lost", 500)
						return
					}
				case "PATCH":
					patches.Add(1)
					if f.pushes.Load() != 0 {
						t.Error("push forwarded before settings")
					}
					if tt.failPatch {
						http.Error(w, "settings failed", 503)
						return
					}
				case "GET":
					f.mu.Lock()
					exists := f.repos["org/"+name] != 0
					f.mu.Unlock()
					if !exists {
						http.NotFound(w, r)
						return
					}
				default:
					t.Errorf("unexpected API request: %s", r.Method)
				}
				json.NewEncoder(w).Encode(map[string]any{"full_name": "org/" + name, "private": !tt.public, "has_pull_requests": false})
			}))
			defer api.Close()
			provider := f.server.Providers["github"]
			provider.Config.APIBaseURL = api.URL
			off := false
			provider.Config.CreationDefaults = config.CreationDefaults{HasIssues: &off, HasPullRequests: &off}
			if tt.public {
				provider.Config.CreationDefaults.Visibility = "public"
			}
			f.proxy = httptest.NewServer(f.server)
			token := f.sign("github.com/org/" + name + ":rwc")
			out, err := gitRun(f.work, token, "push", f.proxy.URL+"/github/org/"+name+".git", "HEAD:refs/heads/agents/a/created")
			if tt.failPatch {
				if err == nil || f.pushes.Load() != 0 || patches.Load() != 1 {
					t.Fatalf("incomplete provisioning forwarded push: %v %s", err, out)
				}
				found := false
				for _, event := range f.events() {
					if event.Operation == "repo.create" && event.Outcome == "configuration_failed" {
						found = true
					}
				}
				if !found {
					t.Fatal("missing incomplete configuration audit event")
				}
			} else {
				if err != nil || f.pushes.Load() != 1 {
					t.Fatalf("push failed: %v %s", err, out)
				}
				want := int32(1)
				if tt.existing {
					want = 0
				}
				if posts.Load() != want || patches.Load() != want {
					t.Fatalf("unexpected creation/settings calls: %d %d", posts.Load(), patches.Load())
				}
			}
		})
	}
}

func TestPublicCreationRejectsUnexpectedPrivateRepository(t *testing.T) {
	f := newFixture(t)
	f.proxy.Close()
	f.server.Providers["github"].Config.CreationDefaults.Visibility = "public"
	// The stub accepts the request but returns an existing private repository
	// during reconciliation. A public profile must not silently accept it.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && f.created.Load() == 0 {
			http.NotFound(w, r)
			return
		}
		if r.Method == "POST" {
			f.created.Add(1)
		}
		json.NewEncoder(w).Encode(map[string]any{"full_name": "org/new", "private": true})
	}))
	defer api.Close()
	f.server.Providers["github"].Config.APIBaseURL = api.URL
	f.proxy = httptest.NewServer(f.server)
	token := f.sign("github.com/org/new:rwc")
	resp := f.request("GET", "/github/org/new.git/info/refs?service=git-receive-pack", token, "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Fatal("visibility mismatch accepted", resp.StatusCode)
	}
	for _, event := range f.events() {
		if event.Operation == "repo.create" && event.Outcome == "rejected" && strings.Contains(event.Reason, "visibility") {
			return
		}
	}
	t.Fatal("missing visibility audit event")
}
