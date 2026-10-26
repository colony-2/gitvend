package forge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/colony-2/gitvend/internal/config"
)

func ptr[T any](v T) *T { return &v }

func TestCreationDefaultsUseGitHubFieldsAndAPICredential(t *testing.T) {
	for _, visibility := range []string{"", "private", "public"} {
		t.Run("visibility="+visibility, func(t *testing.T) {
			t.Setenv("CREATION_GIT_TOKEN", "git-secret")
			t.Setenv("CREATION_API_TOKEN", "api-secret")
			defaults := config.CreationDefaults{Visibility: visibility, Description: ptr("cell repository"), Homepage: ptr("https://example.com"),
				HasIssues: ptr(false), HasProjects: ptr(false), HasWiki: ptr(true), HasPullRequests: ptr(false),
				AllowSquashMerge: ptr(true), AllowMergeCommit: ptr(false), AllowRebaseMerge: ptr(false), AllowAutoMerge: ptr(false), DeleteBranchOnMerge: ptr(true)}
			var posts, patches atomic.Int32
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer api-secret" {
					t.Error("wrong API token")
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				switch r.Method {
				case "POST":
					posts.Add(1)
					want := map[string]any{"name": "cell", "private": visibility != "public", "auto_init": false,
						"description": "cell repository", "homepage": "https://example.com", "has_issues": false, "has_projects": false, "has_wiki": true,
						"allow_squash_merge": true, "allow_merge_commit": false, "allow_rebase_merge": false, "allow_auto_merge": false, "delete_branch_on_merge": true}
					if r.URL.Path != "/orgs/org/repos" || !reflect.DeepEqual(body, want) {
						t.Errorf("POST %s: %#v", r.URL.Path, body)
					}
				case "PATCH":
					patches.Add(1)
					if r.URL.Path != "/repos/org/cell" || !reflect.DeepEqual(body, map[string]any{"has_pull_requests": false}) {
						t.Errorf("PATCH %s: %#v", r.URL.Path, body)
					}
				default:
					t.Errorf("unexpected method %s", r.Method)
				}
				json.NewEncoder(w).Encode(map[string]any{"full_name": "org/cell", "private": visibility != "public", "has_pull_requests": false})
			}))
			defer up.Close()
			g, err := New(config.Provider{APIBaseURL: up.URL, Credential: config.Credential{Kind: "token", SecretRef: "env:CREATION_GIT_TOKEN"}, APICredential: &config.Credential{Kind: "token", SecretRef: "env:CREATION_API_TOKEN"}, CreationDefaults: defaults})
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			repo, err := g.Create(t.Context(), "org", "cell")
			if err != nil {
				t.Fatal(err)
			}
			if err := g.FinishCreation(t.Context(), repo); err != nil {
				t.Fatal(err)
			}
			if posts.Load() != 1 || patches.Load() != 1 {
				t.Fatal("wrong provisioning calls")
			}
		})
	}
}

func TestOmittedCreationFeaturesUseGitHubDefaults(t *testing.T) {
	t.Setenv("CREATION_TOKEN", "secret")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if r.Method != "POST" || !reflect.DeepEqual(body, map[string]any{"name": "cell", "private": true, "auto_init": false}) {
			t.Errorf("unexpected request %s %#v", r.Method, body)
		}
		json.NewEncoder(w).Encode(map[string]any{"full_name": "org/cell", "private": true})
	}))
	defer up.Close()
	g, err := New(config.Provider{APIBaseURL: up.URL, Credential: config.Credential{Kind: "token", SecretRef: "env:CREATION_TOKEN"}})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	repo, err := g.Create(t.Context(), "org", "cell")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.FinishCreation(t.Context(), repo); err != nil {
		t.Fatal(err)
	}
}

func TestFinishCreationRequiresConfirmedSettings(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		body   string
		ok     bool
	}{
		{"confirmed", 200, `{"full_name":"org/cell","private":true,"has_pull_requests":false,"pull_request_creation_policy":"collaborators_only"}`, true},
		{"unauthorized", 403, `{}`, false},
		{"unavailable", 503, `{}`, false},
		{"ignored PR switch", 200, `{"full_name":"org/cell","private":true,"has_pull_requests":true,"pull_request_creation_policy":"collaborators_only"}`, false},
		{"ignored PR policy", 200, `{"full_name":"org/cell","private":true,"has_pull_requests":false,"pull_request_creation_policy":"all"}`, false},
		{"missing PR switch", 200, `{"full_name":"org/cell","private":true,"pull_request_creation_policy":"collaborators_only"}`, false},
		{"wrong repo", 200, `{"full_name":"other/cell","private":true,"has_pull_requests":false,"pull_request_creation_policy":"collaborators_only"}`, false},
		{"wrong visibility", 200, `{"full_name":"org/cell","private":false,"has_pull_requests":false,"pull_request_creation_policy":"collaborators_only"}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CREATION_TOKEN", "secret")
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				json.NewDecoder(r.Body).Decode(&body)
				if r.Method != "PATCH" || !reflect.DeepEqual(body, map[string]any{"has_pull_requests": false, "pull_request_creation_policy": "collaborators_only"}) {
					t.Error("wrong update")
				}
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.body))
			}))
			defer up.Close()
			g, err := New(config.Provider{APIBaseURL: up.URL, Credential: config.Credential{Kind: "token", SecretRef: "env:CREATION_TOKEN"}, CreationDefaults: config.CreationDefaults{HasPullRequests: ptr(false), PullRequestCreationPolicy: "collaborators_only"}})
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			err = g.FinishCreation(t.Context(), Repository{FullName: "org/cell", Private: true})
			if (err == nil) != tt.ok {
				t.Fatalf("ok=%v err=%v", tt.ok, err)
			}
		})
	}
}
