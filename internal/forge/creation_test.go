package forge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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
				HasIssues: ptr(false), HasProjects: ptr(false), HasWiki: ptr(true),
				AllowSquashMerge: ptr(true), AllowMergeCommit: ptr(false), AllowRebaseMerge: ptr(false), AllowAutoMerge: ptr(false), DeleteBranchOnMerge: ptr(true)}
			var posts atomic.Int32
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
				default:
					t.Errorf("unexpected method %s", r.Method)
				}
				json.NewEncoder(w).Encode(map[string]any{"full_name": "org/cell", "private": visibility != "public"})
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
			if posts.Load() != 1 {
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
		name      string
		status    int
		body      string
		ok        bool
		wantError string
	}{
		{"confirmed", 200, `{"full_name":"org/cell","private":true,"pull_request_creation_policy":"collaborators_only"}`, true, ""},
		{"unauthorized", 403, `{"message":"upstream-secret"}`, false, "update pull request settings: forge API status 403"},
		{"unavailable", 503, `{}`, false, "update pull request settings: forge API status 503"},
		{"ignored PR policy", 200, `{"full_name":"org/cell","private":true,"pull_request_creation_policy":"all"}`, false, "pull_request_creation_policy does not match requested value"},
		{"missing PR policy", 200, `{"full_name":"org/cell","private":true}`, false, "forge response omitted pull_request_creation_policy"},
		{"wrong repo", 200, `{"full_name":"other/cell","private":true,"pull_request_creation_policy":"collaborators_only"}`, false, "forge repository identity mismatch after settings update"},
		{"wrong visibility", 200, `{"full_name":"org/cell","private":false,"pull_request_creation_policy":"collaborators_only"}`, false, "repository visibility does not match creation profile after settings update"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CREATION_TOKEN", "secret")
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				json.NewDecoder(r.Body).Decode(&body)
				if r.Method != "PATCH" || !reflect.DeepEqual(body, map[string]any{"pull_request_creation_policy": "collaborators_only"}) {
					t.Error("wrong update")
				}
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.body))
			}))
			defer up.Close()
			g, err := New(config.Provider{APIBaseURL: up.URL, Credential: config.Credential{Kind: "token", SecretRef: "env:CREATION_TOKEN"}, CreationDefaults: config.CreationDefaults{PullRequestCreationPolicy: "collaborators_only"}})
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			err = g.FinishCreation(t.Context(), Repository{FullName: "org/cell", Private: true})
			if (err == nil) != tt.ok {
				t.Fatalf("ok=%v err=%v", tt.ok, err)
			}
			if err != nil && (!strings.Contains(err.Error(), tt.wantError) || strings.Contains(err.Error(), "upstream-secret")) {
				t.Fatalf("want sanitized diagnostic %q, got %v", tt.wantError, err)
			}
		})
	}
}
