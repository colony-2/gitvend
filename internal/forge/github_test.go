package forge

import (
	"context"
	"errors"
	"github.com/colony-2/gitgate/internal/config"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIAndCredentials(t *testing.T) {
	t.Setenv("TEST_FORGE_GIT", "git-secret")
	t.Setenv("TEST_FORGE_API", "api-secret")
	var gotCreate bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("Authorization") != "Bearer api-secret" {
				t.Error("wrong API credential")
			}
			if r.Method == "POST" {
				b, _ := io.ReadAll(r.Body)
				if !strings.Contains(string(b), `"private":true`) || !strings.Contains(string(b), `"auto_init":false`) {
					t.Error(string(b))
				}
				gotCreate = true
			}
			io.WriteString(w, `{"id":7,"full_name":"org/repo","private":true}`)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "x-access-token" || p != "git-secret" {
			t.Error("wrong Git credential")
		}
		io.WriteString(w, "ok")
	}))
	defer up.Close()
	g, e := New(config.Provider{GitBaseURL: up.URL, APIBaseURL: up.URL + "/api", Credential: config.Credential{Kind: "token", SecretRef: "env:TEST_FORGE_GIT"}, APICredential: &config.Credential{Kind: "token", SecretRef: "env:TEST_FORGE_API"}})
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	r, e := g.Lookup(context.Background(), "org/repo")
	if e != nil || r.ID != 7 {
		t.Fatal(r, e)
	}
	if _, e = g.Create(context.Background(), "org", "repo"); e != nil || !gotCreate {
		t.Fatal(e)
	}
	resp, e := g.Git(context.Background(), "POST", "org/repo", "", "git-receive-pack", "", strings.NewReader("body"))
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
}
func TestAPIRejectsRedirectsAndBadMetadata(t *testing.T) {
	t.Setenv("TEST_FORGE_TOKEN", "secret")
	calls := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer other.Close()
	for _, tt := range []struct {
		status int
		body   string
	}{{302, ""}, {404, ""}, {200, `{"id":7,"full_name":"other/repo","private":true}`}, {201, `{"id":7,"full_name":"org/repo","private":false}`}, {200, `{broken`}} {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", other.URL)
			w.WriteHeader(tt.status)
			io.WriteString(w, tt.body)
		}))
		g, e := New(config.Provider{APIBaseURL: up.URL, Credential: config.Credential{Kind: "token", SecretRef: "env:TEST_FORGE_TOKEN"}})
		if e != nil {
			t.Fatal(e)
		}
		if tt.status == 201 {
			_, e = g.Create(context.Background(), "org", "repo")
		} else {
			_, e = g.Lookup(context.Background(), "org/repo")
		}
		if e == nil {
			t.Fatal("invalid response accepted")
		}
		if tt.status == 404 {
			var se *StatusError
			if !errors.As(e, &se) || se.Status != 404 {
				t.Fatal(e)
			}
		}
		g.Close()
		up.Close()
	}
	if calls != 0 {
		t.Fatal("redirect followed")
	}
}
