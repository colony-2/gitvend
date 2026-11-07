package gateway

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/colony-2/gitvend/internal/config"
	"github.com/colony-2/gitvend/internal/forge"
)

// GV-001 through GV-004: both spellings share one canonical route.
func TestOptionalGitRoutes(t *testing.T) {
	g := &forge.GitHub{Config: config.Provider{Host: "github.com", AllowedOwners: []string{"org"}}}
	s := &Server{Providers: map[string]*forge.GitHub{"github": g}}
	for _, service := range []string{"git-upload-pack", "git-receive-pack"} {
		for _, discovery := range []bool{true, false} {
			method, endpoint, query := "POST", service, ""
			if discovery {
				method, endpoint, query = "GET", "info/refs", "?service="+service
			}
			for _, name := range []struct{ raw, canonical string }{
				{"Repo", "repo"}, {"Repo.git", "repo"},
				{"repo.name", "repo.name"}, {"repo.name.git", "repo.name"},
				{"repo.git.git", "repo.git"}, {"repo.GIT", "repo.git"},
			} {
				t.Run(fmt.Sprintf("%s/%s/%s", service, method, name.raw), func(t *testing.T) {
					r, err := s.route(httptest.NewRequest(method, "/github/ORG/"+name.raw+"/"+endpoint+query, nil))
					if err != nil {
						t.Fatal(err)
					}
					if r.provider != g || r.repo.Host != "github.com" || r.repo.Path != "org/"+name.canonical || !r.repo.FoldCase || r.endpoint != endpoint || r.service != service || r.discovery != discovery {
						t.Fatalf("unexpected route: %+v", r)
					}
				})
			}
		}
	}
}

// GV-006 through GV-008: additive syntax must not broaden other routes.
func TestOptionalGitRouteRejections(t *testing.T) {
	s := &Server{Providers: map[string]*forge.GitHub{"github": {Config: config.Provider{Host: "github.com", AllowedOwners: []string{"org"}}}}}
	for _, suffix := range []string{"", ".git"} {
		base := "/github/org/repo" + suffix
		for _, tc := range []struct{ method, path string }{
			{"GET", "/github/org%2Frepo" + suffix + "/info/refs?service=git-upload-pack"},
			{"GET", "/github/org/../repo" + suffix + "/info/refs?service=git-upload-pack"},
			{"GET", "/github/org/repo\\name" + suffix + "/info/refs?service=git-upload-pack"},
			{"GET", "/github//org/repo" + suffix + "/info/refs?service=git-upload-pack"},
			{"GET", "/unknown/org/repo" + suffix + "/info/refs?service=git-upload-pack"},
			{"GET", "/github/other/repo" + suffix + "/info/refs?service=git-upload-pack"},
			{"GET", "/github/org/" + suffix + "/info/refs?service=git-upload-pack"},
			{"GET", "/github/org/bad:name" + suffix + "/info/refs?service=git-upload-pack"},
			{"GET", base + "/extra/info/refs?service=git-upload-pack"},
			{"GET", base}, {"GET", base + "/objects/aa"},
			{"HEAD", base + "/info/refs?service=git-upload-pack"},
			{"POST", base + "/info/refs?service=git-upload-pack"},
			{"GET", base + "/info/refs"},
			{"GET", base + "/info/refs?service=git-upload-pack&x=1"},
			{"GET", base + "/info/refs?service=unknown"},
			{"GET", base + "/git-upload-pack"},
			{"POST", base + "/git-upload-pack?x=1"},
			{"POST", base + "/git-receive-pack?x=1"},
			{"POST", base + "/unknown"},
		} {
			t.Run(tc.method+tc.path, func(t *testing.T) {
				if r, err := s.route(httptest.NewRequest(tc.method, tc.path, nil)); err == nil {
					t.Fatalf("accepted %+v", r)
				}
			})
		}
	}
}
