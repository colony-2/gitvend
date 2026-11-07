package gateway

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/colony-2/gitvend/internal/auth"
	"github.com/golang-jwt/jwt/v5"
)

// GV-009 through GV-012: endpoint normalization must preserve the policy boundary.
func TestOptionalGitAuthorizationParity(t *testing.T) {
	f := newFixture(t)
	claims := auth.NewClaims("test-issuer", "agent-a", "gitvend", 15*time.Minute, auth.Grant{Version: 1, Permissions: []string{"github.com/org/repo#main:r"}})
	claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(-2 * time.Hour))
	claims.NotBefore = claims.IssuedAt
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	expired, err := auth.Sign(claims, f.key, "test", 4096)
	if err != nil {
		t.Fatal(err)
	}
	noRead := f.sign("github.com/org/other#main:r")
	for _, suffix := range []string{".git", ""} {
		for _, tc := range []struct {
			name, token, protocol  string
			status                 int
			missingAuth, denyOwner bool
		}{
			{name: "missing-auth", status: 401, missingAuth: true},
			{name: "invalid", token: "bad", status: 401},
			{name: "expired", token: expired, status: 401},
			{name: "no-read", token: noRead, protocol: "version=2", status: 403},
			{name: "owner-ceiling", token: f.token, protocol: "version=2", status: 403, denyOwner: true},
			{name: "missing-protocol", token: f.token, status: 400},
			{name: "old-protocol", token: f.token, protocol: "version=1", status: 400},
		} {
			for _, method := range []string{"GET", "POST"} {
				t.Run(suffix+"/"+tc.name+"/"+method, func(t *testing.T) {
					path := "/github/org/repo" + suffix + "/git-upload-pack"
					if method == "GET" {
						path = "/github/org/repo" + suffix + "/info/refs?service=git-upload-pack"
					}
					req := httptest.NewRequest(method, path, nil)
					if !tc.missingAuth {
						req.SetBasicAuth("git", tc.token)
					}
					if tc.protocol != "" {
						req.Header.Set("Git-Protocol", tc.protocol)
					}
					key := f.server.Verifier.Keys["test"]
					if tc.denyOwner {
						restricted := key
						restricted.Owners = map[string][]string{"github.com": {"other"}}
						f.server.Verifier.Keys["test"] = restricted
						defer func() { f.server.Verifier.Keys["test"] = key }()
					}
					before := f.upstreamCalls.Load()
					w := httptest.NewRecorder()
					f.server.ServeHTTP(w, req)
					if w.Code != tc.status || f.upstreamCalls.Load() != before {
						t.Fatalf("status %d want %d; upstream calls %d -> %d: %s", w.Code, tc.status, before, f.upstreamCalls.Load(), w.Body.String())
					}
				})
			}
		}
		for _, method := range []string{"GET", "POST"} {
			path := "/github/org/repo" + suffix + "/git-receive-pack"
			if method == "GET" {
				path = "/github/org/repo" + suffix + "/info/refs?service=git-receive-pack"
			}
			req := httptest.NewRequest(method, path, nil)
			req.SetBasicAuth("git", f.token)
			req.Header.Set("Git-Protocol", "version=2")
			before := f.upstreamCalls.Load()
			w := httptest.NewRecorder()
			f.server.ServeHTTP(w, req)
			if w.Code != 400 || f.upstreamCalls.Load() != before {
				t.Fatalf("receive protocol: %d %s", w.Code, w.Body.String())
			}
		}
		denied := f.sign("github.com/org/repo#agents/a/*:rw", "!github.com/org/repo#agents/a/*:w", "github.com/org/new:c")
		before := f.upstreamCalls.Load()
		resp := f.request("GET", "/github/org/new"+suffix+"/info/refs?service=git-receive-pack", denied, "", nil)
		resp.Body.Close()
		if resp.StatusCode != 403 || f.upstreamCalls.Load() != before || f.creates.Load() != 0 {
			t.Fatalf("denied creation: %d", resp.StatusCode)
		}
	}
	f.server.Config.AllowHTTP = false
	for _, suffix := range []string{".git", ""} {
		w := httptest.NewRecorder()
		f.server.ServeHTTP(w, httptest.NewRequest("GET", "/github/org/repo"+suffix+"/info/refs?service=git-upload-pack", nil))
		if w.Code != 400 {
			t.Fatalf("TLS required: %d", w.Code)
		}
	}
}
