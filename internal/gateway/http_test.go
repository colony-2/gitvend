package gateway

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/colony-2/gitvend/internal/auth"
	"github.com/colony-2/gitvend/internal/gitwire"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGzipAndLimits(t *testing.T) {
	f := newFixture(t)
	body := append(gitwire.Line("command=ls-refs\n"), []byte("0001")...)
	body = append(body, gitwire.Line("ref-prefix refs/heads/\n")...)
	body = append(body, []byte("0000")...)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Write(body)
	gz.Close()
	req, _ := http.NewRequest("POST", f.url+"/git-upload-pack", &compressed)
	req.SetBasicAuth("git", f.token)
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Content-Encoding", "gzip")
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || bytes.Contains(b, []byte("secret")) {
		t.Fatal(resp.StatusCode, string(b))
	}
	bad := []byte("0004" + strings.Repeat("x", 2048))
	f.server.Config.MaxControlBytes = 1024
	resp = f.request("POST", "/github/org/repo.git/git-upload-pack", f.token, "version=2", bad)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode)
	}
	for _, enc := range []string{"br", "gzip"} {
		req, _ := http.NewRequest("POST", f.url+"/git-upload-pack", strings.NewReader("bad"))
		req.SetBasicAuth("git", f.token)
		req.Header.Set("Git-Protocol", "version=2")
		req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
		req.Header.Set("Content-Encoding", enc)
		resp, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 && resp.StatusCode != 415 {
			t.Fatal(resp.StatusCode)
		}
	}
}
func TestCanonicalRoutesAndTLS(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/github/org%2frepo.git/info/refs?service=git-upload-pack", "/github/org/../repo.git/info/refs?service=git-upload-pack", "/github//org/repo.git/info/refs?service=git-upload-pack", "/github/org/repo/info/refs?service=git-upload-pack"} {
		req := httptest.NewRequest("GET", path, nil)
		req.SetBasicAuth("git", f.token)
		req.Header.Set("Git-Protocol", "version=2")
		w := httptest.NewRecorder()
		f.server.ServeHTTP(w, req)
		if w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
	f.server.Config.AllowHTTP = false
	w := httptest.NewRecorder()
	f.server.ServeHTTP(w, httptest.NewRequest("GET", "/github/org/repo.git", nil))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}
func TestLimitedReaderAndCapture(t *testing.T) {
	r := &limitedReader{r: strings.NewReader("12345"), remaining: 4}
	if _, e := io.ReadAll(r); e == nil {
		t.Fatal("decoded byte limit")
	}
	r = &limitedReader{r: strings.NewReader("1234"), remaining: 4}
	if b, e := io.ReadAll(r); e != nil || string(b) != "1234" {
		t.Fatal(string(b), e)
	}
	w := &captureWriter{limit: 4}
	if n, e := w.Write([]byte("12345")); n != 5 || e != nil || !w.overflow || w.b.String() != "1234" {
		t.Fatal(w)
	}
}

func TestLargeJWTOverHTTP(t *testing.T) {
	f := newFixture(t)
	rules := []string{"github.com/org/repo#main:r"}
	for i := 0; i < 100; i++ {
		rules = append(rules, "github.com/org/"+strings.Repeat("x", 80)+fmt.Sprint(i)+"#agents/some-agent/*:rw")
	}
	claims := auth.NewClaims("test-issuer", "agent-a", "gitvend", 15*time.Minute, auth.Grant{Version: 1, Permissions: rules})
	token, e := auth.Sign(claims, f.key, "test", 32768)
	if e != nil || len(token) <= 4096 {
		t.Fatal(len(token), e)
	}
	resp := f.request("GET", "/github/org/repo.git/info/refs?service=git-upload-pack", token, "version=2", nil)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("default size budget", resp.StatusCode)
	}
	f.server.Config.MaxTokenBytes = 32768
	f.server.Verifier.MaxBytes = 32768
	resp = f.request("GET", "/github/org/repo.git/info/refs?service=git-upload-pack", token, "version=2", nil)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("configured large JWT", resp.StatusCode)
	}
	out, err := gitRun(f.root, token, "ls-remote", f.url)
	if err != nil || !strings.Contains(out, "refs/heads/main") || strings.Contains(out, "secret") {
		t.Fatal("real Git large JWT", err, out)
	}
}
