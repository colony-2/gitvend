package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/colony-2/gitvend/internal/auth"
	"github.com/colony-2/gitvend/internal/config"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestServeReloadAndShutdown(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	pubPath := filepath.Join(dir, "pub")
	os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600)
	secret := filepath.Join(dir, "token")
	os.WriteFile(secret, []byte("old"), 0600)
	var observed atomic.Value
	observed.Store("")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed.Store(r.Header.Get("Authorization"))
		http.Error(w, "absent", 404)
	}))
	defer up.Close()
	c := config.Defaults()
	c.Listen = "127.0.0.1:0"
	c.AllowHTTP = true
	c.AllowHTTPUpstream = true
	c.Keys = []config.SigningKey{{ID: "key", Issuer: "issuer", PublicKeyFile: pubPath, Owners: map[string][]string{"github.com": {"org"}}}}
	c.Providers = []config.Provider{{Alias: "gh", Host: "github.com", Kind: "github", GitBaseURL: up.URL, APIBaseURL: up.URL, AllowedOwners: []string{"org"}, Credential: config.Credential{Kind: "token", SecretRef: "file:" + secret}}}
	path := filepath.Join(dir, "config.json")
	save := func() {
		t.Helper()
		b, _ := json.Marshal(c)
		if e := writeAtomic(path, b); e != nil {
			t.Fatal(e)
		}
	}
	save()
	signals := make(chan os.Signal, 4)
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- serveWithSignals(path, signals, func(addr string) { ready <- addr }) }()
	var addr string
	select {
	case addr = <-ready:
	case e := <-done:
		t.Fatal(e)
	case <-time.After(5 * time.Second):
		t.Fatal("startup timeout")
	}
	defer func() {
		signals <- syscall.SIGTERM
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(15 * time.Second):
			t.Error("shutdown timeout")
		}
	}()
	token, e := auth.Sign(auth.NewClaims("issuer", "agent", "gitvend", time.Minute, auth.Grant{Version: 1, Permissions: []string{"github.com/org/*:r"}}), key, "key", 4096)
	if e != nil {
		t.Fatal(e)
	}
	request := func() int {
		t.Helper()
		r, _ := http.NewRequest("GET", "http://"+addr+"/gh/org/repo.git/info/refs?service=git-upload-pack", nil)
		r.SetBasicAuth("git", token)
		r.Header.Set("Git-Protocol", "version=2")
		resp, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := request(); code != 404 || observed.Load() != "Basic eC1hY2Nlc3MtdG9rZW46b2xk" {
		t.Fatal(code, observed.Load())
	}
	os.WriteFile(secret, []byte("new"), 0600)
	signals <- syscall.SIGHUP
	until := time.Now().Add(3 * time.Second)
	for observed.Load() != "Basic eC1hY2Nlc3MtdG9rZW46bmV3" && time.Now().Before(until) {
		request()
		time.Sleep(10 * time.Millisecond)
	}
	if observed.Load() != "Basic eC1hY2Nlc3MtdG9rZW46bmV3" {
		t.Fatal("secret reload failed")
	}
	// Invalid reload leaves the running snapshot intact.
	os.WriteFile(path, []byte(`{"unknown":true}`), 0600)
	signals <- syscall.SIGHUP
	time.Sleep(20 * time.Millisecond)
	if code := request(); code != 404 {
		t.Fatal("invalid reload replaced snapshot", code)
	}
	// A valid replacement key-set revokes the old signing key for new requests.
	c.Keys[0].ID = "new-key"
	save()
	signals <- syscall.SIGHUP
	until = time.Now().Add(3 * time.Second)
	code := 0
	for time.Now().Before(until) {
		code = request()
		if code == 401 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code != 401 {
		t.Fatal("key reload failed", code)
	}
	resp, e := http.Get("http://" + addr + "/healthz")
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("server created runtime files beyond config, public key and token: %v, %v", entries, err)
	}
}
func TestCommandFailures(t *testing.T) {
	for _, args := range [][]string{{}, {"unknown"}, {"audit"}, {"sign"}, {"sign", "-key", "missing", "-kid", "x", "-issuer", "i", "-subject", "s", "-permission", "github.com/*:r"}, {"explain", "-repo", "bad"}, {"explain", "-repo", "github.com/org/r", "-action", "bad", "-permission", "github.com/*:r"}, {"credential", "-host", "proxy.example", "get"}} {
		var b bytes.Buffer
		if e := run(args, strings.NewReader(""), &b, &b); e == nil {
			t.Fatal(fmt.Sprint(args))
		}
	}
}
