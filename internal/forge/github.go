// Package forge separates Git transport credentials from repository API operations.
package forge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/colony-2/gitvend/internal/config"
	"io"
	"net/http"
	"strings"
	"time"
)

type Repository struct {
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}
type StatusError struct{ Status int }

func (e *StatusError) Error() string { return fmt.Sprintf("forge API status %d", e.Status) }

type GitHub struct {
	Config             config.Provider
	GitToken, APIToken string
	Client             *http.Client
}

func New(p config.Provider) (*GitHub, error) {
	token, e := config.Secret(p.Credential)
	if e != nil {
		return nil, e
	}
	api := token
	if p.APICredential != nil {
		api, e = config.Secret(*p.APICredential)
		if e != nil {
			return nil, e
		}
	}
	tr := &http.Transport{MaxIdleConns: 128, MaxIdleConnsPerHost: 32, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 60 * time.Second, ExpectContinueTimeout: time.Second, DisableCompression: true}
	return &GitHub{Config: p, GitToken: token, APIToken: api, Client: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (g *GitHub) Close() { g.Client.CloseIdleConnections() }
func (g *GitHub) call(ctx context.Context, method, path string, body any) (Repository, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var reader io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return Repository{}, e
		}
		reader = bytes.NewReader(b)
	}
	r, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.Config.APIBaseURL, "/")+path, reader)
	if e != nil {
		return Repository{}, fmt.Errorf("invalid forge request")
	}
	r.Header.Set("Authorization", "Bearer "+g.APIToken)
	r.Header.Set("Accept", "application/vnd.github+json")
	r.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	r.Header.Set("User-Agent", "gitvend")
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, e := g.Client.Do(r)
	if e != nil {
		return Repository{}, fmt.Errorf("forge API transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Repository{}, &StatusError{resp.StatusCode}
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		return Repository{}, fmt.Errorf("invalid forge response")
	}
	var repo Repository
	if e = json.Unmarshal(b, &repo); e != nil || repo.FullName == "" {
		return repo, fmt.Errorf("invalid forge repository metadata")
	}
	return repo, nil
}
func (g *GitHub) Lookup(ctx context.Context, path string) (Repository, error) {
	r, e := g.call(ctx, "GET", "/repos/"+path, nil)
	if e == nil && !strings.EqualFold(r.FullName, path) {
		return r, fmt.Errorf("forge repository identity mismatch")
	}
	return r, e
}
func (g *GitHub) Create(ctx context.Context, owner, name string) (Repository, error) {
	r, e := g.call(ctx, "POST", "/orgs/"+owner+"/repos", map[string]any{"name": name, "private": true, "auto_init": false})
	if e == nil && (!r.Private || !strings.EqualFold(r.FullName, owner+"/"+name)) {
		return r, fmt.Errorf("created repository does not match private profile")
	}
	return r, e
}
func (g *GitHub) Git(ctx context.Context, method, path, query, service, protocol string, body io.Reader) (*http.Response, error) {
	r, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.Config.GitBaseURL, "/")+"/"+path+".git/"+service, body)
	if e != nil {
		return nil, fmt.Errorf("invalid upstream request")
	}
	r.URL.RawQuery = query
	r.SetBasicAuth("x-access-token", g.GitToken)
	r.Header.Set("User-Agent", "gitvend")
	r.Header.Set("Accept-Encoding", "identity")
	if protocol != "" {
		r.Header.Set("Git-Protocol", protocol)
	}
	if method == "POST" {
		r.Header.Set("Content-Type", "application/x-"+service+"-request")
		r.Header.Set("Accept", "application/x-"+service+"-result")
	}
	resp, e := g.Client.Do(r)
	if e != nil {
		return nil, fmt.Errorf("upstream Git transport failed")
	}
	return resp, nil
}
