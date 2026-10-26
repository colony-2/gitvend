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
	FullName                  string `json:"full_name"`
	Private                   bool   `json:"private"`
	HasPullRequests           *bool  `json:"has_pull_requests"`
	PullRequestCreationPolicy string `json:"pull_request_creation_policy"`
}
type StatusError struct{ Status int }

func (e *StatusError) Error() string { return fmt.Sprintf("forge API status %d", e.Status) }

type GitHub struct {
	Config             config.Provider
	GitToken, APIToken string
	Client             *http.Client
}

func New(p config.Provider) (*GitHub, error) {
	if err := p.CreationDefaults.Validate(); err != nil {
		return nil, err
	}
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
	var response struct {
		Repository
		Private *bool `json:"private"`
	}
	if e = json.Unmarshal(b, &response); e != nil || response.FullName == "" || response.Private == nil {
		return Repository{}, fmt.Errorf("invalid forge repository metadata")
	}
	response.Repository.Private = *response.Private
	return response.Repository, nil
}
func (g *GitHub) Lookup(ctx context.Context, path string) (Repository, error) {
	r, e := g.call(ctx, "GET", "/repos/"+path, nil)
	if e == nil && !strings.EqualFold(r.FullName, path) {
		return r, fmt.Errorf("forge repository identity mismatch")
	}
	return r, e
}
func (g *GitHub) Create(ctx context.Context, owner, name string) (Repository, error) {
	// Use GitHub's native field names. PR availability is update-only and is
	// applied by FinishCreation after creation (or reconciliation) is confirmed.
	b, err := json.Marshal(g.Config.CreationDefaults)
	if err != nil {
		return Repository{}, err
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		return Repository{}, err
	}
	delete(body, "visibility")
	delete(body, "has_pull_requests")
	delete(body, "pull_request_creation_policy")
	body["name"], body["private"], body["auto_init"] = name, g.Config.CreationDefaults.Private(), false
	r, e := g.call(ctx, "POST", "/orgs/"+owner+"/repos", body)
	if e == nil && (r.Private != g.Config.CreationDefaults.Private() || !strings.EqualFold(r.FullName, owner+"/"+name)) {
		return r, fmt.Errorf("created repository does not match creation profile")
	}
	return r, e
}

// FinishCreation applies update-only settings to a confirmed new repository.
// It must not be called for repositories that existed before a create attempt.
func (g *GitHub) FinishCreation(ctx context.Context, repo Repository) error {
	c := g.Config.CreationDefaults
	if repo.Private != c.Private() {
		return fmt.Errorf("repository visibility does not match creation profile")
	}
	body := map[string]any{}
	if c.HasPullRequests != nil {
		body["has_pull_requests"] = *c.HasPullRequests
	}
	if c.PullRequestCreationPolicy != "" {
		body["pull_request_creation_policy"] = c.PullRequestCreationPolicy
	}
	if len(body) == 0 {
		return nil
	}
	r, err := g.call(ctx, "PATCH", "/repos/"+repo.FullName, body)
	if err != nil {
		return err
	}
	if !strings.EqualFold(r.FullName, repo.FullName) || r.Private != c.Private() ||
		c.HasPullRequests != nil && (r.HasPullRequests == nil || *r.HasPullRequests != *c.HasPullRequests) ||
		c.PullRequestCreationPolicy != "" && r.PullRequestCreationPolicy != c.PullRequestCreationPolicy {
		return fmt.Errorf("repository does not match requested pull request settings")
	}
	return nil
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
