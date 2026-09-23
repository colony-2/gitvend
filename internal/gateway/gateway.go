package gateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitgate/internal/auth"
	"gitgate/internal/config"
	"gitgate/internal/forge"
	"gitgate/internal/gitwire"
	"gitgate/internal/policy"
	"gitgate/internal/state"
)

type Server struct {
	Config    config.Config
	Store     *state.Store
	Verifier  *auth.Verifier
	Providers map[string]*forge.GitHub
	slots     chan struct{}
	mu        sync.Mutex
	locks     map[string]*lock
}
type lock struct {
	sem   chan struct{}
	users int
}

func New(c config.Config, st *state.Store) (*Server, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	v, e := c.Verifier()
	if e != nil {
		return nil, e
	}
	s := &Server{Config: c, Store: st, Verifier: v, Providers: map[string]*forge.GitHub{}, slots: make(chan struct{}, c.MaxConcurrent), locks: map[string]*lock{}}
	for _, p := range c.Providers {
		g, e := forge.New(p)
		if e != nil {
			s.Close()
			return nil, e
		}
		s.Providers[p.Alias] = g
	}
	return s, nil
}
func (s *Server) Close() {
	for _, g := range s.Providers {
		g.Close()
	}
}
func (s *Server) acquire(ctx context.Context, key string) (func(), error) {
	s.mu.Lock()
	l := s.locks[key]
	if l == nil {
		l = &lock{sem: make(chan struct{}, 1)}
		s.locks[key] = l
	}
	l.users++
	s.mu.Unlock()
	drop := func() {
		s.mu.Lock()
		l.users--
		if l.users == 0 {
			delete(s.locks, key)
		}
		s.mu.Unlock()
	}
	select {
	case l.sem <- struct{}{}:
		return func() { <-l.sem; drop() }, nil
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	}
}
func requestID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}

type route struct {
	provider          *forge.GitHub
	repo              policy.Repository
	endpoint, service string
	discovery         bool
}

func (s *Server) route(r *http.Request) (route, error) {
	out := route{}
	path := r.URL.EscapedPath()
	if strings.ContainsAny(path, "%\\") || strings.Contains(path, "//") {
		return out, fmt.Errorf("noncanonical path")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 4 && len(parts) != 5 {
		return out, fmt.Errorf("unknown Git endpoint")
	}
	g := s.Providers[parts[0]]
	if g == nil {
		return out, fmt.Errorf("unknown provider")
	}
	owner, name := parts[1], parts[2]
	if !strings.HasSuffix(name, ".git") {
		return out, fmt.Errorf("repository URL must end in .git")
	}
	name = strings.TrimSuffix(name, ".git")
	if !config.ValidName(owner) || !config.ValidName(name) {
		return out, fmt.Errorf("invalid repository path")
	}
	owner = strings.ToLower(owner)
	name = strings.ToLower(name)
	allowed := false
	for _, o := range g.Config.AllowedOwners {
		if owner == o {
			allowed = true
		}
	}
	if !allowed {
		return out, fmt.Errorf("owner not configured")
	}
	out.provider = g
	out.repo = policy.Repository{Host: g.Config.Host, Path: owner + "/" + name, FoldCase: true}
	if len(parts) == 5 && parts[3] == "info" && parts[4] == "refs" && r.Method == "GET" {
		out.discovery = true
		out.endpoint = "info/refs"
		switch r.URL.RawQuery {
		case "service=git-upload-pack":
			out.service = "git-upload-pack"
		case "service=git-receive-pack":
			out.service = "git-receive-pack"
		default:
			return out, fmt.Errorf("invalid discovery query")
		}
	} else if len(parts) == 4 && r.Method == "POST" && (parts[3] == "git-upload-pack" || parts[3] == "git-receive-pack") && r.URL.RawQuery == "" {
		out.endpoint = parts[3]
		out.service = parts[3]
	} else {
		return out, fmt.Errorf("unsupported endpoint or method")
	}
	return out, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		w.WriteHeader(200)
		io.WriteString(w, "ok\n")
		return
	}
	if r.TLS == nil && !s.Config.AllowHTTP {
		http.Error(w, "HTTPS required", 400)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "gateway busy", 429)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.Config.RequestTimeoutSeconds)*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	deadline, _ := ctx.Deadline()
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)
	event := state.Event{ID: requestID(), Time: time.Now().UTC(), Operation: "request", Outcome: "rejected", ConfigRevision: s.Config.Revision}
	w.Header().Set("X-Request-ID", event.ID)
	audited := false
	defer func() {
		if audited {
			if e := s.Store.Audit(event); e != nil {
				slog.Error("audit finalization failed", "request_id", event.ID)
			}
		}
	}()
	fail := func(code int, reason string) {
		event.Outcome = "rejected"
		event.Reason = reason
		if !audited {
			if e := s.Store.Audit(event); e != nil {
				http.Error(w, "audit storage unavailable", 503)
				return
			}
			audited = true
		}
		http.Error(w, reason, code)
	}
	if len(r.Header.Values("Authorization")) != 1 || len(r.Header.Get("Authorization")) > 2*s.Config.MaxTokenBytes+128 {
		w.Header().Set("WWW-Authenticate", `Basic realm="gitgate"`)
		fail(401, "valid gateway JWT required")
		return
	}
	_, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="gitgate"`)
		fail(401, "HTTP Basic with JWT password required")
		return
	}
	id, e := s.Verifier.Verify(password)
	if e != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="gitgate"`)
		fail(401, "invalid or expired gateway JWT")
		return
	}
	event.Issuer = id.Claims.Issuer
	event.Subject = id.Claims.Subject
	event.TokenID = id.Claims.ID
	event.PolicyRevision = id.Claims.PolicyRevision
	rt, e := s.route(r)
	if e != nil {
		fail(404, "unsupported Git route")
		return
	}
	event.Repository = rt.repo.Host + "/" + rt.repo.Path
	event.Operation = rt.service
	if !id.Access(rt.repo) || !id.Policy.Read(rt.repo) {
		fail(403, "repository access denied")
		return
	}
	protocol := ""
	if rt.service == "git-upload-pack" {
		if len(r.Header.Values("Git-Protocol")) != 1 || r.Header.Get("Git-Protocol") != "version=2" {
			fail(400, "Git protocol v2 required; set protocol.version=2")
			return
		}
		protocol = "version=2"
	} else if v := r.Header.Get("Git-Protocol"); v != "" && v != "version=0" {
		fail(400, "receive-pack requires the standard v0 exchange")
		return
	}
	if rt.discovery && r.ContentLength != 0 {
		fail(400, "discovery must not contain a body")
		return
	}
	var requestBody io.Reader
	var push gitwire.Push
	var fetch gitwire.Fetch
	if !rt.discovery {
		ct, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || len(params) > 0 || ct != "application/x-"+rt.service+"-request" {
			fail(415, "invalid Git content type")
			return
		}
		raw := http.MaxBytesReader(w, r.Body, s.Config.MaxPackBytes)
		defer raw.Close()
		var body io.Reader = raw
		switch r.Header.Get("Content-Encoding") {
		case "", "identity":
		case "gzip":
			gz, err := gzip.NewReader(raw)
			if err != nil {
				fail(400, "invalid gzip body")
				return
			}
			defer gz.Close()
			body = gz
		default:
			fail(415, "unsupported content encoding")
			return
		}
		body = &limitedReader{r: body, remaining: s.Config.MaxPackBytes}
		if rt.service == "git-receive-pack" {
			push, e = gitwire.ParsePush(body, int(s.Config.MaxControlBytes), 1024)
			if e != nil {
				fail(400, "invalid or unsupported push: "+e.Error())
				return
			}
			event.Updates = push.Updates
			for _, u := range push.Updates {
				if !id.Policy.Write(rt.repo, u.Ref, u.Action) {
					fail(403, "push denied for "+u.Ref)
					return
				}
			}
			requestBody = io.MultiReader(bytes.NewReader(push.Prefix), body)
		} else {
			b, err := readBounded(body, s.Config.MaxControlBytes)
			if err != nil {
				fail(400, "fetch request too large or incomplete")
				return
			}
			fetch, e = gitwire.ParseFetch(b)
			if e != nil {
				fail(400, "invalid or unsupported fetch: "+e.Error())
				return
			}
			requestBody = bytes.NewReader(b)
		}
	} else if rt.service == "git-receive-pack" {
		allowed, err := id.Policy.CanWrite(rt.repo, false)
		if err != nil {
			fail(403, "grant too complex for discovery")
			return
		}
		if !allowed {
			fail(403, "no discoverable writable refs")
			return
		}
	}
	event.Outcome = "admitted"
	if e = s.Store.Audit(event); e != nil {
		http.Error(w, "audit storage unavailable", 503)
		return
	}
	audited = true
	canCreate := rt.discovery && rt.service == "git-receive-pack"
	if e = s.ensure(ctx, rt, id, canCreate, event.ID); e != nil {
		var he *httpError
		if errors.As(e, &he) {
			fail(he.code, he.msg)
		} else {
			fail(502, "repository verification failed")
		}
		return
	}
	if !time.Now().Before(id.Expiry) {
		fail(401, "gateway JWT expired before upstream request")
		return
	}
	resp, e := rt.provider.Git(ctx, r.Method, rt.repo.Path, r.URL.RawQuery, rt.endpoint, protocol, requestBody)
	if e != nil {
		event.Outcome = "unknown"
		event.Reason = "upstream connection failed"
		http.Error(w, "upstream connection failed; fetch before retrying a push", 502)
		return
	}
	defer resp.Body.Close()
	event.UpstreamRequestID = resp.Header.Get("X-GitHub-Request-Id")
	if resp.StatusCode != 200 {
		status := 502
		if resp.StatusCode == 404 {
			status = 404
		}
		fail(status, "upstream Git request refused")
		return
	}
	ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || ct != gitwire.ExpectedContentType(rt.service, rt.discovery) || resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity" {
		fail(502, "invalid upstream Git response")
		return
	}
	visible := func(ref string) bool { return id.Policy.Discover(rt.repo, ref) }
	if rt.discovery || fetch.Command == "ls-refs" {
		b, err := readBounded(resp.Body, s.Config.MaxControlBytes)
		if err != nil {
			fail(502, "upstream control response too large or incomplete")
			return
		}
		var out []byte
		switch {
		case rt.discovery && rt.service == "git-upload-pack":
			out, e = gitwire.FilterCapabilities(b)
		case rt.discovery:
			out, e = gitwire.FilterPushAdvertisement(b, visible)
		default:
			out, e = gitwire.FilterRefs(b, fetch.Prefixes, visible)
		}
		if e != nil {
			fail(502, "invalid or unsupported upstream control response")
			return
		}
		w.Header().Set("Content-Type", ct)
		if _, e = w.Write(out); e != nil {
			event.Outcome = "unknown"
			event.Reason = "client disconnected"
		} else {
			event.Outcome = "accepted"
		}
		return
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(200)
	if rt.service == "git-receive-pack" {
		capture := &captureWriter{limit: int(s.Config.MaxControlBytes)}
		_, err = io.Copy(w, io.TeeReader(resp.Body, capture))
		if err != nil || capture.overflow {
			event.Outcome = "unknown"
			event.Reason = "incomplete push result"
		} else {
			status := gitwire.Status(capture.b.Bytes(), push.Updates)
			event.Outcome = status.Outcome
			event.Details = status
		}
	} else {
		_, err = io.Copy(w, resp.Body)
		if err != nil {
			event.Outcome = "unknown"
			event.Reason = "interrupted fetch"
		} else {
			event.Outcome = "accepted"
		}
	}
}
func readBounded(r io.Reader, n int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, n+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > n {
		return nil, fmt.Errorf("size limit exceeded")
	}
	return b, nil
}

type limitedReader struct {
	r         io.Reader
	remaining int64
}

func (r *limitedReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		var one [1]byte
		n, e := r.r.Read(one[:])
		if n > 0 {
			return 0, fmt.Errorf("decoded body exceeds limit")
		}
		return 0, e
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, e := r.r.Read(p)
	r.remaining -= int64(n)
	return n, e
}

type captureWriter struct {
	b        bytes.Buffer
	limit    int
	overflow bool
}

func (c *captureWriter) Write(p []byte) (int, error) {
	n := len(p)
	remaining := c.limit - c.b.Len()
	if len(p) > remaining {
		c.overflow = true
		p = p[:remaining]
	}
	c.b.Write(p)
	return n, nil
}

type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }
func (s *Server) ensure(ctx context.Context, rt route, id *auth.Identity, create bool, requestID string) error {
	key := rt.repo.Host + "/" + rt.repo.Path
	bind := func(repo forge.Repository) error {
		if want, ok := id.Claims.Grant.Bindings[key]; ok && want != strconv.FormatInt(repo.ID, 10) {
			return &httpError{403, "repository binding mismatch"}
		}
		_, e := s.Store.Bind(key, repo.ID)
		if e != nil {
			return &httpError{409, "repository identity changed or state unavailable"}
		}
		return nil
	}
	repo, e := rt.provider.Lookup(ctx, rt.repo.Path)
	if e == nil {
		return bind(repo)
	}
	var status *forge.StatusError
	if !errors.As(e, &status) || status.Status != 404 {
		return &httpError{502, "forge repository lookup failed"}
	}
	if !create || !rt.provider.Config.AllowCreation || !id.Policy.Allows(rt.repo, "", "repo.create") {
		return &httpError{404, "repository unavailable"}
	}
	eligible, e := id.Policy.CanWrite(rt.repo, true)
	if e != nil || !eligible {
		return &httpError{403, "creation requires a discoverable writable branch"}
	}
	if _, pinned := id.Claims.Grant.Bindings[key]; pinned {
		return &httpError{409, "bound repository unavailable"}
	}
	release, e := s.acquire(ctx, key)
	if e != nil {
		return &httpError{503, "provisioning wait cancelled"}
	}
	defer release()
	if !time.Now().Before(id.Expiry) {
		return &httpError{401, "JWT expired while waiting to provision"}
	}
	repo, e = rt.provider.Lookup(ctx, rt.repo.Path)
	if e == nil {
		return bind(repo)
	}
	if !errors.As(e, &status) || status.Status != 404 {
		return &httpError{502, "forge repository lookup failed"}
	}
	owner, name, _ := strings.Cut(rt.repo.Path, "/")
	if e = s.Store.Reserve(key, id.Claims.Issuer, id.Claims.Subject, rt.repo.Host+"/"+owner, s.Config.CreatesPerSubjectPerDay, s.Config.CreatesPerOwnerPerDay); e != nil {
		return &httpError{409, "creation quota exhausted or enrolled repository missing"}
	}
	event := state.Event{ID: requestID + "-create", Time: time.Now().UTC(), Issuer: id.Claims.Issuer, Subject: id.Claims.Subject, TokenID: id.Claims.ID, Repository: key, Operation: "repo.create", Outcome: "admitted", PolicyRevision: id.Claims.PolicyRevision, ConfigRevision: s.Config.Revision}
	if e = s.Store.Audit(event); e != nil {
		return &httpError{503, "audit storage unavailable"}
	}
	repo, e = rt.provider.Create(ctx, owner, name)
	created := e == nil
	if e != nil {
		repo, e = rt.provider.Lookup(ctx, rt.repo.Path)
	}
	if e != nil || !repo.Private {
		event.Outcome = "unknown"
		event.Reason = "creation requires reconciliation"
		_ = s.Store.Provisioned(key, "unknown", false)
		_ = s.Store.Audit(event)
		return &httpError{503, "repository creation pending reconciliation"}
	}
	if e = bind(repo); e != nil {
		event.Outcome = "rejected"
		event.Reason = "repository binding failed"
		_ = s.Store.Audit(event)
		return e
	}
	if e = s.Store.Provisioned(key, "ready", created); e != nil {
		return &httpError{503, "provisioning state unavailable"}
	}
	event.Outcome = "accepted"
	if e = s.Store.Audit(event); e != nil {
		return &httpError{503, "audit storage unavailable"}
	}
	return nil
}
