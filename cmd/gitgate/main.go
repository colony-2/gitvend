// gitgate serves Git smart HTTPS with signed branch/repository grants.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"gitgate/internal/auth"
	"gitgate/internal/config"
	"gitgate/internal/gateway"
	"gitgate/internal/jsonutil"
	"gitgate/internal/policy"
	"gitgate/internal/state"
)

func main() {
	if e := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); e != nil {
		fmt.Fprintln(os.Stderr, "gitgate:", e)
		os.Exit(1)
	}
}
func flags(name string, errout io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(errout)
	return f
}

type stringFlags []string

func (s *stringFlags) String() string     { return strings.Join(*s, ",") }
func (s *stringFlags) Set(v string) error { *s = append(*s, v); return nil }
func run(args []string, in io.Reader, out, errout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gitgate serve|keygen|sign|explain|credential|audit")
	}
	switch args[0] {
	case "serve":
		f := flags("serve", errout)
		path := f.String("config", "gitgate.json", "server config")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		return serve(*path)
	case "keygen":
		f := flags("keygen", errout)
		private := f.String("private", "signing.key", "private key output (must not exist)")
		public := f.String("public", "signing.pub", "public key output (must not exist)")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		privDER, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return e
		}
		pubDER, e := x509.MarshalPKIXPublicKey(pub)
		if e != nil {
			return e
		}
		for _, p := range []string{*private, *public} {
			if _, e = os.Stat(p); !os.IsNotExist(e) {
				return fmt.Errorf("key output already exists or is inaccessible: %s", p)
			}
		}
		if e = writeExclusive(*private, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})); e != nil {
			return e
		}
		if e = writeExclusive(*public, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})); e != nil {
			return e
		}
		fmt.Fprintln(out, "Wrote", *private, "and", *public)
		return nil
	case "sign":
		f := flags("sign", errout)
		keyPath := f.String("key", "", "private key PEM")
		kid := f.String("kid", "", "configured key ID")
		issuer := f.String("issuer", "", "configured issuer")
		subject := f.String("subject", "", "agent/task identity")
		aud := f.String("audience", "gitgate", "service audience")
		ttl := f.Duration("ttl", 15*time.Minute, "token lifetime")
		max := f.Int("max-token-bytes", 4096, "serialized JWT budget")
		grantPath := f.String("grant", "", "JSON grant file (v, permissions, optional bindings)")
		output := f.String("output", "", "atomic token file output; default stdout")
		revision := f.String("policy-revision", "", "issuer revision for audit")
		var perms stringFlags
		f.Var(&perms, "permission", "permission string (repeatable)")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *keyPath == "" || *kid == "" || *issuer == "" || *subject == "" || *aud == "" || *ttl <= 0 || *ttl > 24*time.Hour || *max < 512 || *max > 32768 {
			return fmt.Errorf("key, kid, issuer, subject and valid lifetime/size required")
		}
		grant := auth.Grant{Version: 1, Permissions: perms}
		if *grantPath != "" {
			if len(perms) > 0 {
				return fmt.Errorf("use grant file or permissions, not both")
			}
			b, e := os.ReadFile(*grantPath)
			if e != nil {
				return e
			}
			if e = jsonutil.Decode(b, &grant); e != nil {
				return e
			}
		}
		if grant.Version != 1 {
			return fmt.Errorf("unsupported grant version")
		}
		b, e := os.ReadFile(*keyPath)
		if e != nil {
			return e
		}
		key, e := auth.ParsePrivate(b)
		if e != nil {
			return e
		}
		claims := auth.NewClaims(*issuer, *subject, *aud, *ttl, grant)
		claims.PolicyRevision = *revision
		token, e := auth.Sign(claims, key, *kid, *max)
		if e != nil {
			return e
		}
		if *output != "" {
			return writeAtomic(*output, []byte(token+"\n"))
		}
		_, e = fmt.Fprintln(out, token)
		return e
	case "explain":
		f := flags("explain", errout)
		repo := f.String("repo", "", "host/namespace/repo")
		ref := f.String("ref", "", "fully qualified ref")
		action := f.String("action", "ref.update", "repo.read, repo.create, ref.discover, ref.create, ref.update or ref.delete")
		var perms stringFlags
		f.Var(&perms, "permission", "permission string (repeatable)")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		host, path, ok := strings.Cut(*repo, "/")
		if !ok {
			return fmt.Errorf("repo must be host/namespace/repository")
		}
		p, e := policy.Compile(perms)
		if e != nil {
			return e
		}
		r := policy.Repository{Host: host, Path: strings.ToLower(path), FoldCase: true}
		d := p.Explain(r, *ref, *action)
		allowed := d.Allowed
		switch *action {
		case "repo.read", "repo.create":
		case "ref.discover":
			allowed = p.Discover(r, *ref)
		case "ref.create", "ref.update", "ref.delete":
			allowed = p.Write(r, *ref, *action)
		default:
			return fmt.Errorf("unknown action")
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"allowed": allowed, "action": d, "repository_read": p.Explain(r, "", "repo.read"), "discovery": p.Explain(r, *ref, "ref.discover")})
	case "credential":
		return credential(args[1:], in, out, errout)
	case "audit":
		f := flags("audit", errout)
		path := f.String("state", "var/gitgate.db", "state file (server must be stopped)")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		st, e := state.Open(*path)
		if e != nil {
			return e
		}
		defer st.Close()
		events, e := st.Events()
		if e != nil {
			return e
		}
		enc := json.NewEncoder(out)
		for _, event := range events {
			if e = enc.Encode(event); e != nil {
				return e
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func writeExclusive(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	return closeErr
}
func writeAtomic(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".gitgate-token-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}
func credential(args []string, in io.Reader, out, errout io.Writer) error {
	f := flags("credential", errout)
	host := f.String("host", "", "exact gateway host[:port]")
	file := f.String("token-file", "", "injected JWT file")
	env := f.String("token-env", "", "injected JWT environment variable name")
	allowHTTP := f.Bool("allow-http", false, "allow explicit local development HTTP")
	if e := f.Parse(args); e != nil {
		return e
	}
	if !policy.ValidHost(strings.ToLower(*host)) || (*file == "") == (*env == "") {
		return fmt.Errorf("host and exactly one token source required")
	}
	if len(f.Args()) != 1 {
		return fmt.Errorf("credential action required")
	}
	switch f.Arg(0) {
	case "store", "erase":
		return nil
	case "get":
	default:
		return fmt.Errorf("unsupported credential action")
	}
	scanner := bufio.NewScanner(io.LimitReader(in, 131073))
	scanner.Buffer(make([]byte, 1024), 65535)
	fields := map[string]string{}
	total := 0
	for scanner.Scan() {
		line := scanner.Text()
		total += len(line) + 1
		if total > 131072 {
			return fmt.Errorf("credential input too large")
		}
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("invalid credential input")
		}
		if _, exists := fields[k]; exists {
			return fmt.Errorf("duplicate credential field")
		}
		fields[k] = v
	}
	if e := scanner.Err(); e != nil {
		return e
	}
	if !strings.EqualFold(fields["host"], *host) || !(fields["protocol"] == "https" || *allowHTTP && fields["protocol"] == "http") {
		return nil
	}
	var token string
	if *file != "" {
		b, e := os.ReadFile(*file)
		if e != nil {
			return fmt.Errorf("cannot read injected JWT")
		}
		token = strings.TrimSpace(string(b))
	} else {
		token = os.Getenv(*env)
	}
	if token == "" || len(token) > 32768 || strings.ContainsAny(token, "\x00\r\n") {
		return fmt.Errorf("missing or invalid injected JWT")
	}
	_, e := fmt.Fprintf(out, "username=git\npassword=%s\n\n", token)
	return e
}
func load(path string) (config.Config, error) {
	c, e := config.Load(path)
	if e != nil {
		return c, e
	}
	if c.Revision == "" {
		b, _ := json.Marshal(c)
		sum := sha256.Sum256(b)
		c.Revision = hex.EncodeToString(sum[:8])
	}
	return c, nil
}
func serve(path string) error {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	return serveWithSignals(path, signals, nil)
}

func serveWithSignals(path string, signals <-chan os.Signal, ready func(string)) error {
	c, e := load(path)
	if e != nil {
		return e
	}
	st, e := state.Open(c.StateFile)
	if e != nil {
		return e
	}
	defer st.Close()
	initial, e := gateway.New(c, st)
	if e != nil {
		return e
	}
	var current atomic.Pointer[gateway.Server]
	current.Store(initial)
	defer func() { current.Load().Close() }()
	httpServer := &http.Server{Addr: c.Listen, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { current.Load().ServeHTTP(w, r) }), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 65536}
	listener, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return e
	}
	defer listener.Close()
	errs := make(chan error, 1)
	go func() {
		if c.AllowHTTP {
			errs <- httpServer.Serve(listener)
		} else {
			errs <- httpServer.ServeTLS(listener, c.TLSCert, c.TLSKey)
		}
	}()
	if ready != nil {
		ready(listener.Addr().String())
	}
	slog.Info("Git gateway listening", "address", c.Listen, "revision", c.Revision, "tls", !c.AllowHTTP)
	for {
		select {
		case e := <-errs:
			if errors.Is(e, http.ErrServerClosed) {
				return nil
			}
			return e
		case sig := <-signals:
			if sig == syscall.SIGHUP {
				next, err := load(path)
				if err == nil && (next.StateFile != c.StateFile || next.Listen != c.Listen || next.AllowHTTP != c.AllowHTTP || next.TLSCert != c.TLSCert || next.TLSKey != c.TLSKey) {
					err = fmt.Errorf("listener, TLS and state path changes require restart")
				}
				var fresh *gateway.Server
				if err == nil {
					fresh, err = gateway.New(next, st)
				}
				if err != nil {
					slog.Error("configuration reload rejected", "error", err)
					continue
				}
				old := current.Swap(fresh)
				old.Close()
				slog.Info("configuration reloaded", "revision", next.Revision)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			e = httpServer.Shutdown(ctx)
			cancel()
			if e != nil {
				httpServer.Close()
			}
			return e
		}
	}
}
