// gitvend serves Git smart HTTPS with signed branch/repository grants.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"github.com/colony-2/gitvend/internal/config"
	"github.com/colony-2/gitvend/internal/gateway"
	"github.com/colony-2/gitvend/internal/policy"
)

func main() {
	if e := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); e != nil {
		fmt.Fprintln(os.Stderr, "gitvend:", e)
		os.Exit(1)
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
	f, e := os.CreateTemp(filepath.Dir(path), ".gitvend-token-*")
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
func credential(host, file, env string, allowHTTP bool, action string, in io.Reader, out io.Writer) error {
	if !policy.ValidHost(strings.ToLower(host)) || (file == "") == (env == "") {
		return fmt.Errorf("host and exactly one token source required")
	}
	switch action {
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
	if !strings.EqualFold(fields["host"], host) || !(fields["protocol"] == "https" || allowHTTP && fields["protocol"] == "http") {
		return nil
	}
	var token string
	if file != "" {
		b, e := os.ReadFile(file)
		if e != nil {
			return fmt.Errorf("cannot read injected JWT")
		}
		token = strings.TrimSpace(string(b))
	} else {
		token = os.Getenv(env)
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
	auditLog := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	initial, e := gateway.New(c, auditLog)
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
				if err == nil && (next.Listen != c.Listen || next.AllowHTTP != c.AllowHTTP || next.TLSCert != c.TLSCert || next.TLSKey != c.TLSKey) {
					err = fmt.Errorf("listener and TLS changes require restart")
				}
				var fresh *gateway.Server
				if err == nil {
					fresh, err = gateway.New(next, auditLog)
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
