package jobdbprovider

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/colony-2/jobdb/pkg/jobdb"
	"github.com/fsnotify/fsnotify"
)

const (
	reloadDebounce = 100 * time.Millisecond
	reloadRetry    = time.Second
)

// ReloadingProvider publishes complete, immutable provider snapshots. Each
// request captures one snapshot, including its signing key, for both tokens.
type ReloadingProvider struct {
	current atomic.Pointer[Provider]
	path    string
	watcher *fsnotify.Watcher
	report  func(string)
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
}

var _ jobdb.SecretProvider = (*ReloadingProvider)(nil)

// WatchConfig loads the initial configuration and starts watching it and its key.
// report receives fixed diagnostic messages on the watcher goroutine; it may be
// nil and must not block or call Close. Call Close to release watcher resources.
// Initial load errors may include configuration details and need redaction.
func WatchConfig(path string, report func(string)) (*ReloadingProvider, error) {
	if path == "" {
		return nil, fmt.Errorf("configuration file required")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if report == nil {
		report = func(string) {}
	}
	r := &ReloadingProvider{path: path, report: report, stop: make(chan struct{}), done: make(chan struct{})}
	if err := r.reload(); err != nil {
		return nil, err
	}
	go r.watch()
	return r, nil
}

func (r *ReloadingProvider) ResolveSecrets(ctx context.Context, request jobdb.SecretResolveRequest) (jobdb.SecretResolveResult, error) {
	return r.current.Load().ResolveSecrets(ctx, request)
}

// Close stops the watcher and waits for it to exit. It is safe to call repeatedly.
func (r *ReloadingProvider) Close() {
	r.once.Do(func() { close(r.stop) })
	<-r.done
}

func signingKeyPath(path string, p *Provider) string {
	key := p.config.SigningKeyFile
	if !filepath.IsAbs(key) {
		key = filepath.Join(filepath.Dir(path), key)
	}
	return filepath.Clean(key)
}

// reload runs only during initialization or on the watcher goroutine. Watch
// directories so atomic file replacements do not detach the watch. Build a fresh
// watcher before loading: kqueue can retain child-file watches from a renamed
// directory, so re-adding the directory to the old watcher is not sufficient.
// Keep the previous watcher and snapshot until their replacements are ready.
func (r *ReloadingProvider) reload() error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer func() {
		if r.watcher != w {
			_ = w.Close()
		}
	}()
	configDir := filepath.Dir(r.path)
	if err := w.Add(configDir); err != nil {
		return err
	}
	next, err := Load(r.path)
	if err != nil {
		return err
	}
	keyPath := signingKeyPath(r.path, next)
	keyDir := filepath.Dir(keyPath)
	if err := w.Add(keyDir); err != nil {
		return err
	}
	// Read again after installing the key watch to cover changes during startup
	// or a switch to a key in a different directory.
	next, err = Load(r.path)
	if err != nil {
		return err
	}
	if signingKeyPath(r.path, next) != keyPath {
		return fmt.Errorf("signing key path changed while loading")
	}
	old := r.watcher
	r.watcher = w
	r.current.Store(next)
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (r *ReloadingProvider) relevant(event fsnotify.Event) bool {
	if !event.Has(fsnotify.Write | fsnotify.Create | fsnotify.Remove | fsnotify.Rename | fsnotify.Chmod) {
		return false
	}
	name := filepath.Clean(event.Name)
	key := signingKeyPath(r.path, r.current.Load())
	return name == r.path || name == key || name == filepath.Dir(r.path) || name == filepath.Dir(key)
}

func (r *ReloadingProvider) watch() {
	defer close(r.done)
	// reload replaces the watcher; close the current one when stopping.
	defer func() { _ = r.watcher.Close() }()
	var timer *time.Timer
	var tick <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	schedule := func(delay time.Duration) {
		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			timer.Reset(delay)
		}
		tick = timer.C
	}
	failed := false
	for {
		select {
		case <-r.stop:
			return
		case event, ok := <-r.watcher.Events:
			if !ok {
				r.report("configuration watcher stopped; retaining last valid configuration")
				return
			}
			if r.relevant(event) {
				schedule(reloadDebounce)
			}
		case _, ok := <-r.watcher.Errors:
			if !ok {
				r.report("configuration watcher stopped; retaining last valid configuration")
				return
			}
			// An overflow can lose events. Rescan and validate the complete files.
			r.report("configuration watch error; scheduling reload")
			schedule(reloadDebounce)
		case <-tick:
			tick = nil
			if err := r.reload(); err != nil {
				if !failed {
					r.report("configuration reload failed; retaining last valid configuration and retrying")
				}
				failed = true
				// Also handles a new key path that does not exist yet, or a missing
				// directory: neither can be watched until it has been created.
				schedule(reloadRetry)
				continue
			}
			failed = false
			r.report("configuration reloaded")
		}
	}
}
