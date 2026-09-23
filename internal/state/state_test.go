package state

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestDurability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Reserve("h/o/r", "i", "s", "h/o", 1, 1); e != nil {
		t.Fatal(e)
	}
	if e = s.Reserve("h/o/r", "i", "s", "h/o", 1, 1); e != nil {
		t.Fatal("idempotency", e)
	}
	if e = s.Reserve("h/o/r2", "i", "s", "h/o", 1, 1); e == nil {
		t.Fatal("quota")
	}
	if _, e = s.Bind("h/o/r", 42); e != nil {
		t.Fatal(e)
	}
	if e = s.Audit(Event{ID: "one", Outcome: "admitted"}); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r, e := s.Repository("h/o/r")
	if e != nil || r.ID != 42 {
		t.Fatal(r, e)
	}
	if _, e = s.Bind("h/o/r", 43); e == nil {
		t.Fatal("identity substitution")
	}
	events, e := s.Events()
	if e != nil || len(events) != 1 {
		t.Fatal(events, e)
	}
}
func TestConcurrentQuota(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Go(func() {
			if e := s.Reserve("h/o/r", "i", "s", "h/o", 1, 1); e != nil {
				t.Error(e)
			}
		})
	}
	wg.Wait()
}
