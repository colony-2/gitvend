// Package state provides durable audit and provisioning records for a single server instance.
// bbolt takes an exclusive process lock; a second server cannot accidentally use the same database.
package state

import (
	"encoding/json"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Store struct{ db *bolt.DB }
type Repository struct {
	ID          int64     `json:"id"`
	Status      string    `json:"status"`
	Reserved    bool      `json:"reserved"`
	CreatedHere bool      `json:"created_here"`
	Updated     time.Time `json:"updated"`
}
type Event struct {
	ID                string    `json:"id"`
	Time              time.Time `json:"time"`
	Issuer            string    `json:"issuer,omitempty"`
	Subject           string    `json:"subject,omitempty"`
	TokenID           string    `json:"token_id,omitempty"`
	PolicyRevision    string    `json:"policy_revision,omitempty"`
	ConfigRevision    string    `json:"config_revision,omitempty"`
	Repository        string    `json:"repository,omitempty"`
	Operation         string    `json:"operation"`
	Outcome           string    `json:"outcome"`
	Reason            string    `json:"reason,omitempty"`
	Updates           any       `json:"updates,omitempty"`
	UpstreamRequestID string    `json:"upstream_request_id,omitempty"`
	Details           any       `json:"details,omitempty"`
}

func Open(path string) (*Store, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	db, e := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if e != nil {
		return nil, e
	}
	s := &Store{db}
	e = db.Update(func(tx *bolt.Tx) error {
		for _, b := range []string{"repos", "audit", "quota"} {
			if _, e := tx.CreateBucketIfNotExists([]byte(b)); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Audit(e Event) error {
	if e.ID == "" {
		return fmt.Errorf("audit ID required")
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("audit")).Put([]byte(e.ID), b) })
}
func (s *Store) Events() ([]Event, error) {
	out := []Event{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("audit")).ForEach(func(k, b []byte) error {
			var e Event
			if err := json.Unmarshal(b, &e); err != nil {
				return err
			}
			out = append(out, e)
			return nil
		})
	})
	return out, err
}
func readRepo(tx *bolt.Tx, key string) (Repository, error) {
	var r Repository
	if b := tx.Bucket([]byte("repos")).Get([]byte(key)); b != nil {
		if e := json.Unmarshal(b, &r); e != nil {
			return r, e
		}
	}
	return r, nil
}
func putRepo(tx *bolt.Tx, key string, r Repository) error {
	r.Updated = time.Now().UTC()
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	return tx.Bucket([]byte("repos")).Put([]byte(key), b)
}
func (s *Store) Bind(key string, id int64) (Repository, error) {
	var r Repository
	e := s.db.Update(func(tx *bolt.Tx) error {
		var e error
		r, e = readRepo(tx, key)
		if e != nil {
			return e
		}
		if id <= 0 || r.ID != 0 && r.ID != id {
			return fmt.Errorf("repository identity changed")
		}
		r.ID = id
		r.Status = "ready"
		return putRepo(tx, key, r)
	})
	return r, e
}
func (s *Store) Repository(key string) (Repository, error) {
	var r Repository
	e := s.db.View(func(tx *bolt.Tx) error { var e error; r, e = readRepo(tx, key); return e })
	return r, e
}
func (s *Store) Reserve(key, issuer, subject, owner string, subjectLimit, ownerLimit int) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		r, e := readRepo(tx, key)
		if e != nil {
			return e
		}
		if r.ID != 0 {
			return fmt.Errorf("previously enrolled repository is missing")
		}
		if r.Reserved {
			return nil
		}
		day := time.Now().UTC().Format("2006-01-02")
		q := tx.Bucket([]byte("quota"))
		keys := []string{day + "/subject/" + issuer + "\x00" + subject, day + "/owner/" + owner}
		limits := []int{subjectLimit, ownerLimit}
		for i, k := range keys {
			n, _ := strconv.Atoi(string(q.Get([]byte(k))))
			if n >= limits[i] {
				return fmt.Errorf("daily creation quota exceeded")
			}
			if e = q.Put([]byte(k), []byte(strconv.Itoa(n+1))); e != nil {
				return e
			}
		}
		r.Reserved = true
		r.Status = "creating"
		return putRepo(tx, key, r)
	})
}
func (s *Store) Provisioned(key, status string, created bool) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		r, e := readRepo(tx, key)
		if e != nil {
			return e
		}
		r.Status = status
		r.CreatedHere = r.CreatedHere || created
		return putRepo(tx, key, r)
	})
}
