package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/colony-2/gitvend/internal/auth"
)

// ensureSigningKeys serializes initializers on a local persistent volume. The
// private key is committed first; a missing public key can always be recovered
// from it. Existing keys are never replaced, including on corrupt/partial input.
func ensureSigningKeys(privatePath, publicPath string) error {
	privatePath, err := filepath.Abs(privatePath)
	if err != nil {
		return err
	}
	publicPath, err = filepath.Abs(publicPath)
	if err != nil {
		return err
	}
	if privatePath == publicPath || publicPath == privatePath+".lock" {
		return fmt.Errorf("private, public and lock paths must be distinct")
	}
	lock, err := os.OpenFile(privatePath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close() // Closing also releases the lock, including after a crash.
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		return err
	}

	privatePEM, err := os.ReadFile(privatePath)
	if os.IsNotExist(err) {
		if _, err := os.Lstat(publicPath); !os.IsNotExist(err) {
			return fmt.Errorf("private key missing but public key exists or is inaccessible; restore the private key from backup")
		}
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		privatePEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := installKey(privatePath, privatePEM); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	key, err := auth.ParsePrivate(privatePEM)
	if err != nil {
		return fmt.Errorf("invalid existing private key: %w", err)
	}
	if err := os.Chmod(privatePath, 0600); err != nil {
		return err
	}
	public := key.Public().(ed25519.PublicKey)
	publicPEM, err := os.ReadFile(publicPath)
	if err == nil {
		existing, err := auth.ParsePublic(publicPEM)
		if err != nil {
			return fmt.Errorf("invalid existing public key: %w", err)
		}
		if !bytes.Equal(existing, public) {
			return fmt.Errorf("existing public key does not match private key; restore the matching pair")
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return err
	}
	return installKey(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// installKey makes a fully written key visible atomically without overwriting
// anything. Syncing the directory commits the private key before publishing the
// public key on a different volume.
func installKey(path string, contents []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".gitvend-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(contents); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Link(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
