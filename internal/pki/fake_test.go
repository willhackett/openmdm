package pki

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"

	"openmdm/internal/core"
)

// fakeStore implements only the core.Store methods the CA uses.
type fakeStore struct {
	core.Store // anything else panics: the CA must not need it

	mu      sync.Mutex
	blobs   map[string][]byte
	enrols  map[string]*core.Enrollment // by challenge
	certs   map[string]core.IssuedCert  // by sha256
	serial  int64
	failPut bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{blobs: map[string][]byte{}, enrols: map[string]*core.Enrollment{}, certs: map[string]core.IssuedCert{}}
}

func (s *fakeStore) GetBlob(_ context.Context, k string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.blobs[k]
	if !ok {
		return nil, fmt.Errorf("blob %q: %w", k, core.ErrNotFound)
	}
	return append([]byte(nil), v...), nil
}

func (s *fakeStore) PutBlob(_ context.Context, k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[k] = append([]byte(nil), v...)
	return nil
}

func (s *fakeStore) NextSerial(context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serial++
	return s.serial, nil
}

func (s *fakeStore) GetEnrollmentByChallenge(_ context.Context, c string) (core.Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.enrols[c]
	if !ok {
		return core.Enrollment{}, core.ErrNotFound
	}
	return *e, nil
}

func (s *fakeStore) MarkEnrollmentUsed(_ context.Context, c string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.enrols[c]
	if !ok {
		return core.ErrNotFound
	}
	if e.UsedAt != nil {
		return fmt.Errorf("already used: %w", core.ErrInvalid)
	}
	e.UsedAt = &at
	return nil
}

func (s *fakeStore) PutIssuedCert(_ context.Context, c core.IssuedCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certs[c.SHA256] = c
	return nil
}

func (s *fakeStore) GetIssuedCertBySHA256(_ context.Context, h string) (core.IssuedCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.certs[h]
	if !ok {
		return core.IssuedCert{}, core.ErrNotFound
	}
	return c, nil
}

func (s *fakeStore) addEnrollment(challenge, username string, expires time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrols[challenge] = &core.Enrollment{Token: "t-" + challenge, Challenge: challenge, Username: username, ExpiresAt: expires}
}

func newSealer(t testing.TB) core.Sealer {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	s, err := core.NewSealer(base64.StdEncoding.EncodeToString(k))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newTestAuthority(t testing.TB) (*Authority, *fakeStore, core.Sealer) {
	t.Helper()
	caKeyBits = 2048 // quick keys; the production size is not what is under test
	st, sl := newFakeStore(), newSealer(t)
	a, err := New(context.Background(), st, sl, "Acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, st, sl
}

func coreIssued(c *x509.Certificate) core.IssuedCert {
	return core.IssuedCert{Serial: c.SerialNumber.String(), CommonName: c.Subject.CommonName, SHA256: fingerprint(c), NotAfter: c.NotAfter}
}

func errNotFound() error { return core.ErrNotFound }
