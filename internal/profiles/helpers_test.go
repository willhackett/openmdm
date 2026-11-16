package profiles

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sort"
	"sync"
	"testing"
	"time"

	"openmdm/internal/core"
)

type fakeSecrets struct {
	mu          sync.Mutex
	user        map[string]map[string]string
	global      map[string]string
	userCalls   int
	globalCalls int
	err         error
}

func (f *fakeSecrets) UserSecrets(_ context.Context, username string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.userCalls++
	if f.err != nil {
		return nil, f.err
	}
	return f.user[username], nil
}
func (f *fakeSecrets) GlobalSecrets(context.Context) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.globalCalls++
	return f.global, nil
}
func (f *fakeSecrets) SetUserSecret(context.Context, string, string, string) error { return nil }
func (f *fakeSecrets) DeleteUserSecret(context.Context, string, string) error      { return nil }
func (f *fakeSecrets) SetGlobalSecret(context.Context, string, string) error       { return nil }
func (f *fakeSecrets) DeleteGlobalSecret(context.Context, string) error            { return nil }
func (f *fakeSecrets) Health(context.Context) error                                { return nil }

type fakeAuthority struct {
	ca     *x509.Certificate
	signer *x509.Certificate
	key    crypto.Signer
	caPool *x509.CertPool
}

func (a *fakeAuthority) CACertificate() *x509.Certificate { return a.ca }
func (a *fakeAuthority) SigningIdentity() (*x509.Certificate, crypto.Signer) {
	return a.signer, a.key
}
func (a *fakeAuthority) VerifyIssued(context.Context, *x509.Certificate) error { return nil }
func (a *fakeAuthority) Revoke(context.Context, string) error                  { return nil }

func newAuthority(t *testing.T) *fakeAuthority {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA", Organization: []string{"Example"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &fakeAuthority{ca: ca, signer: signer, key: key, caPool: pool}
}

// fakeStore is the part of core.Store the loader uses; the rest panics.
type fakeStore struct {
	core.Store
	mu       sync.Mutex
	profiles map[string]core.Profile
	puts     int
	deletes  int
}

func newFakeStore() *fakeStore { return &fakeStore{profiles: map[string]core.Profile{}} }

func (s *fakeStore) PutProfile(_ context.Context, p core.Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.UpdatedAt = time.Now()
	s.profiles[p.ID] = p
	s.puts++
	return nil
}
func (s *fakeStore) GetProfile(_ context.Context, id string) (core.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[id]
	if !ok {
		return p, core.ErrNotFound
	}
	return p, nil
}
func (s *fakeStore) ListProfiles(context.Context) ([]core.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.Profile{}
	for _, p := range s.profiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (s *fakeStore) DeleteProfile(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.profiles, id)
	s.deletes++
	return nil
}
