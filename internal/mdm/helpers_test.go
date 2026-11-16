package mdm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"howett.net/plist"

	nmdm "github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/push"

	"openmdm/internal/core"
)

// ---- a throwaway CA and device identities ----

type identity struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func (i identity) sha() string {
	sum := sha256.Sum256(i.cert.Raw)
	return hex.EncodeToString(sum[:])
}

type testCA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
	next int64
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, next: 1}
}

func (ca *testCA) issue(t *testing.T, cn string) identity {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ca.next++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(ca.next),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return identity{cert: cert, key: key}
}

// fakeAuthority accepts exactly the certificates it was told to trust.
type fakeAuthority struct {
	ca      *testCA
	mu      sync.Mutex
	trusted map[string]bool
}

func (a *fakeAuthority) trust(ids ...identity) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, i := range ids {
		a.trusted[i.sha()] = true
	}
}

func (a *fakeAuthority) CACertificate() *x509.Certificate { return a.ca.cert }
func (a *fakeAuthority) SigningIdentity() (*x509.Certificate, crypto.Signer) {
	return a.ca.cert, a.ca.key
}
func (a *fakeAuthority) Revoke(context.Context, string) error { return nil }
func (a *fakeAuthority) VerifyIssued(_ context.Context, cert *x509.Certificate) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	sum := sha256.Sum256(cert.Raw)
	if !a.trusted[hex.EncodeToString(sum[:])] {
		return errors.New("not issued by this CA")
	}
	return nil
}

// ---- recording events ----

type recorder struct {
	mu            sync.Mutex
	authenticated []core.Checkin
	tokens        []core.Checkin
	checkouts     []core.Checkin
	results       []core.CommandResult
	panicky       bool
}

func (r *recorder) DeviceAuthenticated(_ context.Context, c core.Checkin) {
	r.mu.Lock()
	r.authenticated = append(r.authenticated, c)
	r.mu.Unlock()
	if r.panicky {
		panic("boom")
	}
}
func (r *recorder) DeviceTokenUpdated(_ context.Context, c core.Checkin) {
	r.mu.Lock()
	r.tokens = append(r.tokens, c)
	r.mu.Unlock()
	if r.panicky {
		panic("boom")
	}
}
func (r *recorder) DeviceCheckedOut(_ context.Context, c core.Checkin) {
	r.mu.Lock()
	r.checkouts = append(r.checkouts, c)
	r.mu.Unlock()
	if r.panicky {
		panic("boom")
	}
}
func (r *recorder) CommandResulted(_ context.Context, c core.CommandResult) {
	r.mu.Lock()
	r.results = append(r.results, c)
	r.mu.Unlock()
	if r.panicky {
		panic("boom")
	}
}

// ---- a fake APNs ----

type fakeAPNs struct {
	mu     sync.Mutex
	pushed []*nmdm.Push
	fail   error
	certs  int
}

func (f *fakeAPNs) NewPushProvider(*tls.Certificate) (push.PushProvider, error) {
	f.mu.Lock()
	f.certs++
	f.mu.Unlock()
	return f, nil
}

func (f *fakeAPNs) Push(_ context.Context, ps []*nmdm.Push) (map[string]*push.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	out := map[string]*push.Response{}
	for _, p := range ps {
		f.pushed = append(f.pushed, p)
		out[p.Token.String()] = &push.Response{Id: "apns-id"}
	}
	return out, nil
}

// ---- the harness ----

type harness struct {
	t    *testing.T
	svc  *Service
	h    http.Handler
	ev   *recorder
	auth *fakeAuthority
	ca   *testCA
	apns *fakeAPNs
	dir  string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ca := newTestCA(t)
	hs := &harness{
		t:    t,
		ev:   &recorder{},
		ca:   ca,
		auth: &fakeAuthority{ca: ca, trusted: map[string]bool{}},
		apns: &fakeAPNs{},
		dir:  t.TempDir(),
	}
	svc, err := New(context.Background(), Options{
		DataDir:       hs.dir,
		Authority:     hs.auth,
		Events:        hs.ev,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		PushProviders: hs.apns,
	})
	if err != nil {
		t.Fatal(err)
	}
	hs.svc, hs.h = svc, svc.Handler()
	return hs
}

func detachedSignature(t *testing.T, id identity, body []byte) string {
	t.Helper()
	sd, err := pkcs7.NewSignedData(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSigner(id.cert, id.key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	sd.Detach()
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

const (
	ctCheckin = "application/x-apple-aspen-mdm-checkin"
	ctCommand = "application/x-apple-aspen-mdm"
)

// put sends body to the handler the way a device does. sig is the identity
// that signs it; nil sends it unsigned.
func (hs *harness) put(sig *identity, contentType string, body []byte) *httptest.ResponseRecorder {
	hs.t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/mdm", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	if sig != nil {
		req.Header.Set("Mdm-Signature", detachedSignature(hs.t, *sig, body))
	}
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	return rec
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := plist.Marshal(v, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (hs *harness) checkin(id *identity, msg map[string]any) *httptest.ResponseRecorder {
	return hs.put(id, ctCheckin, marshal(hs.t, msg))
}

func (hs *harness) report(id *identity, msg map[string]any) *httptest.ResponseRecorder {
	return hs.put(id, ctCommand, marshal(hs.t, msg))
}

func mustOK(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %q", rec.Code, rec.Body.String())
	}
}

// ---- push certificates ----

func pushCert(t *testing.T, topic string, notAfter time.Time) (certPEM, keyPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	name := pkix.Name{CommonName: "APSP:test"}
	if topic != "" {
		name.ExtraNames = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: topic}}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      name,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), key
}
