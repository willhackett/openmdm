package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestCreateThenReload(t *testing.T) {
	a, st, sl := newTestAuthority(t)
	ca := a.CACertificate()
	if ca.Subject.CommonName != "Acme OpenMDM CA" || ca.Subject.Organization[0] != "Acme" {
		t.Errorf("subject = %v", ca.Subject)
	}
	if !ca.IsCA || ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("not a CA with cert+CRL sign: %v %v", ca.IsCA, ca.KeyUsage)
	}
	if d := ca.NotAfter.Sub(ca.NotBefore); d < 9*365*24*time.Hour {
		t.Errorf("validity %v", d)
	}
	if bytes.Contains(st.blobs["pki/ca.key"], []byte("PRIVATE KEY")) {
		t.Error("CA key is stored unsealed")
	}
	sc, sk := a.SigningIdentity()
	if sc.Subject.CommonName != "Acme OpenMDM profile signing" || sc.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("signer cert: %v %v", sc.Subject, sc.KeyUsage)
	}
	if err := sc.CheckSignatureFrom(ca); err != nil {
		t.Error(err)
	}
	if _, ok := sk.(*rsa.PrivateKey); !ok || sk.Public().(*rsa.PublicKey).N.BitLen() != 2048 {
		t.Error("signer key should be RSA 2048")
	}

	b, err := New(context.Background(), st, sl, "Acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.CACertificate().Raw, ca.Raw) {
		t.Error("reloaded a different CA")
	}
	sc2, _ := b.SigningIdentity()
	if !bytes.Equal(sc2.Raw, sc.Raw) {
		t.Error("signing identity was reissued needlessly")
	}
}

func TestWrongSealerFailsLoudly(t *testing.T) {
	a, st, _ := newTestAuthority(t)
	_, err := New(context.Background(), st, newSealer(t), "Acme", nil)
	if err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("err = %v", err)
	}
	if !bytes.Equal(mustPEMBlob(t, st, "pki/ca.crt"), pemCert(a.CACertificate())) {
		t.Error("stored CA was replaced")
	}
}

func TestHalfACAIsAnError(t *testing.T) {
	_, st, sl := newTestAuthority(t)
	delete(st.blobs, "pki/ca.key")
	if _, err := New(context.Background(), st, sl, "Acme", nil); err == nil {
		t.Fatal("expected an error")
	}
}

func mustPEMBlob(t *testing.T, st *fakeStore, k string) []byte {
	t.Helper()
	v, err := st.GetBlob(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSignerRenewal(t *testing.T) {
	a, st, sl := newTestAuthority(t)
	old, _ := a.SigningIdentity()

	// Reload 340 days later: within 30 days of expiry, so it is replaced.
	later := func() time.Time { return time.Now().Add(340 * 24 * time.Hour) }
	b, err := newAuthority(context.Background(), st, sl, "Acme", nil, later)
	if err != nil {
		t.Fatal(err)
	}
	renewed, _ := b.SigningIdentity()
	if bytes.Equal(renewed.Raw, old.Raw) {
		t.Fatal("signing identity not renewed")
	}
	if !renewed.NotAfter.After(old.NotAfter) {
		t.Error("renewed certificate does not last longer")
	}
	if !bytes.Equal(b.CACertificate().Raw, a.CACertificate().Raw) {
		t.Error("CA changed")
	}
	stored, _ := parseCertPEM(mustPEMBlob(t, st, "pki/signer.crt"))
	if !bytes.Equal(stored.Raw, renewed.Raw) {
		t.Error("renewed identity not stored")
	}

	// A running server renews too, when asked for the identity.
	clock := time.Now()
	c, err := newAuthority(context.Background(), newFakeStore(), sl, "Acme", nil, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	before, _ := c.SigningIdentity()
	clock = clock.Add(400 * 24 * time.Hour)
	after, key := c.SigningIdentity()
	if bytes.Equal(before.Raw, after.Raw) {
		t.Error("not renewed while running")
	}
	if !key.Public().(*rsa.PublicKey).Equal(after.PublicKey) {
		t.Error("key does not match renewed certificate")
	}
}

func TestSignerMissingIsIssued(t *testing.T) {
	a, st, sl := newTestAuthority(t)
	old, _ := a.SigningIdentity()
	delete(st.blobs, "pki/signer.crt")
	b, err := New(context.Background(), st, sl, "Acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := b.SigningIdentity(); bytes.Equal(n.Raw, old.Raw) {
		t.Error("expected a new signing identity")
	}
}

// leaf issues a certificate under ca, directly, for VerifyIssued tests.
func leaf(t *testing.T, ca *Authority, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.sign(&x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "dev"},
		NotBefore:    notBefore, NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func record(t *testing.T, a *Authority, c *x509.Certificate) {
	t.Helper()
	st := a.store.(*fakeStore)
	st.certs[fingerprint(c)] = coreIssued(c)
}

func TestVerifyIssued(t *testing.T) {
	ctx := context.Background()
	a, st, _ := newTestAuthority(t)
	now := time.Now()

	good := leaf(t, a, now.Add(-time.Hour), now.Add(time.Hour))
	record(t, a, good)
	if err := a.VerifyIssued(ctx, good); err != nil {
		t.Errorf("good: %v", err)
	}

	other, _, _ := newTestAuthority(t)
	foreign := leaf(t, other, now.Add(-time.Hour), now.Add(time.Hour))
	record(t, a, foreign) // even if recorded, it does not chain
	if err := a.VerifyIssued(ctx, foreign); err == nil {
		t.Error("certificate from another CA accepted")
	}

	expired := leaf(t, a, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	record(t, a, expired)
	if err := a.VerifyIssued(ctx, expired); err == nil {
		t.Error("expired certificate accepted")
	}

	unrecorded := leaf(t, a, now.Add(-time.Hour), now.Add(time.Hour))
	if err := a.VerifyIssued(ctx, unrecorded); err == nil {
		t.Error("unrecorded certificate accepted")
	}

	revoked := leaf(t, a, now.Add(-time.Hour), now.Add(time.Hour))
	record(t, a, revoked)
	if err := a.Revoke(ctx, fingerprint(revoked)); err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyIssued(ctx, revoked); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("revoked certificate: %v", err)
	}
	if st.certs[fingerprint(revoked)].RevokedAt == nil {
		t.Error("RevokedAt not stored")
	}
	if err := a.Revoke(ctx, fingerprint(revoked)); err != nil {
		t.Errorf("second revoke: %v", err)
	}
	if err := a.Revoke(ctx, "00"); err == nil || !errors.Is(err, errNotFound()) {
		t.Errorf("revoke unknown: %v", err)
	}
	if err := a.VerifyIssued(ctx, nil); err == nil {
		t.Error("nil accepted")
	}
}
