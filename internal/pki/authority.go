// Package pki is OpenMDM's certificate authority: a root CA kept in the
// store (its key sealed), the identity profiles are signed with, and the
// SCEP server devices get their identity certificates from.
package pki

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"openmdm/internal/core"
)

// Blob keys under which the CA and the signing identity are kept.
const (
	blobCACert     = "pki/ca.crt"
	blobCAKey      = "pki/ca.key"
	blobSignerCert = "pki/signer.crt"
	blobSignerKey  = "pki/signer.key"
)

const (
	caValidity     = 10 * 365 * 24 * time.Hour
	signerValidity = 365 * 24 * time.Hour
	deviceValidity = 2 * 365 * 24 * time.Hour
	renewWindow    = 30 * 24 * time.Hour
	// Certificates start a little in the past so that a device whose clock
	// is slightly behind does not reject them.
	backdate = 5 * time.Minute
)

// caKeyBits is a variable only so that tests can make keys quickly.
var caKeyBits = 3072

var _ core.Authority = (*Authority)(nil)

// Authority is the built-in CA. It is safe for concurrent use.
type Authority struct {
	store  core.Store
	sealer core.Sealer
	org    string
	logger *slog.Logger
	now    func() time.Time

	caCert *x509.Certificate
	caKey  *rsa.PrivateKey

	mu         sync.RWMutex // guards the signing identity, which is renewed
	signerCert *x509.Certificate
	signerKey  *rsa.PrivateKey
}

// New loads the CA from the store, creating it on first start, and makes
// sure the profile-signing identity exists and is not about to expire.
// A CA key that cannot be opened with the sealer (the wrong master key) is
// an error: the CA is never silently replaced.
func New(ctx context.Context, store core.Store, sealer core.Sealer, organization string, logger *slog.Logger) (*Authority, error) {
	return newAuthority(ctx, store, sealer, organization, logger, time.Now)
}

func newAuthority(ctx context.Context, store core.Store, sealer core.Sealer, organization string, logger *slog.Logger, now func() time.Time) (*Authority, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if organization == "" {
		return nil, fmt.Errorf("pki: organization must not be empty: %w", core.ErrInvalid)
	}
	a := &Authority{store: store, sealer: sealer, org: organization, logger: logger, now: now}
	if err := a.loadOrCreateCA(ctx); err != nil {
		return nil, err
	}
	if err := a.ensureSigner(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

// CACertificate is the root certificate.
func (a *Authority) CACertificate() *x509.Certificate { return a.caCert }

// SigningIdentity is the certificate and key profiles are signed with. If
// the certificate is close to expiry it is renewed first, so a server that
// runs for a year keeps signing.
func (a *Authority) SigningIdentity() (*x509.Certificate, crypto.Signer) {
	a.mu.RLock()
	c, k := a.signerCert, a.signerKey
	a.mu.RUnlock()
	if a.now().Add(renewWindow).After(c.NotAfter) {
		if err := a.ensureSigner(context.Background()); err != nil {
			a.logger.Error("renewing the profile-signing identity failed", "err", err)
		}
		a.mu.RLock()
		c, k = a.signerCert, a.signerKey
		a.mu.RUnlock()
	}
	return c, k
}

// VerifyIssued reports whether cert chains to this CA, is within its
// validity period, and is recorded as issued and not revoked.
func (a *Authority) VerifyIssued(ctx context.Context, cert *x509.Certificate) error {
	if cert == nil || len(cert.Raw) == 0 {
		return fmt.Errorf("pki: no certificate: %w", core.ErrInvalid)
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.caCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: a.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("pki: certificate not valid for this CA: %w", err)
	}
	rec, err := a.store.GetIssuedCertBySHA256(ctx, fingerprint(cert))
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return errors.New("pki: certificate was not issued by this server")
		}
		return fmt.Errorf("pki: looking up certificate: %w", err)
	}
	if rec.RevokedAt != nil {
		return errors.New("pki: certificate has been revoked")
	}
	return nil
}

// Revoke marks an issued certificate (by the hex SHA-256 of its DER) as
// revoked. Revoking twice keeps the first time.
func (a *Authority) Revoke(ctx context.Context, sha256hex string) error {
	rec, err := a.store.GetIssuedCertBySHA256(ctx, sha256hex)
	if err != nil {
		return fmt.Errorf("pki: revoke: %w", err)
	}
	if rec.RevokedAt != nil {
		return nil
	}
	t := a.now().UTC()
	rec.RevokedAt = &t
	if err := a.store.PutIssuedCert(ctx, rec); err != nil {
		return fmt.Errorf("pki: revoke: %w", err)
	}
	a.logger.Info("certificate revoked", "serial", rec.Serial, "common_name", rec.CommonName)
	return nil
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// ---- the root CA ----

func (a *Authority) loadOrCreateCA(ctx context.Context) error {
	certPEM, certErr := a.store.GetBlob(ctx, blobCACert)
	sealedKey, keyErr := a.store.GetBlob(ctx, blobCAKey)
	certMissing := errors.Is(certErr, core.ErrNotFound)
	keyMissing := errors.Is(keyErr, core.ErrNotFound)
	switch {
	case certErr != nil && !certMissing:
		return fmt.Errorf("pki: reading CA certificate: %w", certErr)
	case keyErr != nil && !keyMissing:
		return fmt.Errorf("pki: reading CA key: %w", keyErr)
	case certMissing && keyMissing:
		return a.createCA(ctx)
	case certMissing || keyMissing:
		// Half a CA. Making a new one would orphan every device identity
		// issued by the old one, so stop and let a person decide.
		return errors.New("pki: the store has only one of the CA certificate and key (pki/ca.crt, pki/ca.key); refusing to create a new CA")
	}

	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return fmt.Errorf("pki: stored CA certificate: %w", err)
	}
	key, err := a.openKey(sealedKey)
	if err != nil {
		return fmt.Errorf("pki: cannot open the CA key (is the master key the one it was created with?): %w", err)
	}
	if !samePublicKey(cert, key) {
		return errors.New("pki: the stored CA certificate and key do not match")
	}
	a.caCert, a.caKey = cert, key
	return nil
}

func (a *Authority) createCA(ctx context.Context) error {
	key, err := rsa.GenerateKey(rand.Reader, caKeyBits)
	if err != nil {
		return fmt.Errorf("pki: generating CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := a.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: a.org + " OpenMDM CA", Organization: []string{a.org}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("pki: creating CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	// Key first: a key with no certificate is harmless, the reverse is not.
	if err := a.putKey(ctx, blobCAKey, key); err != nil {
		return err
	}
	if err := a.store.PutBlob(ctx, blobCACert, pemCert(cert)); err != nil {
		return fmt.Errorf("pki: storing CA certificate: %w", err)
	}
	a.caCert, a.caKey = cert, key
	a.logger.Info("created a new certificate authority", "subject", cert.Subject.CommonName, "not_after", cert.NotAfter)
	return nil
}

// ---- the profile-signing identity ----

// ensureSigner loads the signing identity, and issues a new one if it is
// missing, unreadable, not from this CA, or within renewWindow of expiry.
func (a *Authority) ensureSigner(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.signerCert == nil {
		if err := a.loadSigner(ctx); err != nil {
			return err
		}
	}
	if a.signerCert != nil && a.now().Add(renewWindow).Before(a.signerCert.NotAfter) {
		return nil
	}
	return a.issueSigner(ctx)
}

// loadSigner fills in the signing identity if the store has a usable one.
// A sealed key that cannot be opened is an error; anything else wrong with
// it just means a new one will be issued.
func (a *Authority) loadSigner(ctx context.Context) error {
	certPEM, err := a.store.GetBlob(ctx, blobSignerCert)
	if errors.Is(err, core.ErrNotFound) {
		return nil
	} else if err != nil {
		return fmt.Errorf("pki: reading signing certificate: %w", err)
	}
	sealed, err := a.store.GetBlob(ctx, blobSignerKey)
	if errors.Is(err, core.ErrNotFound) {
		return nil
	} else if err != nil {
		return fmt.Errorf("pki: reading signing key: %w", err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		a.logger.Warn("stored signing certificate is unreadable; issuing a new one", "err", err)
		return nil
	}
	key, err := a.openKey(sealed)
	if err != nil {
		return fmt.Errorf("pki: cannot open the signing key (is the master key the one it was created with?): %w", err)
	}
	if !samePublicKey(cert, key) || cert.CheckSignatureFrom(a.caCert) != nil {
		a.logger.Warn("stored signing identity does not belong to this CA; issuing a new one")
		return nil
	}
	a.signerCert, a.signerKey = cert, key
	return nil
}

func (a *Authority) issueSigner(ctx context.Context) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("pki: generating signing key: %w", err)
	}
	serial, err := a.store.NextSerial(ctx)
	if err != nil {
		return fmt.Errorf("pki: allocating serial: %w", err)
	}
	now := a.now()
	cert, err := a.sign(&x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: a.org + " OpenMDM profile signing", Organization: []string{a.org}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(signerValidity),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}, &key.PublicKey)
	if err != nil {
		return err
	}
	if err := a.putKey(ctx, blobSignerKey, key); err != nil {
		return err
	}
	if err := a.store.PutBlob(ctx, blobSignerCert, pemCert(cert)); err != nil {
		return fmt.Errorf("pki: storing signing certificate: %w", err)
	}
	a.signerCert, a.signerKey = cert, key
	a.logger.Info("issued a profile-signing identity", "serial", cert.SerialNumber.String(), "not_after", cert.NotAfter)
	return nil
}

// ---- helpers ----

// sign issues tmpl for pub under the CA.
func (a *Authority) sign(tmpl *x509.Certificate, pub crypto.PublicKey) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, pub, a.caKey)
	if err != nil {
		return nil, fmt.Errorf("pki: signing certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

func (a *Authority) putKey(ctx context.Context, blob string, key *rsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	sealed, err := a.sealer.Seal(der)
	if err != nil {
		return fmt.Errorf("pki: sealing key: %w", err)
	}
	if err := a.store.PutBlob(ctx, blob, sealed); err != nil {
		return fmt.Errorf("pki: storing key: %w", err)
	}
	return nil
}

func (a *Authority) openKey(sealed []byte) (*rsa.PrivateKey, error) {
	der, err := a.sealer.Open(sealed)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("sealed key is not PKCS#8")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("sealed key is not an RSA key")
	}
	return rk, nil
}

func samePublicKey(c *x509.Certificate, k *rsa.PrivateKey) bool {
	pub, ok := c.PublicKey.(*rsa.PublicKey)
	return ok && pub.Equal(&k.PublicKey)
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func parseCertPEM(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func randomSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}
