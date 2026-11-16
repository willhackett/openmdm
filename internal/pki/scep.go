package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"

	kitlog "github.com/go-kit/kit/log"
	scepserver "github.com/micromdm/scep/v2/server"
	"github.com/smallstep/scep"

	"openmdm/internal/core"
)

// SCEPHandler serves SCEP (GetCACaps, GetCACert, PKIOperation; GET and
// POST). Mount it at /scep: whatever path it is reached by, the SCEP
// library sees /scep.
func (a *Authority) SCEPHandler() http.Handler {
	base, err := scepserver.NewService(a.caCert, a.caKey,
		scepserver.CSRSignerContextFunc(a.signCSR),
		scepserver.WithLogger(kitlog.NewNopLogger()), // the library's debug output is not wanted
	)
	if err != nil {
		// NewService only fails if an option does, and ours cannot.
		panic("pki: " + err.Error())
	}
	svc := &service{Service: base}
	h := scepserver.MakeHTTPHandler(scepserver.MakeServerEndpoints(svc), svc, kitlog.NewNopLogger())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path, r2.URL.RawPath = "/scep", ""
		h.ServeHTTP(w, r2)
	})
}

// service is the library's service with an honest capability list.
type service struct{ scepserver.Service }

// GetCACaps lists what this server does. The library's own list claims
// Renewal, SHA-1 and DES3; we do not do renewal and do not want the weak
// algorithms.
func (s *service) GetCACaps(context.Context) ([]byte, error) {
	return []byte("AES\nPOSTPKIOperation\nSCEPStandard\nSHA-256"), nil
}

// GetNextCACert: the library panics here; there is no next CA.
func (s *service) GetNextCACert(context.Context) ([]byte, error) {
	return nil, errors.New("not supported")
}

// signCSR is the SCEP library's hook: it decides whether to issue.
//
// Renewal over SCEP (a device presenting its still valid certificate to get
// a new one without a challenge) is not implemented: every request needs a
// fresh challenge from an enrolment.
//
// Errors here only reach the log; the device is told "bad request" and
// nothing more, so nothing in them is shown to it.
func (a *Authority) signCSR(ctx context.Context, m *scep.CSRReqMessage) (*x509.Certificate, error) {
	csr := m.CSR
	if csr == nil {
		return nil, errors.New("no certificate request")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("certificate request signature: %w", err)
	}
	if err := checkPublicKey(csr.PublicKey); err != nil {
		return nil, err
	}
	cn := csr.Subject.CommonName
	if cn == "" {
		return nil, errors.New("certificate request has no common name")
	}
	if m.ChallengePassword == "" {
		return nil, errors.New("no challenge password")
	}

	// Check everything that can be checked before the challenge is used up,
	// so a malformed request does not burn an enrolment.
	enr, err := a.store.GetEnrollmentByChallenge(ctx, m.ChallengePassword)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil, errors.New("unknown challenge")
		}
		return nil, fmt.Errorf("looking up challenge: %w", err)
	}
	// The lookup is the store's; this comparison is ours.
	if subtle.ConstantTimeCompare([]byte(enr.Challenge), []byte(m.ChallengePassword)) != 1 {
		return nil, errors.New("unknown challenge")
	}
	now := a.now()
	if enr.UsedAt != nil {
		return nil, errors.New("challenge already used")
	}
	if enr.ExpiresAt.Before(now) {
		return nil, errors.New("challenge expired")
	}

	serial, err := a.store.NextSerial(ctx)
	if err != nil {
		return nil, fmt.Errorf("allocating serial: %w", err)
	}

	// MarkEnrollmentUsed is atomic: of two requests with one challenge, one
	// gets an error and loses.
	if err := a.store.MarkEnrollmentUsed(ctx, enr.Challenge, now); err != nil {
		return nil, fmt.Errorf("claiming challenge: %w", err)
	}

	cert, err := a.sign(&x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{a.org}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(deviceValidity),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, csr.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := a.store.PutIssuedCert(ctx, core.IssuedCert{
		Serial:     strconv.FormatInt(serial, 10),
		CommonName: cn,
		Username:   enr.Username,
		SHA256:     fingerprint(cert),
		PEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		NotAfter:   cert.NotAfter.UTC(),
		IssuedAt:   now.UTC(),
	}); err != nil {
		return nil, fmt.Errorf("recording certificate: %w", err)
	}
	a.logger.Info("issued a device certificate", "common_name", cn, "username", enr.Username, "serial", serial)
	return cert, nil
}

func checkPublicKey(pub any) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return errors.New("RSA key shorter than 2048 bits")
		}
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < 256 {
			return errors.New("EC key weaker than P-256")
		}
	default:
		return errors.New("unsupported public key type")
	}
	return nil
}
