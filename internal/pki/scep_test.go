package pki

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kitlog "github.com/go-kit/kit/log"
	scepclient "github.com/micromdm/scep/v2/client"
	"github.com/smallstep/scep"
	"github.com/smallstep/scep/x509util"
)

type scepDevice struct {
	key    *rsa.PrivateKey
	signer *x509.Certificate // the throwaway self-signed cert SCEP clients sign with
}

func newDevice(t *testing.T) *scepDevice {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SCEP SIGNER"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &scepDevice{key: key, signer: c}
}

// enrol runs GetCACert and PKCSReq against url and returns the CertRep.
func (d *scepDevice) enrol(t *testing.T, url, cn, org, challenge string) *scep.PKIMessage {
	t.Helper()
	cl, err := scepclient.New(url, kitlog.NewNopLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// The client learns from GetCACaps whether it may POST.
	if _, err := cl.GetCACaps(ctx); err != nil {
		t.Fatal(err)
	}
	caBytes, n, err := cl.GetCACert(ctx, "")
	if err != nil || n > 1 { // the client reports 0 for a single certificate
		t.Fatalf("GetCACert: %v (%d certs)", err, n)
	}
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{
			Subject:            pkix.Name{CommonName: cn, Organization: []string{org}},
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		ChallengePassword: challenge,
	}, d.key)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(csrDER)
	req, err := scep.NewCSRRequest(csr, &scep.PKIMessage{
		MessageType: scep.PKCSReq, Recipients: []*x509.Certificate{ca},
		SignerKey: d.key, SignerCert: d.signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.PKIOperation(ctx, req.Raw)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := scep.ParsePKIMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	if rep.PKIStatus == scep.SUCCESS {
		if err := rep.DecryptPKIEnvelope(d.signer, d.key); err != nil {
			t.Fatal(err)
		}
	}
	return rep
}

func serve(t *testing.T, a *Authority) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/scep", a.SCEPHandler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL + "/scep"
}

func TestSCEPRoundTrip(t *testing.T) {
	a, st, _ := newTestAuthority(t)
	url := serve(t, a)
	st.addEnrollment("good-challenge", "alice", time.Now().Add(time.Hour))
	d := newDevice(t)

	rep := d.enrol(t, url, "alice-macbook", "Evil Corp", "good-challenge")
	if rep.PKIStatus != scep.SUCCESS {
		t.Fatalf("status %v, fail info %v", rep.PKIStatus, rep.FailInfo)
	}
	cert := rep.CertRepMessage.Certificate
	roots := x509.NewCertPool()
	roots.AddCert(a.CACertificate())
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "alice-macbook" || len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "Acme" {
		t.Errorf("subject %v", cert.Subject)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Errorf("key usage %v", cert.KeyUsage)
	}
	if d := cert.NotAfter.Sub(cert.NotBefore); d < 2*365*24*time.Hour || d > 2*365*24*time.Hour+time.Hour {
		t.Errorf("validity %v", d)
	}
	if !cert.PublicKey.(*rsa.PublicKey).Equal(&d.key.PublicKey) {
		t.Error("certificate is for another key")
	}

	rec, err := st.GetIssuedCertBySHA256(context.Background(), fingerprint(cert))
	if err != nil {
		t.Fatalf("not recorded: %v", err)
	}
	if rec.Username != "alice" || rec.CommonName != "alice-macbook" || rec.Serial != cert.SerialNumber.String() ||
		!rec.NotAfter.Equal(cert.NotAfter) || rec.IssuedAt.IsZero() || !strings.Contains(rec.PEM, "BEGIN CERTIFICATE") {
		t.Errorf("record %+v", rec)
	}
	if err := a.VerifyIssued(context.Background(), cert); err != nil {
		t.Errorf("VerifyIssued: %v", err)
	}

	// The same challenge, again.
	if rep := newDevice(t).enrol(t, url, "x", "", "good-challenge"); rep.PKIStatus != scep.FAILURE {
		t.Errorf("reused challenge: status %v", rep.PKIStatus)
	}
	if len(st.certs) != 1 {
		t.Errorf("%d certificates recorded", len(st.certs))
	}
}

func TestSCEPRefusals(t *testing.T) {
	a, st, _ := newTestAuthority(t)
	url := serve(t, a)
	st.addEnrollment("expired", "bob", time.Now().Add(-time.Minute))
	for _, c := range []string{"expired", "never-heard-of-it"} {
		if rep := newDevice(t).enrol(t, url, "dev", "", c); rep.PKIStatus != scep.FAILURE {
			t.Errorf("challenge %q: status %v", c, rep.PKIStatus)
		}
	}
	if st.enrols["expired"].UsedAt != nil {
		t.Error("an expired challenge was claimed")
	}
	if len(st.certs) != 0 {
		t.Error("a certificate was issued")
	}
	// No challenge at all, and no common name.
	if rep := newDevice(t).enrol(t, url, "dev", "", ""); rep.PKIStatus != scep.FAILURE {
		t.Errorf("empty challenge: %v", rep.PKIStatus)
	}
	st.addEnrollment("fine", "bob", time.Now().Add(time.Hour))
	if rep := newDevice(t).enrol(t, url, "", "", "fine"); rep.PKIStatus != scep.FAILURE {
		t.Errorf("no CN: %v", rep.PKIStatus)
	}
	if st.enrols["fine"].UsedAt != nil {
		t.Error("a malformed request burnt the challenge")
	}
}

func TestSCEPChallengeUsedOnceUnderRace(t *testing.T) {
	a, st, _ := newTestAuthority(t)
	url := serve(t, a)
	st.addEnrollment("race", "carol", time.Now().Add(time.Hour))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		d := newDevice(t)
		go func() {
			defer wg.Done()
			if d.enrol(t, url, "dev", "", "race").PKIStatus == scep.SUCCESS {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Errorf("%d requests won one challenge", wins.Load())
	}
}

func TestSCEPCapsAndMounting(t *testing.T) {
	a, _, _ := newTestAuthority(t)
	h := a.SCEPHandler()
	// Mounted under a prefix that is stripped, as a router would.
	outer := http.NewServeMux()
	outer.Handle("/scep/", http.StripPrefix("/scep", h))
	outer.Handle("/scep", h)
	srv := httptest.NewServer(outer)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/scep?operation=GetCACaps")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	caps := string(buf[:n])
	for _, want := range []string{"SHA-256", "AES", "POSTPKIOperation", "SCEPStandard"} {
		if !strings.Contains(caps, want) {
			t.Errorf("caps %q lack %s", caps, want)
		}
	}
	if strings.Contains(caps, "Renewal") {
		t.Error("renewal is advertised but not implemented")
	}

	resp2, err := http.Get(srv.URL + "/scep/?operation=GetCACert")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 || resp2.Header.Get("Content-Type") != "application/x-x509-ca-cert" {
		t.Errorf("GetCACert: %d %s", resp2.StatusCode, resp2.Header.Get("Content-Type"))
	}
}
