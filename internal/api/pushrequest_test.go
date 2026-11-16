package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"

	"openmdm/internal/core"
)

const (
	signedRequestText = "PD94bWwgdmVyc2lvbj0iMS4wIj8+bWFkZS11cC1zaWduZWQtcmVxdWVzdA==" // made up
	topic             = "com.apple.mgmt.External.5f1c2a3e-0000-4000-8000-000000000001"
)

// fakeSigner stands in for mdmcert.download. Given a request it keeps what
// it was sent and, like the real one would by email, "sends" the signed
// request: the text encrypted to the certificate it was given, as PKCS#7,
// hex-encoded.
type fakeSigner struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	status   int    // HTTP status; 0 means 200
	result   string // "success" by default
	reason   string
	rawBody  string // answers this instead of JSON, if set
	hits     int
	got      signRequest
	header   http.Header
	csr      *x509.CertificateRequest
	emailed  string // the hex file
	badEmail bool   // as if for a different key
}

func newFakeSigner(t *testing.T) *fakeSigner {
	f := &fakeSigner{t: t, result: "success"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSigner) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	f.header = r.Header.Clone()
	if r.Method != http.MethodPost {
		http.Error(w, "post only", http.StatusMethodNotAllowed)
		return
	}
	f.got = signRequest{}
	if err := json.NewDecoder(r.Body).Decode(&f.got); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if f.status != 0 && f.status != 200 {
		w.WriteHeader(f.status)
	}
	if f.rawBody != "" {
		_, _ = w.Write([]byte(f.rawBody))
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"result": f.result, "reason": f.reason})
	if f.result != "success" || f.status != 0 {
		return
	}
	csrPEM, _ := base64.StdEncoding.DecodeString(f.got.CSR)
	blk, _ := pem.Decode(csrPEM)
	if blk != nil {
		f.csr, _ = x509.ParseCertificateRequest(blk.Bytes)
	}
	certPEM, _ := base64.StdEncoding.DecodeString(f.got.Encrypt)
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		f.t.Error("fake signer: no certificate in the request")
		return
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		f.t.Errorf("fake signer: %v", err)
		return
	}
	if f.badEmail {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "other"}, NotAfter: time.Now().Add(time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &other.PublicKey, other)
		cert, _ = x509.ParseCertificate(der)
	}
	enc, err := pkcs7.Encrypt([]byte(signedRequestText), []*x509.Certificate{cert})
	if err != nil {
		f.t.Errorf("fake signer: %v", err)
		return
	}
	f.emailed = hex.EncodeToString(enc)
}

func (f *fakeSigner) set(fn func(f *fakeSigner)) { f.mu.Lock(); fn(f); f.mu.Unlock() }

func (e *env) pending() bool {
	m := e.json(asUser(alice), "GET", "/api/v1/settings/push-certificate/request", nil, 200)
	return m["request"].(map[string]any)["pending"] == true
}

func (e *env) blobsEmpty() bool {
	for _, k := range pendingBlobs {
		if b, err := e.store.GetBlob(e.t.Context(), k); err == nil && len(b) != 0 {
			return false
		}
	}
	return true
}

// issuePushCert makes what Apple would hand back: a certificate for the
// key's public half, from a CA, with the APNs topic as the subject's UID.
func issuePushCert(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Apple CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "APSP:5f1c2a3e",
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: topic}},
		},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (e *env) pendingPrivate() *rsa.PrivateKey {
	e.t.Helper()
	sealed, err := e.store.GetBlob(e.t.Context(), blobPendingKey)
	if err != nil {
		e.t.Fatal(err)
	}
	pemKey, err := e.sealer.Open(sealed)
	if err != nil {
		e.t.Fatal(err)
	}
	k, err := parseKeyPEM(pemKey)
	if err != nil {
		e.t.Fatal(err)
	}
	return k
}

const (
	reqPath = "/api/v1/settings/push-certificate/request"
	csrPath = "/api/v1/settings/push-certificate/csr"
)

func TestPushRequestWholeFlow(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	e.mdm.strictPush = true
	e.mdm.push = core.PushInfo{}

	if e.pending() {
		t.Fatal("pending before anything was asked")
	}
	m := e.json(a, "POST", reqPath, map[string]string{"email": "it@corp.example"}, 200)
	req := m["request"].(map[string]any)
	if req["pending"] != true || req["email"] != "it@corp.example" || req["requested_at"] != e.now.Format(time.RFC3339) {
		t.Fatalf("request %v", req)
	}

	// What the service was sent.
	e.signer.mu.Lock()
	got, hdr, csr := e.signer.got, e.signer.header, e.signer.csr
	e.signer.mu.Unlock()
	if hdr.Get("Content-Type") != "application/json" || hdr.Get("User-Agent") != "micromdm/certhelper" {
		t.Errorf("headers %v", hdr)
	}
	if got.Email != "it@corp.example" || got.Key != signingAPIKey || got.CSR == "" || got.Encrypt == "" {
		t.Errorf("request body %+v", got)
	}
	if csr == nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "OpenMDM push certificate" ||
		len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "Example" {
		t.Fatalf("csr %+v", csr)
	}
	pushKey := e.pendingPrivate()
	if pushKey.N.BitLen() != 2048 || csr.PublicKey.(*rsa.PublicKey).N.Cmp(pushKey.N) != 0 {
		t.Error("the CSR is not for the stored key")
	}
	// Stored: keys sealed (not readable as PEM), certificate and meta not.
	for _, k := range []string{blobPendingKey, blobPendingEncKey} {
		b, _ := e.store.GetBlob(t.Context(), k)
		if len(b) == 0 || strings.Contains(string(b), "PRIVATE KEY") {
			t.Errorf("%s is not sealed", k)
		}
	}
	if b, _ := e.store.GetBlob(t.Context(), blobPendingEncCert); !strings.Contains(string(b), "BEGIN CERTIFICATE") {
		t.Error("encryption certificate not kept")
	}
	if ev := e.store.lastEvent(); ev.Kind != "settings.push_request" || ev.Actor != "alice" || !strings.Contains(ev.Detail, "it@corp.example") {
		t.Errorf("event %+v", ev)
	}

	// GET shows it.
	g := e.json(a, "GET", reqPath, nil, 200)["request"].(map[string]any)
	if g["pending"] != true || g["email"] != "it@corp.example" {
		t.Errorf("get %v", g)
	}

	// The emailed file, pasted with line breaks and spaces around it.
	e.signer.mu.Lock()
	emailed := e.signer.emailed
	e.signer.mu.Unlock()
	pasted := "\n  " + emailed[:100] + "\r\n" + emailed[100:] + " \n\n"
	d := e.json(a, "POST", reqPath+"/decrypt", map[string]string{"encrypted": pasted}, 200)
	if d["filename"] != "push-certificate-request.plist.b64" || d["content"] != signedRequestText {
		t.Fatalf("decrypt %v", d)
	}
	if ev := e.store.lastEvent(); ev.Kind != "settings.push_request_decrypted" {
		t.Errorf("event %+v", ev)
	}
	if !e.pending() {
		t.Fatal("decrypting cleared the request")
	}

	// Apple's answer: only the certificate.
	cert := issuePushCert(t, &pushKey.PublicKey)
	u := e.json(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": cert}, 200)
	push := u["push"].(map[string]any)
	if push["configured"] != true || push["topic"] != topic {
		t.Fatalf("push %v", push)
	}
	if info, _ := e.mdm.PushInfo(t.Context()); !info.Configured || info.Topic != topic {
		t.Fatalf("PushInfo %+v", info)
	}
	if e.pending() || !e.blobsEmpty() {
		t.Error("the request is still there after the upload")
	}
	if ev := e.store.lastEvent(); ev.Kind != "settings.push_certificate" || strings.Contains(fmt.Sprint(ev), "PRIVATE") {
		t.Errorf("event %+v", ev)
	}
	// Nothing left to pair with.
	e.errMsg(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": cert}, 400)
	e.errMsg(a, "POST", reqPath+"/decrypt", map[string]string{"encrypted": emailed}, 400)
}

func TestPushRequestCertificateWithKeyClearsPending(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	e.json(a, "POST", reqPath, map[string]string{"email": "it@corp.example"}, 200)
	// The old way still works, and also drops a pending request.
	e.json(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": "CERT", "key_pem": "KEY"}, 200)
	if e.pending() || !e.blobsEmpty() {
		t.Error("pending request survived an upload with its own key")
	}
	// A failed upload with its own key leaves a pending request alone.
	e.json(a, "POST", reqPath, map[string]string{"email": "it@corp.example"}, 200)
	e.mdm.setErr = fmt.Errorf("%w: bad", core.ErrInvalid)
	e.errMsg(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": "C", "key_pem": "K"}, 400)
	if !e.pending() {
		t.Error("a failed upload cleared the request")
	}
}

func TestPushRequestRefused(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	csr := e.json(a, "POST", "/api/v1/settings/push-certificate/csr", nil, 200)["csr_pem"].(string)
	key := e.pendingPrivate()

	e.signer.set(func(f *fakeSigner) { f.result = "failure"; f.reason = "free email addresses are not accepted" })
	msg := e.errMsg(a, "POST", reqPath, map[string]string{"email": "me@gmail.com"}, 502)
	if !strings.Contains(msg, "free email addresses are not accepted") {
		t.Errorf("message %q", msg)
	}
	// The CSR and key stay; the email and the encryption material go.
	check := func() {
		t.Helper()
		g := e.json(a, "GET", reqPath, nil, 200)["request"].(map[string]any)
		if g["pending"] != true || g["email"] != "" {
			t.Errorf("request %v", g)
		}
		if got := e.json(a, "GET", csrPath, nil, 200)["csr_pem"]; got != csr {
			t.Error("the CSR changed")
		}
		if e.pendingPrivate().N.Cmp(key.N) != 0 {
			t.Error("the key changed")
		}
		for _, k := range encryptionBlobs {
			if b, _ := e.store.GetBlob(t.Context(), k); len(b) != 0 {
				t.Errorf("%s kept", k)
			}
		}
	}
	check()

	// Without a reason; and a bad status; and not JSON; and not reachable.
	e.signer.set(func(f *fakeSigner) { f.result = "failure"; f.reason = "" })
	if msg := e.errMsg(a, "POST", reqPath, map[string]string{"email": "me@corp.example"}, 502); !strings.Contains(msg, "mdmcert.download") {
		t.Errorf("message %q", msg)
	}
	e.signer.set(func(f *fakeSigner) { f.status = 500; f.result = "success" })
	if msg := e.errMsg(a, "POST", reqPath, map[string]string{"email": "me@corp.example"}, 502); !strings.Contains(msg, "500") {
		t.Errorf("message %q", msg)
	}
	e.signer.set(func(f *fakeSigner) { f.status = 0; f.rawBody = "<html>nope</html>" })
	e.errMsg(a, "POST", reqPath, map[string]string{"email": "me@corp.example"}, 502)
	e.signer.srv.Close()
	if msg := e.errMsg(a, "POST", reqPath, map[string]string{"email": "me@corp.example"}, 502); !strings.Contains(msg, "could not be reached") {
		t.Errorf("message %q", msg)
	}
	check()
	// Nothing to decrypt.
	e.errMsg(a, "POST", reqPath+"/decrypt", map[string]string{"encrypted": "00"}, 400)

	// With nothing pending beforehand, a refusal leaves a pending CSR too
	// (the request made one), which can be deleted.
	e.json(a, "DELETE", reqPath, nil, 204)
	e.errMsg(a, "POST", reqPath, map[string]string{"email": "me@corp.example"}, 502)
	if !e.pending() {
		t.Error("the CSR made by a refused request was dropped")
	}
	e.json(a, "DELETE", reqPath, nil, 204)
	if e.pending() || !e.blobsEmpty() {
		t.Error("delete left something")
	}
}

func TestPushRequestValidation(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	for _, bad := range []string{"", "nobody", "a b@corp.example", "Name <a@corp.example>", "a@corp.example\r\nBcc: x@y.example"} {
		e.errMsg(a, "POST", reqPath, map[string]string{"email": bad}, 400)
	}
	e.errMsg(a, "POST", reqPath, nil, 400)
	if e.signer.hits != 0 {
		t.Errorf("the service was called %d times for invalid input", e.signer.hits)
	}
}

func TestPushRequestAgainReusesKeyNewEncryption(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	e.json(a, "POST", reqPath, map[string]string{"email": "one@corp.example"}, 200)
	first := e.pendingPrivate()
	e.signer.mu.Lock()
	firstMail := e.signer.emailed
	e.signer.mu.Unlock()
	e.json(a, "POST", reqPath, map[string]string{"email": "two@corp.example"}, 200)
	if second := e.pendingPrivate(); second.N.Cmp(first.N) != 0 {
		t.Error("the pending key was replaced")
	}
	g := e.json(a, "GET", reqPath, nil, 200)["request"].(map[string]any)
	if g["email"] != "two@corp.example" {
		t.Errorf("get %v", g)
	}
	// The first email no longer decrypts.
	e.errMsg(a, "POST", reqPath+"/decrypt", map[string]string{"encrypted": firstMail}, 400)
}

func TestPlainCSR(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	e.mdm.strictPush = true
	e.errMsg(a, "GET", csrPath, nil, 404)

	m := e.json(a, "POST", csrPath, nil, 200)
	if m["filename"] != "openmdm-push.csr" {
		t.Errorf("filename %v", m["filename"])
	}
	req := m["request"].(map[string]any)
	if req["pending"] != true || req["email"] != "" || req["requested_at"] != e.now.Format(time.RFC3339) {
		t.Errorf("request %v", req)
	}
	csrPEM := m["csr_pem"].(string)
	blk, _ := pem.Decode([]byte(csrPEM))
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("not a CSR: %.60s", csrPEM)
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "OpenMDM push certificate" || csr.Subject.Organization[0] != "Example" {
		t.Fatalf("csr %+v %v", csr, err)
	}
	key := e.pendingPrivate()
	if csr.PublicKey.(*rsa.PublicKey).N.Cmp(key.N) != 0 || key.N.BitLen() != 2048 {
		t.Error("the CSR is not for the sealed pending key")
	}
	if b, _ := e.store.GetBlob(t.Context(), blobPendingKey); strings.Contains(string(b), "PRIVATE KEY") {
		t.Error("key not sealed")
	}
	if e.signer.hits != 0 {
		t.Error("a plain CSR called the service")
	}
	if got := e.json(a, "GET", csrPath, nil, 200); got["csr_pem"] != csrPEM || got["filename"] != "openmdm-push.csr" {
		t.Errorf("get %v", got)
	}
	// A decrypt has nothing to work with: no service request was made.
	e.errMsg(a, "POST", reqPath+"/decrypt", map[string]string{"encrypted": "00"}, 400)

	// The countersign request sends that same CSR.
	e.json(a, "POST", reqPath, map[string]string{"email": "it@corp.example"}, 200)
	sent, _ := base64.StdEncoding.DecodeString(e.signer.got.CSR)
	if string(sent) != csrPEM {
		t.Error("the service was sent a different CSR")
	}
	if got := e.json(a, "GET", csrPath, nil, 200); got["csr_pem"] != csrPEM {
		t.Error("the CSR changed")
	}

	// Apple's certificate for the CSR, uploaded alone.
	u := e.json(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": issuePushCert(t, csr.PublicKey.(*rsa.PublicKey))}, 200)
	if u["push"].(map[string]any)["topic"] != topic {
		t.Fatalf("push %v", u)
	}
	if e.pending() || !e.blobsEmpty() {
		t.Error("still pending after the upload")
	}
	e.errMsg(a, "GET", csrPath, nil, 404)
}

func TestNewCSRLeavesConfiguredCertificateAlone(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	e.mdm.strictPush = true
	e.mdm.push = core.PushInfo{}
	// A certificate in use, made the plain way.
	e.json(a, "POST", csrPath, nil, 200)
	e.json(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": issuePushCert(t, &e.pendingPrivate().PublicKey)}, 200)
	before, _ := e.mdm.PushInfo(t.Context())
	calls := e.mdm.setCalls
	if !before.Configured {
		t.Fatal("not configured")
	}

	// Renewal: a new CSR, then a second one replacing it.
	first := e.json(a, "POST", csrPath, nil, 200)["csr_pem"]
	second := e.json(a, "POST", csrPath, nil, 200)["csr_pem"]
	if first == second {
		t.Error("a new CSR reused the old key")
	}
	if got := e.json(a, "GET", csrPath, nil, 200)["csr_pem"]; got != second {
		t.Error("GET does not return the latest CSR")
	}
	if after, _ := e.mdm.PushInfo(t.Context()); after != before || e.mdm.setCalls != calls {
		t.Errorf("the configured certificate was disturbed: %+v -> %+v", before, after)
	}
	// A certificate that does not fit the new key is refused; the old one stays.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	e.errMsg(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": issuePushCert(t, &other.PublicKey)}, 400)
	if after, _ := e.mdm.PushInfo(t.Context()); after != before || !e.pending() {
		t.Error("a refused upload changed things")
	}
	// Delete forgets everything pending, and still not the configured one.
	e.json(a, "DELETE", reqPath, nil, 204)
	if after, _ := e.mdm.PushInfo(t.Context()); after != before || !e.blobsEmpty() {
		t.Error("delete touched the wrong thing")
	}
	e.errMsg(a, "GET", csrPath, nil, 404)
}

func TestPushRequestDecryptErrors(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	// Nothing pending.
	if msg := e.errMsg(a, "POST", reqPath+"/decrypt", map[string]string{"encrypted": "00"}, 400); !strings.Contains(msg, "no pending") {
		t.Errorf("message %q", msg)
	}
	e.json(a, "POST", reqPath, map[string]string{"email": "it@corp.example"}, 200)
	e.signer.mu.Lock()
	emailed := e.signer.emailed
	e.signer.mu.Unlock()

	for name, in := range map[string]string{
		"empty":       "  \n ",
		"not hex":     "this is not hexadecimal at all",
		"odd hex":     "abc",
		"not pkcs7":   "deadbeef",
		"base64 text": base64.StdEncoding.EncodeToString([]byte("hello")),
		"truncated":   emailed[:len(emailed)/2],
	} {
		msg := e.errMsg(a, "POST", reqPath+"/decrypt", map[string]string{"encrypted": in}, 400)
		if msg == "" || strings.Contains(msg, "panic") {
			t.Errorf("%s: message %q", name, msg)
		}
	}
	// Encrypted to somebody else's certificate.
	e.signer.set(func(f *fakeSigner) { f.badEmail = true })
	e.json(a, "POST", reqPath, map[string]string{"email": "it@corp.example"}, 200)
	e.signer.mu.Lock()
	wrong := e.signer.emailed
	e.signer.mu.Unlock()
	if msg := e.errMsg(a, "POST", reqPath+"/decrypt", map[string]string{"encrypted": wrong}, 400); !strings.Contains(msg, "cannot be decrypted") {
		t.Errorf("message %q", msg)
	}
	if !e.pending() {
		t.Error("a failed decrypt cleared the request")
	}
}

func TestPushRequestCertificateForAnotherKey(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	e.mdm.strictPush = true
	e.json(a, "POST", reqPath, map[string]string{"email": "it@corp.example"}, 200)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	e.errMsg(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": issuePushCert(t, &other.PublicKey)}, 400)
	if !e.pending() || e.blobsEmpty() {
		t.Error("the pending request was lost")
	}
	if info, _ := e.mdm.PushInfo(t.Context()); info.Topic == topic {
		t.Error("a mismatched certificate was installed")
	}
	// The right one still works afterwards.
	e.json(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": issuePushCert(t, &e.pendingPrivate().PublicKey)}, 200)
}

func TestPushRequestDelete(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	e.json(a, "DELETE", reqPath, nil, 204) // nothing pending is fine
	e.json(a, "POST", reqPath, map[string]string{"email": "it@corp.example"}, 200)
	e.json(a, "DELETE", reqPath, nil, 204)
	if e.pending() || !e.blobsEmpty() {
		t.Error("still pending")
	}
	if ev := e.store.lastEvent(); ev.Kind != "settings.push_request_deleted" || ev.Actor != "alice" {
		t.Errorf("event %+v", ev)
	}
	// Certificate alone, nothing pending.
	if msg := e.errMsg(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": "C"}, 400); !strings.Contains(msg, "key_pem") {
		t.Errorf("message %q", msg)
	}
}

func TestPushRequestAdminOnly(t *testing.T) {
	e := newEnv(t)
	g := asUser(george)
	for _, c := range []struct{ method, path string }{
		{"GET", csrPath}, {"POST", csrPath}, {"GET", reqPath}, {"POST", reqPath}, {"DELETE", reqPath}, {"POST", reqPath + "/decrypt"},
	} {
		e.errMsg(g, c.method, c.path, map[string]string{"email": "it@corp.example", "encrypted": "00"}, 403)
	}
	if e.signer.hits != 0 {
		t.Error("a non-admin reached the service")
	}
	e.errMsg(nil, "GET", reqPath, nil, 401)
}
