package api

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"howett.net/plist"

	"openmdm/internal/api/applecerts"
	"openmdm/internal/core"
)

const (
	vendorPath = "/api/v1/settings/vendor-certificate"
	signPath   = "/api/v1/settings/push-certificate/vendor-sign"
)

// testVendor is a throwaway "vendor": a CA and a leaf signed by it, standing
// in for an MDM Vendor CSR Signing Certificate (which only Apple can issue).
type testVendor struct {
	ca      *x509.Certificate
	caKey   *rsa.PrivateKey
	leaf    *x509.Certificate
	leafKey *rsa.PrivateKey
}

func newTestVendor(t *testing.T, notBefore, notAfter time.Time) *testVendor {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Vendor CA", Organization: []string{"Vendor Test"}},
		NotBefore: notBefore, NotAfter: notAfter.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "MDM Vendor: Test", Organization: []string{"Vendor Test"}},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	return &testVendor{ca: ca, caKey: caKey, leaf: leaf, leafKey: leafKey}
}

func (v *testVendor) certPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.leaf.Raw}))
}

func (v *testVendor) keyPEM() string { return string(pemKey(v.leafKey)) }

func (e *env) newVendor() *testVendor {
	return newTestVendor(e.t, e.now.Add(-24*time.Hour), e.now.AddDate(1, 0, 0))
}

// signed is what vendor-sign returned, taken apart.
type signed struct {
	csrDER, sig []byte
	chain       string
	keys        []string
	request     map[string]any
}

func (e *env) vendorSign() signed {
	e.t.Helper()
	m := e.json(asUser(alice), "POST", signPath, nil, 200)
	if m["filename"] != "push-certificate-request.plist.b64" {
		e.t.Errorf("filename %v", m["filename"])
	}
	xml, err := base64.StdEncoding.DecodeString(m["content"].(string))
	if err != nil {
		e.t.Fatalf("content is not base64: %v", err)
	}
	var p map[string]any
	if _, err := plist.Unmarshal(xml, &p); err != nil {
		e.t.Fatalf("content is not a plist: %v", err)
	}
	if !bytes.HasPrefix(xml, []byte("<?xml")) {
		e.t.Errorf("not an XML property list: %.40s", xml)
	}
	var s signed
	for k := range p {
		s.keys = append(s.keys, k)
	}
	if len(p) != 3 {
		e.t.Fatalf("keys %v", s.keys)
	}
	var err1, err2 error
	s.csrDER, err1 = base64.StdEncoding.DecodeString(p["PushCertRequestCSR"].(string))
	s.sig, err2 = base64.StdEncoding.DecodeString(p["PushCertSignature"].(string))
	if err1 != nil || err2 != nil {
		e.t.Fatalf("not base64: %v %v", err1, err2)
	}
	s.chain = p["PushCertCertificateChain"].(string)
	s.request = m["request"].(map[string]any)
	return s
}

func (s signed) check(t *testing.T, v *testVendor, pushKey *rsa.PrivateKey) {
	t.Helper()
	// Exactly the three keys.
	got := map[string]bool{}
	for _, k := range s.keys {
		got[k] = true
	}
	for _, k := range []string{"PushCertRequestCSR", "PushCertSignature", "PushCertCertificateChain"} {
		if !got[k] {
			t.Errorf("missing key %s in %v", k, s.keys)
		}
	}
	// The CSR is the pending one.
	csr, err := x509.ParseCertificateRequest(s.csrDER)
	if err != nil {
		t.Fatalf("CSR does not parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature: %v", err)
	}
	if !csr.PublicKey.(*rsa.PublicKey).Equal(&pushKey.PublicKey) {
		t.Error("the CSR is not for the pending push key")
	}
	// The signature is SHA256WithRSA (PKCS#1 v1.5) over the DER CSR.
	sum := sha256.Sum256(s.csrDER)
	if err := rsa.VerifyPKCS1v15(v.leaf.PublicKey.(*rsa.PublicKey), crypto.SHA256, sum[:], s.sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
	// The chain: vendor, WWDR G3, root; each a PEM block of 64-char lines.
	if n := strings.Count(s.chain, "-----BEGIN CERTIFICATE-----"); n != 3 {
		t.Fatalf("%d certificates in the chain", n)
	}
	want := []*x509.Certificate{v.leaf, applecerts.WWDRG3(), applecerts.Root()}
	rest := []byte(s.chain)
	for i := range want {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil || blk.Type != "CERTIFICATE" || !bytes.Equal(blk.Bytes, want[i].Raw) {
			t.Fatalf("chain certificate %d is not the expected one", i)
		}
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		t.Errorf("trailing data after the chain: %q", rest)
	}
	inBlock := false
	var lines []string
	flush := func() {
		for i, l := range lines {
			if len(l) > 64 || (i < len(lines)-1 && len(l) != 64) {
				t.Errorf("PEM line %q is not 64 characters", l)
			}
		}
		lines = nil
	}
	for _, l := range strings.Split(strings.TrimSpace(s.chain), "\n") {
		switch {
		case strings.HasPrefix(l, "-----BEGIN"):
			inBlock = true
		case strings.HasPrefix(l, "-----END"):
			inBlock = false
			flush()
		case inBlock:
			lines = append(lines, l)
		default:
			t.Errorf("stray line in the chain: %q", l)
		}
	}
	if strings.Contains(s.chain, "\r") {
		t.Error("CR in the chain")
	}
}

func TestVendorCertificateAndSign_PEM(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	v := e.newVendor()

	m := e.json(a, "GET", vendorPath, nil, 200)
	if info := m["vendor"].(map[string]any); info["configured"] != false {
		t.Fatalf("vendor %v", info)
	}

	m = e.json(a, "PUT", vendorPath, map[string]string{"certificate_pem": v.certPEM(), "key_pem": v.keyPEM()}, 200)
	info := m["vendor"].(map[string]any)
	sum := sha256.Sum256(v.leaf.Raw)
	if info["configured"] != true || info["subject"] != v.leaf.Subject.String() ||
		info["not_after"] != v.leaf.NotAfter.UTC().Format(time.RFC3339) || info["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("vendor %v", info)
	}
	// Not issued by Apple's WWDR G3, which no test certificate can be.
	if w, _ := m["warning"].(string); !strings.Contains(w, "WWDR G3") || !strings.Contains(w, "may reject") {
		t.Errorf("warning %q", w)
	}
	if ev := e.store.lastEvent(); ev.Kind != "settings.vendor_certificate_set" || ev.Actor != "alice" {
		t.Errorf("event %+v", ev)
	}
	m = e.json(a, "GET", vendorPath, nil, 200)
	if m["vendor"].(map[string]any)["sha256"] != hex.EncodeToString(sum[:]) || m["warning"] != nil {
		t.Errorf("GET %v", m)
	}

	// Stored: the certificate in the clear, the key sealed.
	cb, _ := e.store.GetBlob(t.Context(), "vendor/cert")
	kb, _ := e.store.GetBlob(t.Context(), "vendor/key")
	if !bytes.Contains(cb, []byte("BEGIN CERTIFICATE")) || bytes.Contains(kb, []byte("PRIVATE KEY")) || len(kb) == 0 {
		t.Errorf("blobs: cert %q, key %d bytes", cb, len(kb))
	}
	if opened, err := e.sealer.Open(kb); err != nil || !bytes.Contains(opened, []byte("PRIVATE KEY")) {
		t.Errorf("key blob does not open: %v", err)
	}

	// No pending request: vendor-sign makes one and signs its CSR.
	if e.pending() {
		t.Fatal("pending already")
	}
	s := e.vendorSign()
	if s.request["pending"] != true {
		t.Errorf("request %v", s.request)
	}
	if !e.pending() {
		t.Fatal("vendor-sign did not leave a pending request")
	}
	s.check(t, v, e.pendingPrivate())
	if ev := e.store.lastEvent(); ev.Kind != "settings.push_vendor_sign" || ev.Actor != "alice" || strings.Contains(ev.Detail, "PRIVATE") {
		t.Errorf("event %+v", ev)
	}

	// A pending request is reused: the same CSR, signed again.
	s2 := e.vendorSign()
	if !bytes.Equal(s.csrDER, s2.csrDER) {
		t.Error("a second vendor-sign made a new CSR")
	}
	if s2.request["requested_at"] != s.request["requested_at"] {
		t.Error("the pending request changed")
	}
	s2.check(t, v, e.pendingPrivate())

	// ...including one made with POST .../csr.
	cm := e.json(a, "POST", csrPath, nil, 200)
	blk, _ := pem.Decode([]byte(cm["csr_pem"].(string)))
	s3 := e.vendorSign()
	if !bytes.Equal(blk.Bytes, s3.csrDER) || bytes.Equal(s3.csrDER, s.csrDER) {
		t.Error("vendor-sign did not use the CSR just made")
	}
	s3.check(t, v, e.pendingPrivate())

	// The certificate Apple returns goes to the existing route, and the
	// request is still pending until then.
	e.mdm.strictPush = true
	e.json(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": issuePushCert(t, &e.pendingPrivate().PublicKey)}, 200)
	if e.pending() {
		t.Error("still pending after the certificate was uploaded")
	}

	// Delete.
	if rr := e.do(a, "DELETE", vendorPath, nil); rr.Code != 204 {
		t.Fatalf("delete %d", rr.Code)
	}
	if ev := e.store.lastEvent(); ev.Kind != "settings.vendor_certificate_deleted" {
		t.Errorf("event %+v", ev)
	}
	if info := e.json(a, "GET", vendorPath, nil, 200)["vendor"].(map[string]any); info["configured"] != false {
		t.Errorf("vendor after delete %v", info)
	}
	if k, _ := e.store.GetBlob(t.Context(), "vendor/key"); len(k) != 0 {
		t.Error("key not cleared")
	}
	if msg := e.errMsg(a, "POST", signPath, nil, 400); !strings.Contains(msg, "vendor certificate") {
		t.Errorf("message %q", msg)
	}
	if rr := e.do(a, "DELETE", vendorPath, nil); rr.Code != 204 {
		t.Errorf("second delete %d", rr.Code)
	}

	// No key material anywhere.
	for _, seen := range append(e.seen, e.logs.String()) {
		if strings.Contains(seen, "PRIVATE KEY") {
			t.Fatalf("a private key leaked: %.100s", seen)
		}
	}
	for _, ev := range mustEvents(t, e) {
		if strings.Contains(ev.Detail+ev.Subject, "PRIVATE") {
			t.Errorf("event %+v", ev)
		}
	}
}

func TestVendorCertificate_DERBase64AndChain(t *testing.T) {
	e := newEnv(t)
	v := e.newVendor()
	der := base64.StdEncoding.EncodeToString(v.leaf.Raw)
	// With line breaks, as a pasted file might have.
	wrapped := der[:40] + "\n" + der[40:]
	e.json(asUser(alice), "PUT", vendorPath, map[string]string{"certificate_pem": wrapped, "key_pem": v.keyPEM()}, 200)
	e.vendorSign().check(t, v, e.pendingPrivate())

	// A PEM file with the whole chain: the certificate that matches the key is used.
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.ca.Raw}))
	e.json(asUser(alice), "PUT", vendorPath, map[string]string{"certificate_pem": ca + v.certPEM(), "key_pem": v.keyPEM()}, 200)
	if info := e.json(asUser(alice), "GET", vendorPath, nil, 200)["vendor"].(map[string]any); info["subject"] != v.leaf.Subject.String() {
		t.Errorf("vendor %v", info)
	}

	// A PKCS#8 key works too.
	p8, _ := x509.MarshalPKCS8PrivateKey(v.leafKey)
	e.json(asUser(alice), "PUT", vendorPath, map[string]string{"certificate_pem": v.certPEM(), "key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}))}, 200)
}

func TestVendorCertificateAndSign_P12(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	v := e.newVendor()
	p12 := buildP12(t, v.leafKey, "p4ssw0rd-Ünï", v.ca, v.leaf) // as Keychain exports: the chain comes along

	e.json(a, "PUT", vendorPath, map[string]string{"p12": base64.StdEncoding.EncodeToString(p12), "password": "p4ssw0rd-Ünï"}, 200)
	if info := e.json(a, "GET", vendorPath, nil, 200)["vendor"].(map[string]any); info["configured"] != true || info["subject"] != v.leaf.Subject.String() {
		t.Fatalf("vendor %v", info)
	}
	e.vendorSign().check(t, v, e.pendingPrivate())
	for _, seen := range append(e.seen, e.logs.String()) {
		if strings.Contains(seen, "p4ssw0rd") {
			t.Fatal("the p12 password leaked")
		}
	}

	bad := func(body map[string]string, want string) {
		t.Helper()
		if msg := e.errMsg(a, "PUT", vendorPath, body, 400); !strings.Contains(msg, want) {
			t.Errorf("%v: message %q, want it to contain %q", keysOf(body), msg, want)
		}
	}
	enc := base64.StdEncoding.EncodeToString(p12)
	bad(map[string]string{"p12": enc, "password": "wrong"}, "password is wrong")
	bad(map[string]string{"p12": enc}, "password is wrong")
	bad(map[string]string{"p12": "!!!", "password": "x"}, "base64")
	bad(map[string]string{"p12": base64.StdEncoding.EncodeToString([]byte("not a p12")), "password": "x"}, ".p12")
	bad(map[string]string{"p12": enc, "password": "p4ssw0rd-Ünï", "certificate_pem": v.certPEM()}, "not both")
}

func TestVendorCertificate_BadInput(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	v := e.newVendor()
	other := e.newVendor()

	bad := func(body any, want string) {
		t.Helper()
		if msg := e.errMsg(a, "PUT", vendorPath, body, 400); !strings.Contains(strings.ToLower(msg), strings.ToLower(want)) {
			t.Errorf("message %q, want it to contain %q", msg, want)
		}
	}
	// The key is someone else's.
	bad(map[string]string{"certificate_pem": v.certPEM(), "key_pem": other.keyPEM()}, "does not belong")
	// Not RSA.
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalECPrivateKey(ek)
	bad(map[string]string{"certificate_pem": v.certPEM(), "key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}))}, "RSA")
	p8, _ := x509.MarshalPKCS8PrivateKey(ek)
	bad(map[string]string{"certificate_pem": v.certPEM(), "key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}))}, "RSA")
	// An EC certificate.
	ecTpl := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "ec"}, NotBefore: e.now.Add(-time.Hour), NotAfter: e.now.AddDate(1, 0, 0)}
	ecCert, _ := x509.CreateCertificate(rand.Reader, ecTpl, ecTpl, &ek.PublicKey, ek)
	bad(map[string]string{"certificate_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ecCert})), "key_pem": v.keyPEM()}, "RSA")
	// Garbage.
	bad(map[string]string{"certificate_pem": "hello", "key_pem": v.keyPEM()}, "certificate")
	bad(map[string]string{"certificate_pem": v.certPEM(), "key_pem": "hello"}, "private key")
	bad(map[string]string{"certificate_pem": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", "key_pem": v.keyPEM()}, "certificate")
	// Encrypted key.
	bad(map[string]string{"certificate_pem": v.certPEM(), "key_pem": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"}, "passphrase")
	// Incomplete or mixed.
	bad(map[string]string{"certificate_pem": v.certPEM()}, "key_pem")
	bad(map[string]string{"key_pem": v.keyPEM()}, "certificate_pem")
	bad(map[string]string{}, "either")
	bad(map[string]string{"certificate_pem": v.certPEM(), "key_pem": v.keyPEM(), "password": "x"}, "password")
	bad(`{"certificate_pem": "x", "unknown": 1}`, "invalid JSON")
	// Expired, and not yet valid.
	old := newTestVendor(t, e.now.AddDate(-2, 0, 0), e.now.AddDate(-1, 0, 0))
	bad(map[string]string{"certificate_pem": old.certPEM(), "key_pem": old.keyPEM()}, "expired")
	future := newTestVendor(t, e.now.AddDate(0, 1, 0), e.now.AddDate(1, 0, 0))
	bad(map[string]string{"certificate_pem": future.certPEM(), "key_pem": future.keyPEM()}, "not valid until")

	// Nothing was stored by any of it.
	if info := e.json(a, "GET", vendorPath, nil, 200)["vendor"].(map[string]any); info["configured"] != false {
		t.Errorf("vendor %v", info)
	}
	for _, k := range []string{"vendor/cert", "vendor/key"} {
		if b, err := e.store.GetBlob(t.Context(), k); err == nil && len(b) != 0 {
			t.Errorf("%s stored", k)
		}
	}
}

func TestVendorSign_Errors(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)

	// Nothing configured: 400, and no request is started as a side effect.
	if msg := e.errMsg(a, "POST", signPath, nil, 400); !strings.Contains(msg, "no MDM vendor certificate") {
		t.Errorf("message %q", msg)
	}
	if e.pending() {
		t.Error("a failed vendor-sign made a pending request")
	}

	// Expired since it was uploaded.
	v := e.newVendor()
	e.json(a, "PUT", vendorPath, map[string]string{"certificate_pem": v.certPEM(), "key_pem": v.keyPEM()}, 200)
	e.now = e.now.AddDate(1, 0, 1)
	if msg := e.errMsg(a, "POST", signPath, nil, 400); !strings.Contains(msg, "expired") {
		t.Errorf("message %q", msg)
	}
	if e.pending() {
		t.Error("a failed vendor-sign made a pending request")
	}
	// It can still be seen, and replaced.
	if info := e.json(a, "GET", vendorPath, nil, 200)["vendor"].(map[string]any); info["configured"] != true {
		t.Errorf("vendor %v", info)
	}
	nv := newTestVendor(t, e.now.Add(-time.Hour), e.now.AddDate(1, 0, 0))
	e.json(a, "PUT", vendorPath, map[string]string{"certificate_pem": nv.certPEM(), "key_pem": nv.keyPEM()}, 200)
	e.vendorSign().check(t, nv, e.pendingPrivate())
}

func TestVendorRoutes_AdminOnly(t *testing.T) {
	e := newEnv(t)
	v := e.newVendor()
	body := map[string]string{"certificate_pem": v.certPEM(), "key_pem": v.keyPEM()}
	for _, as := range []*core.User{asUser(george), asUser(harry)} {
		for _, rt := range []struct {
			method, path string
			body         any
		}{
			{"GET", vendorPath, nil}, {"PUT", vendorPath, body}, {"DELETE", vendorPath, nil}, {"POST", signPath, nil},
		} {
			if rr := e.do(as, rt.method, rt.path, rt.body); rr.Code != 403 {
				t.Errorf("%s %s as %s: %d", rt.method, rt.path, as.Username, rr.Code)
			}
		}
	}
	if rr := e.do(nil, "GET", vendorPath, nil); rr.Code != 401 {
		t.Errorf("not signed in: %d", rr.Code)
	}
	// Nothing happened.
	if info := e.json(asUser(alice), "GET", vendorPath, nil, 200)["vendor"].(map[string]any); info["configured"] != false {
		t.Errorf("vendor %v", info)
	}
	if e.pending() {
		t.Error("pending")
	}
	// The CSRF header is required.
	if rr := e.doHdr(asUser(alice), "POST", signPath, nil, nil); rr.Code != 403 {
		t.Errorf("no csrf header: %d", rr.Code)
	}
}

func keysOf(m map[string]string) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func mustEvents(t *testing.T, e *env) []eventLite {
	t.Helper()
	evs, err := e.store.ListEvents(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []eventLite
	for _, ev := range evs {
		out = append(out, eventLite{Detail: ev.Detail, Subject: ev.Subject})
	}
	return out
}

type eventLite struct{ Detail, Subject string }

// --- a minimal PKCS#12 writer (RFC 7292), only for these tests: the
// production code only reads .p12 files ---

var (
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidCertBag    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidKeyBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidX509Cert   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidPBE3DES    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidSHA1       = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	p12Iterations = 2048
)

func bmp(pw string) []byte {
	out := make([]byte, 0, 2*len(pw)+2)
	for _, c := range utf16.Encode([]rune(pw)) {
		out = append(out, byte(c>>8), byte(c))
	}
	return append(out, 0, 0)
}

// p12KDF is RFC 7292 appendix B.2 with SHA-1.
func p12KDF(pass, salt []byte, id byte, iter, n int) []byte {
	const u, v = 20, 64
	fill := func(b []byte) []byte {
		if len(b) == 0 {
			return nil
		}
		out := make([]byte, v*((len(b)+v-1)/v))
		for i := range out {
			out[i] = b[i%len(b)]
		}
		return out
	}
	I := append(fill(salt), fill(pass)...)
	D := bytes.Repeat([]byte{id}, v)
	var out []byte
	for len(out) < n {
		h := sha1.Sum(append(append([]byte{}, D...), I...))
		A := h[:]
		for i := 1; i < iter; i++ {
			h = sha1.Sum(A)
			A = h[:]
		}
		out = append(out, A...)
		B := new(big.Int).SetBytes(bytes.Repeat(A, v/u+1)[:v])
		B.Add(B, big.NewInt(1))
		for j := 0; j < len(I)/v; j++ {
			x := new(big.Int).SetBytes(I[j*v : (j+1)*v])
			x.Add(x, B)
			b := x.Bytes()
			if len(b) > v {
				b = b[len(b)-v:]
			}
			blk := I[j*v : (j+1)*v]
			clear(blk)
			copy(blk[v-len(b):], b)
		}
	}
	return out[:n]
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type p12Bag struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue // already wrapped in [0], see ctx0
}

// ctx0 is der inside an explicit [0] tag.
func ctx0(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der}
}

type p12ContentInfo struct {
	Type    asn1.ObjectIdentifier
	Content []byte `asn1:"tag:0,explicit"`
}

// buildP12 writes a .p12 with the key (shrouded with 3DES, like Keychain's
// legacy export) and the certificates, MAC'd with the password.
func buildP12(t *testing.T, key *rsa.PrivateKey, password string, certs ...*x509.Certificate) []byte {
	t.Helper()
	pw := bmp(password)
	var bags []p12Bag
	for _, c := range certs {
		cb := mustMarshal(t, struct {
			ID   asn1.ObjectIdentifier
			Cert []byte `asn1:"tag:0,explicit"`
		}{oidX509Cert, c.Raw})
		bags = append(bags, p12Bag{oidCertBag, ctx0(cb)})
	}

	p8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, 8)
	_, _ = rand.Read(salt)
	blk, _ := des.NewTripleDESCipher(p12KDF(pw, salt, 1, p12Iterations, 24))
	pad := 8 - len(p8)%8
	plain := append(append([]byte{}, p8...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	enc := make([]byte, len(plain))
	cipher.NewCBCEncrypter(blk, p12KDF(pw, salt, 2, p12Iterations, 8)).CryptBlocks(enc, plain)
	params := mustMarshal(t, struct {
		Salt  []byte
		Iters int
	}{salt, p12Iterations})
	epki := mustMarshal(t, struct {
		Alg  pkix.AlgorithmIdentifier
		Data []byte
	}{pkix.AlgorithmIdentifier{Algorithm: oidPBE3DES, Parameters: asn1.RawValue{FullBytes: params}}, enc})
	bags = append(bags, p12Bag{oidKeyBag, ctx0(epki)})

	// Two items in the authenticated safe, as Keychain and OpenSSL write them
	// (and as x/crypto/pkcs12 insists): the certificates, then the key.
	certBags, keyBags := mustMarshal(t, bags[:len(bags)-1]), mustMarshal(t, bags[len(bags)-1:])
	authSafe := mustMarshal(t, []p12ContentInfo{{oidData, certBags}, {oidData, keyBags}})

	macSalt := make([]byte, 8)
	_, _ = rand.Read(macSalt)
	mac := hmac.New(sha1.New, p12KDF(pw, macSalt, 3, p12Iterations, 20))
	mac.Write(authSafe)
	type digestInfo struct {
		Alg    pkix.AlgorithmIdentifier
		Digest []byte
	}
	type macData struct {
		Mac   digestInfo
		Salt  []byte
		Iters int
	}
	return mustMarshal(t, struct {
		Version  int
		AuthSafe p12ContentInfo
		Mac      macData
	}{
		3,
		p12ContentInfo{oidData, authSafe},
		macData{digestInfo{pkix.AlgorithmIdentifier{Algorithm: oidSHA1, Parameters: asn1.NullRawValue}, mac.Sum(nil)}, macSalt, p12Iterations},
	})
}
