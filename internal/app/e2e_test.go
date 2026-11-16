package app_test

// An end-to-end test: a simulated device (and a few simulated people) talk to
// the real server, built by app.Build, over real HTTP. Nothing in it is a
// fake except Apple's push service and single sign-on.

import (
	"bytes"
	"context"
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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kitlog "github.com/go-kit/kit/log"
	nmdm "github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/push"
	scepclient "github.com/micromdm/scep/v2/client"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	"github.com/smallstep/scep/x509util"
	"howett.net/plist"

	"openmdm/internal/app"
	"openmdm/internal/core"
)

const (
	ctCheckin = "application/x-apple-aspen-mdm-checkin"
	ctCommand = "application/x-apple-aspen-mdm"

	mailProfile  = "personal-mail"
	mailIdent    = "com.example.openmdm.personal-mail"
	secretKey    = "fastmail_app_password"
	secretValue1 = "pa55&<word>-one-3f9a"
	secretValue2 = "pa55&<word>-two-81cc"
)

// ---- waiting ----

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ---- a fake Apple push service ----

type pushRecorder struct {
	mu     sync.Mutex
	counts map[string]int // push token (hex) -> times woken
}

func (p *pushRecorder) NewPushProvider(*tls.Certificate) (push.PushProvider, error) { return p, nil }

func (p *pushRecorder) Push(_ context.Context, ps []*nmdm.Push) (map[string]*push.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.counts == nil {
		p.counts = map[string]int{}
	}
	out := map[string]*push.Response{}
	for _, x := range ps {
		p.counts[x.Token.String()]++
		out[x.Token.String()] = &push.Response{Id: "fake-apns-id"}
	}
	return out, nil
}

func (p *pushRecorder) count(token []byte) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.counts[hex.EncodeToString(token)]
}

// ---- the server under test ----

type env struct {
	t        *testing.T
	dataDir  string
	profDir  string
	master   string
	srv      *httptest.Server
	handler  atomic.Pointer[http.Handler]
	app      *app.App
	cancel   context.CancelFunc
	pushes   *pushRecorder
	people   map[string]core.User
	adminPEM []byte

	mu     sync.Mutex
	bodies [][]byte // every response body from /api/v1, to be scanned for secrets
}

func newEnv(t *testing.T) *env {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	e := &env{
		t:       t,
		dataDir: filepath.Join(t.TempDir(), "data"),
		profDir: t.TempDir(),
		master:  base64.StdEncoding.EncodeToString(key),
		pushes:  &pushRecorder{},
		people: map[string]core.User{
			"admin":   {Username: "admin", Role: core.RoleAdmin},
			"sam":     {Username: "sam", Role: core.RoleUser},
			"mallory": {Username: "mallory", Role: core.RoleUser},
		},
	}
	e.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := e.handler.Load()
		if h == nil {
			http.Error(w, "not built", http.StatusServiceUnavailable)
			return
		}
		(*h).ServeHTTP(w, r)
	}))
	e.srv.Start()
	t.Cleanup(e.srv.Close)
	e.build()
	t.Cleanup(e.stop)
	// The administrator the session middleware signs in.
	if _, err := e.app.Store.UpsertUser(context.Background(), core.User{Username: "admin", Role: core.RoleAdmin, Name: "Admin"}); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) logger() *slog.Logger {
	if os.Getenv("OPENMDM_E2E_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// build makes an App on the data directory and starts serving it.
func (e *env) build() {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cfg := core.Config{
		Listen:            "127.0.0.1:0",
		PublicURL:         e.srv.URL,
		DataDir:           e.dataDir,
		ProfilesDir:       e.profDir,
		MasterKey:         e.master,
		Organization:      "Acme",
		Secrets:           core.SecretsConfig{Backend: "memory"},
		ReconcileInterval: time.Hour,
		EnrollmentTTL:     time.Hour,
	}
	a, err := app.Build(ctx, cfg, e.logger(), app.Options{
		Version: "e2e",
		SessionMiddleware: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if u, ok := e.people[r.Header.Get("X-Test-User")]; ok {
					r = r.WithContext(core.WithUser(r.Context(), u))
				}
				next.ServeHTTP(w, r)
			})
		},
		PushProviders: e.pushes,
	})
	if err != nil {
		cancel()
		e.t.Fatalf("app.Build: %v", err)
	}
	e.app, e.cancel = a, cancel
	h := a.Handler
	e.handler.Store(&h)
}

func (e *env) stop() {
	if e.app == nil {
		return
	}
	e.cancel()
	_ = e.app.Close()
	e.app = nil
}

// ---- the person's side: the JSON API ----

func (e *env) do(as, method, path string, body any) (int, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if as != "" {
		req.Header.Set("X-Test-User", as)
	}
	req.Header.Set("X-Requested-With", "openmdm")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	e.mu.Lock()
	e.bodies = append(e.bodies, out)
	e.mu.Unlock()
	return resp.StatusCode, out
}

// call expects a status and decodes the JSON answer into v (if not nil).
func (e *env) call(as, method, path string, body any, want int, v any) {
	e.t.Helper()
	code, out := e.do(as, method, path, body)
	if code != want {
		e.t.Fatalf("%s %s as %q: status %d, want %d: %s", method, path, as, code, want, out)
	}
	if v != nil {
		if err := json.Unmarshal(out, v); err != nil {
			e.t.Fatalf("%s %s: bad JSON %q: %v", method, path, out, err)
		}
	}
}

type deviceJSON struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Platform      string `json:"platform"`
	Status        string `json:"status"`
	SerialNumber  string `json:"serial_number"`
	UserChannelID string `json:"user_channel_id"`
}

type planJSON struct {
	ProfileID string `json:"profile_id"`
	State     string `json:"state"`
	Channel   string `json:"channel"`
	Detail    string `json:"detail"`
	Wanted    bool   `json:"wanted"`
}

type deviceDetail struct {
	Device   deviceJSON `json:"device"`
	Owner    *core.User `json:"owner"`
	Profiles []planJSON `json:"profiles"`
	Commands []struct {
		UUID        string `json:"uuid"`
		RequestType string `json:"request_type"`
		Status      string `json:"status"`
		Channel     string `json:"channel"`
	} `json:"commands"`
}

func (e *env) devices(as string) []deviceJSON {
	e.t.Helper()
	var out struct {
		Devices []deviceJSON `json:"devices"`
	}
	e.call(as, "GET", "/api/v1/devices", nil, 200, &out)
	return out.Devices
}

func (e *env) detail(as, id string) deviceDetail {
	e.t.Helper()
	var out deviceDetail
	e.call(as, "GET", "/api/v1/devices/"+id, nil, 200, &out)
	return out
}

// profileOn returns the plan entry for a profile on a device, if there is one.
func (e *env) profileOn(id, profile string) (planJSON, bool) {
	e.t.Helper()
	for _, p := range e.detail("admin", id).Profiles {
		if p.ProfileID == profile {
			return p, true
		}
	}
	return planJSON{}, false
}

func (e *env) waitState(id, profile, state string) planJSON {
	e.t.Helper()
	var last planJSON
	waitFor(e.t, fmt.Sprintf("%s on %s to be %s (last: %+v)", profile, id, state, last), func() bool {
		p, ok := e.profileOn(id, profile)
		last = p
		return ok && p.State == state
	})
	return last
}

func (e *env) waitGone(id, profile string) {
	e.t.Helper()
	waitFor(e.t, profile+" to leave "+id, func() bool {
		_, ok := e.profileOn(id, profile)
		return !ok
	})
}

func (e *env) caPEM() []byte {
	e.t.Helper()
	code, out := e.do("admin", "GET", "/api/v1/settings/ca.pem", nil)
	if code != 200 {
		e.t.Fatalf("ca.pem: %d %s", code, out)
	}
	return out
}

func (e *env) caPool() *x509.CertPool {
	e.t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(e.caPEM()) {
		e.t.Fatal("ca.pem has no certificate")
	}
	return pool
}

// ---- the push certificate ----

func makePushCert(t *testing.T, topic string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject: pkix.Name{CommonName: "APSP:test", ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: topic},
		}},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(300 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
}

// ---- the device's side ----

type simDevice struct {
	e       *env
	udid    string
	serial  string
	product string
	token   []byte // device-channel push token
	utoken  []byte // user-channel push token (a Mac)
	guid    string // the Mac user's GUID

	key      *rsa.PrivateKey
	cert     *x509.Certificate
	mdmURL   string
	topic    string
	scepURL  string
	chall    string
	profile  map[string]any
	scepSign *x509.Certificate
}

func (e *env) newDevice(product, udid, serial string, tokenByte byte) *simDevice {
	e.t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		e.t.Fatal(err)
	}
	fill := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	return &simDevice{
		e: e, udid: udid, serial: serial, product: product, key: key,
		token: fill(tokenByte), utoken: fill(tokenByte + 0x40),
		guid: "A1B2C3D4-0000-1111-2222-" + strings.ToUpper(hex.EncodeToString([]byte(udid[:6]))),
	}
}

// openLink GETs an enrolment link and returns the response.
func (e *env) openLink(url string) (int, string, []byte) {
	e.t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Content-Type"), b
}

// readProfile checks the signature of the enrolment profile against the CA
// and takes from it what the device needs.
func (d *simDevice) readProfile(signed []byte) {
	t := d.e.t
	t.Helper()
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		t.Fatalf("enrolment profile is not CMS: %v", err)
	}
	if err := p7.VerifyWithChain(d.e.caPool()); err != nil {
		t.Fatalf("enrolment profile signature: %v", err)
	}
	var top map[string]any
	if _, err := plist.Unmarshal(p7.Content, &top); err != nil {
		t.Fatalf("enrolment profile content: %v", err)
	}
	d.profile = top
	for _, raw := range top["PayloadContent"].([]any) {
		pl := raw.(map[string]any)
		switch pl["PayloadType"] {
		case "com.apple.security.scep":
			c := pl["PayloadContent"].(map[string]any)
			d.scepURL, d.chall = c["URL"].(string), c["Challenge"].(string)
		case "com.apple.mdm":
			d.mdmURL, d.topic = pl["ServerURL"].(string), pl["Topic"].(string)
		}
	}
	if d.scepURL == "" || d.chall == "" || d.mdmURL == "" || d.topic == "" {
		t.Fatalf("enrolment profile lacks SCEP or MDM settings: %v", top)
	}
}

// scepEnrol asks the SCEP server for an identity certificate with challenge.
// It returns the CertRep; on success the device keeps the certificate.
func (d *simDevice) scepEnrol(challenge string) *scep.PKIMessage {
	t := d.e.t
	t.Helper()
	if d.scepSign == nil {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SCEP SIGNER"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &d.key.PublicKey, d.key)
		if err != nil {
			t.Fatal(err)
		}
		d.scepSign, _ = x509.ParseCertificate(der)
	}
	cl, err := scepclient.New(d.scepURL, kitlog.NewNopLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := cl.GetCACaps(ctx); err != nil {
		t.Fatalf("GetCACaps: %v", err)
	}
	caBytes, n, err := cl.GetCACert(ctx, "")
	if err != nil || n > 1 {
		t.Fatalf("GetCACert: %v (%d certs)", err, n)
	}
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}
	// The profile pins the CA by fingerprint; the device would check it.
	if !ca.Equal(d.e.app.Authority.CACertificate()) {
		t.Fatal("SCEP serves a different CA certificate than the authority holds")
	}
	csrDER, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{
			Subject:            pkix.Name{CommonName: "OpenMDM device identity " + d.udid[:8], Organization: []string{"Acme"}},
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
		SignerKey: d.key, SignerCert: d.scepSign,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.PKIOperation(ctx, req.Raw)
	if err != nil {
		t.Fatalf("PKIOperation: %v", err)
	}
	rep, err := scep.ParsePKIMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	if rep.PKIStatus == scep.SUCCESS {
		if err := rep.DecryptPKIEnvelope(d.scepSign, d.key); err != nil {
			t.Fatal(err)
		}
		d.cert = rep.CertRepMessage.Certificate
	}
	return rep
}

func detachedSignature(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey, body []byte) string {
	t.Helper()
	sd, err := pkcs7.NewSignedData(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	sd.Detach()
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// put sends a plist to the MDM URL the way a device with SignMessage does.
func (d *simDevice) put(contentType string, msg map[string]any, signed bool) (int, []byte) {
	t := d.e.t
	t.Helper()
	body, err := plist.Marshal(msg, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, d.mdmURL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	if signed {
		req.Header.Set("Mdm-Signature", detachedSignature(t, d.cert, d.key, body))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (d *simDevice) checkin(msg map[string]any) []byte {
	d.e.t.Helper()
	code, out := d.put(ctCheckin, msg, true)
	if code != 200 {
		d.e.t.Fatalf("%v: status %d: %s", msg["MessageType"], code, out)
	}
	return out
}

func (d *simDevice) authenticate() {
	d.checkin(map[string]any{
		"MessageType": "Authenticate", "UDID": d.udid, "Topic": d.topic,
		"SerialNumber": d.serial, "OSVersion": "18.1", "BuildVersion": "22B83",
		"ProductName": d.product, "Model": "A1234", "DeviceName": d.product + " of Sam",
	})
}

func (d *simDevice) tokenUpdate(user bool) {
	m := map[string]any{
		"MessageType": "TokenUpdate", "UDID": d.udid, "Topic": d.topic,
		"PushMagic": "MAGIC-" + d.udid, "Token": d.token,
	}
	if user {
		m["Token"] = d.utoken
		m["PushMagic"] = "UMAGIC-" + d.udid
		m["UserID"], m["UserShortName"], m["UserLongName"], m["NotOnConsole"] = d.guid, "sam", "Sam", false
	}
	d.checkin(m)
}

// userChannelUp is what a Mac does when someone logs in.
func (d *simDevice) userChannelUp() {
	t := d.e.t
	t.Helper()
	first := d.checkin(map[string]any{"MessageType": "UserAuthenticate", "UDID": d.udid, "UserID": d.guid, "UserShortName": "sam"})
	if !strings.Contains(string(first), "DigestChallenge") {
		t.Fatalf("first UserAuthenticate should be answered with a DigestChallenge: %q", first)
	}
	d.checkin(map[string]any{"MessageType": "UserAuthenticate", "UDID": d.udid, "UserID": d.guid, "UserShortName": "sam", "DigestResponse": "x"})
	d.tokenUpdate(true)
}

type command struct {
	UUID string
	Type string
	Body map[string]any
}

// report tells the server a command's status (or Idle) and returns the next
// command it hands out, if any.
func (d *simDevice) report(user bool, status, uuid string) *command {
	t := d.e.t
	t.Helper()
	msg := map[string]any{"UDID": d.udid, "Status": status}
	if uuid != "" {
		msg["CommandUUID"] = uuid
	}
	if user {
		msg["UserID"] = d.guid
	}
	code, out := d.put(ctCommand, msg, true)
	if code != 200 {
		t.Fatalf("report %s: status %d: %s", status, code, out)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil
	}
	var c struct {
		CommandUUID string
		Command     map[string]any
	}
	if _, err := plist.Unmarshal(out, &c); err != nil {
		t.Fatalf("not a command: %v: %q", err, out)
	}
	rt, _ := c.Command["RequestType"].(string)
	return &command{UUID: c.CommandUUID, Type: rt, Body: c.Command}
}

func (d *simDevice) poll(user bool) *command { d.e.t.Helper(); return d.report(user, "Idle", "") }

// expect polls and requires a command of the given type.
func (d *simDevice) expect(user bool, typ string) *command {
	d.e.t.Helper()
	c := d.poll(user)
	if c == nil {
		d.e.t.Fatalf("polled (user channel %v) and got nothing; wanted %s", user, typ)
	}
	if c.Type != typ {
		d.e.t.Fatalf("polled (user channel %v) and got %s; wanted %s", user, c.Type, typ)
	}
	return c
}

// ack acknowledges and requires that nothing else is waiting.
func (d *simDevice) ack(user bool, c *command) {
	d.e.t.Helper()
	if next := d.report(user, "Acknowledged", c.UUID); next != nil {
		d.e.t.Fatalf("after acknowledging %s the server sent %s", c.Type, next.Type)
	}
}

func (d *simDevice) nothingWaiting(user bool) {
	d.e.t.Helper()
	if c := d.poll(user); c != nil {
		d.e.t.Fatalf("expected an empty queue (user channel %v); got %s %v", user, c.Type, c.Body)
	}
}

// installedProfile opens an InstallProfile payload as the device would: a CMS
// signature that verifies against the CA, around a property list.
func (d *simDevice) installedProfile(c *command) map[string]any {
	t := d.e.t
	t.Helper()
	raw, ok := c.Body["Payload"].([]byte)
	if !ok {
		t.Fatalf("InstallProfile has no Payload data: %v", c.Body)
	}
	p7, err := pkcs7.Parse(raw)
	if err != nil {
		t.Fatalf("payload is not CMS: %v", err)
	}
	if err := p7.VerifyWithChain(d.e.caPool()); err != nil {
		t.Fatalf("payload signature does not verify against the CA: %v", err)
	}
	var top map[string]any
	if _, err := plist.Unmarshal(p7.Content, &top); err != nil {
		t.Fatalf("payload content: %v", err)
	}
	return top
}

// mailPayload digs the mail account out of the personal-mail profile.
func mailPayload(t *testing.T, top map[string]any) map[string]any {
	t.Helper()
	if top["PayloadIdentifier"] != mailIdent {
		t.Fatalf("identifier %v", top["PayloadIdentifier"])
	}
	for _, raw := range top["PayloadContent"].([]any) {
		if m := raw.(map[string]any); m["PayloadType"] == "com.apple.mail.managed" {
			return m
		}
	}
	t.Fatalf("no mail payload in %v", top)
	return nil
}

func checkMail(t *testing.T, top map[string]any, password string) {
	t.Helper()
	m := mailPayload(t, top)
	for k, want := range map[string]string{
		"EmailAddress":               "sam@example.com",
		"EmailAccountName":           "Sam Example",
		"EmailAccountDescription":    "Personal",
		"IncomingPassword":           password,
		"IncomingMailServerUsername": "sam@example.com",
	} {
		if m[k] != want {
			t.Errorf("%s = %q, want %q", k, m[k], want)
		}
	}
	for _, raw := range top["PayloadContent"].([]any) {
		pl := raw.(map[string]any)
		if pl["PayloadType"] == "com.apple.caldav.account" && pl["CalDAVPassword"] != password {
			t.Errorf("CalDAVPassword = %q", pl["CalDAVPassword"])
		}
	}
}

// enrol runs the whole enrolment of a new device for a person, from the
// admin making the link to the device holding a token.
func (e *env) enrol(user, product, udid, serial string, tokenByte byte) *simDevice {
	e.t.Helper()
	var out struct {
		URL string `json:"url"`
	}
	e.call("admin", "POST", "/api/v1/enrollments", map[string]string{"username": user}, 200, &out)
	code, ct, body := e.openLink(out.URL)
	if code != 200 || ct != "application/x-apple-aspen-config" {
		e.t.Fatalf("enrolment link: %d %s %s", code, ct, body)
	}
	d := e.newDevice(product, udid, serial, tokenByte)
	d.readProfile(body)
	if rep := d.scepEnrol(d.chall); rep.PKIStatus != scep.SUCCESS {
		e.t.Fatalf("SCEP: %v %v", rep.PKIStatus, rep.FailInfo)
	}
	d.authenticate()
	d.tokenUpdate(false)
	return d
}

// ---- the scenario ----

func TestEndToEnd(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// 1. No push certificate yet: an enrolment can be made but its link says
	// so, and stays usable.
	var enr struct {
		Enrollment core.Enrollment `json:"enrollment"`
		URL        string          `json:"url"`
	}
	e.call("admin", "POST", "/api/v1/enrollments", map[string]string{"username": "sam"}, 200, &enr)
	if !strings.HasPrefix(enr.URL, e.srv.URL+"/enroll/") {
		t.Fatalf("link %q", enr.URL)
	}
	code, _, body := e.openLink(enr.URL)
	if code != http.StatusServiceUnavailable || !strings.Contains(string(body), "push certificate") {
		t.Fatalf("link without push certificate: %d %q", code, body)
	}
	const topic = "com.apple.mgmt.External.5c1f6a52-6a0e-4b13-9f0e-2d7f0f3a8e11"
	certPEM, keyPEM := makePushCert(t, topic)
	var pushOut struct {
		Push core.PushInfo `json:"push"`
	}
	e.call("admin", "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": certPEM, "key_pem": keyPEM}, 200, &pushOut)
	if !pushOut.Push.Configured || pushOut.Push.Topic != topic {
		t.Fatalf("push info %+v", pushOut.Push)
	}

	// 2. The link works now, once.
	code, ct, body := e.openLink(enr.URL)
	if code != 200 || ct != "application/x-apple-aspen-config" {
		t.Fatalf("link: %d %s %q", code, ct, body)
	}
	phone := e.newDevice("iPhone15,2", "00008110-001A2B3C4D5E6F01", "F2LXYZ123456", 0x10)
	phone.readProfile(body)
	if phone.topic != topic || phone.mdmURL != e.srv.URL+"/mdm" || phone.scepURL != e.srv.URL+"/scep" {
		t.Fatalf("profile settings: topic %q mdm %q scep %q", phone.topic, phone.mdmURL, phone.scepURL)
	}
	if code, _, _ := e.openLink(enr.URL); code != http.StatusGone {
		t.Fatalf("second GET of the link: %d, want 410", code)
	}
	if code, _, _ := e.openLink(e.srv.URL + "/enroll/no-such-token"); code != http.StatusNotFound {
		t.Fatalf("unknown link: %d, want 404", code)
	}

	// 3. SCEP. The challenge works once.
	if rep := phone.scepEnrol(phone.chall); rep.PKIStatus != scep.SUCCESS {
		t.Fatalf("SCEP: status %v, fail info %v", rep.PKIStatus, rep.FailInfo)
	}
	if err := phone.cert.CheckSignatureFrom(e.app.Authority.CACertificate()); err != nil {
		t.Fatalf("device certificate is not from the CA: %v", err)
	}
	if rep := e.newDevice("iPhone15,2", "00000000-reuse", "REUSE", 1).scepEnrolWithURL(phone.scepURL, phone.chall); rep.PKIStatus != scep.FAILURE {
		t.Fatalf("a reused challenge got status %v", rep.PKIStatus)
	}

	// 4. Check in. Before TokenUpdate the device is only pending.
	phone.authenticate()
	if ds := e.devices("admin"); len(ds) != 1 || ds[0].Status != "pending" {
		t.Fatalf("after Authenticate: %+v", ds)
	}
	phone.tokenUpdate(false)
	waitFor(t, "the phone to be enrolled", func() bool {
		ds := e.devices("admin")
		return len(ds) == 1 && ds[0].Status == "enrolled"
	})
	ds := e.devices("admin")
	if ds[0].ID != phone.udid || ds[0].Platform != "ios" || ds[0].Username != "sam" || ds[0].SerialNumber != phone.serial {
		t.Fatalf("device: %+v", ds[0])
	}
	var users struct {
		Users []core.User `json:"users"`
	}
	e.call("admin", "GET", "/api/v1/users", nil, 200, &users)
	foundSam := false
	for _, u := range users.Users {
		foundSam = foundSam || u.Username == "sam"
	}
	if !foundSam {
		t.Fatalf("no user row for sam: %+v", users.Users)
	}
	phone.nothingWaiting(false)

	// 5. A profile that needs sam's address, name and a secret of theirs.
	if _, err := e.app.Store.UpsertUser(ctx, core.User{Username: "sam", Email: "sam@example.com", Name: "Sam Example", Role: core.RoleUser}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"personal-mail.mobileconfig", "personal-mail.yaml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "examples", "profiles", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(e.profDir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := e.waitState(phone.udid, mailProfile, "blocked")
	if !strings.Contains(p.Detail, secretKey) {
		t.Fatalf("blocked, but the detail does not name the secret: %q", p.Detail)
	}
	var sec struct {
		Secrets []struct {
			Key    string   `json:"key"`
			Set    bool     `json:"set"`
			UsedBy []string `json:"used_by"`
		} `json:"secrets"`
	}
	e.call("admin", "GET", "/api/v1/users/sam/secrets", nil, 200, &sec)
	if len(sec.Secrets) != 1 || sec.Secrets[0].Key != secretKey || sec.Secrets[0].Set || len(sec.Secrets[0].UsedBy) != 1 || sec.Secrets[0].UsedBy[0] != mailProfile {
		t.Fatalf("secrets: %+v", sec.Secrets)
	}

	// 6. Sam's secret arrives; the phone is woken, polls, and installs it.
	before := e.pushes.count(phone.token)
	e.call("admin", "PUT", "/api/v1/users/sam/secrets/"+secretKey, map[string]string{"value": secretValue1}, 204, nil)
	waitFor(t, "the phone to be pushed", func() bool { return e.pushes.count(phone.token) > before })
	cmd := phone.expect(false, "InstallProfile")
	phoneV1 := phone.installedProfile(cmd)
	checkMail(t, phoneV1, secretValue1)
	phone.ack(false, cmd)
	e.waitState(phone.udid, mailProfile, "installed")
	e.call("admin", "GET", "/api/v1/users/sam/secrets", nil, 200, &sec)
	if len(sec.Secrets) != 1 || !sec.Secrets[0].Set {
		t.Fatalf("secrets after set: %+v", sec.Secrets)
	}

	// 8. A Mac for sam. The profile belongs on the user channel, so it waits.
	mac := e.enrol("sam", "MacBookPro18,3", "C02ZZZ111222", "C02ABC123456", 0x20)
	waitFor(t, "the Mac to be enrolled", func() bool {
		for _, d := range e.devices("admin") {
			if d.ID == mac.udid {
				return d.Status == "enrolled" && d.Platform == "macos" && d.Username == "sam"
			}
		}
		return false
	})
	p = e.waitState(mac.udid, mailProfile, "blocked")
	if p.Channel != "user" || !strings.Contains(strings.ToLower(p.Detail), "log in") {
		t.Fatalf("Mac before login: %+v", p)
	}
	mac.nothingWaiting(false)

	beforeUser := e.pushes.count(mac.utoken)
	mac.userChannelUp()
	waitFor(t, "the Mac's user channel to be pushed", func() bool { return e.pushes.count(mac.utoken) > beforeUser })
	if d := e.detail("admin", mac.udid).Device; d.UserChannelID != mac.udid+":"+mac.guid {
		t.Fatalf("Mac user channel ID %q", d.UserChannelID)
	}
	mac.nothingWaiting(false) // nothing for the device channel
	cmd = mac.expect(true, "InstallProfile")
	checkMail(t, mac.installedProfile(cmd), secretValue1)
	mac.ack(true, cmd)
	p = e.waitState(mac.udid, mailProfile, "installed")
	if p.Channel != "user" {
		t.Fatalf("Mac profile channel %q", p.Channel)
	}
	if p, _ := e.profileOn(phone.udid, mailProfile); p.State != "installed" || p.Channel != "device" {
		t.Fatalf("the phone's copy changed: %+v", p)
	}
	phone.nothingWaiting(false)

	// 9. A new secret value: both are sent the profile again.
	beforePhone, beforeMac := e.pushes.count(phone.token), e.pushes.count(mac.utoken)
	e.call("admin", "PUT", "/api/v1/users/sam/secrets/"+secretKey, map[string]string{"value": secretValue2}, 204, nil)
	waitFor(t, "both to be pushed", func() bool {
		return e.pushes.count(phone.token) > beforePhone && e.pushes.count(mac.utoken) > beforeMac
	})
	cmd = phone.expect(false, "InstallProfile")
	checkMail(t, phone.installedProfile(cmd), secretValue2)
	phone.ack(false, cmd)
	cmd = mac.expect(true, "InstallProfile")
	checkMail(t, mac.installedProfile(cmd), secretValue2)
	mac.ack(true, cmd)
	e.waitState(phone.udid, mailProfile, "installed")
	e.waitState(mac.udid, mailProfile, "installed")

	// The profile's files go away: both are told to remove it, each on its
	// own channel.
	beforePhone, beforeMac = e.pushes.count(phone.token), e.pushes.count(mac.utoken)
	for _, f := range []string{"personal-mail.mobileconfig", "personal-mail.yaml"} {
		if err := os.Remove(filepath.Join(e.profDir, f)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "both to be pushed for the removal", func() bool {
		return e.pushes.count(phone.token) > beforePhone && e.pushes.count(mac.utoken) > beforeMac
	})
	cmd = phone.expect(false, "RemoveProfile")
	if cmd.Body["Identifier"] != mailIdent {
		t.Fatalf("phone removal: %v", cmd.Body)
	}
	phone.ack(false, cmd)
	mac.nothingWaiting(false)
	cmd = mac.expect(true, "RemoveProfile")
	if cmd.Body["Identifier"] != mailIdent {
		t.Fatalf("Mac removal: %v", cmd.Body)
	}
	mac.ack(true, cmd)
	e.waitGone(phone.udid, mailProfile)
	e.waitGone(mac.udid, mailProfile)

	// 10. People who are not administrators.
	if got := e.devices("sam"); len(got) != 2 {
		t.Fatalf("sam sees %d devices, want 2", len(got))
	}
	if got := e.devices("mallory"); len(got) != 0 {
		t.Fatalf("mallory sees %+v", got)
	}
	e.call("sam", "GET", "/api/v1/devices/"+phone.udid, nil, 200, nil)
	e.call("sam", "GET", "/api/v1/profiles", nil, 403, nil)
	e.call("sam", "GET", "/api/v1/users/admin/secrets", nil, 403, nil)
	e.call("sam", "GET", "/api/v1/users", nil, 403, nil)
	e.call("sam", "GET", "/api/v1/settings", nil, 403, nil)
	e.call("sam", "PUT", "/api/v1/users/sam/secrets/another_one", map[string]string{"value": "hello-world"}, 204, nil)
	e.call("sam", "PUT", "/api/v1/users/mallory/secrets/another_one", map[string]string{"value": "hello-world"}, 403, nil)
	e.call("mallory", "GET", "/api/v1/devices/"+phone.udid, nil, 404, nil)
	e.call("mallory", "POST", "/api/v1/devices/"+phone.udid+"/sync", nil, 404, nil)
	e.call("", "GET", "/api/v1/devices", nil, 401, nil)

	// 11. Revocation and unsigned requests.
	pad := e.enrol("sam", "iPad13,4", "00008027-0011223344556677", "DMPAD0000001", 0x30)
	waitFor(t, "the iPad to be enrolled", func() bool { return len(e.devices("admin")) == 3 })
	pad.nothingWaiting(false)
	if code, _ := pad.put(ctCommand, map[string]any{"UDID": pad.udid, "Status": "Idle"}, false); code == 200 {
		t.Fatal("an unsigned request to /mdm was accepted")
	}
	sum := sha256.Sum256(pad.cert.Raw)
	type revoker interface {
		Revoke(context.Context, string) error
	}
	rv, ok := e.app.Authority.(revoker)
	if !ok {
		t.Fatal("the authority cannot revoke")
	}
	if err := rv.Revoke(ctx, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if code, out := pad.put(ctCommand, map[string]any{"UDID": pad.udid, "Status": "Idle"}, true); code == 200 {
		t.Fatalf("a revoked device was served: %s", out)
	}
	if code, _ := pad.put(ctCheckin, map[string]any{"MessageType": "TokenUpdate", "UDID": pad.udid, "Topic": pad.topic, "PushMagic": "m", "Token": pad.token}, true); code == 200 {
		t.Fatal("a revoked device could check in")
	}
	phone.nothingWaiting(false) // the others are unaffected

	// 7. Nothing the API said held the secret's value.
	e.checkNoSecrets(secretValue1, secretValue2, "hello-world")

	// 12. Restart on the same data directory and master key.
	caBefore := e.caPEM()
	e.stop()
	e.build()
	if got := e.caPEM(); !bytes.Equal(got, caBefore) {
		t.Fatal("the CA certificate changed across a restart")
	}
	if ds := e.devices("admin"); len(ds) != 3 {
		t.Fatalf("after restart: %+v", ds)
	}
	for _, d := range e.devices("sam") {
		if d.Status != "enrolled" || d.Username != "sam" {
			t.Fatalf("after restart: %+v", d)
		}
	}
	var settings struct {
		Push core.PushInfo `json:"push"`
	}
	e.call("admin", "GET", "/api/v1/settings", nil, 200, &settings)
	if !settings.Push.Configured || settings.Push.Topic != topic {
		t.Fatalf("push certificate after restart: %+v", settings.Push)
	}
	phone.nothingWaiting(false) // still checks in
	mac.nothingWaiting(true)
	if code, _ := pad.put(ctCommand, map[string]any{"UDID": pad.udid, "Status": "Idle"}, true); code == 200 {
		t.Fatal("the revoked device was served after a restart")
	}
	// An enrolment made after the restart still works against the new push
	// certificate topic.
	late := e.enrol("sam", "iPhone14,5", "00008110-00FFEEDDCCBBAA99", "F2LLATE00001", 0x50)
	late.nothingWaiting(false)

	// Leaving: an admin deleting a device asks it to remove the MDM profile;
	// a device that removes it itself checks out and is shown as unenrolled.
	e.call("sam", "DELETE", "/api/v1/devices/"+late.udid, nil, 403, nil)
	e.call("admin", "DELETE", "/api/v1/devices/"+late.udid, nil, 204, nil)
	cmd = late.expect(false, "RemoveProfile")
	if cmd.Body["Identifier"] != "openmdm.enrollment" {
		t.Fatalf("unenrol removal: %v", cmd.Body)
	}
	late.ack(false, cmd)
	e.call("admin", "GET", "/api/v1/devices/"+late.udid, nil, 404, nil)
	phone.checkin(map[string]any{"MessageType": "CheckOut", "UDID": phone.udid, "Topic": phone.topic})
	waitFor(t, "the phone to be unenrolled", func() bool {
		for _, d := range e.devices("sam") {
			if d.ID == phone.udid {
				return d.Status == "unenrolled"
			}
		}
		return false
	})

	e.checkNoSecrets(secretValue1, secretValue2, "hello-world")
}

func (e *env) checkNoSecrets(values ...string) {
	e.t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, b := range e.bodies {
		for _, v := range values {
			// The value may be JSON-escaped or not; look for both.
			esc, _ := json.Marshal(v)
			if bytes.Contains(b, []byte(v)) || bytes.Contains(b, bytes.Trim(esc, `"`)) {
				e.t.Fatalf("API response %d contains a secret value: %s", i, b)
			}
		}
	}
	if len(e.bodies) == 0 {
		e.t.Fatal("no API responses were collected")
	}
}

// scepEnrolWithURL is for a device that was never given the profile itself:
// it is told where SCEP is and what challenge to use.
func (d *simDevice) scepEnrolWithURL(url, challenge string) *scep.PKIMessage {
	d.scepURL = url
	return d.scepEnrol(challenge)
}
