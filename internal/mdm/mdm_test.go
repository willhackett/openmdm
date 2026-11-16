package mdm

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"howett.net/plist"

	nmdm "github.com/micromdm/nanomdm/mdm"

	"openmdm/internal/core"
)

const (
	udid      = "00008103-001A2B3C4D5E6F01"
	userGUID  = "A1B2C3D4-0000-1111-2222-333344445555"
	userEnrol = udid + ":" + userGUID
)

func authenticateMsg(u string) map[string]any {
	return map[string]any{
		"MessageType":  "Authenticate",
		"UDID":         u,
		"Topic":        "com.apple.mgmt.External.test",
		"SerialNumber": "C02ABC123",
		"OSVersion":    "15.1",
		"BuildVersion": "24B83",
		"ProductName":  "MacBookPro18,3",
		"Model":        "MKGP3LL/A",
		"DeviceName":   "Will's Mac",
	}
}

func tokenMsg(u, user string, topic string) map[string]any {
	m := map[string]any{
		"MessageType": "TokenUpdate",
		"UDID":        u,
		"Topic":       topic,
		"PushMagic":   "MAGIC-" + u,
		"Token":       []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
	}
	if user != "" {
		m["UserID"] = user
		m["UserShortName"] = "will"
		m["UserLongName"] = "Will"
		m["NotOnConsole"] = false
	}
	return m
}

// enrol runs the Mac's full sequence: Authenticate, TokenUpdate, the
// UserAuthenticate exchange and the user channel's TokenUpdate.
func enrol(t *testing.T, hs *harness, dev *identity) {
	t.Helper()
	mustOK(t, hs.checkin(dev, authenticateMsg(udid)))
	mustOK(t, hs.checkin(dev, tokenMsg(udid, "", "com.apple.mgmt.External.test")))

	first := hs.checkin(dev, map[string]any{"MessageType": "UserAuthenticate", "UDID": udid, "UserID": userGUID, "UserShortName": "will"})
	mustOK(t, first)
	if !strings.Contains(first.Body.String(), "DigestChallenge") {
		t.Fatalf("UserAuthenticate must be answered with a (zero-length) DigestChallenge so that the Mac opens a user channel; got %q", first.Body.String())
	}
	second := hs.checkin(dev, map[string]any{"MessageType": "UserAuthenticate", "UDID": udid, "UserID": userGUID, "UserShortName": "will", "DigestResponse": "x"})
	mustOK(t, second)
	if strings.TrimSpace(second.Body.String()) != "" {
		t.Fatalf("second UserAuthenticate should get an empty body, got %q", second.Body.String())
	}
	mustOK(t, hs.checkin(dev, tokenMsg(udid, userGUID, "com.apple.mgmt.External.test")))
}

func newDevice(t *testing.T, hs *harness, cn string) *identity {
	t.Helper()
	id := hs.ca.issue(t, cn)
	hs.auth.trust(id)
	return &id
}

func TestCheckinEvents(t *testing.T) {
	hs := newHarness(t)
	dev := newDevice(t, hs, "device")
	enrol(t, hs, dev)

	ev := hs.ev
	if len(ev.authenticated) != 1 {
		t.Fatalf("authenticated events: %d", len(ev.authenticated))
	}
	a := ev.authenticated[0]
	want := core.Checkin{
		DeviceID: udid, EnrollmentID: udid, SerialNumber: "C02ABC123", Model: "MKGP3LL/A",
		ProductName: "MacBookPro18,3", DeviceName: "Will's Mac", OSVersion: "15.1", CertSHA256: dev.sha(),
	}
	if a != want {
		t.Fatalf("Authenticate checkin\n got %+v\nwant %+v", a, want)
	}

	if len(ev.tokens) != 2 {
		t.Fatalf("token events: %d", len(ev.tokens))
	}
	if d := ev.tokens[0]; d.DeviceID != udid || d.EnrollmentID != udid || d.UserID != "" || d.CertSHA256 != dev.sha() {
		t.Fatalf("device-channel token update: %+v", d)
	}
	if u := ev.tokens[1]; u.DeviceID != udid || u.UserID != userGUID || u.EnrollmentID != userEnrol || u.CertSHA256 != dev.sha() {
		t.Fatalf("user-channel token update: %+v", u)
	}

	mustOK(t, hs.checkin(dev, map[string]any{"MessageType": "CheckOut", "UDID": udid, "Topic": "com.apple.mgmt.External.test"}))
	if len(ev.checkouts) != 1 || ev.checkouts[0].DeviceID != udid || ev.checkouts[0].EnrollmentID != udid {
		t.Fatalf("checkout events: %+v", ev.checkouts)
	}
}

// poll is the device asking for work (an Idle report). It returns the
// command the server hands out, if any.
func (hs *harness) poll(dev *identity, ids map[string]any) (uuid string, command map[string]any, raw []byte) {
	hs.t.Helper()
	return hs.answer(dev, ids, map[string]any{"Status": "Idle"})
}

// answer reports a status and returns the next command, if any.
func (hs *harness) answer(dev *identity, ids, report map[string]any) (uuid string, command map[string]any, raw []byte) {
	hs.t.Helper()
	msg := map[string]any{}
	for k, v := range ids {
		msg[k] = v
	}
	for k, v := range report {
		msg[k] = v
	}
	rec := hs.report(dev, msg)
	mustOK(hs.t, rec)
	return parseCommand(hs.t, rec)
}

func parseCommand(t *testing.T, rec *httptest.ResponseRecorder) (string, map[string]any, []byte) {
	t.Helper()
	raw := rec.Body.Bytes()
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", nil, nil
	}
	var c struct {
		CommandUUID string
		Command     map[string]any
	}
	if _, err := plist.Unmarshal(raw, &c); err != nil {
		t.Fatalf("response is not a command: %v: %q", err, raw)
	}
	return c.CommandUUID, c.Command, raw
}

var (
	deviceIDs = map[string]any{"UDID": udid}
	userIDs   = map[string]any{"UDID": udid, "UserID": userGUID}
)

func TestInstallProfileAndResults(t *testing.T) {
	hs := newHarness(t)
	dev := newDevice(t, hs, "device")
	enrol(t, hs, dev)
	ctx := context.Background()

	// Device channel: queue, poll, acknowledge.
	profile := []byte("<?xml version=\"1.0\"?><plist><dict/></plist>")
	id, err := hs.svc.InstallProfile(ctx, udid, profile)
	if err != nil {
		t.Fatal(err)
	}
	if id != strings.ToUpper(id) || len(id) != 36 {
		t.Fatalf("command UUID should be an upper-case UUID: %q", id)
	}
	uuid, cmd, _ := hs.poll(dev, deviceIDs)
	if uuid != id || cmd["RequestType"] != "InstallProfile" {
		t.Fatalf("polled %q %v; queued %q", uuid, cmd, id)
	}
	if !bytes.Equal(cmd["Payload"].([]byte), profile) {
		t.Fatalf("payload not carried: %v", cmd["Payload"])
	}
	next, _, _ := hs.answer(dev, deviceIDs, map[string]any{"Status": "Acknowledged", "CommandUUID": id})
	if next != "" {
		t.Fatalf("queue should be empty, got %q", next)
	}
	if len(hs.ev.results) != 1 {
		t.Fatalf("results: %+v", hs.ev.results)
	}
	r := hs.ev.results[0]
	if r.CommandUUID != id || r.Status != core.CommandAcknowledged || r.EnrollmentID != udid || r.DeviceID != udid || r.ErrorText != "" {
		t.Fatalf("result: %+v", r)
	}
	if !bytes.Contains(r.Raw, []byte("Acknowledged")) {
		t.Fatalf("Raw should be the response plist: %q", r.Raw)
	}

	// An Idle poll is not a result.
	if len(hs.ev.results) != 1 {
		t.Fatalf("Idle must not produce an event")
	}

	// Error with an ErrorChain, on the user channel.
	uid, err := hs.svc.InstallProfile(ctx, userEnrol, profile)
	if err != nil {
		t.Fatal(err)
	}
	// The device channel has nothing; the user channel hands out the command.
	if u, _, _ := hs.poll(dev, deviceIDs); u != "" {
		t.Fatalf("device channel got the user channel's command %q", u)
	}
	if u, _, _ := hs.poll(dev, userIDs); u != uid {
		t.Fatalf("user channel polled %q, want %q", u, uid)
	}
	hs.answer(dev, userIDs, map[string]any{
		"Status": "Error", "CommandUUID": uid,
		"ErrorChain": []any{
			map[string]any{"ErrorCode": 4001, "ErrorDomain": "MCProfileErrorDomain", "LocalizedDescription": "Profile installation failed", "USEnglishDescription": "Profile installation failed"},
			map[string]any{"ErrorCode": 9, "ErrorDomain": "MCInstallationErrorDomain", "LocalizedDescription": "The payload\nis   bad"},
		},
	})
	r = hs.ev.results[1]
	if r.Status != core.CommandError || r.CommandUUID != uid || r.EnrollmentID != userEnrol || r.DeviceID != udid {
		t.Fatalf("error result: %+v", r)
	}
	if want := "Profile installation failed (MCProfileErrorDomain 4001); The payload is bad (MCInstallationErrorDomain 9)"; r.ErrorText != want {
		t.Fatalf("ErrorText = %q, want %q", r.ErrorText, want)
	}

	// NotNow: the command stays queued and is handed out again.
	nid, err := hs.svc.RemoveProfile(ctx, udid, "com.example.profile")
	if err != nil {
		t.Fatal(err)
	}
	if u, c, _ := hs.poll(dev, deviceIDs); u != nid || c["RequestType"] != "RemoveProfile" || c["Identifier"] != "com.example.profile" {
		t.Fatalf("remove command: %q %v", u, c)
	}
	hs.answer(dev, deviceIDs, map[string]any{"Status": "NotNow", "CommandUUID": nid})
	r = hs.ev.results[2]
	if r.Status != core.CommandNotNow || r.CommandUUID != nid {
		t.Fatalf("notnow result: %+v", r)
	}
}

func TestErrorTextFlattening(t *testing.T) {
	got := flattenErrorChain(nil)
	if got != "" {
		t.Fatal(got)
	}
	chain := []nmdm.ErrorChain{
		{ErrorCode: 4001, ErrorDomain: "MCProfileErrorDomain", LocalizedDescription: "Profile installation failed"},
		{ErrorCode: 12, ErrorDomain: "D", USEnglishDescription: "english only"},
		{ErrorCode: 3, ErrorDomain: "Bare"},
	}
	want := "Profile installation failed (MCProfileErrorDomain 4001); english only (D 12); Bare 3"
	if got := flattenErrorChain(chain); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCommandFormatErrorIsAnError(t *testing.T) {
	if commandStatus("CommandFormatError") != core.CommandError || commandStatus("Error") != core.CommandError {
		t.Fatal("device refusals must map to CommandError")
	}
}

func TestEnqueueMergesCommand(t *testing.T) {
	hs := newHarness(t)
	dev := newDevice(t, hs, "device")
	enrol(t, hs, dev)

	id, err := hs.svc.Enqueue(context.Background(), udid, "DeviceLock", map[string]any{"PIN": "123456", "RequestType": "ignored", "Nested": map[string]any{"A": 1}})
	if err != nil {
		t.Fatal(err)
	}
	u, c, _ := hs.poll(dev, deviceIDs)
	if u != id || c["RequestType"] != "DeviceLock" || c["PIN"] != "123456" || c["Nested"] == nil {
		t.Fatalf("%q %v", u, c)
	}
	// nil dictionary is fine.
	if _, err := hs.svc.Enqueue(context.Background(), udid, "DeviceInformation", nil); err != nil {
		t.Fatal(err)
	}
}

func TestEnqueueTargets(t *testing.T) {
	hs := newHarness(t)
	dev := newDevice(t, hs, "device")
	enrol(t, hs, dev)
	ctx := context.Background()

	if _, err := hs.svc.InstallProfile(ctx, "NO-SUCH-DEVICE", []byte("x")); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("unknown target: %v", err)
	}
	if _, err := os.Stat(filepath.Join(hs.dir, "nanomdm", "NO-SUCH-DEVICE")); err == nil {
		t.Fatal("an unknown target must not get a queue directory")
	}
	for _, bad := range []string{"", "../etc", "a/b", udid + ":x:y", ".."} {
		if _, err := hs.svc.InstallProfile(ctx, bad, []byte("x")); !errors.Is(err, core.ErrInvalid) {
			t.Fatalf("target %q: %v", bad, err)
		}
	}
	if _, err := hs.svc.InstallProfile(ctx, udid, nil); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("empty profile: %v", err)
	}
	if _, err := hs.svc.Enqueue(ctx, udid, "", nil); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("empty request type: %v", err)
	}
}

func TestRequestsAreRefused(t *testing.T) {
	hs := newHarness(t)
	dev := newDevice(t, hs, "device")
	mustOK(t, hs.checkin(dev, authenticateMsg(udid)))
	n := len(hs.ev.authenticated)

	t.Run("unsigned", func(t *testing.T) {
		rec := hs.checkin(nil, authenticateMsg("UNSIGNED-1"))
		if rec.Code == http.StatusOK {
			t.Fatal("unsigned request accepted")
		}
		rec = hs.report(nil, map[string]any{"Status": "Idle", "UDID": udid})
		if rec.Code == http.StatusOK {
			t.Fatal("unsigned poll accepted")
		}
	})

	t.Run("certificate the authority rejects", func(t *testing.T) {
		stranger := hs.ca.issue(t, "stranger") // validly formed, but not trusted
		rec := hs.checkin(&stranger, authenticateMsg("STRANGER-1"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d", rec.Code)
		}
	})

	t.Run("signature over another body", func(t *testing.T) {
		body := marshal(t, authenticateMsg("TAMPER-1"))
		req := httptest.NewRequest(http.MethodPut, "/mdm", bytes.NewReader(body))
		req.Header.Set("Content-Type", ctCheckin)
		req.Header.Set("Mdm-Signature", detachedSignature(t, *dev, []byte("something else")))
		rec := httptest.NewRecorder()
		hs.h.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Fatal("tampered request accepted")
		}
	})

	t.Run("second device reusing the first device's certificate", func(t *testing.T) {
		rec := hs.checkin(dev, authenticateMsg("OTHER-DEVICE-UDID"))
		if rec.Code == http.StatusOK {
			t.Fatal("certificate reuse for another device accepted")
		}
		// And it cannot poll as the other device either.
		rec = hs.report(dev, map[string]any{"Status": "Idle", "UDID": "OTHER-DEVICE-UDID"})
		if rec.Code == http.StatusOK {
			t.Fatal("poll as another device accepted")
		}
		// A device with its own certificate enrols fine.
		other := newDevice(t, hs, "other")
		mustOK(t, hs.checkin(other, authenticateMsg("OTHER-DEVICE-UDID")))
		// ...but cannot take over the first device.
		if rec := hs.report(other, map[string]any{"Status": "Idle", "UDID": udid}); rec.Code == http.StatusOK {
			t.Fatal("second device polled as the first")
		}
	})

	if got := len(hs.ev.authenticated); got != n+1 { // only OTHER-DEVICE-UDID
		t.Fatalf("refused requests must not produce events: %d -> %d", n, got)
	}
}

func TestRefusesPathLikeIdentifiers(t *testing.T) {
	hs := newHarness(t)
	dev := newDevice(t, hs, "device")
	for _, bad := range []string{"../escape", "a/b", "x:y", ".."} {
		rec := hs.checkin(dev, authenticateMsg(bad))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("UDID %q: status %d", bad, rec.Code)
		}
	}
	if _, err := os.Stat(filepath.Join(hs.dir, "escape")); err == nil {
		t.Fatal("escaped the storage directory")
	}
}

func TestEventsCannotFailARequest(t *testing.T) {
	hs := newHarness(t)
	hs.ev.panicky = true
	dev := newDevice(t, hs, "device")
	mustOK(t, hs.checkin(dev, authenticateMsg(udid)))
	mustOK(t, hs.checkin(dev, tokenMsg(udid, "", "com.apple.mgmt.External.test")))
	id, err := hs.svc.Enqueue(context.Background(), udid, "DeviceInformation", nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := hs.report(dev, map[string]any{"UDID": udid, "Status": "Acknowledged", "CommandUUID": id})
	mustOK(t, rec)
	mustOK(t, hs.checkin(dev, map[string]any{"MessageType": "CheckOut", "UDID": udid}))
	if len(hs.ev.results) != 1 || len(hs.ev.checkouts) != 1 {
		t.Fatal("events were not delivered")
	}
}

func TestBodyLimitAndMethod(t *testing.T) {
	hs := newHarness(t)
	big := bytes.Repeat([]byte("a"), maxBodyBytes+1)
	req := httptest.NewRequest(http.MethodPut, "/mdm", bytes.NewReader(big))
	req.ContentLength = -1 // as with chunked uploads
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	hs.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mdm", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestPrivateDirectory(t *testing.T) {
	hs := newHarness(t)
	fi, err := os.Stat(filepath.Join(hs.dir, "nanomdm"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestPushCert(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()

	info, err := hs.svc.PushInfo(ctx)
	if err != nil || info.Configured {
		t.Fatalf("fresh: %+v %v", info, err)
	}

	notAfter := time.Now().Add(300 * 24 * time.Hour).Truncate(time.Second)
	topic := "com.apple.mgmt.External.0f0e0d0c-aaaa-bbbb-cccc-121212121212"
	certPEM, keyPEM, _ := pushCert(t, topic, notAfter)
	if err := hs.svc.SetPushCert(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	info, err = hs.svc.PushInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Configured || info.Topic != topic || !info.NotAfter.Equal(notAfter) {
		t.Fatalf("info: %+v", info)
	}

	// The key is only readable by the server.
	fi, err := os.Stat(filepath.Join(hs.dir, "nanomdm", topic+".key"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}

	// It survives a restart: a new Service over the same directory sees it.
	again, err := New(ctx, Options{DataDir: hs.dir, Authority: hs.auth, Events: hs.ev})
	if err != nil {
		t.Fatal(err)
	}
	if i, _ := again.PushInfo(ctx); !i.Configured || i.Topic != topic {
		t.Fatalf("after restart: %+v", i)
	}

	// Rejections.
	otherCert, otherKey, _ := pushCert(t, topic, notAfter)
	_ = otherCert
	if err := hs.svc.SetPushCert(ctx, certPEM, otherKey); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("mismatched key: %v", err)
	}
	noTopic, noTopicKey, _ := pushCert(t, "", notAfter)
	if err := hs.svc.SetPushCert(ctx, noTopic, noTopicKey); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("no topic: %v", err)
	}
	wrong, wrongKey, _ := pushCert(t, "com.example.other", notAfter)
	if err := hs.svc.SetPushCert(ctx, wrong, wrongKey); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("wrong topic: %v", err)
	}
	evil, evilKey, _ := pushCert(t, "com.apple.mgmt/../../evil", notAfter)
	if err := hs.svc.SetPushCert(ctx, evil, evilKey); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("path-like topic: %v", err)
	}
	old, oldKey, _ := pushCert(t, "com.apple.mgmt.External.old", time.Now().Add(-time.Minute))
	if err := hs.svc.SetPushCert(ctx, old, oldKey); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("expired: %v", err)
	}
	if err := hs.svc.SetPushCert(ctx, []byte("junk"), []byte("junk")); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("junk: %v", err)
	}
	// None of that disturbed the good one.
	if i, _ := hs.svc.PushInfo(ctx); i.Topic != topic {
		t.Fatalf("after rejections: %+v", i)
	}
}

func TestPush(t *testing.T) {
	hs := newHarness(t)
	dev := newDevice(t, hs, "device")
	ctx := context.Background()
	topic := "com.apple.mgmt.External.test"

	// Authenticated, no token yet, no certificate: nothing to do, no error.
	mustOK(t, hs.checkin(dev, authenticateMsg(udid)))
	if err := hs.svc.Push(ctx, udid); err != nil {
		t.Fatalf("no cert configured: %v", err)
	}
	if err := hs.svc.Push(ctx); err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, _ := pushCert(t, topic, time.Now().Add(time.Hour))
	if err := hs.svc.SetPushCert(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}

	// Configured, but the device has no push token yet, and an unknown one.
	if err := hs.svc.Push(ctx, udid, "UNKNOWN"); err != nil {
		t.Fatalf("no token: %v", err)
	}
	if len(hs.apns.pushed) != 0 {
		t.Fatalf("pushed without a token: %+v", hs.apns.pushed)
	}

	// With a token, on both channels.
	mustOK(t, hs.checkin(dev, tokenMsg(udid, "", topic)))
	mustOK(t, hs.checkin(dev, map[string]any{"MessageType": "UserAuthenticate", "UDID": udid, "UserID": userGUID, "UserShortName": "will"}))
	mustOK(t, hs.checkin(dev, tokenMsg(udid, userGUID, topic)))
	if err := hs.svc.Push(ctx, udid, userEnrol, udid); err != nil {
		t.Fatal(err)
	}
	if len(hs.apns.pushed) != 2 {
		t.Fatalf("pushed %d, want 2 (duplicates collapsed): %+v", len(hs.apns.pushed), hs.apns.pushed)
	}
	if p := hs.apns.pushed[0]; p.Topic != topic || !strings.HasPrefix(p.PushMagic, "MAGIC-") {
		t.Fatalf("push: %+v", p)
	}

	// A transport failure is an error.
	hs.apns.fail = errors.New("connection refused")
	if err := hs.svc.Push(ctx, udid); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("transport failure: %v", err)
	}
	hs.apns.fail = nil

	// A certificate for a different topic than the device's is an error
	// (the device could never be woken), not a silent skip.
	h2 := newHarness(t)
	dev2 := newDevice(t, h2, "device")
	mustOK(t, h2.checkin(dev2, authenticateMsg(udid)))
	mustOK(t, h2.checkin(dev2, tokenMsg(udid, "", topic)))
	otherPEM, otherKey, _ := pushCert(t, "com.apple.mgmt.External.other", time.Now().Add(time.Hour))
	if err := h2.svc.SetPushCert(ctx, otherPEM, otherKey); err != nil {
		t.Fatal(err)
	}
	if err := h2.svc.Push(ctx, udid); err == nil {
		t.Fatal("expected an error for a topic with no certificate")
	}

	if err := hs.svc.Push(ctx, "../x"); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("bad target: %v", err)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	hs := newHarness(t)
	if _, err := New(context.Background(), Options{Authority: hs.auth, Events: hs.ev}); err == nil {
		t.Fatal("DataDir")
	}
	if _, err := New(context.Background(), Options{DataDir: t.TempDir(), Events: hs.ev}); err == nil {
		t.Fatal("Authority")
	}
	if _, err := New(context.Background(), Options{DataDir: t.TempDir(), Authority: hs.auth}); err == nil {
		t.Fatal("Events")
	}
}
