package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openmdm/internal/core"
)

// secretMarker is a recognisable secret value. No response and no log line
// may ever contain it.
const secretMarker = "S3CR3T-VALUE-d41d8cd98f"

var (
	alice  = core.User{Username: "alice", Email: "alice@example.com", Role: core.RoleAdmin}
	george = core.User{Username: "george", Email: "george@example.com", Role: core.RoleUser, Groups: []string{"family"}}
	harry  = core.User{Username: "harry", Email: "harry@example.com", Role: core.RoleUser}
)

type env struct {
	t       *testing.T
	store   *memStore
	secrets *fakeSecrets
	rec     *fakeReconciler
	mdm     *fakeMDM
	enr     *fakeEnroller
	auth    *fakeAuthority
	api     *API
	h       http.Handler
	logs    *bytes.Buffer
	now     time.Time
	seen    []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		t: t, store: newMemStore(), secrets: newFakeSecrets(), rec: &fakeReconciler{},
		mdm: &fakeMDM{push: core.PushInfo{Configured: true, Topic: "com.apple.mgmt.External.x"}},
		enr: &fakeEnroller{}, auth: newFakeAuthority(), logs: &bytes.Buffer{},
		now: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC),
	}
	e.api = New(Deps{
		Store: e.store, Secrets: e.secrets, Renderer: fakeRenderer{}, Reconciler: e.rec, MDM: e.mdm,
		Enroller: e.enr, Authority: e.auth, Version: "1.2.3",
		Config: core.Config{PublicURL: "https://mdm.example.com/", Organization: "Example", Secrets: core.SecretsConfig{Backend: "openbao", Token: "hvs.configured-token-value"}},
		Logger: slog.New(slog.NewTextHandler(e.logs, nil)),
		Now:    func() time.Time { return e.now },
	})
	e.h = e.api.Handler()
	ctx := t.Context()
	for _, u := range []core.User{alice, george, harry} {
		if _, err := e.store.UpsertUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	devs := []core.Device{
		{ID: "d1", Username: "george", Platform: core.PlatformMacOS, SerialNumber: "SER1", Status: core.DeviceEnrolled, UserChannelID: "d1:GUID"},
		{ID: "d2", Username: "harry", Platform: core.PlatformIOS, SerialNumber: "SER2", Status: core.DeviceEnrolled},
		{ID: "d3", Platform: core.PlatformIPadOS, SerialNumber: "SER3", Status: core.DeviceEnrolled},
		{ID: "d4", Username: "george", Platform: core.PlatformIOS, SerialNumber: "SER4", Status: core.DeviceUnenrolled},
	}
	for _, d := range devs {
		_ = e.store.UpsertDevice(ctx, d)
	}
	t.Cleanup(func() {
		for _, s := range e.seen {
			if strings.Contains(s, secretMarker) {
				t.Errorf("a response contains a secret value: %.200s", s)
			}
		}
		if strings.Contains(e.logs.String(), secretMarker) {
			t.Errorf("the log contains a secret value")
		}
	})
	return e
}

// do makes a request as `as` (nil: nobody), with the CSRF header on anything
// that is not a GET.
func (e *env) do(as *core.User, method, path string, body any) *httptest.ResponseRecorder {
	hdr := http.Header{}
	if method != http.MethodGet {
		hdr.Set("X-Requested-With", "openmdm")
	}
	return e.doHdr(as, method, path, body, hdr)
}

func (e *env) doHdr(as *core.User, method, path string, body any, hdr http.Header) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd *strings.Reader
	switch b := body.(type) {
	case nil:
		rd = strings.NewReader("")
	case string:
		rd = strings.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = strings.NewReader(string(j))
	}
	req := httptest.NewRequest(method, path, rd)
	for k, v := range hdr {
		req.Header[k] = v
	}
	if as != nil {
		req = req.WithContext(core.WithUser(req.Context(), *as))
	}
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	e.record(rr)
	return rr
}

func (e *env) record(rr *httptest.ResponseRecorder) {
	e.seen = append(e.seen, rr.Body.String()+fmt.Sprint(rr.Header()))
}

func asUser(u core.User) *core.User { return &u }

func (e *env) json(as *core.User, method, path string, body any, wantStatus int) map[string]any {
	e.t.Helper()
	rr := e.do(as, method, path, body)
	if rr.Code != wantStatus {
		e.t.Fatalf("%s %s: status %d, want %d; body %s", method, path, rr.Code, wantStatus, rr.Body)
	}
	var m map[string]any
	if rr.Body.Len() > 0 {
		if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
			e.t.Fatalf("%s %s: not JSON: %v: %s", method, path, err, rr.Body)
		}
	}
	return m
}

func (e *env) errMsg(as *core.User, method, path string, body any, wantStatus int) string {
	e.t.Helper()
	m := e.json(as, method, path, body, wantStatus)
	s, _ := m["error"].(string)
	if s == "" {
		e.t.Fatalf("%s %s: no error message in %v", method, path, m)
	}
	return s
}

func list(t *testing.T, m map[string]any, key string) []any {
	t.Helper()
	l, ok := m[key].([]any)
	if !ok {
		t.Fatalf("%q is not a list in %v", key, m)
	}
	return l
}

// --- authorization ---

type route struct {
	method, path string
	body         any
	admin, user  int // status for an admin; for george, on his own things or on someone else's as the row says
}

func routes() []route {
	validProfile := map[string]any{"name": "N", "platforms": []string{"macos"}, "template": "<plist/>"}
	return []route{
		{"GET", "/api/v1/me", nil, 200, 200},
		{"GET", "/api/v1/users", nil, 200, 403},
		{"GET", "/api/v1/users/george", nil, 200, 200},
		{"GET", "/api/v1/users/harry", nil, 200, 403},
		{"GET", "/api/v1/users/george/secrets", nil, 200, 200},
		{"GET", "/api/v1/users/harry/secrets", nil, 200, 403},
		{"PUT", "/api/v1/users/george/secrets/k", map[string]string{"value": "v"}, 204, 204},
		{"PUT", "/api/v1/users/harry/secrets/k", map[string]string{"value": "v"}, 204, 403},
		{"DELETE", "/api/v1/users/george/secrets/k", nil, 204, 204},
		{"DELETE", "/api/v1/users/harry/secrets/k", nil, 204, 403},
		{"GET", "/api/v1/secrets/global", nil, 200, 403},
		{"PUT", "/api/v1/secrets/global/k", map[string]string{"value": "v"}, 204, 403},
		{"DELETE", "/api/v1/secrets/global/k", nil, 204, 403},
		{"GET", "/api/v1/devices", nil, 200, 200},
		{"GET", "/api/v1/devices/d1", nil, 200, 200},
		{"GET", "/api/v1/devices/d2", nil, 200, 404},
		{"GET", "/api/v1/devices/d3", nil, 200, 404},
		{"PUT", "/api/v1/devices/d1/owner", map[string]string{"username": "harry"}, 204, 403},
		{"POST", "/api/v1/devices/d1/sync", nil, 204, 204},
		{"POST", "/api/v1/devices/d2/sync", nil, 204, 404},
		{"POST", "/api/v1/devices/d1/lock", map[string]string{"pin": "123456"}, 200, 200},
		{"POST", "/api/v1/devices/d2/lock", nil, 200, 404},
		{"POST", "/api/v1/devices/d3/lock", nil, 200, 404},
		{"POST", "/api/v1/devices/d1/erase", map[string]string{"confirm": "SER1"}, 200, 403},
		{"DELETE", "/api/v1/devices/d1", nil, 204, 403},
		{"GET", "/api/v1/profiles", nil, 200, 403},
		{"GET", "/api/v1/profiles/p1", nil, 200, 403},
		{"PUT", "/api/v1/profiles/p1", validProfile, 200, 403},
		{"DELETE", "/api/v1/profiles/p1", nil, 204, 403},
		{"POST", "/api/v1/profiles/validate", validProfile, 200, 403},
		{"POST", "/api/v1/enrollments", map[string]string{}, 200, 200},
		{"POST", "/api/v1/enrollments", map[string]string{"username": "george"}, 200, 200},
		{"POST", "/api/v1/enrollments", map[string]string{"username": "harry"}, 200, 403},
		{"GET", "/api/v1/enrollments", nil, 200, 200},
		{"GET", "/api/v1/settings", nil, 200, 403},
		{"PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": "c", "key_pem": "k"}, 200, 403},
		{"GET", "/api/v1/settings/ca.pem", nil, 200, 403},
		{"GET", "/api/v1/events", nil, 200, 403},
	}
}

func seedProfile(e *env, id, source, template string) {
	_ = e.store.PutProfile(e.t.Context(), core.Profile{
		ID: id, Name: id, Platforms: []core.Platform{core.PlatformMacOS}, Source: source,
		Assignment: core.Assignment{Everyone: true}, Template: template,
	})
}

func TestAuthorizationMatrix(t *testing.T) {
	for _, rt := range routes() {
		for _, who := range []struct {
			name string
			u    *core.User
			want int
		}{{"admin", asUser(alice), rt.admin}, {"user", asUser(george), rt.user}} {
			t.Run(who.name+" "+rt.method+" "+rt.path, func(t *testing.T) {
				e := newEnv(t)
				seedProfile(e, "p1", "ui", "<plist/>")
				rr := e.do(who.u, rt.method, rt.path, rt.body)
				if rr.Code != who.want {
					t.Fatalf("status %d, want %d; body %s", rr.Code, who.want, rr.Body)
				}
				if rr.Code >= 400 {
					var m map[string]string
					if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil || m["error"] == "" {
						t.Fatalf("error body is not {\"error\": ...}: %s", rr.Body)
					}
				}
			})
		}
	}
}

func TestNoUserIs401(t *testing.T) {
	e := newEnv(t)
	for _, rt := range routes() {
		rr := e.do(nil, rt.method, rt.path, rt.body)
		if rr.Code != 401 {
			t.Errorf("%s %s: status %d, want 401", rt.method, rt.path, rr.Code)
		}
	}
	// 401 comes before the CSRF check, and before routing.
	if rr := e.doHdr(nil, "POST", "/api/v1/devices/d1/sync", nil, nil); rr.Code != 401 {
		t.Errorf("no user, no header: %d", rr.Code)
	}
	if rr := e.do(nil, "GET", "/api/v1/nothing", nil); rr.Code != 401 {
		t.Errorf("unknown path, no user: %d", rr.Code)
	}
	if len(e.mdm.enqueued)+len(e.mdm.pushed) != 0 {
		t.Error("an unauthenticated request did something")
	}
}

func TestUnknownRoutes(t *testing.T) {
	e := newEnv(t)
	e.errMsg(asUser(alice), "GET", "/api/v1/nothing", nil, 404)
	e.errMsg(asUser(alice), "GET", "/elsewhere", nil, 404)
	e.errMsg(asUser(alice), "PATCH", "/api/v1/me", nil, 405)
}

func TestCSRFHeader(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		name string
		hdr  http.Header
		want int
	}{
		{"none", http.Header{}, 403},
		{"wrong value", http.Header{"X-Requested-With": {"XMLHttpRequest"}}, 403},
		{"right", http.Header{"X-Requested-With": {"openmdm"}}, 204},
	} {
		rr := e.doHdr(asUser(alice), "POST", "/api/v1/devices/d1/sync", nil, tc.hdr)
		if rr.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, rr.Code, tc.want)
		}
	}
	// Every verb that changes something needs it.
	for _, m := range []string{"PUT", "DELETE", "POST"} {
		rr := e.doHdr(asUser(alice), m, "/api/v1/secrets/global/k", map[string]string{"value": "x"}, http.Header{})
		if rr.Code != 403 {
			t.Errorf("%s without header: %d", m, rr.Code)
		}
	}
	if _, ok := e.secrets.global["k"]; ok {
		t.Error("a request without the header changed a secret")
	}
	// A GET needs none.
	if rr := e.doHdr(asUser(alice), "GET", "/api/v1/me", nil, http.Header{}); rr.Code != 200 {
		t.Errorf("GET: %d", rr.Code)
	}
}

// --- shapes ---

func TestMeAndUsers(t *testing.T) {
	e := newEnv(t)
	m := e.json(asUser(george), "GET", "/api/v1/me", nil, 200)
	if m["public_url"] != "https://mdm.example.com/" || m["version"] != "1.2.3" {
		t.Errorf("me: %v", m)
	}
	if m["user"].(map[string]any)["username"] != "george" || m["push"].(map[string]any)["configured"] != true {
		t.Errorf("me: %v", m)
	}
	if got := len(list(t, e.json(asUser(alice), "GET", "/api/v1/users", nil, 200), "users")); got != 3 {
		t.Errorf("users: %d", got)
	}
	m = e.json(asUser(george), "GET", "/api/v1/users/George", nil, 200) // case does not matter
	if m["user"].(map[string]any)["username"] != "george" {
		t.Errorf("user: %v", m)
	}
	if got := len(list(t, m, "devices")); got != 2 {
		t.Errorf("george's devices: %d", got)
	}
	e.errMsg(asUser(alice), "GET", "/api/v1/users/nobody", nil, 404)
	e.errMsg(asUser(alice), "GET", "/api/v1/users/a%2Fb", nil, 400)
}

func TestDevicesList(t *testing.T) {
	e := newEnv(t)
	if got := len(list(t, e.json(asUser(alice), "GET", "/api/v1/devices", nil, 200), "devices")); got != 4 {
		t.Errorf("admin sees %d devices", got)
	}
	devs := list(t, e.json(asUser(george), "GET", "/api/v1/devices", nil, 200), "devices")
	if len(devs) != 2 {
		t.Errorf("george sees %d devices", len(devs))
	}
	e.store.devices = map[string]core.Device{}
	m := e.json(asUser(harry), "GET", "/api/v1/devices", nil, 200)
	if m["devices"] == nil || len(list(t, m, "devices")) != 0 {
		t.Errorf("empty list should be []: %v", m)
	}
}

func TestDeviceDetail(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 60; i++ {
		_ = e.store.PutCommand(t.Context(), core.CommandRecord{UUID: fmt.Sprint("c", i), DeviceID: "d1", RequestType: "InstallProfile"})
	}
	m := e.json(asUser(george), "GET", "/api/v1/devices/d1", nil, 200)
	if m["device"].(map[string]any)["id"] != "d1" {
		t.Errorf("device: %v", m)
	}
	if m["owner"].(map[string]any)["username"] != "george" {
		t.Errorf("owner: %v", m["owner"])
	}
	if got := len(list(t, m, "commands")); got != 50 {
		t.Errorf("commands: %d, want 50", got)
	}
	if p := list(t, m, "profiles"); len(p) != 1 || p[0].(map[string]any)["profile_id"] != "p1" {
		t.Errorf("profiles: %v", p)
	}
	// An admin sees an ownerless device; owner is null.
	m = e.json(asUser(alice), "GET", "/api/v1/devices/d3", nil, 200)
	if v, ok := m["owner"]; !ok || v != nil {
		t.Errorf("owner of an ownerless device should be null: %v", m)
	}
	e.errMsg(asUser(alice), "GET", "/api/v1/devices/zzz", nil, 404)
	e.rec.planErr = errors.New("database is on fire")
	if msg := e.errMsg(asUser(alice), "GET", "/api/v1/devices/d1", nil, 500); strings.Contains(msg, "fire") {
		t.Errorf("a 500 must be generic, got %q", msg)
	}
	if !strings.Contains(e.logs.String(), "database is on fire") {
		t.Error("the cause of a 500 should be logged")
	}
}

func TestSetOwner(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	e.json(a, "PUT", "/api/v1/devices/d3/owner", map[string]string{"username": "Harry"}, 204)
	if d, _ := e.store.GetDevice(t.Context(), "d3"); d.Username != "harry" {
		t.Errorf("owner %q", d.Username)
	}
	if tr, _ := e.rec.snapshot(); len(tr) != 1 || tr[0] != "d3" {
		t.Errorf("triggered %v", tr)
	}
	if ev := e.store.lastEvent(); ev.Kind != "device.owner" || ev.Actor != "alice" || ev.Subject != "d3" {
		t.Errorf("event %+v", ev)
	}
	e.json(a, "PUT", "/api/v1/devices/d3/owner", map[string]string{"username": ""}, 204)
	if d, _ := e.store.GetDevice(t.Context(), "d3"); d.Username != "" {
		t.Errorf("owner not cleared: %q", d.Username)
	}
	e.errMsg(a, "PUT", "/api/v1/devices/d3/owner", map[string]string{"username": "ghost"}, 400)
	e.errMsg(a, "PUT", "/api/v1/devices/nope/owner", map[string]string{"username": "harry"}, 404)
	e.errMsg(a, "PUT", "/api/v1/devices/d3/owner", `{"username":"harry","extra":1}`, 400)
}

func TestSync(t *testing.T) {
	e := newEnv(t)
	e.json(asUser(george), "POST", "/api/v1/devices/d1/sync", nil, 204)
	e.json(asUser(george), "POST", "/api/v1/devices/d4/sync", nil, 204)
	tr, _ := e.rec.snapshot()
	if len(tr) != 2 || tr[0] != "d1" {
		t.Errorf("triggered %v", tr)
	}
	if len(e.mdm.pushed) != 2 || strings.Join(e.mdm.pushed[0], ",") != "d1,d1:GUID" || strings.Join(e.mdm.pushed[1], ",") != "d4" {
		t.Errorf("pushed %v", e.mdm.pushed)
	}
}

func TestLock(t *testing.T) {
	e := newEnv(t)
	g := asUser(george)
	e.errMsg(g, "POST", "/api/v1/devices/d1/lock", nil, 400) // a Mac needs a PIN
	e.errMsg(g, "POST", "/api/v1/devices/d1/lock", map[string]string{"pin": "12345"}, 400)
	e.errMsg(g, "POST", "/api/v1/devices/d1/lock", map[string]string{"pin": "12345a"}, 400)
	if len(e.mdm.enqueued) != 0 {
		t.Fatal("a bad request queued a command")
	}
	m := e.json(g, "POST", "/api/v1/devices/d1/lock", map[string]string{"pin": "123456", "message": "call me"}, 200)
	if m["command_uuid"] != "cmd-1" {
		t.Errorf("response %v", m)
	}
	c := e.mdm.enqueued[0]
	if c.Target != "d1" || c.Type != "DeviceLock" || c.Cmd["PIN"] != "123456" || c.Cmd["Message"] != "call me" {
		t.Errorf("enqueued %+v", c)
	}
	if rec, err := e.store.GetCommand(t.Context(), "cmd-1"); err != nil || rec.RequestType != "DeviceLock" || rec.DeviceID != "d1" || rec.Status != core.CommandQueued {
		t.Errorf("command record %+v %v", rec, err)
	}
	if len(e.mdm.pushed) != 1 || len(e.mdm.pushed[0]) != 2 {
		t.Errorf("pushed %v", e.mdm.pushed)
	}
	if ev := e.store.lastEvent(); ev.Kind != "device.lock" || ev.Actor != "george" || strings.Contains(ev.Detail, "123456") {
		t.Errorf("event %+v", ev)
	}
	// An iPhone: no PIN, whatever was sent is ignored.
	e.json(asUser(harry), "POST", "/api/v1/devices/d2/lock", map[string]string{"pin": "654321", "message": "lost"}, 200)
	c = e.mdm.enqueued[1]
	if _, has := c.Cmd["PIN"]; has || c.Cmd["Message"] != "lost" {
		t.Errorf("iOS lock enqueued %+v", c)
	}
	// Empty body is fine for an iPhone.
	e.json(asUser(harry), "POST", "/api/v1/devices/d2/lock", nil, 200)
	// A device that has left.
	e.errMsg(g, "POST", "/api/v1/devices/d4/lock", nil, 409)
}

func TestErase(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	e.errMsg(a, "POST", "/api/v1/devices/d1/erase", map[string]string{"confirm": "ser1"}, 400)
	e.errMsg(a, "POST", "/api/v1/devices/d1/erase", map[string]string{"confirm": ""}, 400)
	e.errMsg(a, "POST", "/api/v1/devices/d1/erase", map[string]string{"confirm": "d1"}, 400)
	e.errMsg(a, "POST", "/api/v1/devices/d1/erase", nil, 400)
	if len(e.mdm.enqueued) != 0 {
		t.Fatal("a refused erase queued a command")
	}
	m := e.json(a, "POST", "/api/v1/devices/d1/erase", map[string]string{"confirm": "SER1"}, 200)
	if m["command_uuid"] == "" {
		t.Errorf("response %v", m)
	}
	c := e.mdm.enqueued[0]
	pin, _ := c.Cmd["PIN"].(string)
	if c.Type != "EraseDevice" || c.Target != "d1" || !pinRE.MatchString(pin) {
		t.Errorf("enqueued %+v", c)
	}
	if m["pin"] != pin {
		t.Errorf("the generated PIN must be returned once: %v", m)
	}
	if ev := e.store.lastEvent(); ev.Kind != "device.erase" || strings.Contains(ev.Detail, pin) {
		t.Errorf("event %+v", ev)
	}
	// A supplied PIN is used and not echoed.
	m = e.json(a, "POST", "/api/v1/devices/d1/erase", map[string]string{"confirm": "SER1", "pin": "111222"}, 200)
	if e.mdm.enqueued[1].Cmd["PIN"] != "111222" {
		t.Errorf("enqueued %+v", e.mdm.enqueued[1])
	}
	if _, has := m["pin"]; has {
		t.Errorf("a supplied PIN was echoed: %v", m)
	}
	e.errMsg(a, "POST", "/api/v1/devices/d1/erase", map[string]string{"confirm": "SER1", "pin": "12"}, 400)
	// An iPhone: no PIN at all.
	e.json(a, "POST", "/api/v1/devices/d2/erase", map[string]string{"confirm": "SER2"}, 200)
	if c := e.mdm.enqueued[2]; c.Cmd != nil || c.Type != "EraseDevice" {
		t.Errorf("iOS erase enqueued %+v", c)
	}
	if rec, err := e.store.GetCommand(t.Context(), "cmd-3"); err != nil || rec.RequestType != "EraseDevice" {
		t.Errorf("command record %+v %v", rec, err)
	}
}

func TestDeleteDevice(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	e.json(a, "DELETE", "/api/v1/devices/d1", nil, 204)
	if len(e.mdm.removed) != 1 || e.mdm.removed[0] != [2]string{"d1", "openmdm.enrollment"} {
		t.Errorf("removed %v", e.mdm.removed)
	}
	if len(e.mdm.pushed) != 1 {
		t.Errorf("pushed %v", e.mdm.pushed)
	}
	if _, err := e.store.GetDevice(t.Context(), "d1"); !errors.Is(err, core.ErrNotFound) {
		t.Error("device not deleted")
	}
	if ev := e.store.lastEvent(); ev.Kind != "device.deleted" || ev.Subject != "d1" {
		t.Errorf("event %+v", ev)
	}
	// Best effort: a failing removal does not stop the delete.
	e.mdm.removeErr = errors.New("no push token")
	e.json(a, "DELETE", "/api/v1/devices/d2", nil, 204)
	if _, err := e.store.GetDevice(t.Context(), "d2"); !errors.Is(err, core.ErrNotFound) {
		t.Error("device not deleted after a failed removal")
	}
	// An unenrolled one is only forgotten.
	before := len(e.mdm.removed)
	e.json(a, "DELETE", "/api/v1/devices/d4", nil, 204)
	if len(e.mdm.removed) != before {
		t.Error("RemoveProfile sent to a device that is not enrolled")
	}
	e.errMsg(a, "DELETE", "/api/v1/devices/d4", nil, 404)
}

// --- secrets ---

func TestSecrets(t *testing.T) {
	e := newEnv(t)
	a, g := asUser(alice), asUser(george)
	// Profiles: one for everyone naming two user secrets and a global one; one
	// for harry only; one for the family group.
	_ = e.store.PutProfile(t.Context(), core.Profile{ID: "mail", Source: "ui", Assignment: core.Assignment{Everyone: true},
		Template: `{{ secret "mail_pw" }} {{ secret "extra" }} {{ globalSecret "wifi" }}`})
	_ = e.store.PutProfile(t.Context(), core.Profile{ID: "harry-only", Source: "ui", Assignment: core.Assignment{Users: []string{"harry"}},
		Template: `{{ secret "harry_key" }}`})
	_ = e.store.PutProfile(t.Context(), core.Profile{ID: "family", Source: "ui", Assignment: core.Assignment{Groups: []string{"family"}},
		Template: `{{ secret "mail_pw" }} {{ globalSecret "wifi" }} {{ globalSecret "other" }}`})
	_ = e.store.PutProfile(t.Context(), core.Profile{ID: "bad", Source: "ui", Assignment: core.Assignment{Everyone: true}, Template: `BROKEN {{ secret "nope" }}`})

	e.json(g, "PUT", "/api/v1/users/george/secrets/mail_pw", map[string]string{"value": secretMarker}, 204)
	e.json(g, "PUT", "/api/v1/users/george/secrets/stray", map[string]string{"value": secretMarker}, 204)
	if e.secrets.users["george"]["mail_pw"] != secretMarker {
		t.Error("not stored as given")
	}
	if tr, _ := e.rec.snapshot(); len(tr) != 4 { // d1 and d4 for each of the two secrets
		t.Errorf("triggered %v", tr)
	}
	ev := e.store.lastEvent()
	if ev.Kind != "secret.set" || ev.Actor != "george" || ev.Subject != "george/stray" || strings.Contains(fmt.Sprint(ev), secretMarker) {
		t.Errorf("event %+v", ev)
	}

	m := e.json(g, "GET", "/api/v1/users/george/secrets", nil, 200)
	want := `[{"key":"extra","set":false,"used_by":["mail"]},{"key":"mail_pw","set":true,"used_by":["family","mail"]},{"key":"stray","set":true,"used_by":[]}]`
	got, _ := json.Marshal(m["secrets"])
	if string(got) != want {
		t.Errorf("secrets\n got %s\nwant %s", got, want)
	}

	// Global.
	e.json(a, "PUT", "/api/v1/secrets/global/wifi", map[string]string{"value": secretMarker}, 204)
	if _, all := e.rec.snapshot(); all != 1 {
		t.Errorf("TriggerAll called %d times", all)
	}
	if ev := e.store.lastEvent(); ev.Kind != "secret.set" || ev.Subject != "global/wifi" {
		t.Errorf("event %+v", ev)
	}
	m = e.json(a, "GET", "/api/v1/secrets/global", nil, 200)
	got, _ = json.Marshal(m["secrets"])
	if want := `[{"key":"other","set":false,"used_by":["family"]},{"key":"wifi","set":true,"used_by":["family","mail"]}]`; string(got) != want {
		t.Errorf("global\n got %s\nwant %s", got, want)
	}
	e.json(a, "DELETE", "/api/v1/secrets/global/wifi", nil, 204)
	if _, all := e.rec.snapshot(); all != 2 {
		t.Errorf("TriggerAll called %d times", all)
	}
	if ev := e.store.lastEvent(); ev.Kind != "secret.deleted" || ev.Subject != "global/wifi" {
		t.Errorf("event %+v", ev)
	}

	// Delete a user's.
	e.json(g, "DELETE", "/api/v1/users/george/secrets/stray", nil, 204)
	if _, has := e.secrets.users["george"]["stray"]; has {
		t.Error("not deleted")
	}
	if ev := e.store.lastEvent(); ev.Kind != "secret.deleted" || ev.Subject != "george/stray" {
		t.Errorf("event %+v", ev)
	}
}

func TestSecretValidation(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	p := "/api/v1/users/george/secrets/"
	e.errMsg(a, "PUT", p+"Bad-Key", map[string]string{"value": "x"}, 400)
	e.errMsg(a, "PUT", p+"bad%20key", map[string]string{"value": "x"}, 400)
	e.errMsg(a, "DELETE", p+"Bad", nil, 400)
	e.errMsg(a, "PUT", "/api/v1/secrets/global/UP", map[string]string{"value": "x"}, 400)
	e.errMsg(a, "PUT", p+"k", map[string]string{"value": ""}, 400)
	e.errMsg(a, "PUT", p+"k", nil, 400)
	e.errMsg(a, "PUT", p+"k", `{"value":"x","encoding":"hex"}`, 400)
	e.errMsg(a, "PUT", p+"k", `{"value":"x","surprise":true}`, 400)
	e.errMsg(a, "PUT", p+"k", `{"value":"x"} {"value":"y"}`, 400)
	e.errMsg(a, "PUT", p+"k", `{"value":`, 400)
	msg := e.errMsg(a, "PUT", p+"k", map[string]string{"value": secretMarker + "!!!", "encoding": "base64"}, 400)
	if strings.Contains(msg, secretMarker) {
		t.Error("error echoes the value")
	}
	// Valid base64 is stored as given, not decoded.
	enc := base64.StdEncoding.EncodeToString([]byte("binary\x00data"))
	e.json(a, "PUT", p+"cert", map[string]string{"value": enc, "encoding": "base64"}, 204)
	if e.secrets.users["george"]["cert"] != enc {
		t.Errorf("stored %q", e.secrets.users["george"]["cert"])
	}
	// A body over 2 MiB.
	big := `{"value":"` + strings.Repeat("a", 3<<20) + `"}`
	e.errMsg(a, "PUT", p+"k", big, http.StatusRequestEntityTooLarge)
	if _, has := e.secrets.users["george"]["k"]; has {
		t.Error("something was stored")
	}
}

func TestSecretForPersonWhoHasNotSignedIn(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	if _, err := e.store.GetUser(t.Context(), "newbie"); err == nil {
		t.Fatal("precondition")
	}
	e.json(a, "PUT", "/api/v1/users/Newbie/secrets/pw", map[string]string{"value": "v"}, 204)
	u, err := e.store.GetUser(t.Context(), "newbie")
	if err != nil || u.Role != core.RoleUser || u.Username != "newbie" {
		t.Errorf("user %+v %v", u, err)
	}
	// An existing person is left alone.
	e.json(a, "PUT", "/api/v1/users/george/secrets/pw", map[string]string{"value": "v"}, 204)
	if g, _ := e.store.GetUser(t.Context(), "george"); g.Email != "george@example.com" || len(g.Groups) != 1 {
		t.Errorf("george was overwritten: %+v", g)
	}
	// Listing for one without a row still works.
	e.json(a, "GET", "/api/v1/users/ghost/secrets", nil, 200)
	// So does an enrolment.
	m := e.json(a, "POST", "/api/v1/enrollments", map[string]string{"username": "Another"}, 200)
	if m["enrollment"].(map[string]any)["username"] != "another" {
		t.Errorf("enrollment %v", m)
	}
	if u, err := e.store.GetUser(t.Context(), "another"); err != nil || u.Role != core.RoleUser {
		t.Errorf("user %+v %v", u, err)
	}
}

// Store a recognisable value, then ask for everything there is.
func TestNoRouteReturnsASecretValue(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	_ = e.secrets.SetUserSecret(t.Context(), "george", "mail_pw", secretMarker)
	_ = e.secrets.SetGlobalSecret(t.Context(), "wifi", secretMarker)
	e.json(a, "PUT", "/api/v1/users/george/secrets/other", map[string]string{"value": secretMarker}, 204)
	seedProfile(e, "p1", "ui", `{{ secret "mail_pw" }} {{ globalSecret "wifi" }}`)
	for _, rt := range routes() {
		if rt.method == "GET" {
			e.do(a, "GET", rt.path, nil)
			e.do(asUser(george), "GET", rt.path, nil)
		}
	}
	e.do(a, "GET", "/api/v1/profiles/p1", nil)
	e.do(nil, "GET", "/api/v1/users/george/secrets", nil)
	rr := httptest.NewRecorder()
	e.api.HealthHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	e.record(rr)
	// The cleanup of newEnv scans every response recorded, and the log.
}

// --- profiles ---

func TestProfiles(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	seedProfile(e, "from-file", "file", `{{ secret "pw" }}`)
	seedProfile(e, "broken", "ui", "BROKEN")
	_ = e.store.PutDeviceProfile(t.Context(), core.DeviceProfile{DeviceID: "d1", ProfileID: "from-file", State: core.StateInstalled})
	_ = e.store.PutDeviceProfile(t.Context(), core.DeviceProfile{DeviceID: "d2", ProfileID: "from-file", State: core.StateInstalled})
	_ = e.store.PutDeviceProfile(t.Context(), core.DeviceProfile{DeviceID: "d3", ProfileID: "from-file", State: core.StateBlocked})
	_ = e.store.PutDeviceProfile(t.Context(), core.DeviceProfile{DeviceID: "gone", ProfileID: "from-file", State: core.StateFailed})

	m := e.json(a, "GET", "/api/v1/profiles", nil, 200)
	ps := list(t, m, "profiles")
	if len(ps) != 2 {
		t.Fatalf("profiles: %v", ps)
	}
	byID := map[string]map[string]any{}
	for _, p := range ps {
		pm := p.(map[string]any)
		byID[pm["id"].(string)] = pm
		if _, has := pm["template"]; has {
			t.Errorf("template in the list: %v", pm)
		}
	}
	ff := byID["from-file"]
	counts := ff["counts"].(map[string]any)
	if counts["installed"] != 2.0 || counts["blocked"] != 1.0 || counts["failed"] != 1.0 || counts["pending"] != 0.0 {
		t.Errorf("counts %v", counts)
	}
	if ff["info"].(map[string]any)["user_secrets"].([]any)[0] != "pw" || ff["source"] != "file" {
		t.Errorf("from-file %v", ff)
	}
	if _, has := ff["error"]; has {
		t.Errorf("unexpected error: %v", ff)
	}
	if msg, _ := byID["broken"]["error"].(string); !strings.Contains(msg, "does not parse") || strings.HasPrefix(msg, "invalid") {
		t.Errorf("broken profile error %q", msg)
	}
	if byID["broken"]["info"] == nil {
		t.Error("info must be present even when the template is broken")
	}

	m = e.json(a, "GET", "/api/v1/profiles/from-file", nil, 200)
	if m["profile"].(map[string]any)["template"] == "" || m["info"] == nil {
		t.Errorf("profile %v", m)
	}
	devs := list(t, m, "devices")
	if len(devs) != 3 { // "gone" is skipped
		t.Errorf("devices %v", devs)
	}
	if d := devs[0].(map[string]any); d["device"].(map[string]any)["id"] != "d1" || d["state"].(map[string]any)["state"] != "installed" {
		t.Errorf("device entry %v", d)
	}
	e.errMsg(a, "GET", "/api/v1/profiles/none", nil, 404)
}

func TestPutProfile(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	body := map[string]any{
		"id": "ignored", "name": "Mail", "platforms": []string{"macos", "ios"}, "source": "file",
		"assignment": map[string]any{"everyone": true}, "template": `<plist>{{ secret "pw" }}</plist>`,
	}
	m := e.json(a, "PUT", "/api/v1/profiles/mail", body, 200)
	p := m["profile"].(map[string]any)
	if p["id"] != "mail" || p["source"] != "ui" || p["macos_channel"] != "device" || p["updated_at"] == "" {
		t.Errorf("profile %v", p)
	}
	if m["info"].(map[string]any)["user_secrets"].([]any)[0] != "pw" {
		t.Errorf("info %v", m["info"])
	}
	if _, all := e.rec.snapshot(); all != 1 {
		t.Errorf("TriggerAll %d", all)
	}
	if ev := e.store.lastEvent(); ev.Kind != "profile.saved" || ev.Subject != "mail" || ev.Actor != "alice" {
		t.Errorf("event %+v", ev)
	}
	// Replacing a UI profile is fine.
	e.json(a, "PUT", "/api/v1/profiles/mail", body, 200)

	// Validation failures: nothing saved.
	bad := map[string]any{"name": "x", "platforms": []string{"macos"}, "template": "BROKEN"}
	if msg := e.errMsg(a, "PUT", "/api/v1/profiles/new", bad, 400); msg != "template does not parse" {
		t.Errorf("message %q", msg)
	}
	if _, err := e.store.GetProfile(t.Context(), "new"); err == nil {
		t.Error("an invalid profile was saved")
	}
	e.errMsg(a, "PUT", "/api/v1/profiles/Bad_ID", body, 400)
	e.errMsg(a, "PUT", "/api/v1/profiles/new", map[string]any{"template": "<plist/>"}, 400)
	e.errMsg(a, "PUT", "/api/v1/profiles/new", map[string]any{"platforms": []string{"windows"}, "template": "<plist/>"}, 400)
	e.errMsg(a, "PUT", "/api/v1/profiles/new", map[string]any{"platforms": []string{"macos"}, "macos_channel": "both", "template": "<plist/>"}, 400)
	e.errMsg(a, "PUT", "/api/v1/profiles/new", map[string]any{"platforms": []string{"macos"}, "bogus": 1}, 400)
}

func TestFileProfilesAreReadOnly(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	seedProfile(e, "f", "file", "<plist/>")
	body := map[string]any{"name": "x", "platforms": []string{"macos"}, "template": "<plist>changed</plist>"}
	e.errMsg(a, "PUT", "/api/v1/profiles/f", body, 409)
	e.errMsg(a, "DELETE", "/api/v1/profiles/f", nil, 409)
	if p, _ := e.store.GetProfile(t.Context(), "f"); p.Template != "<plist/>" || p.Source != "file" {
		t.Errorf("file profile was touched: %+v", p)
	}
	if _, all := e.rec.snapshot(); all != 0 {
		t.Error("reconcile triggered by a refused change")
	}
	// A UI profile can be deleted.
	seedProfile(e, "u", "ui", "<plist/>")
	e.json(a, "DELETE", "/api/v1/profiles/u", nil, 204)
	if _, all := e.rec.snapshot(); all != 1 {
		t.Errorf("TriggerAll %d", all)
	}
	if ev := e.store.lastEvent(); ev.Kind != "profile.deleted" || ev.Subject != "u" {
		t.Errorf("event %+v", ev)
	}
	e.errMsg(a, "DELETE", "/api/v1/profiles/u", nil, 404)
}

func TestValidateProfile(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	m := e.json(a, "POST", "/api/v1/profiles/validate", map[string]any{"template": `{{ globalSecret "g" }}`}, 200)
	info := m["info"].(map[string]any)
	if info["global_secrets"].([]any)[0] != "g" || info["user_secrets"] == nil {
		t.Errorf("info %v", info)
	}
	if msg := e.errMsg(a, "POST", "/api/v1/profiles/validate", map[string]any{"template": "BROKEN"}, 400); msg != "template does not parse" {
		t.Errorf("message %q", msg)
	}
	if len(e.store.profiles) != 0 {
		t.Error("validate saved something")
	}
	if _, all := e.rec.snapshot(); all != 0 {
		t.Error("validate reconciled")
	}
}

// --- enrolments ---

func TestCreateEnrollment(t *testing.T) {
	e := newEnv(t)
	m := e.json(asUser(george), "POST", "/api/v1/enrollments", nil, 200) // no body at all
	en := m["enrollment"].(map[string]any)
	token := en["token"].(string)
	if en["username"] != "george" || en["created_by"] != "george" {
		t.Errorf("enrollment %v", en)
	}
	if _, has := en["challenge"]; has {
		t.Error("the challenge must not be in the response")
	}
	if len(token) != 43 || strings.ContainsAny(token, "=+/") {
		t.Errorf("token %q should be 32 bytes of base64url without padding", token)
	}
	if m["url"] != "https://mdm.example.com/enroll/"+token {
		t.Errorf("url %v", m["url"])
	}
	if en["expires_at"] != e.now.Add(time.Hour).Format(time.RFC3339) {
		t.Errorf("expires_at %v (default TTL is 1h)", en["expires_at"])
	}
	stored := e.store.enrolls[token]
	if len(stored.Challenge) != 43 || stored.Challenge == token {
		t.Errorf("challenge %q", stored.Challenge)
	}
	if ev := e.store.lastEvent(); ev.Kind != "enrollment.created" || ev.Subject != "george" || strings.Contains(fmt.Sprint(ev), token) || strings.Contains(fmt.Sprint(ev), stored.Challenge) {
		t.Errorf("event %+v", ev)
	}
	// Admin for someone else, with a configured TTL.
	e.api.d.Config.EnrollmentTTL = 10 * time.Minute
	m = e.json(asUser(alice), "POST", "/api/v1/enrollments", map[string]string{"username": "harry"}, 200)
	en = m["enrollment"].(map[string]any)
	if en["username"] != "harry" || en["created_by"] != "alice" || en["expires_at"] != e.now.Add(10*time.Minute).Format(time.RFC3339) {
		t.Errorf("enrollment %v", en)
	}
	if m["enrollment"].(map[string]any)["token"] == token {
		t.Error("tokens repeat")
	}
}

func TestListEnrollments(t *testing.T) {
	e := newEnv(t)
	e.json(asUser(george), "POST", "/api/v1/enrollments", nil, 200)
	e.json(asUser(alice), "POST", "/api/v1/enrollments", map[string]string{"username": "harry"}, 200)
	if n := len(list(t, e.json(asUser(alice), "GET", "/api/v1/enrollments", nil, 200), "enrollments")); n != 2 {
		t.Errorf("admin sees %d", n)
	}
	l := list(t, e.json(asUser(george), "GET", "/api/v1/enrollments", nil, 200), "enrollments")
	if len(l) != 1 || l[0].(map[string]any)["username"] != "george" {
		t.Errorf("george sees %v", l)
	}
	if n := len(list(t, e.json(asUser(core.User{Username: "x", Role: core.RoleUser}), "GET", "/api/v1/enrollments", nil, 200), "enrollments")); n != 0 {
		t.Errorf("a stranger sees %d", n)
	}
}

func (e *env) enrollGet(token string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	e.api.EnrollHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/enroll/"+token, nil))
	e.record(rr)
	return rr
}

func newToken(t *testing.T, e *env) string {
	t.Helper()
	m := e.json(asUser(george), "POST", "/api/v1/enrollments", nil, 200)
	return m["enrollment"].(map[string]any)["token"].(string)
}

func TestEnrollLink(t *testing.T) {
	e := newEnv(t)
	token := newToken(t, e)

	rr := e.enrollGet(token)
	if rr.Code != 200 {
		t.Fatalf("status %d: %s", rr.Code, rr.Body)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/x-apple-aspen-config" {
		t.Errorf("content type %q", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); cd != `attachment; filename="enroll.mobileconfig"` {
		t.Errorf("disposition %q", cd)
	}
	if rr.Body.String() != "<plist>enrol for george</plist>" {
		t.Errorf("body %q", rr.Body)
	}
	if e.store.enrolls[token].DownloadedAt == nil {
		t.Error("not marked as downloaded")
	}
	// Once.
	rr = e.enrollGet(token)
	if rr.Code != http.StatusGone || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain") || rr.Body.Len() == 0 {
		t.Errorf("second download: %d %q %q", rr.Code, rr.Header().Get("Content-Type"), rr.Body)
	}
	// Unknown.
	rr = e.enrollGet("no-such-token")
	if rr.Code != 404 || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("unknown: %d", rr.Code)
	}
	// Expired.
	token2 := newToken(t, e)
	e.now = e.now.Add(2 * time.Hour)
	if rr = e.enrollGet(token2); rr.Code != 404 {
		t.Errorf("expired: %d", rr.Code)
	}
	if e.store.enrolls[token2].DownloadedAt != nil {
		t.Error("an expired link was claimed")
	}
}

func TestEnrollNotReadyLeavesLinkUsable(t *testing.T) {
	e := newEnv(t)
	token := newToken(t, e)
	e.enr.err = fmt.Errorf("%w: no push certificate has been uploaded yet", core.ErrInvalid)
	for i := 0; i < 2; i++ {
		rr := e.enrollGet(token)
		if rr.Code != http.StatusServiceUnavailable || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain") {
			t.Fatalf("status %d %q", rr.Code, rr.Header().Get("Content-Type"))
		}
		if !strings.Contains(rr.Body.String(), "no push certificate has been uploaded yet") {
			t.Errorf("body %q", rr.Body)
		}
	}
	if e.store.enrolls[token].DownloadedAt != nil {
		t.Fatal("a 503 used up the link")
	}
	e.enr.err = nil
	if rr := e.enrollGet(token); rr.Code != 200 {
		t.Errorf("after setup: %d %s", rr.Code, rr.Body)
	}
	// Another failure is a 500 with nothing to read, and also leaves it.
	token = newToken(t, e)
	e.enr.err = errors.New("signing key at /secret/path exploded")
	rr := e.enrollGet(token)
	if rr.Code != 500 || strings.Contains(rr.Body.String(), "exploded") {
		t.Errorf("%d %q", rr.Code, rr.Body)
	}
	if e.store.enrolls[token].DownloadedAt != nil {
		t.Error("a 500 used up the link")
	}
}

func TestEnrollRaceLoser(t *testing.T) {
	e := newEnv(t)
	token := newToken(t, e)
	// Someone claims it between the check and the claim: the store says invalid.
	e.enr.err = nil
	e.api.d.Store = &racyStore{memStore: e.store, token: token}
	if rr := e.enrollGet(token); rr.Code != http.StatusGone || strings.Contains(rr.Body.String(), "<plist>") {
		t.Errorf("%d %q", rr.Code, rr.Body)
	}
}

// racyStore refuses the claim as if another request had won it.
type racyStore struct {
	*memStore
	token string
}

func (r *racyStore) MarkEnrollmentDownloaded(context.Context, string, time.Time) error {
	return fmt.Errorf("already downloaded: %w", core.ErrInvalid)
}

// --- settings, events, health ---

func TestSettings(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	m := e.json(a, "GET", "/api/v1/settings", nil, 200)
	ca := m["ca"].(map[string]any)
	if !strings.Contains(ca["subject"].(string), "Test CA") || len(ca["sha256"].(string)) != 64 || ca["not_after"] != "2040-01-01T00:00:00Z" {
		t.Errorf("ca %v", ca)
	}
	sec := m["secrets"].(map[string]any)
	if sec["backend"] != "openbao" || sec["healthy"] != true || sec["error"] != "" {
		t.Errorf("secrets %v", sec)
	}
	if m["public_url"] != "https://mdm.example.com/" || m["organization"] != "Example" || m["push"].(map[string]any)["topic"] == "" {
		t.Errorf("settings %v", m)
	}
	e.secrets.health = errors.New(`Get "https://user:hunter2@bao.internal:8200/v1/sys/health": dial tcp: refused; token=hvs.configured-token-value`)
	sec = e.json(a, "GET", "/api/v1/settings", nil, 200)["secrets"].(map[string]any)
	if sec["healthy"] != false || sec["error"] == "" {
		t.Fatalf("secrets %v", sec)
	}
	for _, bad := range []string{"hunter2", "hvs.configured-token-value"} {
		if strings.Contains(sec["error"].(string), bad) {
			t.Errorf("settings error leaks %q: %v", bad, sec["error"])
		}
	}
}

func TestCAPEM(t *testing.T) {
	e := newEnv(t)
	rr := e.do(asUser(alice), "GET", "/api/v1/settings/ca.pem", nil)
	if rr.Code != 200 || rr.Header().Get("Content-Type") != "application/x-pem-file" || !strings.HasPrefix(rr.Body.String(), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("%d %q %.40s", rr.Code, rr.Header().Get("Content-Type"), rr.Body)
	}
}

func TestPushCertificate(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	const key = "-----BEGIN PRIVATE KEY-----KEYMATERIAL-----END PRIVATE KEY-----"
	m := e.json(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": "CERT", "key_pem": key}, 200)
	if m["push"].(map[string]any)["configured"] != true || m["push"].(map[string]any)["topic"] != "com.apple.mgmt.External.test" {
		t.Errorf("push %v", m)
	}
	if ev := e.store.lastEvent(); ev.Kind != "settings.push_certificate" || strings.Contains(fmt.Sprint(ev), "KEYMATERIAL") {
		t.Errorf("event %+v", ev)
	}
	e.mdm.setErr = fmt.Errorf("%w: the key does not match the certificate", core.ErrInvalid)
	if msg := e.errMsg(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": "C", "key_pem": key}, 400); msg != "the key does not match the certificate" {
		t.Errorf("message %q", msg)
	}
	e.errMsg(a, "PUT", "/api/v1/settings/push-certificate", map[string]string{"certificate_pem": "C"}, 400)
	if e.mdm.setCalls != 2 {
		t.Errorf("SetPushCert called %d times", e.mdm.setCalls)
	}
}

func TestEvents(t *testing.T) {
	e := newEnv(t)
	a := asUser(alice)
	for i := 0; i < 1100; i++ {
		_ = e.store.AppendEvent(t.Context(), core.Event{Kind: "k", Subject: fmt.Sprint(i)})
	}
	n := func(q string) int { return len(list(t, e.json(a, "GET", "/api/v1/events"+q, nil, 200), "events")) }
	if n("") != 200 || n("?limit=5") != 5 || n("?limit=5000") != 1000 {
		t.Errorf("limits: %d %d %d", n(""), n("?limit=5"), n("?limit=5000"))
	}
	e.errMsg(a, "GET", "/api/v1/events?limit=abc", nil, 400)
	e.errMsg(a, "GET", "/api/v1/events?limit=0", nil, 400)
	e.store.events = nil
	if m := e.json(a, "GET", "/api/v1/events", nil, 200); m["events"] == nil {
		t.Error("events should be []")
	}
}

func TestHealth(t *testing.T) {
	e := newEnv(t)
	get := func() (int, map[string]any) {
		rr := httptest.NewRecorder()
		e.api.HealthHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil)) // no session needed
		var m map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &m)
		return rr.Code, m
	}
	if code, m := get(); code != 200 || m["status"] != "ok" {
		t.Errorf("%d %v", code, m)
	}
	e.secrets.health = errors.New(`Put "https://svc:p4ssw0rd@bao.example:8200/v1/x": 403 permission denied, X-Vault-Token: hvs.CAESIJabcdefghijklmnopqrstuvwxyz0123456789 and hvs.configured-token-value`)
	code, m := get()
	if code != 503 || m["status"] != "degraded" {
		t.Fatalf("%d %v", code, m)
	}
	probs := m["problems"].([]any)
	if len(probs) != 1 {
		t.Fatalf("problems %v", probs)
	}
	s := probs[0].(string)
	for _, bad := range []string{"p4ssw0rd", "svc:", "CAESIJ", "configured-token-value"} {
		if strings.Contains(s, bad) {
			t.Errorf("problem leaks %q: %s", bad, s)
		}
	}
	if !strings.Contains(s, "permission denied") {
		t.Errorf("problem lost its meaning: %s", s)
	}
	// POST is not a health check.
	rr := httptest.NewRecorder()
	e.api.HealthHandler().ServeHTTP(rr, httptest.NewRequest("POST", "/healthz", nil))
	if rr.Code != 405 {
		t.Errorf("POST: %d", rr.Code)
	}
}

func TestSanitize(t *testing.T) {
	for in, bad := range map[string]string{
		"password=abc123xyz failed":          "abc123xyz",
		"Authorization: Bearer abcdef.ghijk": "abcdef",
		"https://u:pw@host/x":                "u:pw",
	} {
		if out := sanitize(in, core.Config{}); strings.Contains(out, bad) {
			t.Errorf("sanitize(%q) = %q", in, out)
		}
	}
	if out := sanitize("connection refused", core.Config{}); out != "connection refused" {
		t.Errorf("%q", out)
	}
}

func TestPanicBecomes500JSON(t *testing.T) {
	e := newEnv(t)
	e.api.d.Reconciler = nil // a nil interface call panics
	rr := e.do(asUser(alice), "POST", "/api/v1/devices/d1/sync", nil)
	if rr.Code != 500 || !strings.Contains(rr.Body.String(), `"error"`) {
		t.Errorf("%d %s", rr.Code, rr.Body)
	}
}
