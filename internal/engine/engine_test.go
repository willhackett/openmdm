package engine

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"openmdm/internal/core"
)

func TestDeviceAuthenticated(t *testing.T) {
	h := newHarness(t)
	h.st.certs["abc"] = core.IssuedCert{Username: "will"}
	h.device("D1", core.PlatformMacOS, "old-owner")
	h.st.UpsertDevice(h.ctx, core.Device{ID: "D1", Username: "old-owner", UserChannelID: "D1:U", Status: core.DeviceEnrolled})
	h.st.PutDeviceProfile(h.ctx, core.DeviceProfile{DeviceID: "D1", ProfileID: "p", State: core.StateInstalled})
	h.st.UpsertUser(h.ctx, core.User{Username: "other", Role: core.RoleAdmin, Name: "Other"})

	c := core.Checkin{DeviceID: "D1", SerialNumber: "S", Model: "MacBookPro18,3", DeviceName: "Mac", OSVersion: "15", CertSHA256: "abc"}
	h.e.DeviceAuthenticated(h.ctx, c)

	d, _ := h.st.GetDevice(h.ctx, "D1")
	if d.Status != core.DevicePending || d.Username != "will" || d.UserChannelID != "" ||
		d.Platform != core.PlatformMacOS || d.SerialNumber != "S" || d.EnrolledAt != h.clk.Now() || d.CertSHA256 != "abc" {
		t.Fatalf("device = %+v", d)
	}
	if _, ok := h.st.row("D1", "p"); ok {
		t.Fatal("profile rows survived re-authentication")
	}
	if u, err := h.st.GetUser(h.ctx, "will"); err != nil || u.Role != core.RoleUser {
		t.Fatalf("owner not created: %+v %v", u, err)
	}
	if got := h.st.kinds(); !reflect.DeepEqual(got, []string{"device.authenticated"}) || h.st.events[0].Actor != "device:D1" {
		t.Fatalf("events = %+v", h.st.events)
	}

	// An existing user is never overwritten; an unknown certificate keeps the owner.
	h.st.certs["def"] = core.IssuedCert{Username: "other"}
	h.e.DeviceAuthenticated(h.ctx, core.Checkin{DeviceID: "D2", CertSHA256: "def", ProductName: "iPad13,4"})
	if u, _ := h.st.GetUser(h.ctx, "other"); u.Role != core.RoleAdmin || u.Name != "Other" {
		t.Fatalf("user overwritten: %+v", u)
	}
	if d, _ := h.st.GetDevice(h.ctx, "D2"); d.Platform != core.PlatformIPadOS || d.Username != "other" {
		t.Fatalf("D2 = %+v", d)
	}
	h.e.DeviceAuthenticated(h.ctx, core.Checkin{DeviceID: "D1", CertSHA256: "unknown", Model: "iPhone15,2"})
	d, _ = h.st.GetDevice(h.ctx, "D1")
	if d.Username != "will" || d.Platform != core.PlatformIOS || d.CertSHA256 != "unknown" { // platform falls back to Model
		t.Fatalf("D1 = %+v", d)
	}
}

func TestDeviceTokenUpdated(t *testing.T) {
	h := newHarness(t)
	h.e.DeviceAuthenticated(h.ctx, core.Checkin{DeviceID: "D1", ProductName: "Mac14,7"})
	h.clk.Advance(time.Minute)
	h.e.DeviceTokenUpdated(h.ctx, core.Checkin{DeviceID: "D1", EnrollmentID: "D1"})
	d, _ := h.st.GetDevice(h.ctx, "D1")
	if d.Status != core.DeviceEnrolled || d.LastSeenAt != h.clk.Now() {
		t.Fatalf("d = %+v", d)
	}
	if !reflect.DeepEqual(h.e.queue, []string{"D1"}) {
		t.Fatalf("not triggered: %v", h.e.queue)
	}
	// user channel
	h.e.DeviceTokenUpdated(h.ctx, core.Checkin{DeviceID: "D1", UserID: "U", EnrollmentID: "D1:U"})
	d, _ = h.st.GetDevice(h.ctx, "D1")
	if d.UserChannelID != "D1:U" || d.Status != core.DeviceEnrolled {
		t.Fatalf("d = %+v", d)
	}
	// the certificate is recorded when it was not known, and not replaced when it was
	h.e.DeviceTokenUpdated(h.ctx, core.Checkin{DeviceID: "D1", EnrollmentID: "D1", CertSHA256: "other"})
	if d, _ = h.st.GetDevice(h.ctx, "D1"); d.CertSHA256 != "other" {
		t.Fatalf("certificate not recorded on token update: %+v", d)
	}
	h.e.DeviceTokenUpdated(h.ctx, core.Checkin{DeviceID: "D1", EnrollmentID: "D1", CertSHA256: "third"})
	if d, _ = h.st.GetDevice(h.ctx, "D1"); d.CertSHA256 != "other" {
		t.Fatalf("certificate replaced on token update: %+v", d)
	}
	// audit only on the transition
	if got := h.st.kinds(); !reflect.DeepEqual(got, []string{"device.authenticated", "device.enrolled"}) {
		t.Fatalf("events = %v", got)
	}
	// lost database
	h.e.DeviceTokenUpdated(h.ctx, core.Checkin{DeviceID: "NEW", EnrollmentID: "NEW", ProductName: "iPhone15,2", SerialNumber: "X", CertSHA256: "newcert"})
	n, err := h.st.GetDevice(h.ctx, "NEW")
	if err != nil || n.CertSHA256 != "newcert" || n.Status != core.DeviceEnrolled || n.Platform != core.PlatformIOS || n.SerialNumber != "X" {
		t.Fatalf("created = %+v %v", n, err)
	}
}

func TestDeviceCheckedOut(t *testing.T) {
	h := newHarness(t)
	d := h.device("D1", core.PlatformMacOS, "")
	d.UserChannelID = "D1:U"
	h.st.UpsertDevice(h.ctx, d)
	h.st.PutDeviceProfile(h.ctx, core.DeviceProfile{DeviceID: "D1", ProfileID: "p"})

	h.e.DeviceCheckedOut(h.ctx, core.Checkin{DeviceID: "D1", UserID: "U", EnrollmentID: "D1:U"})
	if d, _ := h.st.GetDevice(h.ctx, "D1"); d.Status != core.DeviceEnrolled || d.UserChannelID != "" {
		t.Fatalf("user-channel check-out: %+v", d)
	}
	h.e.DeviceCheckedOut(h.ctx, core.Checkin{DeviceID: "D1", EnrollmentID: "D1"})
	if d, _ := h.st.GetDevice(h.ctx, "D1"); d.Status != core.DeviceUnenrolled {
		t.Fatalf("d = %+v", d)
	}
	if _, ok := h.st.row("D1", "p"); ok {
		t.Fatal("rows kept")
	}
	if got := h.st.kinds(); !reflect.DeepEqual(got, []string{"device.checked_out"}) {
		t.Fatalf("events = %v", got)
	}
	h.e.DeviceCheckedOut(h.ctx, core.Checkin{DeviceID: "unknown"}) // must not panic
}

func TestCommandResulted(t *testing.T) {
	tests := []struct {
		name   string
		from   core.ProfileState
		status core.CommandStatus
		text   string
		want   core.ProfileState // "(none)" = row deleted
		detail string
		audit  string
	}{
		{"sent+ack", core.StateSent, core.CommandAcknowledged, "", core.StateInstalled, "", "profile.installed"},
		{"sent+error", core.StateSent, core.CommandError, "bad payload", core.StateFailed, "bad payload", "profile.failed"},
		{"sent+notnow", core.StateSent, core.CommandNotNow, "", core.StateSent, "", ""},
		{"removing+ack", core.StateRemoving, core.CommandAcknowledged, "", "(none)", "", "profile.removed"},
		{"removing+error", core.StateRemoving, core.CommandError, "not installed", "(none)", "", "profile.removed"},
		{"removing+notnow", core.StateRemoving, core.CommandNotNow, "", core.StateRemoving, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.device("D1", core.PlatformIOS, "")
			h.st.PutCommand(h.ctx, core.CommandRecord{UUID: "c1", DeviceID: "D1", Status: core.CommandQueued})
			h.st.PutDeviceProfile(h.ctx, core.DeviceProfile{DeviceID: "D1", ProfileID: "p", State: tc.from, CommandUUID: "c1"})
			h.clk.Advance(time.Minute)
			h.e.CommandResulted(h.ctx, core.CommandResult{CommandUUID: "c1", DeviceID: "D1", Status: tc.status, ErrorText: tc.text})

			if got := h.state("D1", "p"); got != tc.want {
				t.Fatalf("state = %s, want %s", got, tc.want)
			}
			if r, ok := h.st.row("D1", "p"); ok && r.Detail != tc.detail {
				t.Fatalf("detail = %q", r.Detail)
			}
			c, _ := h.st.GetCommand(h.ctx, "c1")
			if c.Status != tc.status || c.Detail != tc.text {
				t.Fatalf("command = %+v", c)
			}
			if d, _ := h.st.GetDevice(h.ctx, "D1"); d.LastSeenAt != h.clk.Now() {
				t.Fatal("LastSeenAt not updated")
			}
			kinds := h.st.kinds()
			if (tc.audit == "") != (len(kinds) == 0) || (tc.audit != "" && kinds[0] != tc.audit) {
				t.Fatalf("audit = %v", kinds)
			}
			if triggered := len(h.e.queue) > 0; triggered != (tc.audit != "") {
				t.Fatalf("triggered = %v", triggered)
			}
		})
	}
}

func TestStaleResultIgnored(t *testing.T) {
	h := newHarness(t)
	h.device("D1", core.PlatformIOS, "")
	h.st.PutDeviceProfile(h.ctx, core.DeviceProfile{DeviceID: "D1", ProfileID: "p", State: core.StateSent, CommandUUID: "new"})
	h.result("old", core.CommandAcknowledged, "")
	h.result("unknown", core.CommandError, "x")
	if h.state("D1", "p") != core.StateSent || len(h.e.queue) != 0 {
		t.Fatal("stale result acted on")
	}
}

func TestFullPath(t *testing.T) {
	h := newHarness(t)
	h.user("will")
	h.device("D1", core.PlatformIOS, "will")
	h.profile("wifi", core.ChannelDevice, everyone)

	h.reconcile("D1")
	r, _ := h.st.row("D1", "wifi")
	if r.State != core.StateSent || r.Channel != core.ChannelDevice || r.Identifier != "com.test.wifi" || r.ContentHash == "" || r.CommandUUID == "" {
		t.Fatalf("row = %+v", r)
	}
	if len(h.md.installs) != 1 || h.md.installs[0].Target != "D1" || !strings.HasPrefix(h.md.installs[0].What, "signed:") {
		t.Fatalf("installs = %+v", h.md.installs)
	}
	if !reflect.DeepEqual(h.md.pushes, [][]string{{"D1"}}) {
		t.Fatalf("pushes = %v", h.md.pushes)
	}
	cmd, _ := h.st.GetCommand(h.ctx, r.CommandUUID)
	if cmd.RequestType != "InstallProfile" || cmd.ProfileID != "wifi" || cmd.Status != core.CommandQueued {
		t.Fatalf("cmd = %+v", cmd)
	}

	h.result(r.CommandUUID, core.CommandAcknowledged, "")
	if h.state("D1", "wifi") != core.StateInstalled {
		t.Fatal("not installed")
	}
	h.e.queue = nil
	h.e.queued = map[string]bool{}
	h.reconcile("D1")
	if i, rm, p := h.md.counts(); i != 1 || rm != 0 || p != 1 {
		t.Fatalf("settled device was touched: %d %d %d", i, rm, p)
	}
}

func TestSkipsDevicesNotEnrolled(t *testing.T) {
	h := newHarness(t)
	d := h.device("D1", core.PlatformIOS, "")
	d.Status = core.DevicePending
	h.st.UpsertDevice(h.ctx, d)
	h.profile("p", core.ChannelDevice, everyone)
	h.reconcile("D1")
	h.reconcile("nobody")
	if _, ok := h.st.row("D1", "p"); ok {
		t.Fatal("pending device reconciled")
	}
}

func TestMissingSecretBlockedThenSent(t *testing.T) {
	h := newHarness(t)
	h.user("will")
	h.device("D1", core.PlatformIOS, "will")
	h.profile("mail", core.ChannelDevice, everyone)
	h.rn.set(func() { h.rn.missing["mail"] = []string{`secret "a"`, `global secret "b"`} })

	h.reconcile("D1")
	r, _ := h.st.row("D1", "mail")
	if r.State != core.StateBlocked || r.Detail != `waiting for secret "a", global secret "b"` {
		t.Fatalf("row = %+v", r)
	}
	if i, _, p := h.md.counts(); i != 0 || p != 0 {
		t.Fatal("something was sent")
	}
	dp, _ := h.st.puts()
	h.reconcile("D1") // unchanged: no rewrite
	if dp2, _ := h.st.puts(); dp2 != dp {
		t.Fatal("blocked row rewritten")
	}

	h.rn.set(func() { delete(h.rn.missing, "mail") })
	h.reconcile("D1")
	if h.state("D1", "mail") != core.StateSent {
		t.Fatalf("state = %s", h.state("D1", "mail"))
	}
}

func TestNoOwner(t *testing.T) {
	h := newHarness(t)
	h.device("D1", core.PlatformIOS, "")
	h.device("D2", core.PlatformIOS, "ghost") // owner row missing
	h.profile("all", core.ChannelDevice, everyone)
	h.profile("mine", core.ChannelDevice, core.Assignment{Users: []string{"ghost"}})
	for _, id := range []string{"D1", "D2"} {
		h.reconcile(id)
		if h.state(id, "all") != core.StateSent || h.state(id, "mine") != "(none)" {
			t.Fatalf("%s: all=%s mine=%s", id, h.state(id, "all"), h.state(id, "mine"))
		}
	}
}

func TestMacUserChannel(t *testing.T) {
	h := newHarness(t)
	h.user("will")
	mac := h.device("M1", core.PlatformMacOS, "will")
	h.device("P1", core.PlatformIOS, "will")
	h.profile("acct", core.ChannelUser, everyone)

	h.reconcile("M1")
	r, _ := h.st.row("M1", "acct")
	if r.State != core.StateBlocked || r.Detail != "waiting for someone to log in to this Mac" {
		t.Fatalf("row = %+v", r)
	}
	h.reconcile("P1")
	if r, _ := h.st.row("P1", "acct"); r.State != core.StateSent || r.Channel != core.ChannelDevice {
		t.Fatalf("iphone row = %+v", r)
	}
	if h.md.installs[0].Target != "P1" {
		t.Fatalf("target = %s", h.md.installs[0].Target)
	}

	mac.UserChannelID = "M1:GUID"
	h.st.UpsertDevice(h.ctx, mac)
	h.reconcile("M1")
	r, _ = h.st.row("M1", "acct")
	if r.State != core.StateSent || r.Channel != core.ChannelUser {
		t.Fatalf("row = %+v", r)
	}
	if got := h.md.installs[1].Target; got != "M1:GUID" {
		t.Fatalf("target = %s", got)
	}
	if last := h.md.pushes[len(h.md.pushes)-1]; !reflect.DeepEqual(last, []string{"M1:GUID"}) {
		t.Fatalf("push = %v", last)
	}
}

func TestContentChangeResent(t *testing.T) {
	h := newHarness(t)
	h.device("D1", core.PlatformIOS, "")
	p := h.profile("p", core.ChannelDevice, everyone)
	h.reconcile("D1")
	first, _ := h.st.row("D1", "p")
	h.result(first.CommandUUID, core.CommandAcknowledged, "")

	p.Template = "v2"
	h.st.PutProfile(h.ctx, p)
	h.reconcile("D1")
	r, _ := h.st.row("D1", "p")
	if r.State != core.StateSent || r.ContentHash == first.ContentHash || r.CommandUUID == first.CommandUUID {
		t.Fatalf("row = %+v", r)
	}
	if i, rm, _ := h.md.counts(); i != 2 || rm != 0 {
		t.Fatalf("installs=%d removes=%d", i, rm)
	}
	// the old command's late answer is ignored
	h.result(first.CommandUUID, core.CommandError, "late")
	if h.state("D1", "p") != core.StateSent {
		t.Fatal("stale result applied")
	}
}

func TestIdentifierChange(t *testing.T) {
	h := newHarness(t)
	h.device("D1", core.PlatformIOS, "")
	h.profile("p", core.ChannelDevice, everyone)
	h.reconcile("D1")
	first, _ := h.st.row("D1", "p")
	h.result(first.CommandUUID, core.CommandAcknowledged, "")

	h.rn.set(func() { h.rn.idents["p"] = "com.test.new" })
	h.reconcile("D1")
	if len(h.md.removes) != 1 || h.md.removes[0] != (call{"D1", "com.test.p"}) {
		t.Fatalf("removes = %+v", h.md.removes)
	}
	r, _ := h.st.row("D1", "p")
	if r.Identifier != "com.test.new" || r.State != core.StateSent {
		t.Fatalf("row = %+v", r)
	}
	var types []string
	for _, c := range h.st.cmds {
		types = append(types, c.RequestType)
	}
	if len(types) != 3 {
		t.Fatalf("commands = %v", types)
	}
}

func TestUnassignRemoves(t *testing.T) {
	for _, answer := range []core.CommandStatus{core.CommandAcknowledged, core.CommandError} {
		t.Run(string(answer), func(t *testing.T) {
			h := newHarness(t)
			h.user("will")
			h.device("D1", core.PlatformIOS, "will")
			p := h.profile("p", core.ChannelDevice, core.Assignment{Users: []string{"will"}})
			h.reconcile("D1")
			r, _ := h.st.row("D1", "p")
			h.result(r.CommandUUID, core.CommandAcknowledged, "")

			p.Assignment = core.Assignment{Users: []string{"george"}}
			h.st.PutProfile(h.ctx, p)
			h.reconcile("D1")
			r, _ = h.st.row("D1", "p")
			if r.State != core.StateRemoving || len(h.md.removes) != 1 || h.md.removes[0] != (call{"D1", "com.test.p"}) {
				t.Fatalf("row=%+v removes=%+v", r, h.md.removes)
			}
			if c, _ := h.st.GetCommand(h.ctx, r.CommandUUID); c.RequestType != "RemoveProfile" {
				t.Fatalf("cmd = %+v", c)
			}
			h.reconcile("D1") // already removing: nothing more
			if _, rm, _ := h.md.counts(); rm != 1 {
				t.Fatal("removed twice")
			}
			h.result(r.CommandUUID, answer, "")
			if h.state("D1", "p") != "(none)" {
				t.Fatal("row kept")
			}
		})
	}
}

func TestRemovingThenWantedAgain(t *testing.T) {
	h := newHarness(t)
	h.user("will")
	h.device("D1", core.PlatformIOS, "will")
	p := h.profile("p", core.ChannelDevice, core.Assignment{Users: []string{"will"}})
	h.reconcile("D1")
	p.Assignment = core.Assignment{}
	h.st.PutProfile(h.ctx, p)
	h.reconcile("D1")
	p.Assignment = core.Assignment{Everyone: true}
	h.st.PutProfile(h.ctx, p)
	h.reconcile("D1")
	if r, _ := h.st.row("D1", "p"); r.State != core.StateSent {
		t.Fatalf("row = %+v", r)
	}
	if i, rm, _ := h.md.counts(); i != 2 || rm != 1 {
		t.Fatalf("installs=%d removes=%d", i, rm)
	}
}

func TestProfileDeletedFromStore(t *testing.T) {
	h := newHarness(t)
	h.device("D1", core.PlatformIOS, "")
	h.profile("p", core.ChannelDevice, everyone)
	h.reconcile("D1")
	h.st.DeleteProfile(h.ctx, "p")
	h.reconcile("D1")
	r, _ := h.st.row("D1", "p")
	if r.State != core.StateRemoving || len(h.md.removes) != 1 || h.md.removes[0].What != "com.test.p" {
		t.Fatalf("row=%+v removes=%+v", r, h.md.removes)
	}
	plan, _ := h.e.Plan(h.ctx, "D1")
	if len(plan) != 1 || plan[0].Wanted || plan[0].State != core.StateRemoving {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestNothingSentIsJustDeleted(t *testing.T) {
	h := newHarness(t)
	h.device("D1", core.PlatformIOS, "")
	p := h.profile("p", core.ChannelDevice, everyone)
	h.rn.set(func() { h.rn.missing["p"] = []string{"an owner"} })
	h.reconcile("D1")
	p.Assignment = core.Assignment{}
	h.st.PutProfile(h.ctx, p)
	h.reconcile("D1")
	if h.state("D1", "p") != "(none)" {
		t.Fatal("blocked row kept")
	}
	if _, rm, _ := h.md.counts(); rm != 0 {
		t.Fatal("removal sent for something never sent")
	}
}

func TestFailedRetry(t *testing.T) {
	h := newHarness(t)
	h.device("D1", core.PlatformIOS, "")
	h.profile("p", core.ChannelDevice, everyone)
	h.reconcile("D1")
	r, _ := h.st.row("D1", "p")
	h.result(r.CommandUUID, core.CommandError, "refused")

	h.clk.Advance(59 * time.Minute)
	h.reconcile("D1")
	if i, _, _ := h.md.counts(); i != 1 {
		t.Fatal("retried within the hour")
	}
	h.clk.Advance(2 * time.Minute)
	h.reconcile("D1")
	if i, _, _ := h.md.counts(); i != 2 {
		t.Fatal("not retried after the hour")
	}
	if h.state("D1", "p") != core.StateSent {
		t.Fatal("not sent again")
	}
	h.result(h.lastCmd("p"), core.CommandError, "refused again")
	h.reconcile("D1") // the new failure is fresh
	if i, _, _ := h.md.counts(); i != 2 {
		t.Fatal("retried at once")
	}
}

func (h *harness) lastCmd(prof string) string {
	r, _ := h.st.row("D1", prof)
	return r.CommandUUID
}

func TestBrokenTemplate(t *testing.T) {
	h := newHarness(t)
	h.device("D1", core.PlatformIOS, "")
	p := h.profile("p", core.ChannelDevice, everyone)
	h.rn.set(func() { h.rn.errs["p"] = errors.New("line 3: unexpected }") })
	h.reconcile("D1")
	r, _ := h.st.row("D1", "p")
	if r.State != core.StateFailed || r.Detail != "the profile's template is broken: line 3: unexpected }" {
		t.Fatalf("row = %+v", r)
	}
	dp, _ := h.st.puts()
	h.clk.Advance(5 * time.Hour)
	h.reconcile("D1")
	if dp2, _ := h.st.puts(); dp2 != dp {
		t.Fatal("rewritten")
	}
	// fixed: sent at once
	h.rn.set(func() { delete(h.rn.errs, "p") })
	p.Template = "fixed"
	h.st.PutProfile(h.ctx, p)
	h.reconcile("D1")
	if h.state("D1", "p") != core.StateSent {
		t.Fatal("fixed template not sent")
	}
}

func TestNotNowKeepsSentAndNudge(t *testing.T) {
	h := newHarness(t)
	h.device("D1", core.PlatformIOS, "")
	h.profile("p", core.ChannelDevice, everyone)
	h.reconcile("D1")
	r, _ := h.st.row("D1", "p")
	h.result(r.CommandUUID, core.CommandNotNow, "")
	if h.state("D1", "p") != core.StateSent {
		t.Fatal("NotNow changed state")
	}
	h.reconcile("D1")
	if i, _, p := h.md.counts(); i != 1 || p != 1 {
		t.Fatal("touched too soon")
	}
	h.clk.Advance(25 * time.Hour)
	h.reconcile("D1")
	i, _, p := h.md.counts()
	if i != 1 || p != 2 || !reflect.DeepEqual(h.md.pushes[1], []string{"D1"}) {
		t.Fatalf("nudge: installs=%d pushes=%v", i, h.md.pushes)
	}
	h.reconcile("D1") // not again at once
	if _, _, p := h.md.counts(); p != 2 {
		t.Fatal("nudged twice")
	}
}

func TestReauthenticateClearsRows(t *testing.T) {
	h := newHarness(t)
	h.device("D1", core.PlatformIOS, "")
	h.profile("p", core.ChannelDevice, everyone)
	h.reconcile("D1")
	h.e.DeviceAuthenticated(h.ctx, core.Checkin{DeviceID: "D1", ProductName: "iPhone"})
	if h.state("D1", "p") != "(none)" {
		t.Fatal("row kept")
	}
	h.e.DeviceTokenUpdated(h.ctx, core.Checkin{DeviceID: "D1", EnrollmentID: "D1"})
	h.reconcile("D1")
	if i, _, _ := h.md.counts(); i != 2 {
		t.Fatal("not reinstalled after wipe")
	}
}

func TestOnePushPerTarget(t *testing.T) {
	h := newHarness(t)
	h.device("D1", core.PlatformIOS, "")
	h.profile("a", core.ChannelDevice, everyone)
	h.profile("b", core.ChannelDevice, everyone)
	h.reconcile("D1")
	if !reflect.DeepEqual(h.md.pushes, [][]string{{"D1"}}) {
		t.Fatalf("pushes = %v", h.md.pushes)
	}
}

func TestInstallErrorWritesNothing(t *testing.T) {
	h := newHarness(t)
	h.device("D1", core.PlatformIOS, "")
	h.profile("p", core.ChannelDevice, everyone)
	h.md.fail = errors.New("queue down")
	h.reconcile("D1")
	if h.state("D1", "p") != "(none)" {
		t.Fatal("row written for a command that was not queued")
	}
	h.md.fail = nil
	h.reconcile("D1")
	if h.state("D1", "p") != core.StateSent {
		t.Fatal("not retried")
	}
}

func TestPlan(t *testing.T) {
	h := newHarness(t)
	h.user("will", "family")
	h.user("george")
	h.device("D1", core.PlatformIPadOS, "will")
	h.profile("all", core.ChannelDevice, everyone)
	h.profile("me", core.ChannelDevice, core.Assignment{Users: []string{"will"}})
	h.profile("grp", core.ChannelDevice, core.Assignment{Groups: []string{"family"}})
	h.profile("geo", core.ChannelDevice, core.Assignment{Users: []string{"george"}})
	h.profile("mac", core.ChannelDevice, everyone, core.PlatformMacOS)
	h.profile("sec", core.ChannelDevice, core.Assignment{Users: []string{"will"}})
	h.rn.set(func() { h.rn.missing["sec"] = []string{`secret "x"`} })

	if _, err := h.e.Plan(h.ctx, "nope"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	dp, cp := h.st.puts()
	plan, err := h.e.Plan(h.ctx, "D1")
	if err != nil {
		t.Fatal(err)
	}
	if dp2, cp2 := h.st.puts(); dp != dp2 || cp != cp2 {
		t.Fatal("Plan wrote")
	}
	if i, rm, p := h.md.counts(); i+rm+p != 0 {
		t.Fatal("Plan queued")
	}
	type want struct {
		wanted bool
		reason string
		state  core.ProfileState
		detail string
	}
	wants := map[string]want{
		"all": {true, "assigned to everyone", core.StatePending, ""},
		"me":  {true, "assigned to will", core.StatePending, ""},
		"grp": {true, "assigned to group family", core.StatePending, ""},
		"sec": {true, "assigned to will", core.StateBlocked, `waiting for secret "x"`},
	}
	for _, e := range plan {
		w, ok := wants[e.ProfileID]
		if !ok {
			t.Fatalf("unexpected entry %+v", e)
		}
		if e.Wanted != w.wanted || e.Reason != w.reason || e.State != w.state || e.Detail != w.detail || e.Channel != core.ChannelDevice {
			t.Fatalf("%s = %+v", e.ProfileID, e)
		}
		delete(wants, e.ProfileID)
	}
	if len(wants) != 0 {
		t.Fatalf("missing entries %v", wants)
	}

	// After reconcile, the rows hold what the plan said they would become.
	h.reconcile("D1")
	if h.state("D1", "sec") != core.StateBlocked || h.state("D1", "all") != core.StateSent || h.state("D1", "geo") != "(none)" {
		t.Fatal("reconcile disagrees with plan")
	}
	// Entries for unwanted profiles appear only when there is a row.
	g := h.profile("geo", core.ChannelDevice, core.Assignment{Users: []string{"will"}})
	h.reconcile("D1")
	g.Assignment = core.Assignment{Users: []string{"george"}}
	h.st.PutProfile(h.ctx, g)
	h.profile("mac2", core.ChannelDevice, everyone, core.PlatformMacOS)
	plan, _ = h.e.Plan(h.ctx, "D1")
	for _, e := range plan {
		switch e.ProfileID {
		case "geo":
			if e.Wanted || e.Reason != "not assigned to will" || e.State != core.StateRemoving {
				t.Fatalf("geo = %+v", e)
			}
		case "mac", "mac2":
			t.Fatalf("platform-excluded profile without a row listed: %+v", e)
		case "all":
			if e.State != core.StateSent {
				t.Fatalf("all = %+v", e)
			}
		}
	}
	// A wrong-platform profile that has a row says why.
	h.st.PutDeviceProfile(h.ctx, core.DeviceProfile{DeviceID: "D1", ProfileID: "mac", State: core.StateInstalled, Channel: core.ChannelDevice, CommandUUID: "x", Identifier: "i"})
	plan, _ = h.e.Plan(h.ctx, "D1")
	for _, e := range plan {
		if e.ProfileID == "mac" && (e.Reason != "not for ipados" || e.Wanted) {
			t.Fatalf("mac = %+v", e)
		}
	}
}

func TestNothingRewrittenWhenUnchanged(t *testing.T) {
	h := newHarness(t)
	h.user("will")
	h.device("D1", core.PlatformMacOS, "will")
	h.profile("a", core.ChannelDevice, everyone)
	h.profile("b", core.ChannelUser, everyone) // blocked: no user channel
	h.rn.set(func() { h.rn.errs["c"] = errors.New("x") })
	h.profile("c", core.ChannelDevice, everyone)
	h.reconcile("D1")
	r, _ := h.st.row("D1", "a")
	h.result(r.CommandUUID, core.CommandAcknowledged, "")
	dp, cp := h.st.puts()
	i, rm, p := h.md.counts()
	for n := 0; n < 3; n++ {
		h.clk.Advance(10 * time.Minute)
		h.reconcile("D1")
	}
	dp2, cp2 := h.st.puts()
	i2, rm2, p2 := h.md.counts()
	if dp != dp2 || cp != cp2 || i != i2 || rm != rm2 || p != p2 {
		t.Fatalf("writes happened: dp %d>%d cp %d>%d pushes %d>%d", dp, dp2, cp, cp2, p, p2)
	}
}

// ---- the queue and the worker ----

type countingStore struct {
	*memStore
	mu   sync.Mutex
	gets map[string]int
	slow chan struct{}
}

func (c *countingStore) ListDeviceProfiles(ctx context.Context, id string) ([]core.DeviceProfile, error) {
	c.mu.Lock()
	c.gets[id]++
	c.mu.Unlock()
	return c.memStore.ListDeviceProfiles(ctx, id)
}

func waitIdle(t *testing.T, e *Engine) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !e.idle() {
		if time.Now().After(deadline) {
			t.Fatal("engine never went idle")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCoalescingAndRun(t *testing.T) {
	h := newHarness(t)
	cs := &countingStore{memStore: h.st, gets: map[string]int{}}
	h.e = New(cs, h.rn, h.md, h.e.log, Options{Now: h.clk.Now, Interval: time.Hour})
	h.device("D1", core.PlatformIOS, "")
	h.device("D2", core.PlatformIOS, "")
	h.profile("p", core.ChannelDevice, everyone)

	// Triggers before Run starts are not lost, and do not block.
	for i := 0; i < 100; i++ {
		h.e.Trigger("D1")
	}
	h.e.Trigger("D2")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- h.e.Run(ctx) }()
	waitIdle(t, h.e)

	cs.mu.Lock()
	n1, n2 := cs.gets["D1"], cs.gets["D2"]
	cs.mu.Unlock()
	// Run also does a TriggerAll at start, which coalesces with the queue.
	if n1 < 1 || n1 > 2 || n2 < 1 || n2 > 2 {
		t.Fatalf("reconciled D1 %d times, D2 %d times", n1, n2)
	}
	if h.state("D1", "p") != core.StateSent || h.state("D2", "p") != core.StateSent {
		t.Fatal("devices not reconciled")
	}

	// A trigger while running works, and TriggerAll reaches everyone.
	h.profile("q", core.ChannelDevice, everyone)
	h.e.TriggerAll()
	waitIdle(t, h.e)
	if h.state("D1", "q") != core.StateSent || h.state("D2", "q") != core.StateSent {
		t.Fatal("TriggerAll did not reconcile everyone")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunPeriodic(t *testing.T) {
	h := newHarness(t)
	h.e = New(h.st, h.rn, h.md, h.e.log, Options{Now: h.clk.Now, Interval: 20 * time.Millisecond})
	h.device("D1", core.PlatformIOS, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.e.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.st.mu.Lock()
		n := h.st.listDevs
		h.st.mu.Unlock()
		if n >= 3 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d periodic passes", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestConcurrentEvents(t *testing.T) {
	h := newHarness(t)
	h.user("will")
	h.device("D1", core.PlatformIOS, "will")
	h.profile("p", core.ChannelDevice, everyone)
	ctx, cancel := context.WithCancel(context.Background())
	go h.e.Run(ctx)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				h.e.DeviceTokenUpdated(ctx, core.Checkin{DeviceID: "D1", EnrollmentID: "D1"})
				if r, ok := h.st.row("D1", "p"); ok {
					h.e.CommandResulted(ctx, core.CommandResult{CommandUUID: r.CommandUUID, DeviceID: "D1", Status: core.CommandAcknowledged})
				}
				h.e.Trigger("D1")
				h.e.TriggerAll()
			}
		}()
	}
	wg.Wait()
	waitIdle(t, h.e)
	cancel()
}
