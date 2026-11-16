package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"openmdm/internal/core"
)

var ctx = context.Background()

func openMem(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func openFile(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "sub", "openmdm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func notFoundErr(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestUsers(t *testing.T) {
	s := openMem(t)
	_, err := s.GetUser(ctx, "nobody")
	notFoundErr(t, err)
	if l, err := s.ListUsers(ctx); err != nil || l == nil || len(l) != 0 {
		t.Fatalf("empty list: %v %v", l, err)
	}

	login := time.Date(2026, 1, 2, 3, 4, 5, 6, time.FixedZone("x", 3600))
	u, err := s.UpsertUser(ctx, core.User{Username: "Alice", Email: "a@x", Name: "Alice", Groups: []string{"eng", "ops"}, Role: core.RoleAdmin, LastLoginAt: login})
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" || u.CreatedAt.IsZero() || !u.LastLoginAt.Equal(login) || u.LastLoginAt.Location() != time.UTC {
		t.Fatalf("bad user %+v", u)
	}
	if len(u.Groups) != 2 || u.Role != core.RoleAdmin {
		t.Fatalf("bad user %+v", u)
	}
	// Second upsert: zero LastLoginAt must not clear, CreatedAt kept.
	u2, err := s.UpsertUser(ctx, core.User{Username: "ALICE", Email: "new@x", CreatedAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if !u2.CreatedAt.Equal(u.CreatedAt) || !u2.LastLoginAt.Equal(login) || u2.Email != "new@x" || u2.Role != core.RoleUser {
		t.Fatalf("bad update %+v (was %+v)", u2, u)
	}
	if u2.Groups == nil || len(u2.Groups) != 0 {
		t.Fatalf("groups should be empty, non-nil: %#v", u2.Groups)
	}
	g, err := s.GetUser(ctx, "aLiCe")
	if err != nil || g.Email != "new@x" {
		t.Fatalf("get: %+v %v", g, err)
	}
	if _, err := s.UpsertUser(ctx, core.User{Username: "bob"}); err != nil {
		t.Fatal(err)
	}
	l, _ := s.ListUsers(ctx)
	if len(l) != 2 || l[0].Username != "alice" || l[1].Username != "bob" {
		t.Fatalf("list %+v", l)
	}
	if _, err := s.UpsertUser(ctx, core.User{}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

func TestDevices(t *testing.T) {
	s := openMem(t)
	_, err := s.GetDevice(ctx, "nope")
	notFoundErr(t, err)
	if l, err := s.ListDevices(ctx); err != nil || l == nil {
		t.Fatal("list must be non-nil", err)
	}
	if l, err := s.ListDevicesByUser(ctx, "x"); err != nil || l == nil {
		t.Fatal("list must be non-nil", err)
	}

	enrolled := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	d := core.Device{ID: "U1", Username: "Alice", Platform: core.PlatformMacOS, SerialNumber: "S1", Model: "Mac14,7",
		DeviceName: "mbp", OSVersion: "15.1", Status: core.DeviceEnrolled, UserChannelID: "U1:G", EnrolledAt: enrolled, LastSeenAt: enrolled.Add(time.Hour)}
	if err := s.UpsertDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDevice(ctx, "U1")
	if err != nil {
		t.Fatal(err)
	}
	d.Username = "alice"
	if got != d {
		t.Fatalf("got %+v want %+v", got, d)
	}
	// Zero EnrolledAt keeps the old one.
	d2 := d
	d2.EnrolledAt = time.Time{}
	d2.Status = core.DeviceUnenrolled
	if err := s.UpsertDevice(ctx, d2); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetDevice(ctx, "U1")
	if !got.EnrolledAt.Equal(enrolled) || got.Status != core.DeviceUnenrolled {
		t.Fatalf("got %+v", got)
	}
	if err := s.UpsertDevice(ctx, core.Device{ID: "U2", Username: "bob"}); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.ListDevices(ctx); len(l) != 2 {
		t.Fatalf("list %+v", l)
	}
	if l, _ := s.ListDevicesByUser(ctx, "ALICE"); len(l) != 1 || l[0].ID != "U1" {
		t.Fatalf("by user %+v", l)
	}

	// DeleteDevice removes its DeviceProfiles, not others'.
	_ = s.PutDeviceProfile(ctx, core.DeviceProfile{DeviceID: "U1", ProfileID: "p"})
	_ = s.PutDeviceProfile(ctx, core.DeviceProfile{DeviceID: "U2", ProfileID: "p"})
	if err := s.DeleteDevice(ctx, "U1"); err != nil {
		t.Fatal(err)
	}
	_, err = s.GetDevice(ctx, "U1")
	notFoundErr(t, err)
	if l, _ := s.ListDeviceProfiles(ctx, "U1"); len(l) != 0 {
		t.Fatalf("device profiles left: %+v", l)
	}
	if l, _ := s.ListDeviceProfiles(ctx, "U2"); len(l) != 1 {
		t.Fatalf("other device's profiles gone: %+v", l)
	}
	if err := s.DeleteDevice(ctx, "U1"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

func TestProfiles(t *testing.T) {
	s := openMem(t)
	_, err := s.GetProfile(ctx, "x")
	notFoundErr(t, err)
	if l, err := s.ListProfiles(ctx); err != nil || l == nil {
		t.Fatal("list must be non-nil", err)
	}
	p := core.Profile{ID: "wifi", Name: "Wi-Fi", Description: "d", Platforms: []core.Platform{core.PlatformMacOS, core.PlatformIOS},
		MacOSChannel: core.ChannelUser, Assignment: core.Assignment{Everyone: false, Users: []string{"alice"}, Groups: []string{"eng"}},
		Template: "<plist/>", Source: "ui", UpdatedAt: time.Unix(1, 0)}
	before := time.Now().Add(-time.Second)
	if err := s.PutProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetProfile(ctx, "wifi")
	if err != nil {
		t.Fatal(err)
	}
	if got.UpdatedAt.Before(before) {
		t.Fatalf("UpdatedAt not set: %v", got.UpdatedAt)
	}
	p.UpdatedAt = got.UpdatedAt
	if fmt.Sprint(got) != fmt.Sprint(p) {
		t.Fatalf("got %+v want %+v", got, p)
	}
	// Nil slices come back non-nil.
	if err := s.PutProfile(ctx, core.Profile{ID: "bare", Name: "A"}); err != nil {
		t.Fatal(err)
	}
	b, _ := s.GetProfile(ctx, "bare")
	if b.Platforms == nil || b.Assignment.Users == nil || b.Assignment.Groups == nil {
		t.Fatalf("nil slices: %#v", b)
	}
	// Replace.
	p.Name = "Wi-Fi 2"
	_ = s.PutProfile(ctx, p)
	if g, _ := s.GetProfile(ctx, "wifi"); g.Name != "Wi-Fi 2" {
		t.Fatal("not replaced")
	}
	if l, _ := s.ListProfiles(ctx); len(l) != 2 {
		t.Fatalf("list %+v", l)
	}
	// DeleteProfile leaves device profiles.
	_ = s.PutDeviceProfile(ctx, core.DeviceProfile{DeviceID: "d", ProfileID: "wifi"})
	if err := s.DeleteProfile(ctx, "wifi"); err != nil {
		t.Fatal(err)
	}
	_, err = s.GetProfile(ctx, "wifi")
	notFoundErr(t, err)
	if l, _ := s.ListDeviceProfilesByProfile(ctx, "wifi"); len(l) != 1 {
		t.Fatalf("device profiles should remain: %+v", l)
	}
}

func TestDeviceProfiles(t *testing.T) {
	s := openMem(t)
	_, err := s.GetDeviceProfileByCommand(ctx, "c")
	notFoundErr(t, err)
	_, err = s.GetDeviceProfileByCommand(ctx, "")
	notFoundErr(t, err)
	if l, err := s.ListDeviceProfiles(ctx, "d"); err != nil || l == nil {
		t.Fatal("non-nil", err)
	}
	if l, err := s.ListDeviceProfilesByProfile(ctx, "p"); err != nil || l == nil {
		t.Fatal("non-nil", err)
	}
	dp := core.DeviceProfile{DeviceID: "d1", ProfileID: "p1", State: core.StateSent, Channel: core.ChannelUser,
		Identifier: "com.x", ContentHash: "abc", CommandUUID: "cmd-1", Detail: "hi", UpdatedAt: time.Unix(5, 0)}
	if err := s.PutDeviceProfile(ctx, dp); err != nil {
		t.Fatal(err)
	}
	_ = s.PutDeviceProfile(ctx, core.DeviceProfile{DeviceID: "d1", ProfileID: "p2", CommandUUID: "cmd-2"})
	_ = s.PutDeviceProfile(ctx, core.DeviceProfile{DeviceID: "d2", ProfileID: "p1"})
	got, err := s.GetDeviceProfileByCommand(ctx, "cmd-1")
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(got.UpdatedAt) > time.Minute {
		t.Fatalf("UpdatedAt not set: %v", got.UpdatedAt)
	}
	dp.UpdatedAt = got.UpdatedAt
	if got != dp {
		t.Fatalf("got %+v want %+v", got, dp)
	}
	// Replace.
	dp.State = core.StateInstalled
	_ = s.PutDeviceProfile(ctx, dp)
	if l, _ := s.ListDeviceProfiles(ctx, "d1"); len(l) != 2 || l[0].State != core.StateInstalled {
		t.Fatalf("%+v", l)
	}
	if l, _ := s.ListDeviceProfilesByProfile(ctx, "p1"); len(l) != 2 {
		t.Fatalf("%+v", l)
	}
	if err := s.DeleteDeviceProfile(ctx, "d1", "p1"); err != nil {
		t.Fatal(err)
	}
	_, err = s.GetDeviceProfileByCommand(ctx, "cmd-1")
	notFoundErr(t, err)
	if err := s.DeleteDeviceProfile(ctx, "d1", "p1"); err != nil {
		t.Fatal(err)
	}
}

func TestCommands(t *testing.T) {
	s := openMem(t)
	_, err := s.GetCommand(ctx, "x")
	notFoundErr(t, err)
	if l, err := s.ListCommands(ctx, "d", 10); err != nil || l == nil {
		t.Fatal("non-nil", err)
	}
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		c := core.CommandRecord{UUID: fmt.Sprintf("u%d", i), DeviceID: "d", Channel: core.ChannelDevice, RequestType: "InstallProfile",
			ProfileID: "p", Status: core.CommandQueued, CreatedAt: base.Add(time.Duration(i) * time.Second), UpdatedAt: base}
		if err := s.PutCommand(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.PutCommand(ctx, core.CommandRecord{UUID: "other", DeviceID: "e", CreatedAt: base})
	l, _ := s.ListCommands(ctx, "d", 3)
	if len(l) != 3 || l[0].UUID != "u4" || l[2].UUID != "u2" {
		t.Fatalf("%+v", l)
	}
	if l, _ := s.ListCommands(ctx, "d", 0); len(l) != 5 {
		t.Fatalf("limit 0 should be unlimited, got %d", len(l))
	}
	// Replace with zero CreatedAt keeps the original.
	err = s.PutCommand(ctx, core.CommandRecord{UUID: "u0", DeviceID: "d", Status: core.CommandAcknowledged, Detail: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.GetCommand(ctx, "u0")
	if err != nil {
		t.Fatal(err)
	}
	if !c.CreatedAt.Equal(base) || c.Status != core.CommandAcknowledged || c.Detail != "ok" || c.UpdatedAt.Equal(base) {
		t.Fatalf("%+v", c)
	}
}

func TestEnrollments(t *testing.T) {
	s := openMem(t)
	_, err := s.GetEnrollment(ctx, "t")
	notFoundErr(t, err)
	_, err = s.GetEnrollmentByChallenge(ctx, "c")
	notFoundErr(t, err)
	notFoundErr(t, s.MarkEnrollmentDownloaded(ctx, "t", time.Now()))
	notFoundErr(t, s.MarkEnrollmentUsed(ctx, "c", time.Now()))
	if l, err := s.ListEnrollments(ctx); err != nil || l == nil {
		t.Fatal("non-nil", err)
	}

	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		e := core.Enrollment{Token: fmt.Sprintf("t%d", i), Challenge: fmt.Sprintf("c%d", i), Username: "Alice", CreatedBy: "admin",
			CreatedAt: base.Add(time.Duration(i) * time.Minute), ExpiresAt: base.Add(time.Hour)}
		if err := s.CreateEnrollment(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateEnrollment(ctx, core.Enrollment{Token: "t1", Challenge: "zz"}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("duplicate token: %v", err)
	}
	e, err := s.GetEnrollment(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if e.Challenge != "c1" || e.Username != "alice" || e.DownloadedAt != nil || e.UsedAt != nil || !e.ExpiresAt.Equal(base.Add(time.Hour)) {
		t.Fatalf("%+v", e)
	}
	if e2, err := s.GetEnrollmentByChallenge(ctx, "c1"); err != nil || e2.Token != "t1" {
		t.Fatalf("%+v %v", e2, err)
	}
	at := base.Add(5 * time.Minute)
	if err := s.MarkEnrollmentDownloaded(ctx, "t1", at); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkEnrollmentDownloaded(ctx, "t1", at); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("second download: %v", err)
	}
	if err := s.MarkEnrollmentUsed(ctx, "c1", at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkEnrollmentUsed(ctx, "c1", at); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("second use: %v", err)
	}
	e, _ = s.GetEnrollment(ctx, "t1")
	if e.DownloadedAt == nil || !e.DownloadedAt.Equal(at) || e.UsedAt == nil || !e.UsedAt.Equal(at.Add(time.Minute)) {
		t.Fatalf("%+v", e)
	}
	l, _ := s.ListEnrollments(ctx)
	if len(l) != 3 || l[0].Token != "t2" || l[2].Token != "t0" {
		t.Fatalf("order %+v", l)
	}
}

func TestMarkEnrollmentConcurrent(t *testing.T) {
	for name, s := range map[string]*Store{"memory": openMem(t), "file": openFile(t)} {
		t.Run(name, func(t *testing.T) {
			if err := s.CreateEnrollment(ctx, core.Enrollment{Token: "tok", Challenge: "chal", CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			for _, mark := range []func() error{
				func() error { return s.MarkEnrollmentDownloaded(ctx, "tok", time.Now()) },
				func() error { return s.MarkEnrollmentUsed(ctx, "chal", time.Now()) },
			} {
				var wins, invalid, other atomic.Int32
				var wg sync.WaitGroup
				start := make(chan struct{})
				for i := 0; i < 64; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						switch err := mark(); {
						case err == nil:
							wins.Add(1)
						case errors.Is(err, core.ErrInvalid):
							invalid.Add(1)
						default:
							t.Errorf("unexpected: %v", err)
							other.Add(1)
						}
					}()
				}
				close(start)
				wg.Wait()
				if wins.Load() != 1 || invalid.Load() != 63 {
					t.Fatalf("wins=%d invalid=%d other=%d", wins.Load(), invalid.Load(), other.Load())
				}
			}
		})
	}
}

func TestIssuedCerts(t *testing.T) {
	s := openMem(t)
	_, err := s.GetIssuedCertBySHA256(ctx, "ab")
	notFoundErr(t, err)
	if l, err := s.ListIssuedCerts(ctx); err != nil || l == nil {
		t.Fatal("non-nil", err)
	}
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	c := core.IssuedCert{Serial: "2", CommonName: "dev", Username: "Alice", SHA256: "ABCD", PEM: "pem", NotAfter: base.AddDate(1, 0, 0), IssuedAt: base}
	if err := s.PutIssuedCert(ctx, c); err != nil {
		t.Fatal(err)
	}
	_ = s.PutIssuedCert(ctx, core.IssuedCert{Serial: "3", SHA256: "ef", IssuedAt: base.Add(time.Hour)})
	got, err := s.GetIssuedCertBySHA256(ctx, "abcd")
	if err != nil {
		t.Fatal(err)
	}
	if got.Serial != "2" || got.Username != "alice" || got.PEM != "pem" || got.RevokedAt != nil || !got.NotAfter.Equal(c.NotAfter) {
		t.Fatalf("%+v", got)
	}
	rev := base.Add(48 * time.Hour)
	c.RevokedAt = &rev
	_ = s.PutIssuedCert(ctx, c)
	got, _ = s.GetIssuedCertBySHA256(ctx, "ABCD")
	if got.RevokedAt == nil || !got.RevokedAt.Equal(rev) {
		t.Fatalf("%+v", got)
	}
	l, _ := s.ListIssuedCerts(ctx)
	if len(l) != 2 || l[0].Serial != "3" {
		t.Fatalf("%+v", l)
	}
}

func TestNextSerialConcurrent(t *testing.T) {
	for name, s := range map[string]*Store{"memory": openMem(t), "file": openFile(t)} {
		t.Run(name, func(t *testing.T) {
			const n = 200
			var mu sync.Mutex
			seen := map[int64]bool{}
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					v, err := s.NextSerial(ctx)
					if err != nil {
						t.Error(err)
						return
					}
					mu.Lock()
					defer mu.Unlock()
					if v <= 1 || seen[v] {
						t.Errorf("bad or repeated serial %d", v)
					}
					seen[v] = true
				}()
			}
			wg.Wait()
			if len(seen) != n {
				t.Fatalf("got %d distinct", len(seen))
			}
		})
	}
}

func TestBlobs(t *testing.T) {
	s := openMem(t)
	_, err := s.GetBlob(ctx, "k")
	notFoundErr(t, err)
	if err := s.PutBlob(ctx, "k", []byte{0, 1, 2, 255}); err != nil {
		t.Fatal(err)
	}
	v, err := s.GetBlob(ctx, "k")
	if err != nil || !bytes.Equal(v, []byte{0, 1, 2, 255}) {
		t.Fatalf("%v %v", v, err)
	}
	_ = s.PutBlob(ctx, "k", nil)
	v, err = s.GetBlob(ctx, "k")
	if err != nil || v == nil || len(v) != 0 {
		t.Fatalf("empty blob: %#v %v", v, err)
	}
}

func TestEvents(t *testing.T) {
	s := openMem(t)
	if l, err := s.ListEvents(ctx, 10); err != nil || l == nil || len(l) != 0 {
		t.Fatal("non-nil", err)
	}
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if err := s.AppendEvent(ctx, core.Event{ID: 999, At: base.Add(time.Duration(i) * time.Second), Actor: "a", Kind: "k", Subject: fmt.Sprint(i), Detail: "d"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.AppendEvent(ctx, core.Event{Actor: "system", Kind: "now"})
	l, _ := s.ListEvents(ctx, 3)
	if len(l) != 3 || l[0].Kind != "now" || l[1].Subject != "4" || l[2].Subject != "3" {
		t.Fatalf("%+v", l)
	}
	if time.Since(l[0].At) > time.Minute {
		t.Fatalf("At not defaulted: %v", l[0].At)
	}
	if l[0].ID == 0 || l[0].ID == 999 || l[0].ID <= l[1].ID {
		t.Fatalf("ids %+v", l)
	}
	if all, _ := s.ListEvents(ctx, 0); len(all) != 6 {
		t.Fatalf("limit 0: %d", len(all))
	}
}

func TestReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openmdm.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var last int64
	for i := 0; i < 3; i++ {
		if last, err = s.NextSerial(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.UpsertUser(ctx, core.User{Username: "alice", Groups: []string{"g"}}); err != nil {
		t.Fatal(err)
	}
	_ = s.PutBlob(ctx, "ca", []byte("secret"))
	_ = s.AppendEvent(ctx, core.Event{Kind: "x"})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if u, err := s.GetUser(ctx, "alice"); err != nil || len(u.Groups) != 1 {
		t.Fatalf("%+v %v", u, err)
	}
	if b, err := s.GetBlob(ctx, "ca"); err != nil || string(b) != "secret" {
		t.Fatalf("%q %v", b, err)
	}
	if l, _ := s.ListEvents(ctx, 5); len(l) != 1 {
		t.Fatalf("%+v", l)
	}
	next, err := s.NextSerial(ctx)
	if err != nil || next != last+1 {
		t.Fatalf("serial after reopen: %d (last %d) %v", next, last, err)
	}
	var n int
	if err := s.r.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("migrations table: %d %v", n, err)
	}
}

func TestPragmas(t *testing.T) {
	s := openFile(t)
	var mode string
	var fk, bt int
	s.w.QueryRow(`PRAGMA journal_mode`).Scan(&mode)
	s.w.QueryRow(`PRAGMA foreign_keys`).Scan(&fk)
	s.r.QueryRow(`PRAGMA busy_timeout`).Scan(&bt)
	if mode != "wal" || fk != 1 || bt < 1000 {
		t.Fatalf("mode=%s fk=%d busy=%d", mode, fk, bt)
	}
}

// Many goroutines reading and writing a file database: no "database is
// locked" errors, no data races.
func TestConcurrentMixed(t *testing.T) {
	s := openFile(t)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				id := fmt.Sprintf("d%d-%d", g, i)
				if err := s.UpsertDevice(ctx, core.Device{ID: id, Username: "u", EnrolledAt: time.Now()}); err != nil {
					t.Error(err)
					return
				}
				if err := s.AppendEvent(ctx, core.Event{Kind: "k", Subject: id}); err != nil {
					t.Error(err)
					return
				}
				if _, err := s.NextSerial(ctx); err != nil {
					t.Error(err)
					return
				}
				if _, err := s.ListDevicesByUser(ctx, "u"); err != nil {
					t.Error(err)
					return
				}
				if _, err := s.GetDevice(ctx, id); err != nil {
					t.Error(err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	if l, _ := s.ListDevices(ctx); len(l) != 16*40 {
		t.Fatalf("%d devices", len(l))
	}
}

func TestMemoryIsPrivatePerStore(t *testing.T) {
	a, b := openMem(t), openMem(t)
	_, _ = a.UpsertUser(ctx, core.User{Username: "x"})
	_, err := b.GetUser(ctx, "x")
	notFoundErr(t, err)
}

func TestMigrationsLoad(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil || len(ms) == 0 || ms[0].version != 1 {
		t.Fatalf("%+v %v", ms, err)
	}
}
