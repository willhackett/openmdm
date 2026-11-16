package profiles

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"openmdm/internal/core"
)

const loaderTpl = `<?xml version="1.0"?><plist version="1.0"><dict>
<key>PayloadIdentifier</key><string>com.example.%s</string>
<key>PayloadUUID</key><string>{{ uuid "x" }}</string>
<key>PayloadContent</key><array><dict><key>PayloadType</key><string>%s</string></dict></array>
</dict></plist>`

const loaderYAML = "name: %s\nplatforms: [macos]\nassign:\n  everyone: true\n"

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pair(t *testing.T, dir, id, name, ptype string) {
	t.Helper()
	tplText := strings.Replace(strings.Replace(loaderTpl, "%s", id, 1), "%s", ptype, 1)
	write(t, dir, id+".mobileconfig", tplText)
	write(t, dir, id+".yaml", strings.Replace(loaderYAML, "%s", name, 1))
}

func newLoader(t *testing.T, dir string, st *fakeStore, calls *atomic.Int32) *Loader {
	r := newRenderer(t, &fakeSecrets{})
	return NewLoader(dir, st, r, func() { calls.Add(1) }, nil)
}

func TestLoaderSync(t *testing.T) {
	dir := t.TempDir()
	st := newFakeStore()
	var calls atomic.Int32
	l := newLoader(t, dir, st, &calls)
	ctx := context.Background()

	pair(t, dir, "one", "One", "com.apple.a")
	pair(t, dir, "two", "Two", "com.apple.b")
	if err := l.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(st.profiles) != 2 || calls.Load() != 1 || st.puts != 2 {
		t.Fatalf("add: %d profiles, %d calls, %d puts", len(st.profiles), calls.Load(), st.puts)
	}
	p := st.profiles["one"]
	if p.Source != "file" || p.Name != "One" || !p.Assignment.Everyone || p.Platforms[0] != core.PlatformMacOS {
		t.Fatalf("%+v", p)
	}

	// No change: no writes, no onChange.
	if err := l.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if st.puts != 2 || calls.Load() != 1 {
		t.Fatalf("unchanged sync wrote: puts=%d calls=%d", st.puts, calls.Load())
	}

	// Change.
	pair(t, dir, "one", "One renamed", "com.apple.a")
	l.Sync(ctx)
	if st.profiles["one"].Name != "One renamed" || st.puts != 3 || calls.Load() != 2 {
		t.Fatalf("change: %+v puts=%d calls=%d", st.profiles["one"], st.puts, calls.Load())
	}

	// Invalid file keeps the old version.
	write(t, dir, "one.mobileconfig", "not a plist {{")
	if err := l.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if st.profiles["one"].Name != "One renamed" || !strings.Contains(st.profiles["one"].Template, "com.apple.a") || calls.Load() != 2 {
		t.Fatal("invalid file replaced the old version")
	}
	// A yaml typo is also skipped.
	write(t, dir, "two.yaml", "name: Two\nplatform: [macos]\n")
	l.Sync(ctx)
	if st.profiles["two"].Name != "Two" || st.puts != 3 {
		t.Fatal("bad yaml was loaded")
	}

	// Half a pair deletes nothing.
	os.Remove(filepath.Join(dir, "two.yaml"))
	l.Sync(ctx)
	if _, ok := st.profiles["two"]; !ok {
		t.Fatal("half pair removed the profile")
	}

	// Remove: both files gone.
	os.Remove(filepath.Join(dir, "two.mobileconfig"))
	l.Sync(ctx)
	if _, ok := st.profiles["two"]; ok || calls.Load() != 3 {
		t.Fatalf("remove: calls=%d", calls.Load())
	}
}

func TestLoaderUIProfilesUntouched(t *testing.T) {
	dir := t.TempDir()
	st := newFakeStore()
	var calls atomic.Int32
	l := newLoader(t, dir, st, &calls)
	st.profiles["ui-one"] = core.Profile{ID: "ui-one", Source: "ui", Name: "Mine"}
	st.profiles["clash"] = core.Profile{ID: "clash", Source: "ui", Name: "Mine too"}
	pair(t, dir, "clash", "From file", "com.apple.a")
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.profiles["clash"].Name != "Mine too" || st.puts != 0 || st.deletes != 0 || calls.Load() != 0 {
		t.Fatal("ui profile touched")
	}
	// Even when its file goes away.
	os.Remove(filepath.Join(dir, "clash.yaml"))
	os.Remove(filepath.Join(dir, "clash.mobileconfig"))
	l.Sync(context.Background())
	if _, ok := st.profiles["clash"]; !ok || st.deletes != 0 {
		t.Fatal("ui profile deleted")
	}
}

func TestLoaderMissingDir(t *testing.T) {
	st := newFakeStore()
	st.profiles["f"] = core.Profile{ID: "f", Source: "file"}
	var calls atomic.Int32
	l := newLoader(t, filepath.Join(t.TempDir(), "nope"), st, &calls)
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(st.profiles) != 1 || st.deletes != 0 {
		t.Fatal("deleted with no directory")
	}
}

func TestLoaderRun(t *testing.T) {
	dir := t.TempDir()
	st := newFakeStore()
	var calls atomic.Int32
	l := newLoader(t, dir, st, &calls)
	l.debounce = 50 * time.Millisecond
	pair(t, dir, "one", "One", "com.apple.a")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	waitFor(t, func() bool { _, err := st.GetProfile(ctx, "one"); return err == nil })

	pair(t, dir, "two", "Two", "com.apple.b")
	waitFor(t, func() bool { _, err := st.GetProfile(ctx, "two"); return err == nil })

	os.Remove(filepath.Join(dir, "two.yaml"))
	os.Remove(filepath.Join(dir, "two.mobileconfig"))
	waitFor(t, func() bool { _, err := st.GetProfile(ctx, "two"); return err != nil })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func TestExamplesValidate(t *testing.T) {
	r := newRenderer(t, &fakeSecrets{})
	st := newFakeStore()
	var calls atomic.Int32
	l := NewLoader("../../examples/profiles", st, r, func() { calls.Add(1) }, nil)
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	mail, smime := st.profiles["personal-mail"], st.profiles["smime"]
	if mail.ID == "" || smime.ID == "" {
		t.Fatalf("examples did not load: %v", st.profiles)
	}
	info, err := r.Validate(mail)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(info.UserSecrets, ",") != "fastmail_app_password" ||
		strings.Join(info.PayloadTypes, ",") != "com.apple.mail.managed,com.apple.caldav.account,com.apple.carddav.account" ||
		mail.MacOSChannel != core.ChannelUser || !mail.Assignment.Everyone || len(mail.Platforms) != 3 {
		t.Fatalf("%+v %+v", info, mail)
	}
	info, err = r.Validate(smime)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(info.UserSecrets, ",") != "smime_p12,smime_p12_password" || smime.Assignment.Everyone || len(smime.Assignment.Users) != 0 {
		t.Fatalf("%+v %+v", info, smime)
	}
	// And render for a real owner.
	secrets := &fakeSecrets{user: map[string]map[string]string{"will": {"fastmail_app_password": "x&y", "smime_p12": "QUJD", "smime_p12_password": "p"}}}
	r2 := newRenderer(t, secrets)
	for _, p := range []core.Profile{mail, smime} {
		got, err := r2.Render(context.Background(), p, core.Device{ID: "D", Platform: core.PlatformMacOS}, &core.User{Username: "will", Email: "a@b.c", Name: "N"})
		if err != nil || got.Content == nil {
			t.Fatalf("%s: %v %v", p.ID, err, got.Missing)
		}
	}
}
