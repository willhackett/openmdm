package profiles

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"openmdm/internal/core"
)

const wrap = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadIdentifier</key><string>com.example.t</string>
<key>PayloadUUID</key><string>{{ uuid "top" }}</string>
<key>PayloadContent</key><array>%s</array>
</dict></plist>`

func tpl(body string) string { return strings.Replace(wrap, "%s", body, 1) }

func prof(body string) core.Profile {
	return core.Profile{ID: "t", Name: "T", Platforms: []core.Platform{core.PlatformMacOS}, Template: tpl(body)}
}

var (
	dev   = core.Device{ID: "DEV-1", Platform: core.PlatformIOS, SerialNumber: "S1"}
	owner = &core.User{Username: "will", Email: "w@example.com", Name: `A&B <c> "d" 'e'`}
)

func newRenderer(t *testing.T, s *fakeSecrets) *Renderer {
	return NewRenderer(s, newAuthority(t), `Org & "Co"`)
}

func TestEscaping(t *testing.T) {
	secrets := &fakeSecrets{
		user:   map[string]map[string]string{"will": {"pw": `p&<>"'w`, "p12": "QUJD"}},
		global: map[string]string{"g": `g&<`},
	}
	r := newRenderer(t, secrets)
	p := prof(`<dict><key>PayloadType</key><string>x</string>
<key>N</key><string>{{ .User.Name }}</string>
<key>O</key><string>{{ .Organization }}</string>
<key>P</key><string>{{ secret "pw" }}</string>
<key>G</key><string>{{ globalSecret "g" }}</string>
<key>D</key><data>{{ secretData "p12" }}</data></dict>`)
	got, err := r.Render(context.Background(), p, dev, owner)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Missing) != 0 || got.Content == nil {
		t.Fatalf("missing: %v", got.Missing)
	}
	var top map[string]any
	if _, err := plistUnmarshal(got.Content, &top); err != nil {
		t.Fatal(err)
	}
	d := top["PayloadContent"].([]any)[0].(map[string]any)
	if d["N"] != owner.Name || d["P"] != `p&<>"'w` || d["G"] != `g&<` || d["O"] != `Org & "Co"` {
		t.Fatalf("values did not round-trip (escaped twice or not at all): %v", d)
	}
	if string(d["D"].([]byte)) != "ABC" {
		t.Fatalf("data: %v", d["D"])
	}
	if strings.Contains(string(got.Content), "A&B ") || strings.Contains(string(got.Content), "&amp;amp;") {
		t.Fatal("bad escaping in output")
	}
}

func TestSecretDataMustBeBase64(t *testing.T) {
	secrets := &fakeSecrets{user: map[string]map[string]string{"will": {"p12": "</data><evil/>"}}}
	r := newRenderer(t, secrets)
	_, err := r.Render(context.Background(), prof(`<dict><key>a</key><data>{{ secretData "p12" }}</data></dict>`), dev, owner)
	if !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	if strings.Contains(err.Error(), "evil") {
		t.Fatal("value in error")
	}
}

func TestMissingAndNoOwner(t *testing.T) {
	secrets := &fakeSecrets{
		user:   map[string]map[string]string{"will": {"empty": "", "ok": "x"}},
		global: map[string]string{},
	}
	r := newRenderer(t, secrets)
	p := prof(`<dict><key>PayloadType</key><string>x</string>
<key>a</key><string>{{ secret "nope" }}{{ secret "ok" }}{{ secret "empty" }}{{ secret "nope" }}</string>
<key>b</key><string>{{ globalSecret "wifi" }}</string></dict>`)
	got, err := r.Render(context.Background(), p, dev, owner)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`secret "nope"`, `secret "empty"`, `global secret "wifi"`}
	if got.Content != nil || strings.Join(got.Missing, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q content=%v", got.Missing, got.Content != nil)
	}

	p = prof(`<dict><key>a</key><string>{{ .User.Email }} {{ .User.Name }} {{ secret "x" }} {{ globalSecret "g" }}</string></dict>`)
	secrets.global["g"] = "v"
	got, err = r.Render(context.Background(), p, dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Content != nil || strings.Join(got.Missing, "|") != "an owner" {
		t.Fatalf("got %q", got.Missing)
	}
}

func TestSingleFetchAndLazy(t *testing.T) {
	secrets := &fakeSecrets{
		user:   map[string]map[string]string{"will": {"a": "1", "b": "2"}},
		global: map[string]string{"g": "1", "h": "2"},
	}
	r := newRenderer(t, secrets)
	p := prof(`<dict><key>PayloadType</key><string>x</string><key>a</key><string>{{ secret "a" }}{{ secret "b" }}{{ globalSecret "g" }}{{ globalSecret "h" }}{{ secret "a" }}</string></dict>`)
	if _, err := r.Render(context.Background(), p, dev, owner); err != nil {
		t.Fatal(err)
	}
	if secrets.userCalls != 1 || secrets.globalCalls != 1 {
		t.Fatalf("calls: %d %d", secrets.userCalls, secrets.globalCalls)
	}
	secrets.userCalls, secrets.globalCalls = 0, 0
	p = prof(`<dict><key>PayloadType</key><string>x</string></dict>`)
	if _, err := r.Render(context.Background(), p, dev, owner); err != nil {
		t.Fatal(err)
	}
	if secrets.userCalls != 0 || secrets.globalCalls != 0 {
		t.Fatal("fetched without need")
	}
}

func TestUUIDAndHash(t *testing.T) {
	r := newRenderer(t, &fakeSecrets{})
	p := prof(`<dict><key>PayloadType</key><string>x</string><key>U</key><string>{{ uuid "a" }}|{{ uuid "b" }}</string></dict>`)
	a, err := r.Render(context.Background(), p, dev, owner)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := r.Render(context.Background(), p, dev, owner)
	if a.Hash != b.Hash || a.Hash == "" || a.Identifier != "com.example.t" {
		t.Fatalf("unstable: %v %v", a.Hash, b.Hash)
	}
	other := dev
	other.ID = "DEV-2"
	c, _ := r.Render(context.Background(), p, other, owner)
	if c.Hash == a.Hash {
		t.Fatal("uuid does not depend on the device")
	}
	s := string(a.Content)
	i := strings.Index(s, "<string>")
	_ = i
	var top map[string]any
	plistUnmarshal(a.Content, &top)
	u := top["PayloadUUID"].(string)
	if u != strings.ToUpper(u) || len(u) != 36 || u[14] != '5' {
		t.Fatalf("not an upper-case v5 uuid: %s", u)
	}
	pairs := strings.Split(top["PayloadContent"].([]any)[0].(map[string]any)["U"].(string), "|")
	if pairs[0] == pairs[1] {
		t.Fatal("labels give the same uuid")
	}
}

func TestRenderErrors(t *testing.T) {
	r := newRenderer(t, &fakeSecrets{})
	cases := map[string]string{
		"not plist":     `hello`,
		"no identifier": `<?xml version="1.0"?><plist version="1.0"><dict><key>PayloadUUID</key><string>x</string></dict></plist>`,
		"no uuid":       `<?xml version="1.0"?><plist version="1.0"><dict><key>PayloadIdentifier</key><string>x</string></dict></plist>`,
		"bad template":  `{{ .Nope }}`,
		"unparsed":      `{{ if }}`,
		"missing field": `{{ .User.Nothing }}`,
	}
	for name, src := range cases {
		_, err := r.Render(context.Background(), core.Profile{ID: "t", Template: src}, dev, owner)
		if !errors.Is(err, core.ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "hello") {
			t.Errorf("%s: content in error", name)
		}
	}
}

func TestSecretStoreErrorHasNoValues(t *testing.T) {
	secrets := &fakeSecrets{err: errors.New("bao unreachable")}
	r := newRenderer(t, secrets)
	_, err := r.Render(context.Background(), prof(`<dict><key>a</key><string>{{ secret "a" }}</string></dict>`), dev, owner)
	if err == nil || !strings.Contains(err.Error(), "bao unreachable") {
		t.Fatalf("got %v", err)
	}
}

func TestNoSecretValueInAnyError(t *testing.T) {
	const val = "SUPERSECRETVALUE"
	secrets := &fakeSecrets{user: map[string]map[string]string{"will": {"a": val}}, global: map[string]string{"g": val}}
	r := newRenderer(t, secrets)
	bodies := []string{
		`{{ secret "a" }} not a plist`,
		`<dict><key>a</key><string>{{ secret "a" }}</string>{{ .Missing }}</dict>`,
		`<dict>{{ secretData "a" }}</dict>`,
		`<dict>{{ globalSecretData "g" }}</dict>`,
		`{{ secret "a" }}{{ if }}`,
	}
	for _, b := range bodies {
		_, err := r.Render(context.Background(), core.Profile{ID: "t", Template: b}, dev, owner)
		if err != nil && strings.Contains(err.Error(), val) {
			t.Errorf("secret in error for %q: %v", b, err)
		}
	}
	// Valid XML wrapper with the value in an unexpected place.
	_, err := r.Render(context.Background(), core.Profile{ID: "t", Template: `<plist><dict><key>{{ secret "a" }}</key></dict></plist>`}, dev, owner)
	if err != nil && strings.Contains(err.Error(), val) {
		t.Errorf("secret in error: %v", err)
	}
	_ = base64.StdEncoding
}

func TestValidate(t *testing.T) {
	r := newRenderer(t, &fakeSecrets{})
	p := prof(`<dict><key>PayloadType</key><string>com.apple.mail.managed</string>
<key>a</key><string>{{ secret "zeta" }}{{ secret "alpha" }}{{ secret "zeta" }}</string>
{{ if eq .Device.Platform "macos" }}<key>b</key><data>{{ globalSecretData "p12" }}</data>{{ end }}
<key>c</key><string>{{ (globalSecret "wifi") }}</string></dict><dict><key>PayloadType</key><string>com.apple.caldav.account</string></dict>`)
	info, err := r.Validate(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(info.UserSecrets, ",") != "alpha,zeta" || strings.Join(info.GlobalSecrets, ",") != "p12,wifi" {
		t.Fatalf("%+v", info)
	}
	if info.Identifier != "com.example.t" || strings.Join(info.PayloadTypes, ",") != "com.apple.mail.managed,com.apple.caldav.account" {
		t.Fatalf("%+v", info)
	}
}

func TestValidateFailures(t *testing.T) {
	r := newRenderer(t, &fakeSecrets{})
	good := prof(`<dict><key>PayloadType</key><string>x</string></dict>`)
	mod := func(f func(p *core.Profile)) core.Profile { p := good; f(&p); return p }
	cases := map[string]core.Profile{
		"bad id":       mod(func(p *core.Profile) { p.ID = "Bad_ID" }),
		"empty id":     mod(func(p *core.Profile) { p.ID = "" }),
		"no name":      mod(func(p *core.Profile) { p.Name = " " }),
		"no platform":  mod(func(p *core.Profile) { p.Platforms = nil }),
		"bad platform": mod(func(p *core.Profile) { p.Platforms = []core.Platform{"windows"} }),
		"bad channel":  mod(func(p *core.Profile) { p.MacOSChannel = "both" }),
		"unparsed":     mod(func(p *core.Profile) { p.Template = "{{ if }}" }),
		"nonliteral":   mod(func(p *core.Profile) { p.Template = `{{ secret .User.Name }}` }),
		"piped":        mod(func(p *core.Profile) { p.Template = `{{ "a" | secret }}` }),
		"not plist":    mod(func(p *core.Profile) { p.Template = `hello` }),
		"no ident": mod(func(p *core.Profile) {
			p.Template = `<plist><dict><key>PayloadUUID</key><string>x</string></dict></plist>`
		}),
		"exec error": mod(func(p *core.Profile) { p.Template = `{{ .Device.Nope }}` }),
	}
	for name, p := range cases {
		_, err := r.Validate(p)
		if !errors.Is(err, core.ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	for _, ch := range []core.Channel{"", core.ChannelDevice, core.ChannelUser} {
		p := good
		p.MacOSChannel = ch
		if _, err := r.Validate(p); err != nil {
			t.Errorf("channel %q: %v", ch, err)
		}
	}
}
