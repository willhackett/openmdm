package secrets

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openmdm/internal/core"
)

func baoStore(t *testing.T, f *fakeKV, cfg core.SecretsConfig) core.SecretStore {
	cfg.Backend = "openbao"
	if cfg.Address == "" {
		cfg.Address = f.srv.URL
	}
	return mustNew(t, cfg)
}

func TestBaoLayoutAndCAS(t *testing.T) {
	f := newFakeKV("kv")
	defer f.Close()
	f.addToken("tok")
	s := baoStore(t, f, core.SecretsConfig{Token: "tok", Mount: "kv", Prefix: "mdm/prod"})
	must(t, s.SetUserSecret(ctx(t), "George@Example.com", "k", "v"))
	must(t, s.SetGlobalSecret(ctx(t), "g", "v"))
	if f.version("mdm/prod/users/george@example.com") != 1 || f.version("mdm/prod/global") != 1 {
		t.Errorf("docs: %v", f.docs)
	}
	// Setting the same value again writes nothing; a new key writes version 2.
	must(t, s.SetUserSecret(ctx(t), "george@example.com", "k", "v"))
	must(t, s.SetUserSecret(ctx(t), "george@example.com", "k2", "v"))
	if got := f.version("mdm/prod/users/george@example.com"); got != 2 {
		t.Errorf("versions = %d", got)
	}
	// Deleting the last key keeps history: an empty document, a new version.
	must(t, s.DeleteUserSecret(ctx(t), "george@example.com", "k"))
	must(t, s.DeleteUserSecret(ctx(t), "george@example.com", "k2"))
	if got := f.version("mdm/prod/users/george@example.com"); got != 4 {
		t.Errorf("versions = %d", got)
	}
	eq(t, get(t, s, "george@example.com"), map[string]string{})
}

func TestBaoNeverLeavesPrefix(t *testing.T) {
	f := newFakeKV("secret")
	defer f.Close()
	f.addToken("tok")
	s := baoStore(t, f, core.SecretsConfig{Token: "tok"})
	c := ctx(t)
	for _, u := range []string{"../global", "..", "a/../../x", "a/b", "%2e%2e", "x/../../../sys/policies", "a?b=c", "a#b", "a\\b"} {
		if _, err := s.UserSecrets(c, u); !errors.Is(err, core.ErrInvalid) {
			t.Errorf("%q: %v", u, err)
		}
		if err := s.SetUserSecret(c, u, "k", "v"); !errors.Is(err, core.ErrInvalid) {
			t.Errorf("%q: %v", u, err)
		}
	}
	for _, k := range []string{"../global", "a/b", "a.b"} {
		if err := s.SetGlobalSecret(c, k, "v"); !errors.Is(err, core.ErrInvalid) {
			t.Errorf("%q: %v", k, err)
		}
	}
	// And the valid but awkward ones stay under the prefix.
	for _, u := range []string{"a.b", "a@b.c", "-x-", "_"} {
		must(t, s.SetUserSecret(c, u, "k", "v"))
	}
	must(t, s.SetGlobalSecret(c, "g", "v"))
	for _, p := range f.seen() {
		if !strings.HasPrefix(p, "/v1/secret/data/openmdm/users/") && p != "/v1/secret/data/openmdm/global" {
			t.Errorf("request outside the prefix: %s", p)
		}
		if strings.Contains(p, "..") {
			t.Errorf("request with ..: %s", p)
		}
	}
	if len(f.seen()) == 0 {
		t.Fatal("no requests seen")
	}
}

func TestBaoTokenChecked(t *testing.T) {
	f := newFakeKV("secret")
	defer f.Close()
	f.addToken("good")
	s := baoStore(t, f, core.SecretsConfig{Token: "bad-token-xyz"})
	_, err := s.UserSecrets(ctx(t), "george")
	if err == nil || strings.Contains(err.Error(), "bad-token-xyz") {
		t.Fatalf("err = %v", err)
	}
	if err := s.Health(ctx(t)); err == nil {
		t.Error("health ok with a bad token")
	}
	// The value never appears in an error: write to a server that always fails.
	g := newFakeKV("other") // wrong mount: every data path is 404 -> write 404
	defer g.Close()
	g.addToken("tok")
	s = baoStore(t, g, core.SecretsConfig{Token: "tok"})
	err = s.SetUserSecret(ctx(t), "george", "k", "SUPERSECRETVALUE")
	if err == nil || strings.Contains(err.Error(), "SUPERSECRETVALUE") || strings.Contains(err.Error(), "tok\"") {
		t.Fatalf("err = %v", err)
	}
}

func TestBaoTokenFileReread(t *testing.T) {
	f := newFakeKV("secret")
	defer f.Close()
	f.addToken("one")
	f.addToken("two")
	path := filepath.Join(t.TempDir(), "token")
	must(t, os.WriteFile(path, []byte("one\n"), 0o600))
	s := baoStore(t, f, core.SecretsConfig{TokenFile: path})
	must(t, s.SetGlobalSecret(ctx(t), "k", "v"))
	// Rotate: the old token dies, the file gets the new one (mtime moves).
	f.mu.Lock()
	delete(f.tokens, "one")
	f.mu.Unlock()
	must(t, os.WriteFile(path, []byte("two\n"), 0o600))
	later := time.Now().Add(2 * time.Second)
	os.Chtimes(path, later, later)
	g, err := s.GlobalSecrets(ctx(t))
	must(t, err)
	eq(t, g, map[string]string{"k": "v"})
}

func TestBaoAppRole(t *testing.T) {
	f := newFakeKV("secret")
	defer f.Close()
	f.roleID, f.secretID, f.lease = "role", "sid", 3600
	sidFile := filepath.Join(t.TempDir(), "sid")
	must(t, os.WriteFile(sidFile, []byte("sid\n"), 0o600))
	for name, cfg := range map[string]core.SecretsConfig{
		"secret_id":      {RoleID: "role", SecretID: "sid"},
		"secret_id_file": {RoleID: "role", SecretIDFile: sidFile},
	} {
		t.Run(name, func(t *testing.T) {
			f.mu.Lock()
			f.logins = 0
			f.mu.Unlock()
			f.revokeAll()
			s := baoStore(t, f, cfg)
			must(t, s.SetUserSecret(ctx(t), "george", "k", "v"))
			must(t, s.SetUserSecret(ctx(t), "george", "k2", "v"))
			if f.logins != 1 {
				t.Fatalf("logins = %d, want the token cached", f.logins)
			}
			// The server forgets the token (revoked): one 403, one new login, success.
			f.revokeAll()
			eq(t, get(t, s, "george"), map[string]string{"k": "v", "k2": "v"})
			if f.logins != 2 {
				t.Fatalf("logins = %d, want a re-login after 403", f.logins)
			}
			must(t, s.Health(ctx(t)))
		})
	}
}

func TestBaoAppRoleGivesUp(t *testing.T) {
	f := newFakeKV("secret")
	defer f.Close()
	f.roleID, f.secretID, f.lease = "role", "sid", 3600
	f.denyData = true // logins work, but the policy allows nothing
	s := baoStore(t, f, core.SecretsConfig{RoleID: "role", SecretID: "sid"})
	_, err := s.UserSecrets(ctx(t), "george")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
	if f.logins != 2 {
		t.Errorf("logins = %d, want the first plus exactly one retry", f.logins)
	}
	// A wrong secret ID is an error that does not repeat the secret.
	bad := baoStore(t, f, core.SecretsConfig{RoleID: "role", SecretID: "wrong-sid"})
	_, err = bad.UserSecrets(ctx(t), "george")
	if err == nil || strings.Contains(err.Error(), "wrong-sid") {
		t.Fatalf("err = %v", err)
	}
}

func TestBaoLoginAgainWhenExpiring(t *testing.T) {
	f := newFakeKV("secret")
	defer f.Close()
	f.roleID, f.secretID, f.lease = "role", "sid", 10 // inside the 30s slack
	s := baoStore(t, f, core.SecretsConfig{RoleID: "role", SecretID: "sid"})
	_, err := s.GlobalSecrets(ctx(t))
	must(t, err)
	_, err = s.GlobalSecrets(ctx(t))
	must(t, err)
	if f.logins != 2 {
		t.Errorf("logins = %d, want one per request while the token is about to expire", f.logins)
	}
}

func TestBao404IsEmpty(t *testing.T) {
	f := newFakeKV("secret")
	defer f.Close()
	f.addToken("tok")
	s := baoStore(t, f, core.SecretsConfig{Token: "tok"})
	m, err := s.UserSecrets(ctx(t), "nobody")
	if err != nil || m == nil || len(m) != 0 {
		t.Fatalf("%v %v", m, err)
	}
}

func TestBaoHealthCapabilities(t *testing.T) {
	f := newFakeKV("secret")
	defer f.Close()
	f.addToken("tok")
	s := baoStore(t, f, core.SecretsConfig{Token: "tok"})
	must(t, s.Health(ctx(t)))
	for _, caps := range [][]string{{"read"}, {"read", "create"}, {"deny"}, nil, {"create", "update"}} {
		f.mu.Lock()
		f.caps = caps
		f.mu.Unlock()
		if err := s.Health(ctx(t)); err == nil {
			t.Errorf("health ok with %v", caps)
		}
	}
	f.mu.Lock()
	f.caps = []string{"root"}
	f.mu.Unlock()
	must(t, s.Health(ctx(t)))
	for _, p := range f.seen() {
		if p == "/v1/secret/data/openmdm/global" {
			t.Error("health touched the data path")
		}
	}
}

func TestBaoCAFile(t *testing.T) {
	f := newFakeKV("secret")
	f.Close()
	f = &fakeKV{mount: "secret", docs: map[string][]map[string]any{}, tokens: map[string]bool{"tok": true}}
	srv := httptest.NewUnstartedServer(f)
	srv.StartTLS()
	defer srv.Close()
	cert := srv.Certificate()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	must(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600))

	// Without the CA the connection is refused.
	plain := mustNew(t, core.SecretsConfig{Backend: "openbao", Address: srv.URL, Token: "tok"})
	if _, err := plain.GlobalSecrets(ctx(t)); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	s := mustNew(t, core.SecretsConfig{Backend: "openbao", Address: srv.URL, Token: "tok", CAFile: caFile})
	must(t, s.SetGlobalSecret(ctx(t), "k", "v"))
	_ = tls.VersionTLS12

	if _, err := New(core.SecretsConfig{Backend: "openbao", Address: srv.URL, Token: "t", CAFile: filepath.Join(t.TempDir(), "none")}, nil); err == nil {
		t.Error("missing CA file accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(bad, []byte("not pem"), 0o600)
	if _, err := New(core.SecretsConfig{Backend: "openbao", Address: srv.URL, Token: "t", CAFile: bad}, nil); err == nil {
		t.Error("bad CA file accepted")
	}
}

func TestBaoTimeoutAndContext(t *testing.T) {
	f := newFakeKV("secret")
	f.addToken("tok")
	url := f.srv.URL
	f.Close() // nothing is listening any more
	s := mustNew(t, core.SecretsConfig{Backend: "openbao", Address: url, Token: "tok"})
	if _, err := s.GlobalSecrets(ctx(t)); err == nil {
		t.Error("no error from a dead server")
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.SetGlobalSecret(c, "k", "v"); err == nil {
		t.Error("cancelled context not honoured")
	}
}
