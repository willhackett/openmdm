package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"openmdm/internal/core"
)

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func mustNew(t *testing.T, cfg core.SecretsConfig) core.SecretStore {
	t.Helper()
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewUnknownBackend(t *testing.T) {
	for _, b := range []string{"", "vault", "OPENBAO"} {
		if _, err := New(core.SecretsConfig{Backend: b}, nil); !errors.Is(err, core.ErrInvalid) {
			t.Errorf("backend %q: err = %v", b, err)
		}
	}
	if _, err := New(core.SecretsConfig{Backend: "file"}, nil); err == nil {
		t.Error("file without path accepted")
	}
	if _, err := New(core.SecretsConfig{Backend: "openbao", Address: "http://x"}, nil); err == nil {
		t.Error("openbao without auth accepted")
	}
	if _, err := New(core.SecretsConfig{Backend: "openbao", Address: "http://x", Token: "t", Prefix: "a/../b"}, nil); err == nil {
		t.Error("prefix with .. accepted")
	}
}

func TestMemory(t *testing.T) {
	runSuite(t, func(t *testing.T) core.SecretStore { return mustNew(t, core.SecretsConfig{Backend: "memory"}) })
}

func TestFile(t *testing.T) {
	runSuite(t, func(t *testing.T) core.SecretStore {
		return mustNew(t, core.SecretsConfig{Backend: "file", File: filepath.Join(t.TempDir(), "s.json")})
	})
}

func TestOpenBao(t *testing.T) {
	runSuite(t, func(t *testing.T) core.SecretStore {
		f := newFakeKV("secret")
		t.Cleanup(f.Close)
		f.addToken("tok")
		return mustNew(t, core.SecretsConfig{Backend: "openbao", Address: f.srv.URL, Token: "tok"})
	})
}

// runSuite is the behaviour every backend must show.
func runSuite(t *testing.T, mk func(*testing.T) core.SecretStore) {
	t.Run("empty", func(t *testing.T) {
		s := mk(t)
		m, err := s.UserSecrets(ctx(t), "george")
		if err != nil || m == nil || len(m) != 0 {
			t.Fatalf("got %v, %v", m, err)
		}
		g, err := s.GlobalSecrets(ctx(t))
		if err != nil || g == nil || len(g) != 0 {
			t.Fatalf("global: got %v, %v", g, err)
		}
	})
	t.Run("set get delete", func(t *testing.T) {
		s := mk(t)
		c := ctx(t)
		must(t, s.SetUserSecret(c, "george", "a", "1"))
		must(t, s.SetUserSecret(c, "george", "b", "2"))
		must(t, s.SetUserSecret(c, "george", "a", "3"))
		must(t, s.SetUserSecret(c, "amy", "a", "x"))
		must(t, s.SetGlobalSecret(c, "wifi_psk", "g"))
		eq(t, get(t, s, "george"), map[string]string{"a": "3", "b": "2"})
		eq(t, get(t, s, "amy"), map[string]string{"a": "x"})
		g, _ := s.GlobalSecrets(c)
		eq(t, g, map[string]string{"wifi_psk": "g"})
		must(t, s.DeleteUserSecret(c, "george", "a"))
		must(t, s.DeleteUserSecret(c, "george", "nope"))
		must(t, s.DeleteUserSecret(c, "nobody", "nope"))
		eq(t, get(t, s, "george"), map[string]string{"b": "2"})
		must(t, s.DeleteUserSecret(c, "george", "b"))
		eq(t, get(t, s, "george"), map[string]string{})
		must(t, s.DeleteGlobalSecret(c, "wifi_psk"))
		g, _ = s.GlobalSecrets(c)
		eq(t, g, map[string]string{})
		must(t, s.SetUserSecret(c, "george", "empty", ""))
		eq(t, get(t, s, "george"), map[string]string{"empty": ""})
	})
	t.Run("usernames are lower-cased", func(t *testing.T) {
		s := mk(t)
		must(t, s.SetUserSecret(ctx(t), "George.Smith@Example.com", "k", "v"))
		eq(t, get(t, s, "george.smith@example.com"), map[string]string{"k": "v"})
	})
	t.Run("returned maps are copies", func(t *testing.T) {
		s := mk(t)
		must(t, s.SetUserSecret(ctx(t), "george", "k", "v"))
		m := get(t, s, "george")
		m["k"] = "changed"
		m["z"] = "new"
		eq(t, get(t, s, "george"), map[string]string{"k": "v"})
	})
	t.Run("validation", func(t *testing.T) {
		s := mk(t)
		c := ctx(t)
		badUsers := []string{"", "..", ".", "a/b", "../x", "a/../b", "a..b", `a\b`, "a b", "a%2fb", "a\x00b", "é", "x?y", "x#y", strings.Repeat("a", 129), "global", "a:b"}
		for _, u := range badUsers {
			if u == "global" {
				continue // a valid name: documents live under users/
			}
			if _, err := s.UserSecrets(c, u); !errors.Is(err, core.ErrInvalid) {
				t.Errorf("UserSecrets(%q) err = %v", u, err)
			}
			if err := s.SetUserSecret(c, u, "k", "v"); !errors.Is(err, core.ErrInvalid) {
				t.Errorf("SetUserSecret(%q) err = %v", u, err)
			}
			if err := s.DeleteUserSecret(c, u, "k"); !errors.Is(err, core.ErrInvalid) {
				t.Errorf("DeleteUserSecret(%q) err = %v", u, err)
			}
		}
		badKeys := []string{"", "A", "a-b", "a.b", "a/b", "../a", "a b", "a\n", strings.Repeat("a", 65)}
		for _, k := range badKeys {
			if err := s.SetUserSecret(c, "george", k, "v"); !errors.Is(err, core.ErrInvalid) {
				t.Errorf("SetUserSecret key %q err = %v", k, err)
			}
			if err := s.DeleteUserSecret(c, "george", k); !errors.Is(err, core.ErrInvalid) {
				t.Errorf("DeleteUserSecret key %q err = %v", k, err)
			}
			if err := s.SetGlobalSecret(c, k, "v"); !errors.Is(err, core.ErrInvalid) {
				t.Errorf("SetGlobalSecret key %q err = %v", k, err)
			}
			if err := s.DeleteGlobalSecret(c, k); !errors.Is(err, core.ErrInvalid) {
				t.Errorf("DeleteGlobalSecret key %q err = %v", k, err)
			}
		}
		if err := s.SetGlobalSecret(c, "k", strings.Repeat("v", maxValueLen+1)); !errors.Is(err, core.ErrInvalid) {
			t.Errorf("huge value err = %v", err)
		}
		// A user named "global" must not be the global document.
		must(t, s.SetUserSecret(c, "global", "k", "user"))
		g, _ := s.GlobalSecrets(c)
		eq(t, g, map[string]string{})
	})
	t.Run("concurrent writers keep every key", func(t *testing.T) {
		s := mk(t)
		c := ctx(t)
		const n = 10
		var wg sync.WaitGroup
		errs := make(chan error, 2*n)
		for i := 0; i < n; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				errs <- s.SetUserSecret(c, "george", fmt.Sprintf("k%d", i), fmt.Sprintf("v%d", i))
			}()
			go func() {
				defer wg.Done()
				errs <- s.SetGlobalSecret(c, fmt.Sprintf("g%d", i), "x")
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			must(t, err)
		}
		got := get(t, s, "george")
		g, _ := s.GlobalSecrets(c)
		if len(got) != n || len(g) != n {
			t.Fatalf("lost writes: user %d/%d, global %d/%d", len(got), n, len(g), n)
		}
		for i := 0; i < n; i++ {
			if got[fmt.Sprintf("k%d", i)] != fmt.Sprintf("v%d", i) {
				t.Errorf("k%d missing or wrong", i)
			}
		}
	})
	t.Run("context", func(t *testing.T) {
		s := mk(t)
		c, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := s.UserSecrets(c, "george"); err == nil {
			t.Error("cancelled context not honoured")
		}
	})
	t.Run("health", func(t *testing.T) {
		if err := mk(t).Health(ctx(t)); err != nil {
			t.Fatal(err)
		}
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, s core.SecretStore, u string) map[string]string {
	t.Helper()
	m, err := s.UserSecrets(ctx(t), u)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func eq(t *testing.T, got, want map[string]string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFileFormatAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	s := mustNew(t, core.SecretsConfig{Backend: "file", File: path})
	must(t, s.SetUserSecret(ctx(t), "George", "k", "v"))
	must(t, s.SetGlobalSecret(ctx(t), "g", "w"))
	fi, err := os.Stat(path)
	must(t, err)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode())
	}
	b, _ := os.ReadFile(path)
	for _, want := range []string{`"users"`, `"george"`, `"global"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("file lacks %s: %s", want, b)
		}
	}
	// A second store on the same file sees it; a leftover temp file is not left behind.
	s2 := mustNew(t, core.SecretsConfig{Backend: "file", File: path})
	eq(t, get(t, s2, "george"), map[string]string{"k": "v"})
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Errorf("directory has %d entries", len(ents))
	}
	// A corrupt file is an error that does not quote it.
	os.WriteFile(path, []byte(`{"users": "TOPSECRET`), 0o600)
	_, err = s2.UserSecrets(ctx(t), "george")
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") {
		t.Errorf("err = %v", err)
	}
}
