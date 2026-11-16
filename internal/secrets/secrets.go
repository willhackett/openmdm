// Package secrets implements core.SecretStore: OpenBao/Vault (KV v2), a JSON
// file, or memory.
package secrets

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"openmdm/internal/core"
)

const (
	maxUsernameLen = 128
	maxKeyLen      = 64
	maxValueLen    = 512 << 10
	globalDoc      = "global"
)

// backend stores documents (maps of string fields) by name: "global" or
// "users/<username>". Names are already validated when they get here.
type backend interface {
	// get returns a copy of the document; empty if it does not exist.
	get(ctx context.Context, doc string) (map[string]string, error)
	// update reads the document, lets fn change it, and writes it back if fn
	// returns true. It must not lose concurrent updates to other fields.
	update(ctx context.Context, doc string, fn func(m map[string]string) bool) error
	health(ctx context.Context) error
}

// New builds the SecretStore chosen by cfg.Backend: "openbao", "file" or
// "memory". A nil logger discards logs. Secret values and tokens are never
// logged or put in errors.
func New(cfg core.SecretsConfig, logger *slog.Logger) (core.SecretStore, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	var b backend
	var err error
	switch cfg.Backend {
	case "openbao":
		b, err = newBao(cfg, logger)
	case "file":
		b, err = newFileBackend(cfg.File)
	case "memory":
		b = newMemoryBackend()
	default:
		return nil, fmt.Errorf("%w: unknown secrets backend %q (want openbao, file or memory)", core.ErrInvalid, cfg.Backend)
	}
	if err != nil {
		return nil, err
	}
	return &store{b: b}, nil
}

// store adds the validation shared by every backend.
type store struct{ b backend }

var _ core.SecretStore = (*store)(nil)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", core.ErrInvalid, fmt.Sprintf(format, a...))
}

// userDoc validates and lower-cases a username and returns the document name.
// Only [a-z0-9._@-] is allowed, so no "/" or "\" or escapes can appear, and
// ".." and "." are refused so the name cannot climb out of users/.
func userDoc(username string) (string, error) {
	u := strings.ToLower(username)
	if u == "" || len(u) > maxUsernameLen {
		return "", invalid("username must be 1 to %d characters", maxUsernameLen)
	}
	for _, r := range u {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '@', r == '-':
		default:
			return "", invalid("username has a character that is not allowed")
		}
	}
	if u == "." || strings.Contains(u, "..") {
		return "", invalid("username is not allowed")
	}
	return "users/" + u, nil
}

func checkKey(key string) error {
	if key == "" || len(key) > maxKeyLen {
		return invalid("secret key must be 1 to %d characters", maxKeyLen)
	}
	for _, r := range key {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return invalid("secret key must match [a-z0-9_]+")
		}
	}
	return nil
}

func checkValue(v string) error {
	if len(v) > maxValueLen {
		return invalid("secret value is too large")
	}
	return nil
}

func (s *store) UserSecrets(ctx context.Context, username string) (map[string]string, error) {
	doc, err := userDoc(username)
	if err != nil {
		return nil, err
	}
	return s.b.get(ctx, doc)
}

func (s *store) SetUserSecret(ctx context.Context, username, key, value string) error {
	doc, err := userDoc(username)
	if err != nil {
		return err
	}
	return s.set(ctx, doc, key, value)
}

func (s *store) DeleteUserSecret(ctx context.Context, username, key string) error {
	doc, err := userDoc(username)
	if err != nil {
		return err
	}
	return s.del(ctx, doc, key)
}

func (s *store) GlobalSecrets(ctx context.Context) (map[string]string, error) {
	return s.b.get(ctx, globalDoc)
}

func (s *store) SetGlobalSecret(ctx context.Context, key, value string) error {
	return s.set(ctx, globalDoc, key, value)
}

func (s *store) DeleteGlobalSecret(ctx context.Context, key string) error {
	return s.del(ctx, globalDoc, key)
}

func (s *store) Health(ctx context.Context) error { return s.b.health(ctx) }

func (s *store) set(ctx context.Context, doc, key, value string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	if err := checkValue(value); err != nil {
		return err
	}
	return s.b.update(ctx, doc, func(m map[string]string) bool {
		if old, ok := m[key]; ok && old == value {
			return false
		}
		m[key] = value
		return true
	})
}

func (s *store) del(ctx context.Context, doc, key string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	return s.b.update(ctx, doc, func(m map[string]string) bool {
		if _, ok := m[key]; !ok {
			return false
		}
		delete(m, key)
		return true
	})
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
