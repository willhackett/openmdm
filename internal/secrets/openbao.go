package secrets

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"openmdm/internal/core"
)

const (
	requestTimeout = 15 * time.Second
	casAttempts    = 12
	maxBody        = 4 << 20
	// A login token is replaced this long before it expires.
	expirySlack = 30 * time.Second
)

// errCAS means a KV v2 check-and-set write lost to another writer.
var errCAS = errors.New("check-and-set conflict")

// baoBackend talks to OpenBao (or Vault) KV v2 over net/http. One document
// per person at <mount>/data/<prefix>/users/<username>, one global at
// <mount>/data/<prefix>/global. Every path is built from validated, escaped
// segments, so nothing outside <prefix> can be named.
type baoBackend struct {
	base   string // https://host:8200, no trailing slash
	mount  string // escaped path segments, e.g. "secret"
	prefix string // escaped path segments, e.g. "openmdm"
	rawMnt string
	rawPfx string
	hc     *http.Client
	auth   authenticator
	log    *slog.Logger
}

type authenticator interface {
	// token returns a client token, logging in or re-reading as needed.
	token(ctx context.Context, b *baoBackend) (string, error)
	// invalidate drops tok after a 403; it reports whether asking for a new
	// token could help (a static token cannot be replaced).
	invalidate(tok string) bool
}

func cleanSegments(what, s string) (escaped, raw string, err error) {
	s = strings.Trim(s, "/")
	if s == "" {
		return "", "", invalid("secrets %s is empty", what)
	}
	parts := strings.Split(s, "/")
	for i, p := range parts {
		if p == "" || p == "." || p == ".." {
			return "", "", invalid("secrets %s has an empty or relative segment", what)
		}
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/"), s, nil
}

func newBao(cfg core.SecretsConfig, logger *slog.Logger) (*baoBackend, error) {
	u, err := url.Parse(cfg.Address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, invalid("secrets address must be an http(s) URL")
	}
	mount := cfg.Mount
	if mount == "" {
		mount = "secret"
	}
	prefix := cfg.Prefix
	if prefix == "" {
		prefix = "openmdm"
	}
	b := &baoBackend{
		base: strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"),
		log:  logger,
	}
	if b.mount, b.rawMnt, err = cleanSegments("mount", mount); err != nil {
		return nil, err
	}
	if b.prefix, b.rawPfx, err = cleanSegments("prefix", prefix); err != nil {
		return nil, err
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("secrets ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, invalid("secrets ca_file has no PEM certificate")
		}
		tlsCfg.RootCAs = pool
	}
	tr.TLSClientConfig = tlsCfg
	b.hc = &http.Client{Transport: tr, Timeout: requestTimeout}

	switch {
	case cfg.Token != "":
		b.auth = &staticAuth{tok: cfg.Token}
	case cfg.TokenFile != "":
		b.auth = &fileAuth{path: cfg.TokenFile}
	case cfg.RoleID != "" && (cfg.SecretID != "" || cfg.SecretIDFile != ""):
		b.auth = &roleAuth{roleID: cfg.RoleID, secretID: cfg.SecretID, secretIDFile: cfg.SecretIDFile}
	default:
		return nil, invalid("secrets: give a token, a token_file, or role_id with secret_id or secret_id_file")
	}
	return b, nil
}

// ---- authentication ----

type staticAuth struct{ tok string }

func (a *staticAuth) token(context.Context, *baoBackend) (string, error) { return a.tok, nil }
func (a *staticAuth) invalidate(string) bool                             { return false }

// fileAuth re-reads the token file whenever its mtime or size changes.
type fileAuth struct {
	path string
	mu   sync.Mutex
	tok  string
	mod  time.Time
	size int64
}

func (a *fileAuth) token(context.Context, *baoBackend) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fi, err := os.Stat(a.path)
	if err != nil {
		return "", fmt.Errorf("secrets token_file: %w", err)
	}
	if a.tok == "" || !fi.ModTime().Equal(a.mod) || fi.Size() != a.size {
		b, err := os.ReadFile(a.path)
		if err != nil {
			return "", fmt.Errorf("secrets token_file: %w", err)
		}
		t := strings.TrimSpace(string(b))
		if t == "" {
			return "", errors.New("secrets token_file is empty")
		}
		a.tok, a.mod, a.size = t, fi.ModTime(), fi.Size()
	}
	return a.tok, nil
}

func (a *fileAuth) invalidate(string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tok = "" // force a re-read
	return true
}

// roleAuth logs in with AppRole and caches the client token.
type roleAuth struct {
	roleID, secretID, secretIDFile string
	mu                             sync.Mutex
	tok                            string
	expires                        time.Time // zero: no expiry known
}

func (a *roleAuth) token(ctx context.Context, b *baoBackend) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tok != "" && (a.expires.IsZero() || time.Now().Before(a.expires.Add(-expirySlack))) {
		return a.tok, nil
	}
	a.tok = ""
	sid := a.secretID
	if a.secretIDFile != "" {
		raw, err := os.ReadFile(a.secretIDFile)
		if err != nil {
			return "", fmt.Errorf("secrets secret_id_file: %w", err)
		}
		sid = strings.TrimSpace(string(raw))
	}
	payload, _ := json.Marshal(map[string]string{"role_id": a.roleID, "secret_id": sid})
	status, body, err := b.send(ctx, http.MethodPost, "/v1/auth/approle/login", "", payload)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", statusErr("approle login", status, body)
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Auth.ClientToken == "" {
		return "", errors.New("openbao approle login: unexpected response")
	}
	a.tok = out.Auth.ClientToken
	a.expires = time.Time{}
	if out.Auth.LeaseDuration > 0 {
		a.expires = time.Now().Add(time.Duration(out.Auth.LeaseDuration) * time.Second)
	}
	b.log.Debug("openbao approle login ok", "lease_seconds", out.Auth.LeaseDuration)
	return a.tok, nil
}

func (a *roleAuth) invalidate(tok string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tok == tok { // another goroutine may have logged in again already
		a.tok = ""
	}
	return true
}

// ---- HTTP ----

// statusErr describes a failed call. It carries Vault's own error strings,
// which are about the request, never about our values.
func statusErr(what string, status int, body []byte) error {
	var e struct {
		Errors []string `json:"errors"`
	}
	msg := ""
	if json.Unmarshal(body, &e) == nil && len(e.Errors) > 0 {
		msg = ": " + strings.Join(e.Errors, "; ")
		if len(msg) > 200 {
			msg = msg[:200]
		}
	}
	return fmt.Errorf("openbao %s: status %d%s", what, status, msg)
}

// send makes one request. tok may be "" (login).
func (b *baoBackend) send(ctx context.Context, method, path, tok string, payload []byte) (int, []byte, error) {
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.base+path, rd)
	if err != nil {
		return 0, nil, errors.New("openbao: bad request")
	}
	if tok != "" {
		req.Header.Set("X-Vault-Token", tok)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := b.hc.Do(req)
	if err != nil {
		// *url.Error holds the URL only (no headers or body), which is safe.
		return 0, nil, fmt.Errorf("openbao: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return 0, nil, fmt.Errorf("openbao: reading response: %w", err)
	}
	return resp.StatusCode, body, nil
}

// do sends an authenticated request; on a 403 it gets a new token and tries
// once more, then gives up with the error.
func (b *baoBackend) do(ctx context.Context, method, path string, payload []byte) (int, []byte, error) {
	for attempt := 0; ; attempt++ {
		tok, err := b.auth.token(ctx, b)
		if err != nil {
			return 0, nil, err
		}
		status, body, err := b.send(ctx, method, path, tok, payload)
		if err != nil {
			return 0, nil, err
		}
		if status == http.StatusForbidden && attempt == 0 && b.auth.invalidate(tok) {
			continue
		}
		return status, body, nil
	}
}

func (b *baoBackend) dataPath(doc string) string {
	segs := strings.Split(doc, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return b.mount + "/data/" + b.prefix + "/" + strings.Join(segs, "/")
}

// readDoc returns the document and the KV version to hand to cas. A missing
// document is empty at version 0 (cas 0 means "must not exist yet").
func (b *baoBackend) readDoc(ctx context.Context, doc string) (map[string]string, int, error) {
	status, body, err := b.do(ctx, http.MethodGet, "/v1/"+b.dataPath(doc), nil)
	if err != nil {
		return nil, 0, err
	}
	var out struct {
		Data struct {
			Data     map[string]any `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	switch status {
	case http.StatusOK:
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, 0, errors.New("openbao: unexpected response reading secrets")
		}
	case http.StatusNotFound:
		// Never written (version 0), or its latest version was deleted
		// elsewhere (the body still says which version that was).
		_ = json.Unmarshal(body, &out)
		return map[string]string{}, out.Data.Metadata.Version, nil
	default:
		return nil, 0, statusErr("read", status, body)
	}
	m := make(map[string]string, len(out.Data.Data))
	for k, v := range out.Data.Data {
		if s, ok := v.(string); ok { // our documents only hold strings
			m[k] = s
		}
	}
	return m, out.Data.Metadata.Version, nil
}

func (b *baoBackend) writeDoc(ctx context.Context, doc string, m map[string]string, version int) error {
	payload, err := json.Marshal(map[string]any{
		"options": map[string]any{"cas": version},
		"data":    m,
	})
	if err != nil {
		return err
	}
	status, body, err := b.do(ctx, http.MethodPost, "/v1/"+b.dataPath(doc), payload)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case status == http.StatusBadRequest && bytes.Contains(bytes.ToLower(body), []byte("check-and-set")):
		return errCAS
	}
	return statusErr("write", status, body)
}

func (b *baoBackend) get(ctx context.Context, doc string) (map[string]string, error) {
	m, _, err := b.readDoc(ctx, doc)
	return m, err
}

// update is read-modify-write guarded by KV v2 check-and-set, so two writers
// of different keys cannot overwrite each other: the loser re-reads and
// applies its change again.
func (b *baoBackend) update(ctx context.Context, doc string, fn func(map[string]string) bool) error {
	for attempt := 0; attempt < casAttempts; attempt++ {
		m, version, err := b.readDoc(ctx, doc)
		if err != nil {
			return err
		}
		if !fn(m) {
			return nil
		}
		err = b.writeDoc(ctx, doc, m, version)
		if !errors.Is(err, errCAS) {
			return err
		}
		wait := time.Duration(1+rand.IntN(5*(attempt+1))) * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return errors.New("openbao: gave up writing secrets after repeated write conflicts")
}

// health checks that the token works and may read, create and update the
// global document, using sys/capabilities-self, which writes nothing.
func (b *baoBackend) health(ctx context.Context) error {
	p := b.rawMnt + "/data/" + b.rawPfx + "/" + globalDoc
	payload, _ := json.Marshal(map[string]any{"paths": []string{p}, "path": p})
	status, body, err := b.do(ctx, http.MethodPost, "/v1/sys/capabilities-self", payload)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return statusErr("capabilities check", status, body)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(body, &out); err != nil {
		return errors.New("openbao: unexpected capabilities response")
	}
	if d, ok := out["data"]; ok { // newer servers also nest it under data
		var inner map[string]json.RawMessage
		if json.Unmarshal(d, &inner) == nil {
			for k, v := range inner {
				if _, dup := out[k]; !dup {
					out[k] = v
				}
			}
		}
	}
	var caps []string
	if raw, ok := out[b.rawMnt+"/data/"+b.rawPfx+"/"+globalDoc]; ok {
		_ = json.Unmarshal(raw, &caps)
	} else if raw, ok := out["capabilities"]; ok {
		_ = json.Unmarshal(raw, &caps)
	}
	have := map[string]bool{}
	for _, c := range caps {
		have[c] = true
	}
	if have["root"] || (have["read"] && have["create"] && have["update"] && !have["deny"]) {
		return nil
	}
	return fmt.Errorf("openbao token lacks read, create and update on %s (has %v)", p, caps)
}
