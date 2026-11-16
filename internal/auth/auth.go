// Package auth is single sign-on with OpenID Connect, and the sessions that
// follow it. There are no local passwords.
//
// A person is sent to the identity provider (authorization code flow with
// PKCE), comes back to /auth/callback, and gets a session cookie holding only
// their username and an expiry. On every request the user is read fresh from
// the store, so a change of role or a removed user takes effect at once.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"

	"openmdm/internal/core"
)

const (
	sessionCookie = "openmdm_session"
	flowCookie    = "openmdm_oidc"
	keysBlob      = "auth/session-keys"
	sessionTTL    = 12 * time.Hour
	flowTTL       = 10 * time.Minute
)

// Auth does the sign-in and the sessions. Build one with New.
type Auth struct {
	cfg    core.OIDCConfig
	store  core.Store
	log    *slog.Logger
	bases  []base
	client *http.Client
	now    func() time.Time

	mu       sync.Mutex // guards the lazily built parts below
	provider *oidc.Provider
	oauth    *oauth2.Config
	sc       *securecookie.SecureCookie
}

// base is one external name the server is known by.
type base struct {
	host   string // host[:port], lower case: what a request's Host is compared with
	secure bool   // the base's scheme is https
	url    string // scheme://host[:port], no trailing slash
}

func (b base) redirectURI() string { return b.url + "/auth/callback" }

// baseFor returns the base whose host is the request's Host header.
func (a *Auth) baseFor(r *http.Request) (base, bool) {
	return a.baseByHost(r.Host)
}

func (a *Auth) baseByHost(host string) (base, bool) {
	host = strings.ToLower(host)
	for _, b := range a.bases {
		if b.host == host {
			return b, true
		}
	}
	return base{}, false
}

// New checks the configuration and builds an Auth. baseURLs are the external
// addresses the server is known by (admin_url and public_url); sign-in works
// on each, using the one a request came in on for the redirect address. It
// does not contact the identity provider, which may be down or not started
// yet: that happens on first use and is retried on a later request.
func New(cfg core.OIDCConfig, baseURLs []string, store core.Store, logger *slog.Logger) (*Auth, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" {
		return nil, errors.New("auth: oidc issuer and client_id are required")
	}
	var bases []base
	for _, raw := range baseURLs {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("auth: URL %q is not an http(s) URL", raw)
		}
		host := strings.ToLower(u.Host)
		dup := false
		for _, b := range bases {
			dup = dup || b.host == host
		}
		if !dup {
			bases = append(bases, base{host: host, secure: u.Scheme == "https", url: u.Scheme + "://" + u.Host})
		}
	}
	if len(bases) == 0 {
		return nil, errors.New("auth: at least one external URL is required")
	}
	if store == nil {
		return nil, errors.New("auth: store is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "preferred_username"
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("auth: reading oidc ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("auth: oidc ca_file holds no certificate")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &Auth{
		cfg:    cfg,
		store:  store,
		log:    logger,
		bases:  bases,
		client: &http.Client{Transport: tr, Timeout: 15 * time.Second},
		now:    time.Now,
	}, nil
}

// RedirectURIs are what the identity provider must list as allowed: one per
// name the server is known by.
func (a *Auth) RedirectURIs() []string {
	out := make([]string, 0, len(a.bases))
	for _, b := range a.bases {
		out = append(out, b.redirectURI())
	}
	return out
}

// discover returns the provider's configuration, fetching it the first time
// and again after a failure.
func (a *Auth) discover() (*oidc.Provider, *oauth2.Config, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.provider != nil {
		return a.provider, a.oauth, nil
	}
	// Not the request's context: go-oidc keeps it to fetch signing keys later.
	ctx := oidc.ClientContext(context.Background(), a.client)
	p, err := oidc.NewProvider(ctx, a.cfg.Issuer)
	if err != nil {
		return nil, nil, err
	}
	a.provider = p
	a.oauth = &oauth2.Config{
		ClientID:     a.cfg.ClientID,
		ClientSecret: a.cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return a.provider, a.oauth, nil
}

type storedKeys struct {
	Hash  []byte `json:"hash"`
	Block []byte `json:"block"`
}

// codec returns the cookie encoder, creating and saving the keys on first
// use so that sessions survive a restart.
func (a *Auth) codec(ctx context.Context) (*securecookie.SecureCookie, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sc != nil {
		return a.sc, nil
	}
	var k storedKeys
	raw, err := a.store.GetBlob(ctx, keysBlob)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &k); err != nil || len(k.Hash) != 32 || len(k.Block) != 32 {
			return nil, errors.New("auth: stored session keys are damaged")
		}
	case errors.Is(err, core.ErrNotFound):
		k = storedKeys{Hash: make([]byte, 32), Block: make([]byte, 32)}
		if _, err := rand.Read(k.Hash); err != nil {
			return nil, err
		}
		if _, err := rand.Read(k.Block); err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(k)
		if err := a.store.PutBlob(ctx, keysBlob, raw); err != nil {
			return nil, fmt.Errorf("auth: saving session keys: %w", err)
		}
	default:
		return nil, fmt.Errorf("auth: loading session keys: %w", err)
	}
	sc := securecookie.New(k.Hash, k.Block)
	sc.MaxAge(0) // expiry is checked by us, from the payload
	sc.SetSerializer(securecookie.JSONEncoder{})
	a.sc = sc
	return sc, nil
}

type sessionData struct {
	User string `json:"u"`
	Exp  int64  `json:"e"`
}

type flowData struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Base     string `json:"b"` // the external base URL the login came in on
	Exp      int64  `json:"e"`
}

func (a *Auth) setCookie(w http.ResponseWriter, secure bool, name, value, path string, ttl time.Duration) {
	c := &http.Cookie{
		Name: name, Value: value, Path: path,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	}
	if ttl > 0 {
		c.MaxAge = int(ttl.Seconds())
		c.Expires = a.now().Add(ttl)
	} else {
		c.MaxAge = -1
		c.Expires = time.Unix(0, 0)
	}
	http.SetCookie(w, c)
}

// Routes serves /auth/login, /auth/callback and /auth/logout. Mount it at
// the server root.
func (a *Auth) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", a.login)
	mux.HandleFunc("/auth/callback", a.callback)
	mux.HandleFunc("/auth/logout", a.logout)
	return mux
}

func (a *Auth) fail(w http.ResponseWriter, status int, msg string, err error) {
	if err != nil {
		a.log.Warn("sign-in failed", "reason", msg, "error", err.Error())
	} else {
		a.log.Warn("sign-in failed", "reason", msg)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, "Sign-in failed: %s.\n\nTry again: /auth/login\n", msg)
}

// safeNext returns next if it is a local path, else "/".
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, "\\") {
		return "/"
	}
	for _, r := range next {
		if r < 0x20 || r == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	return next
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *Auth) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b, ok := a.baseFor(r)
	if !ok {
		a.unknownHost(w, r)
		return
	}
	_, conf, err := a.discover()
	if err != nil {
		a.fail(w, http.StatusBadGateway, "the identity provider could not be reached", err)
		return
	}
	conf = withRedirect(conf, b)
	sc, err := a.codec(r.Context())
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "the server could not prepare a session", err)
		return
	}
	state, err1 := randomString()
	nonce, err2 := randomString()
	if err1 != nil || err2 != nil {
		a.fail(w, http.StatusInternalServerError, "no randomness available", errors.Join(err1, err2))
		return
	}
	fd := flowData{
		State: state, Nonce: nonce, Verifier: oauth2.GenerateVerifier(),
		Next: safeNext(r.URL.Query().Get("next")), Base: b.url,
		Exp: a.now().Add(flowTTL).Unix(),
	}
	enc, err := sc.Encode(flowCookie, fd)
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "could not start sign-in", err)
		return
	}
	a.setCookie(w, b.secure, flowCookie, enc, "/auth", flowTTL)
	authURL := conf.AuthCodeURL(state, oauth2.S256ChallengeOption(fd.Verifier), oidc.Nonce(nonce))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusFound)
}

// unknownHost refuses a request that came in on a name the server is not
// known by. A redirect address is never built from an unknown Host.
func (a *Auth) unknownHost(w http.ResponseWriter, r *http.Request) {
	a.log.Warn("sign-in refused: unknown host", "host", sanitize(r.Host))
	http.Error(w, "bad request: this server is not known by that name", http.StatusBadRequest)
}

// withRedirect returns a copy of conf whose redirect address is on base b.
func withRedirect(conf *oauth2.Config, b base) *oauth2.Config {
	c := *conf
	c.RedirectURL = b.redirectURI()
	return &c
}

func (a *Auth) callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b, ok := a.baseFor(r)
	if !ok {
		a.unknownHost(w, r)
		return
	}
	sc, err := a.codec(r.Context())
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "the server could not prepare a session", err)
		return
	}
	// The flow cookie is single use whatever happens next.
	a.setCookie(w, b.secure, flowCookie, "", "/auth", 0)

	ck, err := r.Cookie(flowCookie)
	if err != nil {
		a.fail(w, http.StatusBadRequest, "the sign-in did not start here or took too long", err)
		return
	}
	var fd flowData
	if err := sc.Decode(flowCookie, ck.Value, &fd); err != nil || a.now().Unix() > fd.Exp {
		a.fail(w, http.StatusBadRequest, "the sign-in did not start here or took too long", err)
		return
	}
	// The exchange must use the redirect address the login used.
	if fd.Base != b.url {
		a.fail(w, http.StatusBadRequest, "the sign-in did not start on this name", nil)
		return
	}
	q := r.URL.Query()
	if got := q.Get("state"); fd.State == "" || !same(got, fd.State) {
		a.fail(w, http.StatusBadRequest, "the sign-in response did not match the request", nil)
		return
	}
	if e := q.Get("error"); e != "" {
		a.fail(w, http.StatusUnauthorized, "the identity provider refused the sign-in ("+sanitize(e)+")", nil)
		return
	}
	code := q.Get("code")
	if code == "" {
		a.fail(w, http.StatusBadRequest, "the sign-in response had no code", nil)
		return
	}
	provider, conf, err := a.discover()
	if err != nil {
		a.fail(w, http.StatusBadGateway, "the identity provider could not be reached", err)
		return
	}
	conf = withRedirect(conf, b)
	ctx, cancel := context.WithTimeout(oidc.ClientContext(r.Context(), a.client), 30*time.Second)
	defer cancel()

	tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(fd.Verifier))
	if err != nil {
		a.fail(w, http.StatusBadGateway, "the identity provider would not give a token", scrubErr(err))
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		a.fail(w, http.StatusBadGateway, "the identity provider sent no ID token", nil)
		return
	}
	idt, err := provider.Verifier(&oidc.Config{ClientID: a.cfg.ClientID}).Verify(ctx, rawID)
	if err != nil {
		a.fail(w, http.StatusUnauthorized, "the ID token could not be verified", scrubErr(err))
		return
	}
	if idt.Nonce == "" || !same(idt.Nonce, fd.Nonce) {
		a.fail(w, http.StatusUnauthorized, "the ID token was not issued for this sign-in", nil)
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		a.fail(w, http.StatusBadGateway, "the ID token could not be read", err)
		return
	}
	// Ask the userinfo endpoint only for what the ID token left out.
	_, hasGroups := claims[a.cfg.GroupsClaim]
	if str(claims[a.cfg.UsernameClaim]) == "" || str(claims["email"]) == "" || !hasGroups {
		var ui map[string]any
		if info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err != nil {
			a.log.Info("userinfo not available", "error", scrubErr(err).Error())
		} else if info.Claims(&ui) == nil {
			if info.Subject != idt.Subject {
				a.log.Warn("userinfo subject differs from ID token; ignoring userinfo")
			} else {
				for k, v := range ui {
					if _, ok := claims[k]; !ok {
						claims[k] = v
					}
				}
			}
		}
	}

	email := strings.TrimSpace(str(claims["email"]))
	username := strings.ToLower(strings.TrimSpace(str(claims[a.cfg.UsernameClaim])))
	if username == "" {
		username = strings.ToLower(email)
	}
	if !validUsername(username) {
		a.fail(w, http.StatusForbidden, "the identity provider gave no usable username or email", nil)
		return
	}
	groups := stringList(claims[a.cfg.GroupsClaim])
	role := core.RoleUser
	if a.cfg.AdminGroup != "" {
		for _, g := range groups {
			if g == a.cfg.AdminGroup {
				role = core.RoleAdmin
				break
			}
		}
	}
	now := a.now().UTC()
	if _, err := a.store.UpsertUser(r.Context(), core.User{
		Username: username, Email: email, Name: strings.TrimSpace(str(claims["name"])),
		Groups: groups, Role: role, LastLoginAt: now,
	}); err != nil {
		a.fail(w, http.StatusInternalServerError, "the server could not record the sign-in", err)
		return
	}
	if err := a.store.AppendEvent(r.Context(), core.Event{At: now, Actor: username, Kind: "auth.login", Subject: username}); err != nil {
		a.log.Error("audit event for login not saved", "error", err.Error())
	}
	enc, err := sc.Encode(sessionCookie, sessionData{User: username, Exp: now.Add(sessionTTL).Unix()})
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "could not make a session", err)
		return
	}
	a.setCookie(w, b.secure, sessionCookie, enc, "/", sessionTTL)
	a.log.Info("signed in", "user", username, "role", string(role))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, safeNext(fd.Next), http.StatusFound)
}

func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	secure := r.TLS != nil
	if b, ok := a.baseFor(r); ok {
		secure = b.secure
	}
	a.setCookie(w, secure, sessionCookie, "", "/", 0)
	w.WriteHeader(http.StatusNoContent)
}

// userFrom returns the signed-in person for a request, if any.
func (a *Auth) userFrom(r *http.Request) (core.User, bool) {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return core.User{}, false
	}
	sc, err := a.codec(r.Context())
	if err != nil {
		a.log.Error("session keys unavailable", "error", err.Error())
		return core.User{}, false
	}
	var sd sessionData
	if err := sc.Decode(sessionCookie, ck.Value, &sd); err != nil || sd.User == "" || a.now().Unix() >= sd.Exp {
		return core.User{}, false
	}
	u, err := a.store.GetUser(r.Context(), sd.User)
	if err != nil {
		if !errors.Is(err, core.ErrNotFound) {
			a.log.Error("loading session user", "error", err.Error())
		}
		return core.User{}, false
	}
	return u, true
}

// Middleware lets signed-in requests through with the user in the context.
// Others get 401 JSON under /api/, and a redirect to sign in elsewhere.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := a.userFrom(r); ok {
			next.ServeHTTP(w, r.WithContext(core.WithUser(r.Context(), u)))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"not signed in"}` + "\n"))
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	})
}

// Optional is Middleware for pages that work either way: without a session
// the request passes through with no user.
func (a *Auth) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := a.userFrom(r); ok {
			r = r.WithContext(core.WithUser(r.Context(), u))
		}
		next.ServeHTTP(w, r)
	})
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// stringList reads a claim that should be a list of strings, tolerating a
// missing claim, a single string, or stray non-strings.
func stringList(v any) []string {
	out := []string{}
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	case string:
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// validUsername keeps out names that would be dangerous as a path element in
// the secret store, which is keyed by username.
func validUsername(s string) bool {
	if s == "" || len(s) > 254 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

func sanitize(s string) string {
	if len(s) > 60 {
		s = s[:60]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

// scrubErr keeps an error's text for the log but drops anything that could
// carry a token or code: oauth2 errors include the response body.
func scrubErr(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		return fmt.Errorf("token endpoint answered %s", re.Response.Status)
	}
	return err
}

func same(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
