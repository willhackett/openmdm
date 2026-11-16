package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"openmdm/internal/core"
)

// fakeStore implements the part of core.Store that auth uses.
type fakeStore struct {
	core.Store // anything else panics: auth must not use it
	mu         sync.Mutex
	users      map[string]core.User
	blobs      map[string][]byte
	events     []core.Event
}

func newFakeStore() *fakeStore {
	return &fakeStore{users: map[string]core.User{}, blobs: map[string][]byte{}}
}

func (s *fakeStore) UpsertUser(_ context.Context, u core.User) (core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.users[u.Username]; ok {
		u.CreatedAt = old.CreatedAt
	} else {
		u.CreatedAt = time.Now().UTC()
	}
	s.users[u.Username] = u
	return u, nil
}
func (s *fakeStore) GetUser(_ context.Context, name string) (core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[name]
	if !ok {
		return core.User{}, core.ErrNotFound
	}
	return u, nil
}
func (s *fakeStore) GetBlob(_ context.Context, k string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.blobs[k]
	if !ok {
		return nil, core.ErrNotFound
	}
	return b, nil
}
func (s *fakeStore) PutBlob(_ context.Context, k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[k] = v
	return nil
}
func (s *fakeStore) AppendEvent(_ context.Context, e core.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

// fakeIdP is a minimal OpenID provider.
type fakeIdP struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey

	mu          sync.Mutex
	down        bool           // discovery answers 503
	claims      map[string]any // ID token claims besides the standard ones
	userinfo    map[string]any // nil: userinfo endpoint answers 404
	nonceOver   string         // if set, the ID token carries this nonce
	pending     map[string]codeInfo
	userinfoHit int
}

type codeInfo struct{ challenge, nonce, redirect string }

func newFakeIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{t: t, key: key, pending: map[string]codeInfo{}, claims: map[string]any{}}
	p.srv = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeIdP) set(f func(p *fakeIdP)) { p.mu.Lock(); f(p); p.mu.Unlock() }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (p *fakeIdP) sign(claims map[string]any) string {
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	pl, _ := json.Marshal(claims)
	in := b64(hdr) + "." + b64(pl)
	h := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, h[:])
	if err != nil {
		p.t.Fatal(err)
	}
	return in + "." + b64(sig)
}

func (p *fakeIdP) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	base := p.srv.URL
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		if p.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": base, "authorization_endpoint": base + "/authorize",
			"token_endpoint": base + "/token", "jwks_uri": base + "/jwks",
			"userinfo_endpoint":                     base + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	case "/jwks":
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": b64(p.key.N.Bytes()), "e": b64(big.NewInt(int64(p.key.E)).Bytes()),
		}}})
	case "/authorize":
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
			q.Get("response_type") != "code" || q.Get("client_id") != "mdm" || q.Get("nonce") == "" ||
			q.Get("scope") != "openid profile email" {
			http.Error(w, "bad authorize request: "+r.URL.RawQuery, http.StatusBadRequest)
			return
		}
		code := "code-" + q.Get("state")
		p.pending[code] = codeInfo{q.Get("code_challenge"), q.Get("nonce"), q.Get("redirect_uri")}
		ru, _ := url.Parse(q.Get("redirect_uri"))
		rq := ru.Query()
		rq.Set("code", code)
		rq.Set("state", q.Get("state"))
		ru.RawQuery = rq.Encode()
		http.Redirect(w, r, ru.String(), http.StatusFound)
	case "/token":
		r.ParseForm()
		ci, ok := p.pending[r.Form.Get("code")]
		if !ok {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		if r.Form.Get("redirect_uri") != ci.redirect {
			http.Error(w, `{"error":"invalid_grant","error_description":"redirect_uri mismatch"}`, http.StatusBadRequest)
			return
		}
		h := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if b64(h[:]) != ci.challenge {
			http.Error(w, `{"error":"invalid_grant","error_description":"pkce"}`, http.StatusBadRequest)
			return
		}
		delete(p.pending, r.Form.Get("code"))
		nonce := ci.nonce
		if p.nonceOver != "" {
			nonce = p.nonceOver
		}
		claims := map[string]any{
			"iss": base, "aud": "mdm", "sub": "sub-1", "nonce": nonce,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}
		for k, v := range p.claims {
			claims[k] = v
		}
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "id_token": p.sign(claims),
		})
	case "/userinfo":
		p.userinfoHit++
		if p.userinfo == nil {
			http.NotFound(w, r)
			return
		}
		out := map[string]any{"sub": "sub-1"}
		for k, v := range p.userinfo {
			out[k] = v
		}
		json.NewEncoder(w).Encode(out)
	default:
		http.NotFound(w, r)
	}
}

type env struct {
	idp   *fakeIdP
	store *fakeStore
	auth  *Auth
	app   *httptest.Server
	cl    *http.Client
	// alsoLocalhost makes the server known by localhost:<port> as well.
	alsoLocalhost bool
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{idp: newFakeIdP(t), store: newFakeStore()}
	e.idp.claims = map[string]any{
		"preferred_username": "Alice", "email": "alice@example.com", "name": "Alice A",
		"groups": []string{"staff", "mdm-admins"},
	}
	e.start(t, e.store)
	return e
}

func (e *env) start(t *testing.T, store core.Store) {
	t.Helper()
	// The app's URL is only known once it listens, so the handler reads a.
	mux := http.NewServeMux()
	e.app = httptest.NewServer(mux)
	t.Cleanup(e.app.Close)
	bases := []string{e.app.URL}
	if e.alsoLocalhost {
		_, port, _ := strings.Cut(strings.TrimPrefix(e.app.URL, "http://"), ":")
		bases = append(bases, "http://localhost:"+port)
	}
	a, err := New(core.OIDCConfig{
		Issuer: e.idp.srv.URL, ClientID: "mdm", ClientSecret: "s3cret", AdminGroup: "mdm-admins",
	}, bases, store, slog.New(slog.NewTextHandler(testWriter{t}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e.auth = a
	mux.Handle("/auth/", a.Routes())
	mux.Handle("/api/", a.Middleware(http.HandlerFunc(whoami)))
	mux.Handle("/page", a.Middleware(http.HandlerFunc(whoami)))
	mux.Handle("/open", a.Optional(http.HandlerFunc(whoami)))
	jar, _ := cookiejar.New(nil)
	e.cl = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func whoami(w http.ResponseWriter, r *http.Request) {
	if u, ok := core.UserFrom(r.Context()); ok {
		io.WriteString(w, u.Username+" "+string(u.Role))
		return
	}
	io.WriteString(w, "anonymous")
}

// get follows redirects by hand, across the app and the provider, until the
// response is not a redirect or the redirect would leave both.
func (e *env) get(t *testing.T, rawURL string) *http.Response {
	t.Helper()
	for i := 0; i < 10; i++ {
		resp, err := e.cl.Get(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		loc := resp.Header.Get("Location")
		if resp.StatusCode/100 != 3 || loc == "" {
			return resp
		}
		u, _ := resp.Request.URL.Parse(loc)
		// Follow only the sign-in hops; the final redirect is the answer.
		if !strings.HasPrefix(u.String(), e.idp.srv.URL) && u.Path != "/auth/callback" && u.Path != "/auth/login" {
			return resp
		}
		resp.Body.Close()
		rawURL = u.String()
	}
	t.Fatal("too many redirects")
	return nil
}

func body(r *http.Response) string {
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

func (e *env) login(t *testing.T, next string) *http.Response {
	return e.get(t, e.app.URL+"/auth/login?next="+url.QueryEscape(next))
}

func (e *env) who(t *testing.T) string {
	r := e.get(t, e.app.URL+"/open")
	return body(r)
}

func TestFullLoginAdmin(t *testing.T) {
	e := newEnv(t)
	resp := e.login(t, "/page?x=1")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/page?x=1" {
		t.Fatalf("got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if got := e.who(t); got != "alice admin" {
		t.Fatalf("who = %q", got)
	}
	u := e.store.users["alice"]
	if u.Email != "alice@example.com" || u.Name != "Alice A" || u.LastLoginAt.IsZero() || len(u.Groups) != 2 {
		t.Fatalf("user = %+v", u)
	}
	if len(e.store.events) != 1 || e.store.events[0].Kind != "auth.login" || e.store.events[0].Actor != "alice" {
		t.Fatalf("events = %+v", e.store.events)
	}
	if e.idp.userinfoHit != 0 {
		t.Fatal("userinfo used though the ID token had everything")
	}
	// Cookie attributes.
	cu, _ := url.Parse(e.app.URL)
	for _, c := range e.cl.Jar.Cookies(cu) {
		if c.Name == flowCookie {
			t.Fatal("flow cookie not cleared")
		}
	}
}

func TestCookieAttributes(t *testing.T) {
	e := newEnv(t)
	// Drive the flow without a jar to see the raw Set-Cookie of the callback.
	r := e.get(t, e.app.URL+"/auth/login")
	r.Body.Close()
	jar := e.cl.Jar
	cu, _ := url.Parse(e.app.URL)
	if len(jar.Cookies(cu)) == 0 {
		t.Fatal("no cookie")
	}
	// Inspect directly using the handler.
	rec := httptest.NewRecorder()
	e.auth.setCookie(rec, false, sessionCookie, "v", "/", sessionTTL)
	c := rec.Result().Cookies()[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Secure {
		t.Fatalf("cookie %+v", c)
	}
	rec = httptest.NewRecorder()
	e.auth.setCookie(rec, true, sessionCookie, "v", "/", sessionTTL)
	if !rec.Result().Cookies()[0].Secure {
		t.Fatal("not Secure on https")
	}
	a2, _ := New(core.OIDCConfig{Issuer: "https://x", ClientID: "c"}, []string{"https://mdm.example.internal/", "http://plain.example"}, e.store, nil)
	uris := a2.RedirectURIs()
	if len(uris) != 2 || uris[0] != "https://mdm.example.internal/auth/callback" || uris[1] != "http://plain.example/auth/callback" {
		t.Fatalf("redirects=%q", uris)
	}
	if b, ok := a2.baseByHost("MDM.Example.Internal"); !ok || !b.secure {
		t.Fatalf("base = %+v %v", b, ok)
	}
	if b, ok := a2.baseByHost("plain.example"); !ok || b.secure {
		t.Fatalf("base = %+v %v", b, ok)
	}
}

func TestRoleByGroup(t *testing.T) {
	e := newEnv(t)
	e.idp.set(func(p *fakeIdP) { p.claims["groups"] = []string{"staff"} })
	e.login(t, "/").Body.Close()
	if got := e.who(t); got != "alice user" {
		t.Fatalf("who = %q", got)
	}
}

func TestGroupsMissingTolerated(t *testing.T) {
	e := newEnv(t)
	e.idp.set(func(p *fakeIdP) { delete(p.claims, "groups") })
	e.login(t, "/").Body.Close()
	if got := e.who(t); got != "alice user" {
		t.Fatalf("who = %q", got)
	}
	if g := e.store.users["alice"].Groups; g == nil || len(g) != 0 {
		t.Fatalf("groups = %#v", g)
	}
}

func TestUsernameFallsBackToEmail(t *testing.T) {
	e := newEnv(t)
	e.idp.set(func(p *fakeIdP) { delete(p.claims, "preferred_username"); p.claims["email"] = "Bob@Example.com" })
	e.login(t, "/").Body.Close()
	if got := e.who(t); got != "bob@example.com admin" {
		t.Fatalf("who = %q", got)
	}
}

func TestNoUsernameNoEmailRefused(t *testing.T) {
	e := newEnv(t)
	e.idp.set(func(p *fakeIdP) { delete(p.claims, "preferred_username"); delete(p.claims, "email") })
	resp := e.login(t, "/")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body(resp), "/auth/login") {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := e.who(t); got != "anonymous" {
		t.Fatalf("who = %q", got)
	}
}

func TestUserinfoFillsGaps(t *testing.T) {
	e := newEnv(t)
	e.idp.set(func(p *fakeIdP) {
		delete(p.claims, "groups")
		delete(p.claims, "preferred_username")
		p.userinfo = map[string]any{"preferred_username": "carol", "groups": []string{"mdm-admins"}}
	})
	e.login(t, "/").Body.Close()
	if got := e.who(t); got != "carol admin" {
		t.Fatalf("who = %q", got)
	}
}

func TestUserinfoFailureTolerated(t *testing.T) {
	e := newEnv(t)
	e.idp.set(func(p *fakeIdP) { delete(p.claims, "groups") }) // userinfo is 404
	e.login(t, "/").Body.Close()
	if got := e.who(t); got != "alice user" {
		t.Fatalf("who = %q", got)
	}
}

// redirectFor starts a login and returns a callback URL with a wrong state.
func (a *Auth) redirectFor(t *testing.T, e *env) string {
	t.Helper()
	resp, err := e.cl.Get(e.app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return e.app.URL + "/auth/callback?code=whatever&state=wrong"
}

func TestStateMismatchRefused(t *testing.T) {
	e := newEnv(t)
	cb := e.auth.redirectFor(t, e)
	resp := e.get(t, cb)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := e.who(t); got != "anonymous" {
		t.Fatalf("who = %q", got)
	}
}

func TestCallbackWithoutFlowCookie(t *testing.T) {
	e := newEnv(t)
	resp := e.get(t, e.app.URL+"/auth/callback?code=x&state=y")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestNonceMismatch(t *testing.T) {
	e := newEnv(t)
	e.idp.set(func(p *fakeIdP) { p.nonceOver = "someone-elses-nonce" })
	resp := e.login(t, "/")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := e.who(t); got != "anonymous" {
		t.Fatalf("who = %q", got)
	}
}

func TestProviderError(t *testing.T) {
	e := newEnv(t)
	r := e.get(t, e.app.URL+"/auth/login")
	r.Body.Close()
	// Find the state from the flow cookie is not possible; use a bad code instead.
	resp := e.get(t, e.app.URL+"/auth/callback?error=access_denied&state=nope")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestTamperedSession(t *testing.T) {
	e := newEnv(t)
	e.login(t, "/").Body.Close()
	cu, _ := url.Parse(e.app.URL)
	var sess *http.Cookie
	for _, c := range e.cl.Jar.Cookies(cu) {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	if sess == nil {
		t.Fatal("no session")
	}
	for _, v := range []string{sess.Value[:len(sess.Value)-4] + "AAAA", "garbage", ""} {
		req, _ := http.NewRequest("GET", e.app.URL+"/page", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: v})
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 302 {
			t.Fatalf("tampered %q accepted: %d", v, resp.StatusCode)
		}
	}
}

func TestExpiredSession(t *testing.T) {
	e := newEnv(t)
	e.login(t, "/").Body.Close()
	if e.who(t) != "alice admin" {
		t.Fatal("not signed in")
	}
	e.auth.now = func() time.Time { return time.Now().Add(13 * time.Hour) }
	if got := e.who(t); got != "anonymous" {
		t.Fatalf("expired session still works: %q", got)
	}
}

func TestRemovedUserNotSignedIn(t *testing.T) {
	e := newEnv(t)
	e.login(t, "/").Body.Close()
	delete(e.store.users, "alice")
	if got := e.who(t); got != "anonymous" {
		t.Fatalf("who = %q", got)
	}
}

func TestRoleReadFresh(t *testing.T) {
	e := newEnv(t)
	e.login(t, "/").Body.Close()
	u := e.store.users["alice"]
	u.Role = core.RoleUser
	e.store.users["alice"] = u
	if got := e.who(t); got != "alice user" {
		t.Fatalf("who = %q", got)
	}
}

func TestOpenRedirects(t *testing.T) {
	for _, bad := range []string{"//evil.example", "https://evil.example", `/\evil`, "/\\evil.example", "evil", "javascript:alert(1)", "/a\nb", "///evil", ""} {
		if got := safeNext(bad); got != "/" {
			t.Errorf("safeNext(%q) = %q", bad, got)
		}
	}
	for _, ok := range []string{"/", "/devices", "/devices?id=1&x=%2F%2F"} {
		if got := safeNext(ok); got != ok {
			t.Errorf("safeNext(%q) = %q", ok, got)
		}
	}
	// End to end.
	e := newEnv(t)
	resp := e.login(t, "//evil.example")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/" {
		t.Fatalf("got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestMiddlewareUnauthenticated(t *testing.T) {
	e := newEnv(t)
	resp := e.get(t, e.app.URL+"/api/v1/me")
	if resp.StatusCode != 401 || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var m map[string]string
	json.Unmarshal([]byte(body(resp)), &m)
	if m["error"] != "not signed in" {
		t.Fatalf("body %v", m)
	}
	resp, err := e.cl.Get(e.app.URL + "/page?a=b&c=d")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/auth/login?next=%2Fpage%3Fa%3Db%26c%3Dd" {
		t.Fatalf("got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if got := e.who(t); got != "anonymous" {
		t.Fatalf("optional: %q", got)
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	e.login(t, "/").Body.Close()
	resp := e.get(t, e.app.URL+"/auth/logout")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout: %d", resp.StatusCode)
	}
	if e.who(t) != "alice admin" {
		t.Fatal("GET logged out")
	}
	resp, err := e.cl.Post(e.app.URL+"/auth/logout", "text/plain", bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("POST logout: %d", resp.StatusCode)
	}
	if got := e.who(t); got != "anonymous" {
		t.Fatalf("who = %q", got)
	}
}

func TestDiscoveryRetried(t *testing.T) {
	idp := newFakeIdP(t)
	idp.down = true // before New: New must not care
	e := &env{idp: idp, store: newFakeStore()}
	idp.claims = map[string]any{"preferred_username": "alice", "groups": []string{}}
	e.start(t, e.store)

	resp := e.login(t, "/")
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body(resp), "/auth/login") {
		t.Fatalf("status %d", resp.StatusCode)
	}
	idp.set(func(p *fakeIdP) { p.down = false })
	resp = e.login(t, "/")
	if resp.StatusCode != 302 {
		t.Fatalf("after recovery: %d", resp.StatusCode)
	}
	if got := e.who(t); got != "alice user" {
		t.Fatalf("who = %q", got)
	}
}

func TestSessionKeysPersisted(t *testing.T) {
	e := newEnv(t)
	e.login(t, "/").Body.Close()
	if len(e.store.blobs[keysBlob]) == 0 {
		t.Fatal("keys not stored")
	}
	before := string(e.store.blobs[keysBlob])

	// A second Auth on the same store accepts the first one's session.
	a2, err := New(core.OIDCConfig{Issuer: e.idp.srv.URL, ClientID: "mdm"}, []string{e.app.URL}, e.store, nil)
	if err != nil {
		t.Fatal(err)
	}
	cu, _ := url.Parse(e.app.URL)
	req := httptest.NewRequest("GET", "/page", nil)
	for _, c := range e.cl.Jar.Cookies(cu) {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	a2.Middleware(http.HandlerFunc(whoami)).ServeHTTP(rec, req)
	if rec.Body.String() != "alice admin" {
		t.Fatalf("second Auth: %d %q", rec.Code, rec.Body.String())
	}
	if string(e.store.blobs[keysBlob]) != before {
		t.Fatal("keys were replaced")
	}

	// A different store means different keys: the session is refused.
	a3, _ := New(core.OIDCConfig{Issuer: e.idp.srv.URL, ClientID: "mdm"}, []string{e.app.URL}, newFakeStoreWith(e.store.users), nil)
	rec = httptest.NewRecorder()
	a3.Middleware(http.HandlerFunc(whoami)).ServeHTTP(rec, req)
	if rec.Code != 302 {
		t.Fatalf("foreign keys accepted: %d", rec.Code)
	}
}

func newFakeStoreWith(users map[string]core.User) *fakeStore {
	s := newFakeStore()
	s.users = users
	return s
}

func TestNewValidation(t *testing.T) {
	st := newFakeStore()
	if _, err := New(core.OIDCConfig{ClientID: "c"}, []string{"https://x"}, st, nil); err == nil {
		t.Error("missing issuer accepted")
	}
	if _, err := New(core.OIDCConfig{Issuer: "https://i", ClientID: "c"}, []string{"not a url"}, st, nil); err == nil {
		t.Error("bad admin url accepted")
	}
	if _, err := New(core.OIDCConfig{Issuer: "https://i", ClientID: "c"}, nil, st, nil); err == nil {
		t.Error("no URL accepted")
	}
	if _, err := New(core.OIDCConfig{Issuer: "https://i", ClientID: "c", CAFile: "/nonexistent"}, []string{"https://x"}, st, nil); err == nil {
		t.Error("missing CA file accepted")
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

// twoNames starts the app known by two names that reach the same server:
// 127.0.0.1:port and localhost:port.
func twoNames(t *testing.T) (e *env, ip, name string) {
	t.Helper()
	e = &env{idp: newFakeIdP(t), store: newFakeStore()}
	e.idp.claims = map[string]any{"preferred_username": "alice", "groups": []string{"mdm-admins"}}
	e.alsoLocalhost = true
	e.start(t, e.store)
	_, port, _ := strings.Cut(strings.TrimPrefix(e.app.URL, "http://"), ":")
	return e, e.app.URL, "http://localhost:" + port
}

func (e *env) whoAt(t *testing.T, base string) string {
	return body(e.get(t, base+"/open"))
}

func TestSignInOnBothNames(t *testing.T) {
	e, ip, name := twoNames(t)

	// Sign in on the first name: a session there, none on the other.
	if r := e.get(t, ip+"/auth/login?next=/page"); r.StatusCode != 302 || r.Header.Get("Location") != "/page" {
		t.Fatalf("login on ip: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if got := e.whoAt(t, ip); got != "alice admin" {
		t.Fatalf("ip: %q", got)
	}
	if got := e.whoAt(t, name); got != "anonymous" {
		t.Fatalf("a session on one name is a session on the other: %q", got)
	}

	// Sign in on the second name; the identity provider must have been given
	// that name's redirect address (the fake checks the exchange matches).
	if r := e.get(t, name+"/auth/login?next=/page"); r.StatusCode != 302 || r.Header.Get("Location") != "/page" {
		t.Fatalf("login on name: %d %q (%s)", r.StatusCode, r.Header.Get("Location"), "")
	}
	if got := e.whoAt(t, name); got != "alice admin" {
		t.Fatalf("name: %q", got)
	}
}

func TestRedirectURIFollowsTheHost(t *testing.T) {
	e, ip, name := twoNames(t)
	for _, base := range []string{ip, name} {
		resp, err := e.cl.Get(base + "/auth/login")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		u, _ := url.Parse(resp.Header.Get("Location"))
		if got := u.Query().Get("redirect_uri"); got != base+"/auth/callback" {
			t.Fatalf("login on %s asked for redirect_uri %q", base, got)
		}
	}
}

func TestCallbackMustMatchLoginName(t *testing.T) {
	e, ip, name := twoNames(t)
	// Login on one name; take its flow cookie to the callback of the other.
	resp, err := e.cl.Get(ip + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var flow *http.Cookie
	ipu, _ := url.Parse(ip + "/auth/")
	for _, c := range e.cl.Jar.Cookies(ipu) {
		if c.Name == flowCookie {
			flow = c
		}
	}
	if flow == nil {
		t.Fatal("no flow cookie")
	}
	req, _ := http.NewRequest("GET", name+"/auth/callback?code=x&state=y", nil)
	req.AddCookie(flow)
	r2, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", r2.StatusCode)
	}
}

func TestForeignHostRefused(t *testing.T) {
	e, ip, _ := twoNames(t)
	for _, path := range []string{"/auth/login", "/auth/callback?code=x&state=y"} {
		req, _ := http.NewRequest("GET", ip+path, nil)
		req.Host = "evil.example"
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b := body(resp)
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" || strings.Contains(b, "evil.example") {
			t.Fatalf("%s: %d %q", path, resp.StatusCode, b)
		}
		if len(resp.Cookies()) != 0 {
			t.Fatalf("%s set cookies", path)
		}
	}
	// The host is compared without regard to case.
	req, _ := http.NewRequest("GET", ip+"/auth/login", nil)
	req.Host = strings.ToUpper(strings.TrimPrefix(ip, "http://"))
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("upper-case host: %d", resp.StatusCode)
	}
	_ = e
}
