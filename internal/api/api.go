// Package api is the HTTP API the UI talks to (docs/API.md), the enrolment
// link and the health check. It knows the rest of OpenMDM only through the
// interfaces in internal/core.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"

	"openmdm/internal/core"
)

const (
	maxBody    = 2 << 20 // request bodies are limited to 2 MiB
	csrfHeader = "X-Requested-With"
	csrfValue  = "openmdm"
)

// Deps is everything the API needs, all as core interfaces.
type Deps struct {
	Store      core.Store
	Secrets    core.SecretStore
	Renderer   core.Renderer
	Reconciler core.Reconciler
	MDM        core.MDM
	Enroller   core.Enroller
	Authority  core.Authority
	// Sealer seals the private keys of a pending push certificate request.
	Sealer  core.Sealer
	Config  core.Config
	Version string
	Logger  *slog.Logger
	// Now is the clock; time.Now if nil.
	Now func() time.Time
	// SigningURL and SigningClient reach the push certificate signing
	// service (mdmcert.download); the defaults are the real service. Tests
	// point them at a fake.
	SigningURL    string
	SigningClient *http.Client
}

// API serves the handlers.
type API struct {
	d Deps
	// pushMu serialises everything that touches a pending push request.
	pushMu sync.Mutex
	log    *slog.Logger
	now    func() time.Time
}

// New builds an API. Missing Logger and Now get defaults.
func New(d Deps) *API {
	a := &API{d: d, log: d.Logger, now: d.Now}
	if a.log == nil {
		a.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if a.now == nil {
		a.now = time.Now
	}
	return a
}

// Handler serves everything under /api/v1. It is mounted at the server root,
// so it matches full paths. An outer middleware must have put the signed-in
// person in the request context (core.WithUser).
func (a *API) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(a.recoverer, a.baseHeaders)
	r.NotFound(func(w http.ResponseWriter, r *http.Request) { writeError(w, http.StatusNotFound, "not found") })
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	})
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(a.requireUser, a.csrf)
		admin := a.requireAdmin

		r.Get("/me", a.me)

		r.With(admin).Get("/users", a.listUsers)
		r.Get("/users/{username}", a.getUser)
		r.Get("/users/{username}/secrets", a.listUserSecrets)
		r.Put("/users/{username}/secrets/{key}", a.putUserSecret)
		r.Delete("/users/{username}/secrets/{key}", a.deleteUserSecret)
		r.With(admin).Get("/secrets/global", a.listGlobalSecrets)
		r.With(admin).Put("/secrets/global/{key}", a.putGlobalSecret)
		r.With(admin).Delete("/secrets/global/{key}", a.deleteGlobalSecret)

		r.Get("/devices", a.listDevices)
		r.Get("/devices/{id}", a.getDevice)
		r.With(admin).Put("/devices/{id}/owner", a.setOwner)
		r.Post("/devices/{id}/sync", a.syncDevice)
		r.Post("/devices/{id}/lock", a.lockDevice)
		r.With(admin).Post("/devices/{id}/erase", a.eraseDevice)
		r.With(admin).Delete("/devices/{id}", a.deleteDevice)

		r.With(admin).Get("/profiles", a.listProfiles)
		r.With(admin).Post("/profiles/validate", a.validateProfile)
		r.With(admin).Get("/profiles/{id}", a.getProfile)
		r.With(admin).Put("/profiles/{id}", a.putProfile)
		r.With(admin).Delete("/profiles/{id}", a.deleteProfile)

		r.Post("/enrollments", a.createEnrollment)
		r.Get("/enrollments", a.listEnrollments)

		r.With(admin).Get("/settings", a.getSettings)
		r.With(admin).Put("/settings/push-certificate", a.putPushCertificate)
		r.With(admin).Post("/settings/push-certificate/csr", a.postPushCSR)
		r.With(admin).Get("/settings/push-certificate/csr", a.getPushCSR)
		r.With(admin).Post("/settings/push-certificate/request", a.postPushRequest)
		r.With(admin).Get("/settings/push-certificate/request", a.getPushRequest)
		r.With(admin).Delete("/settings/push-certificate/request", a.deletePushRequest)
		r.With(admin).Post("/settings/push-certificate/request/decrypt", a.decryptPushRequest)
		r.With(admin).Get("/settings/ca.pem", a.getCAPEM)

		r.With(admin).Get("/events", a.listEvents)
	})
	return r
}

// EnrollHandler serves GET /enroll/{token}. The caller mounts it behind the
// session middleware: the handler needs the signed-in person.
func (a *API) EnrollHandler() http.Handler {
	r := chi.NewRouter()
	r.Use(a.recoverer)
	r.Get("/enroll/{token}", a.enroll)
	return r
}

// HealthHandler serves GET /healthz.
func (a *API) HealthHandler() http.Handler {
	r := chi.NewRouter()
	r.Use(a.recoverer)
	r.Get("/healthz", a.healthz)
	return r
}

// --- middleware ---

func (a *API) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				a.log.Error("panic in handler", "path", r.URL.Path, "panic", v)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (a *API) baseHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (a *API) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := core.UserFrom(r.Context()); !ok {
			writeError(w, http.StatusUnauthorized, "not signed in")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrf: a request that changes anything must carry a header that a browser
// will not add to a cross-site form post.
func (a *API) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if r.Header.Get(csrfHeader) != csrfValue {
				writeError(w, http.StatusForbidden, "missing "+csrfHeader+": "+csrfValue+" header")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(caller(r)) {
			writeError(w, http.StatusForbidden, "administrators only")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- helpers ---

func caller(r *http.Request) core.User {
	u, _ := core.UserFrom(r.Context())
	return u
}

func isAdmin(u core.User) bool { return u.Role == core.RoleAdmin }

func param(r *http.Request, name string) string {
	v := chi.URLParam(r, name)
	if u, err := url.PathUnescape(v); err == nil {
		return u
	}
	return v
}

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// isSelf: the caller is the person the path names.
func isSelf(u core.User, username string) bool { return lower(u.Username) == lower(username) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func noContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// fail maps an error to a response: the core errors to their status, anything
// else to a generic 500 with the cause logged.
func (a *API) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, core.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, core.ErrInvalid):
		writeError(w, http.StatusBadRequest, invalidMessage(err))
	case errors.Is(err, core.ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden")
	default:
		a.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", sanitize(err.Error(), a.d.Config))
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// invalidMessage shows the message wrapped around core.ErrInvalid, without
// the sentinel's own word.
func invalidMessage(err error) string {
	m := err.Error()
	m = strings.TrimPrefix(m, core.ErrInvalid.Error()+": ")
	m = strings.TrimSuffix(m, ": "+core.ErrInvalid.Error())
	if m == "" || m == core.ErrInvalid.Error() {
		return "invalid request"
	}
	return m
}

func badRequest(w http.ResponseWriter, msg string) { writeError(w, http.StatusBadRequest, msg) }

// decode reads a JSON body of at most 2 MiB, rejecting unknown fields and
// trailing data. With optional, an empty body leaves v alone. It writes the
// error response itself and reports whether to go on.
func decode(w http.ResponseWriter, r *http.Request, v any, optional bool) bool {
	body := http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		if _, err2 := dec.Token(); err2 != io.EOF {
			badRequest(w, "unexpected data after the JSON body")
			return false
		}
		return true
	}
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		writeError(w, http.StatusRequestEntityTooLarge, "request body is larger than 2 MiB")
	case errors.Is(err, io.EOF) && optional:
		return true
	case errors.Is(err, io.EOF):
		badRequest(w, "a JSON body is required")
	default:
		badRequest(w, "invalid JSON body: "+err.Error())
	}
	return false
}

// validUsername keeps junk and path tricks out of the secret store's paths.
func validUsername(s string) bool {
	if s == "" || len(s) > 128 || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		if !(unicode.IsLetter(c) || unicode.IsDigit(c) || strings.ContainsRune("._@+-", c)) {
			return false
		}
	}
	return true
}

var keyRE = regexp.MustCompile(`^[a-z0-9_]+$`)

func validKey(s string) bool { return len(s) <= 128 && keyRE.MatchString(s) }

// ensureUser creates a bare user row for a person who has not signed in yet,
// so that admins can prepare things for them. An existing row is left alone.
func (a *API) ensureUser(ctx context.Context, username string) error {
	if _, err := a.d.Store.GetUser(ctx, username); err == nil {
		return nil
	} else if !errors.Is(err, core.ErrNotFound) {
		return err
	}
	_, err := a.d.Store.UpsertUser(ctx, core.User{Username: username, Role: core.RoleUser})
	return err
}

// audit appends an event. Failing to is logged, not fatal: the change is made.
func (a *API) audit(ctx context.Context, actor, kind, subject, detail string) {
	err := a.d.Store.AppendEvent(ctx, core.Event{At: a.now().UTC(), Actor: actor, Kind: kind, Subject: subject, Detail: detail})
	if err != nil {
		a.log.Error("cannot write audit event", "kind", kind, "subject", subject, "error", err)
	}
}

var (
	userinfoRE = regexp.MustCompile(`://[^/\s@]*@`)
	kvSecretRE = regexp.MustCompile(`(?i)\b(token|secret|secret_id|password|passwd|authorization|api[_-]?key|x-vault-token)(["']?\s*[=:]\s*)["']?[^\s"',;]+`)
	bearerRE   = regexp.MustCompile(`(?i)\bbearer\s+\S+`)
	vaultTokRE = regexp.MustCompile(`\b(hv[sbr]\.|s\.)[A-Za-z0-9_-]{16,}`)
)

// sanitize makes an error text safe to show or log: no credentials in URLs,
// no values after words like "token", and not the configured credentials
// themselves.
func sanitize(s string, cfg core.Config) string {
	for _, c := range []string{cfg.Secrets.Token, cfg.Secrets.SecretID, cfg.Secrets.RoleID, cfg.MasterKey, cfg.OIDC.ClientSecret} {
		if len(c) >= 6 {
			s = strings.ReplaceAll(s, c, "[redacted]")
		}
	}
	s = userinfoRE.ReplaceAllString(s, "://")
	s = vaultTokRE.ReplaceAllString(s, "[redacted]")
	s = bearerRE.ReplaceAllString(s, "bearer [redacted]")
	s = kvSecretRE.ReplaceAllString(s, "$1=[redacted]")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func isNotFound(err error) bool { return errors.Is(err, core.ErrNotFound) }
