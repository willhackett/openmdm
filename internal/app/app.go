// Package app is the composition root: the one place that knows the concrete
// type of every part. It builds them, hands each the interfaces it needs,
// and returns the HTTP handler. cmd/openmdm calls it; so do the end-to-end
// tests.
package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/micromdm/nanomdm/push"

	"openmdm/internal/api"
	"openmdm/internal/auth"
	"openmdm/internal/core"
	"openmdm/internal/engine"
	"openmdm/internal/mdm"
	"openmdm/internal/pki"
	"openmdm/internal/profiles"
	"openmdm/internal/secrets"
	"openmdm/internal/store"
	"openmdm/web"
)

// Options are for tests; the zero value is what the real server uses.
type Options struct {
	// Version is reported by the API.
	Version string
	// SessionMiddleware replaces single sign-on: it must put a core.User in
	// the request context. Nil means OIDC as configured.
	SessionMiddleware func(http.Handler) http.Handler
	// PushProviders replaces the APNs client.
	PushProviders push.PushProviderFactory
	// SigningURL and SigningClient replace the push certificate signing
	// service (mdmcert.download).
	SigningURL    string
	SigningClient *http.Client
}

// App is the built server.
type App struct {
	Handler    http.Handler
	Store      core.Store
	Secrets    core.SecretStore
	Authority  core.Authority
	MDM        core.MDM
	Reconciler core.Reconciler
	closers    []func() error
}

// Close releases what Build opened. Cancel the context given to Build first.
func (a *App) Close() error {
	var first error
	for _, c := range a.closers {
		if err := c(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// lateEvents lets the MDM layer be built before the engine that receives
// its events (the engine needs the MDM layer to send commands).
type lateEvents struct{ core.Events }

// Build makes every part and starts the background work (the engine, the
// profiles directory watcher), which stops when ctx is done.
func Build(ctx context.Context, cfg core.Config, logger *slog.Logger, opts Options) (*App, error) {
	if opts.Version == "" {
		opts.Version = "dev"
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	sealer, err := core.NewSealer(cfg.MasterKey)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "openmdm.db"))
	if err != nil {
		return nil, fmt.Errorf("opening the database: %w", err)
	}
	a := &App{Store: st, closers: []func() error{st.Close}}
	fail := func(err error) (*App, error) { _ = a.Close(); return nil, err }

	secretStore, err := secrets.New(cfg.Secrets, logger.With("part", "secrets"))
	if err != nil {
		return fail(fmt.Errorf("secret store: %w", err))
	}
	authority, err := pki.New(ctx, st, sealer, cfg.Organization, logger.With("part", "pki"))
	if err != nil {
		return fail(fmt.Errorf("certificate authority: %w", err))
	}
	renderer := profiles.NewRenderer(secretStore, authority, cfg.Organization)

	events := &lateEvents{}
	mdmService, err := mdm.New(ctx, mdm.Options{
		DataDir:       cfg.DataDir,
		Authority:     authority,
		Events:        events,
		Logger:        logger.With("part", "mdm"),
		PushProviders: opts.PushProviders,
	})
	if err != nil {
		return fail(fmt.Errorf("mdm: %w", err))
	}
	eng := engine.New(st, renderer, mdmService, logger.With("part", "engine"), engine.Options{Interval: cfg.ReconcileInterval})
	events.Events = eng

	enroller := profiles.NewEnroller(authority, renderer, profiles.EnrollerOptions{
		PublicURL:    cfg.PublicURL,
		Organization: cfg.Organization,
		Topic: func(ctx context.Context) (string, error) {
			info, err := mdmService.PushInfo(ctx)
			return info.Topic, err
		},
	})
	apiService := api.New(api.Deps{
		Store: st, Secrets: secretStore, Renderer: renderer, Reconciler: eng, MDM: mdmService,
		Enroller: enroller, Authority: authority, Sealer: sealer, Config: cfg, Version: opts.Version,
		Logger:     logger.With("part", "api"),
		SigningURL: opts.SigningURL, SigningClient: opts.SigningClient,
	})

	mux := http.NewServeMux()
	// What devices use; no session.
	mux.Handle("/mdm", mdmService.Handler())
	mux.Handle("/scep", authority.SCEPHandler())
	mux.Handle("/healthz", apiService.HealthHandler())
	// What people use.
	session := opts.SessionMiddleware
	if session == nil {
		authn, err := auth.New(cfg.OIDC, externalURLs(cfg), st, logger.With("part", "auth"))
		if err != nil {
			return fail(fmt.Errorf("sign-in: %w", err))
		}
		mux.Handle("/auth/", authn.Routes())
		session = authn.Middleware
	}
	// The enrolment link is a page people open: it needs a session too, so
	// that even an invited person signs in first.
	mux.Handle("/enroll/", session(apiService.EnrollHandler()))
	mux.Handle("/api/", session(apiService.Handler()))
	ui, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		return fail(err)
	}
	mux.Handle("/", session(spa(ui)))

	go func() {
		if err := eng.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("engine stopped", "error", err)
		}
	}()
	if cfg.ProfilesDir != "" {
		loader := profiles.NewLoader(cfg.ProfilesDir, st, renderer, eng.TriggerAll, logger.With("part", "profiles"))
		go func() {
			if err := loader.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("profiles directory watcher stopped", "error", err)
			}
		}()
	}
	eng.TriggerAll()

	a.Handler = securityHeaders(mux)
	a.Secrets, a.Authority, a.MDM, a.Reconciler = secretStore, authority, mdmService, eng
	return a, nil
}

// externalURLs are the names the server is known by: admin_url and
// public_url, without repeats.
func externalURLs(cfg core.Config) []string {
	var out []string
	seen := map[string]bool{}
	for _, u := range []string{cfg.AdminURL, cfg.PublicURL} {
		key := strings.ToLower(strings.TrimRight(u, "/"))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, u)
	}
	return out
}

// spa serves the built UI, answering index.html for any path that is not a
// file so that the UI's own routes survive a reload.
func spa(ui fs.FS) http.Handler {
	files := http.FileServerFS(ui)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name != "" {
			if info, err := fs.Stat(ui, name); err == nil && !info.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFileFS(w, r, ui, "index.html")
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
