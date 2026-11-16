// Command openmdm is the whole server: it reads the configuration, builds
// each part, hands every part the interfaces it needs, and serves HTTP.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"openmdm/internal/app"
	"openmdm/internal/core"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	configPath := flag.String("config", "openmdm.yaml", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(*configPath, logger); err != nil {
		logger.Error("openmdm stopped", "error", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (core.Config, error) {
	var cfg core.Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading the configuration: %w", err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	// Secrets may come from the environment so the file can be committed.
	for env, dst := range map[string]*string{
		"OPENMDM_MASTER_KEY":         &cfg.MasterKey,
		"OPENMDM_OIDC_CLIENT_SECRET": &cfg.OIDC.ClientSecret,
		"OPENMDM_OPENBAO_TOKEN":      &cfg.Secrets.Token,
		"OPENMDM_OPENBAO_SECRET_ID":  &cfg.Secrets.SecretID,
	} {
		if v := os.Getenv(env); v != "" {
			*dst = v
		}
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}
	if cfg.Organization == "" {
		cfg.Organization = "OpenMDM"
	}
	if cfg.ReconcileInterval == 0 {
		cfg.ReconcileInterval = 15 * time.Minute
	}
	if cfg.EnrollmentTTL == 0 {
		cfg.EnrollmentTTL = time.Hour
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	cfg.AdminURL = strings.TrimRight(cfg.AdminURL, "/")
	if cfg.AdminURL == "" {
		cfg.AdminURL = cfg.PublicURL
	}
	var problems []string
	if !strings.HasPrefix(cfg.PublicURL, "https://") && !strings.HasPrefix(cfg.PublicURL, "http://") {
		problems = append(problems, "public_url must be set (devices only accept https)")
	}
	if cfg.MasterKey == "" {
		problems = append(problems, "master_key (or OPENMDM_MASTER_KEY) must be set: 32 random bytes, base64 (openssl rand -base64 32)")
	}
	if cfg.OIDC.Issuer == "" || cfg.OIDC.ClientID == "" {
		problems = append(problems, "oidc.issuer and oidc.client_id must be set: there are no local accounts")
	}
	if cfg.Secrets.Backend == "" {
		problems = append(problems, `secrets.backend must be "openbao", "file" or "memory"`)
	}
	if len(problems) > 0 {
		return cfg, errors.New("configuration: " + strings.Join(problems, "; "))
	}
	return cfg, nil
}

func run(configPath string, logger *slog.Logger) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	built, err := app.Build(ctx, cfg, logger, app.Options{Version: version})
	if err != nil {
		return err
	}
	defer built.Close()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           built.Handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	logger.Info("openmdm listening", "address", cfg.Listen, "public_url", cfg.PublicURL, "version", version)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
