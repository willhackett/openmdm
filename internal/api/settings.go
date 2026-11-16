package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"strconv"
	"time"

	"openmdm/internal/core"
)

func (a *API) secretsHealth(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return a.d.Secrets.Health(ctx)
}

func (a *API) getSettings(w http.ResponseWriter, r *http.Request) {
	push, err := a.d.MDM.PushInfo(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var ca any // null if the authority has no certificate
	if c := a.d.Authority.CACertificate(); c != nil {
		sum := sha256.Sum256(c.Raw)
		ca = map[string]any{
			"subject":   c.Subject.String(),
			"not_after": c.NotAfter.UTC(),
			"sha256":    hex.EncodeToString(sum[:]),
		}
	}
	health := map[string]any{"backend": a.d.Config.Secrets.Backend, "healthy": true, "error": ""}
	if err := a.secretsHealth(r.Context()); err != nil {
		health["healthy"] = false
		health["error"] = sanitize(err.Error(), a.d.Config)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"push": push, "ca": ca, "secrets": health,
		"public_url": a.d.Config.PublicURL, "organization": a.d.Config.Organization,
	})
}

func (a *API) putPushCertificate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CertificatePEM string `json:"certificate_pem"`
		KeyPEM         string `json:"key_pem"`
	}
	if !decode(w, r, &body, false) {
		return
	}
	if body.CertificatePEM == "" || body.KeyPEM == "" {
		badRequest(w, "certificate_pem and key_pem are both required")
		return
	}
	ctx := r.Context()
	if err := a.d.MDM.SetPushCert(ctx, []byte(body.CertificatePEM), []byte(body.KeyPEM)); err != nil {
		a.fail(w, r, err)
		return
	}
	push, err := a.d.MDM.PushInfo(ctx)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(ctx, caller(r).Username, "settings.push_certificate", push.Topic, "")
	writeJSON(w, http.StatusOK, map[string]any{"push": push})
}

func (a *API) getCAPEM(w http.ResponseWriter, r *http.Request) {
	c := a.d.Authority.CACertificate()
	if c == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func (a *API) listEvents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			badRequest(w, "limit must be a positive number")
			return
		}
		limit = min(n, 1000)
	}
	events, err := a.d.Store.ListEvents(r.Context(), limit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if events == nil {
		events = []core.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (a *API) healthz(w http.ResponseWriter, r *http.Request) {
	if err := a.secretsHealth(r.Context()); err != nil {
		a.log.Warn("health check: secret store", "error", sanitize(err.Error(), a.d.Config))
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status":   "degraded",
			"problems": []string{"secret store: " + sanitize(err.Error(), a.d.Config)},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
