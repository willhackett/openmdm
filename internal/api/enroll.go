package api

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"openmdm/internal/core"
)

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *API) createEnrollment(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
	}
	if !decode(w, r, &body, true) {
		return
	}
	me := caller(r)
	name := lower(body.Username)
	if name == "" {
		name = lower(me.Username)
	}
	if !isAdmin(me) && !isSelf(me, name) {
		writeError(w, http.StatusForbidden, "you may only make an enrolment for yourself")
		return
	}
	if !validUsername(name) {
		badRequest(w, "invalid username")
		return
	}
	ctx := r.Context()
	if err := a.ensureUser(ctx, name); err != nil {
		a.fail(w, r, err)
		return
	}
	token, err := randomToken()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	challenge, err := randomToken()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	ttl := a.d.Config.EnrollmentTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	now := a.now().UTC()
	e := core.Enrollment{
		Token: token, Challenge: challenge, Username: name, CreatedBy: me.Username,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	if err := a.d.Store.CreateEnrollment(ctx, e); err != nil {
		a.fail(w, r, err)
		return
	}
	// The token is the link's secret: it is in the response, not in the log.
	a.audit(ctx, me.Username, "enrollment.created", name, "expires "+e.ExpiresAt.Format(time.RFC3339))
	writeJSON(w, http.StatusOK, map[string]any{
		"enrollment": e,
		"url":        strings.TrimRight(a.d.Config.PublicURL, "/") + "/enroll/" + token,
	})
}

func (a *API) listEnrollments(w http.ResponseWriter, r *http.Request) {
	all, err := a.d.Store.ListEnrollments(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	me := caller(r)
	out := make([]core.Enrollment, 0, len(all))
	for _, e := range all {
		if isAdmin(me) || isSelf(me, e.Username) {
			out = append(out, e)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrollments": out})
}

func plain(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg + "\n"))
}

// enroll hands over the enrolment profile, once. The profile is built before
// the link is claimed, so that a failure to build it (no push certificate
// yet, say) leaves the link usable.
func (a *API) enroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	me, ok := core.UserFrom(ctx)
	if !ok {
		plain(w, http.StatusUnauthorized, "Sign in to open this link.")
		return
	}
	token := param(r, "token")
	e, err := a.d.Store.GetEnrollment(ctx, token)
	if err != nil {
		if isNotFound(err) {
			plain(w, http.StatusNotFound, "This enrolment link is not known or has expired.")
			return
		}
		a.log.Error("cannot read enrolment", "error", err)
		plain(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	if !a.now().Before(e.ExpiresAt) {
		plain(w, http.StatusNotFound, "This enrolment link is not known or has expired.")
		return
	}
	// Unknown and expired are answered above, so that a signed-in stranger
	// learns nothing more than "no such link".
	if !isAdmin(me) && !isSelf(me, e.Username) {
		plain(w, http.StatusForbidden, "This enrolment link is for someone else. Ask for your own.")
		return
	}
	if e.DownloadedAt != nil {
		plain(w, http.StatusGone, "This enrolment link has already been used. Ask for a new one.")
		return
	}
	content, err := a.d.Enroller.EnrollmentProfile(ctx, e)
	if err != nil {
		if errors.Is(err, core.ErrInvalid) {
			plain(w, http.StatusServiceUnavailable, "The server cannot enrol devices yet: "+invalidMessage(err)+". The link still works; try again once it is set up.")
			return
		}
		a.log.Error("cannot build enrolment profile", "error", sanitize(err.Error(), a.d.Config))
		plain(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	if err := a.d.Store.MarkEnrollmentDownloaded(ctx, token, a.now().UTC()); err != nil {
		if errors.Is(err, core.ErrInvalid) {
			plain(w, http.StatusGone, "This enrolment link has already been used. Ask for a new one.")
			return
		}
		a.log.Error("cannot mark enrolment downloaded", "error", err)
		plain(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	a.audit(ctx, me.Username, "enrollment.downloaded", e.Username, "")
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="enroll.mobileconfig"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(content)
}
