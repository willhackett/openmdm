package api

import (
	"encoding/base64"
	"net/http"
	"sort"
	"strings"

	"openmdm/internal/core"
)

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	push, err := a.d.MDM.PushInfo(r.Context())
	if err != nil {
		// The page must still load without a push certificate.
		a.log.Error("cannot read push certificate info", "error", sanitize(err.Error(), a.d.Config))
		push = core.PushInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       caller(r),
		"push":       push,
		"public_url": a.d.Config.PublicURL,
		"version":    a.d.Version,
	})
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.d.Store.ListUsers(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if users == nil {
		users = []core.User{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

// pathUser reads {username} and checks the caller may act on that person:
// themselves, or anyone for an admin.
func (a *API) pathUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := lower(param(r, "username"))
	if !isAdmin(caller(r)) && !isSelf(caller(r), name) {
		writeError(w, http.StatusForbidden, "you may only do this for yourself")
		return "", false
	}
	if !validUsername(name) {
		badRequest(w, "invalid username")
		return "", false
	}
	return name, true
}

func (a *API) getUser(w http.ResponseWriter, r *http.Request) {
	name, ok := a.pathUser(w, r)
	if !ok {
		return
	}
	u, err := a.d.Store.GetUser(r.Context(), name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	devs, err := a.d.Store.ListDevicesByUser(r.Context(), name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if devs == nil {
		devs = []core.Device{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "devices": devs})
}

// --- secrets ---

type secretEntry struct {
	Key    string   `json:"key"`
	Set    bool     `json:"set"`
	UsedBy []string `json:"used_by"`
}

// secretList joins the keys that are set with the keys profiles name. names
// gives, for each profile, the keys it names.
func secretList(set map[string]string, named map[string][]string) []secretEntry {
	byKey := map[string]*secretEntry{}
	get := func(k string) *secretEntry {
		e := byKey[k]
		if e == nil {
			e = &secretEntry{Key: k, UsedBy: []string{}}
			byKey[k] = e
		}
		return e
	}
	for k := range set {
		get(k).Set = true
	}
	for profileID, keys := range named {
		for _, k := range keys {
			e := get(k)
			e.UsedBy = append(e.UsedBy, profileID)
		}
	}
	out := make([]secretEntry, 0, len(byKey))
	for _, e := range byKey {
		sort.Strings(e.UsedBy)
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (a *API) listUserSecrets(w http.ResponseWriter, r *http.Request) {
	name, ok := a.pathUser(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	set, err := a.d.Secrets.UserSecrets(ctx, name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// A person who has not signed in has no row: groups are unknown, so only
	// profiles assigned by name or to everyone count.
	u, err := a.d.Store.GetUser(ctx, name)
	if err != nil {
		if !isNotFound(err) {
			a.fail(w, r, err)
			return
		}
		u = core.User{Username: name}
	}
	profiles, err := a.d.Store.ListProfiles(ctx)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	named := map[string][]string{}
	for _, p := range profiles {
		if !p.Assignment.Wants(&u) {
			continue
		}
		info, err := a.d.Renderer.Validate(p)
		if err != nil {
			continue // a broken template names nothing we can trust
		}
		if len(info.UserSecrets) > 0 {
			named[p.ID] = info.UserSecrets
		}
	}
	// The values are in `set`; only its keys go on.
	writeJSON(w, http.StatusOK, map[string]any{"secrets": secretList(set, named)})
}

func (a *API) listGlobalSecrets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	set, err := a.d.Secrets.GlobalSecrets(ctx)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	profiles, err := a.d.Store.ListProfiles(ctx)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	named := map[string][]string{}
	for _, p := range profiles {
		info, err := a.d.Renderer.Validate(p)
		if err != nil {
			continue
		}
		if len(info.GlobalSecrets) > 0 {
			named[p.ID] = info.GlobalSecrets
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"secrets": secretList(set, named)})
}

type secretBody struct {
	Value    string `json:"value"`
	Encoding string `json:"encoding"`
}

// readSecretBody reads and checks the body of a PUT of a secret. The value is
// never echoed back in an error.
func readSecretBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	var b secretBody
	if !decode(w, r, &b, false) {
		return "", false
	}
	if b.Value == "" {
		badRequest(w, "value must not be empty")
		return "", false
	}
	switch b.Encoding {
	case "":
	case "base64":
		if !isBase64(b.Value) {
			badRequest(w, "value is not valid base64")
			return "", false
		}
	default:
		badRequest(w, `encoding must be "base64" or omitted`)
		return "", false
	}
	return b.Value, true
}

func isBase64(s string) bool {
	s = strings.NewReplacer("\r", "", "\n", "", " ", "").Replace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if _, err := enc.DecodeString(s); err == nil {
			return true
		}
	}
	return false
}

func (a *API) putUserSecret(w http.ResponseWriter, r *http.Request) {
	name, ok := a.pathUser(w, r)
	if !ok {
		return
	}
	key := param(r, "key")
	if !validKey(key) {
		badRequest(w, "a secret's name may only use a-z, 0-9 and _")
		return
	}
	value, ok := readSecretBody(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := a.ensureUser(ctx, name); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.d.Secrets.SetUserSecret(ctx, name, key, value); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(ctx, caller(r).Username, "secret.set", name+"/"+key, "")
	a.triggerUser(r, name)
	noContent(w)
}

func (a *API) deleteUserSecret(w http.ResponseWriter, r *http.Request) {
	name, ok := a.pathUser(w, r)
	if !ok {
		return
	}
	key := param(r, "key")
	if !validKey(key) {
		badRequest(w, "a secret's name may only use a-z, 0-9 and _")
		return
	}
	ctx := r.Context()
	if err := a.d.Secrets.DeleteUserSecret(ctx, name, key); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(ctx, caller(r).Username, "secret.deleted", name+"/"+key, "")
	a.triggerUser(r, name)
	noContent(w)
}

func (a *API) putGlobalSecret(w http.ResponseWriter, r *http.Request) {
	key := param(r, "key")
	if !validKey(key) {
		badRequest(w, "a secret's name may only use a-z, 0-9 and _")
		return
	}
	value, ok := readSecretBody(w, r)
	if !ok {
		return
	}
	if err := a.d.Secrets.SetGlobalSecret(r.Context(), key, value); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r.Context(), caller(r).Username, "secret.set", "global/"+key, "")
	a.d.Reconciler.TriggerAll()
	noContent(w)
}

func (a *API) deleteGlobalSecret(w http.ResponseWriter, r *http.Request) {
	key := param(r, "key")
	if !validKey(key) {
		badRequest(w, "a secret's name may only use a-z, 0-9 and _")
		return
	}
	if err := a.d.Secrets.DeleteGlobalSecret(r.Context(), key); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r.Context(), caller(r).Username, "secret.deleted", "global/"+key, "")
	a.d.Reconciler.TriggerAll()
	noContent(w)
}

// triggerUser reconciles the devices of one person.
func (a *API) triggerUser(r *http.Request, username string) {
	devs, err := a.d.Store.ListDevicesByUser(r.Context(), username)
	if err != nil {
		a.log.Error("cannot list devices to reconcile", "username", username, "error", err)
		a.d.Reconciler.TriggerAll()
		return
	}
	for _, d := range devs {
		a.d.Reconciler.Trigger(d.ID)
	}
}
