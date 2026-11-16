package api

import (
	"net/http"
	"regexp"
	"time"

	"openmdm/internal/core"
)

var profileIDRE = regexp.MustCompile(`^[a-z0-9-]+$`)

// profileSummary is a Profile without its template, for the list.
type profileSummary struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Platforms    []core.Platform   `json:"platforms"`
	MacOSChannel core.Channel      `json:"macos_channel"`
	Assignment   core.Assignment   `json:"assignment"`
	Source       string            `json:"source"`
	UpdatedAt    time.Time         `json:"updated_at"`
	Info         core.TemplateInfo `json:"info"`
	Error        string            `json:"error,omitempty"`
	Counts       map[string]int    `json:"counts"`
}

// normInfo makes the lists of a TemplateInfo [] and not null.
func normInfo(i core.TemplateInfo) core.TemplateInfo {
	if i.UserSecrets == nil {
		i.UserSecrets = []string{}
	}
	if i.GlobalSecrets == nil {
		i.GlobalSecrets = []string{}
	}
	if i.PayloadTypes == nil {
		i.PayloadTypes = []string{}
	}
	return i
}

func normProfile(p core.Profile) core.Profile {
	if p.Platforms == nil {
		p.Platforms = []core.Platform{}
	}
	if p.Assignment.Users == nil {
		p.Assignment.Users = []string{}
	}
	if p.Assignment.Groups == nil {
		p.Assignment.Groups = []string{}
	}
	return p
}

func (a *API) listProfiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	profiles, err := a.d.Store.ListProfiles(ctx)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]profileSummary, 0, len(profiles))
	for _, p := range profiles {
		p = normProfile(p)
		s := profileSummary{
			ID: p.ID, Name: p.Name, Description: p.Description, Platforms: p.Platforms,
			MacOSChannel: p.MacOSChannel, Assignment: p.Assignment, Source: p.Source, UpdatedAt: p.UpdatedAt,
		}
		info, verr := a.d.Renderer.Validate(p)
		s.Info = normInfo(info)
		if verr != nil {
			s.Error = invalidMessage(verr)
		}
		// Always the same keys, so the UI need not guess.
		s.Counts = map[string]int{}
		for _, st := range []core.ProfileState{core.StateInstalled, core.StatePending, core.StateBlocked, core.StateFailed, core.StateSent, core.StateRemoving} {
			s.Counts[string(st)] = 0
		}
		dps, err := a.d.Store.ListDeviceProfilesByProfile(ctx, p.ID)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		for _, dp := range dps {
			s.Counts[string(dp.State)]++
		}
		out = append(out, s)
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": out})
}

func (a *API) getProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := a.d.Store.GetProfile(ctx, param(r, "id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	p = normProfile(p)
	info, verr := a.d.Renderer.Validate(p)
	dps, err := a.d.Store.ListDeviceProfilesByProfile(ctx, p.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	type entry struct {
		Device core.Device        `json:"device"`
		State  core.DeviceProfile `json:"state"`
	}
	devices := []entry{}
	for _, dp := range dps {
		d, err := a.d.Store.GetDevice(ctx, dp.DeviceID)
		if err != nil {
			if isNotFound(err) {
				continue // the device was forgotten; its rows are on their way out
			}
			a.fail(w, r, err)
			return
		}
		devices = append(devices, entry{Device: d, State: dp})
	}
	resp := map[string]any{"profile": p, "info": normInfo(info), "devices": devices}
	if verr != nil {
		resp["error"] = invalidMessage(verr)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) validateProfile(w http.ResponseWriter, r *http.Request) {
	var p core.Profile
	if !decode(w, r, &p, false) {
		return
	}
	info, err := a.d.Renderer.Validate(p)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"info": normInfo(info)})
}

func (a *API) putProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := param(r, "id")
	if !profileIDRE.MatchString(id) || len(id) > 100 {
		badRequest(w, "a profile's id may only use a-z, 0-9 and -")
		return
	}
	var p core.Profile
	if !decode(w, r, &p, false) {
		return
	}
	if existing, err := a.d.Store.GetProfile(ctx, id); err == nil {
		if existing.Source == "file" {
			writeError(w, http.StatusConflict, "this profile comes from a file in the profiles directory and cannot be changed here")
			return
		}
	} else if !isNotFound(err) {
		a.fail(w, r, err)
		return
	}
	p.ID = id
	p.Source = "ui"
	if p.Name == "" {
		p.Name = id
	}
	if len(p.Platforms) == 0 {
		badRequest(w, "platforms must list at least one of macos, ios, ipados")
		return
	}
	for _, pl := range p.Platforms {
		if pl != core.PlatformMacOS && pl != core.PlatformIOS && pl != core.PlatformIPadOS {
			badRequest(w, "unknown platform: "+string(pl))
			return
		}
	}
	switch p.MacOSChannel {
	case "":
		p.MacOSChannel = core.ChannelDevice
	case core.ChannelDevice, core.ChannelUser:
	default:
		badRequest(w, `macos_channel must be "device" or "user"`)
		return
	}
	info, err := a.d.Renderer.Validate(p)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.d.Store.PutProfile(ctx, p); err != nil {
		a.fail(w, r, err)
		return
	}
	if saved, err := a.d.Store.GetProfile(ctx, id); err == nil {
		p = saved
	}
	a.audit(ctx, caller(r).Username, "profile.saved", id, "")
	a.d.Reconciler.TriggerAll()
	writeJSON(w, http.StatusOK, map[string]any{"profile": normProfile(p), "info": normInfo(info)})
}

func (a *API) deleteProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := param(r, "id")
	existing, err := a.d.Store.GetProfile(ctx, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if existing.Source == "file" {
		writeError(w, http.StatusConflict, "this profile comes from a file in the profiles directory; remove the file instead")
		return
	}
	if err := a.d.Store.DeleteProfile(ctx, id); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(ctx, caller(r).Username, "profile.deleted", id, "")
	a.d.Reconciler.TriggerAll()
	noContent(w)
}
