package api

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"regexp"

	"openmdm/internal/core"
)

var pinRE = regexp.MustCompile(`^[0-9]{6}$`)

// ownsDevice: a user may reach only a device that names them as its owner.
func ownsDevice(u core.User, d core.Device) bool {
	return d.Username != "" && isSelf(u, d.Username)
}

// loadDevice finds the device in the path. A user asking for someone else's
// device, or one with no owner, is told it does not exist.
func (a *API) loadDevice(w http.ResponseWriter, r *http.Request) (core.Device, bool) {
	d, err := a.d.Store.GetDevice(r.Context(), param(r, "id"))
	if err != nil {
		a.fail(w, r, err)
		return core.Device{}, false
	}
	if u := caller(r); !isAdmin(u) && !ownsDevice(u, d) {
		writeError(w, http.StatusNotFound, "not found")
		return core.Device{}, false
	}
	return d, true
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request) {
	var devs []core.Device
	var err error
	if u := caller(r); isAdmin(u) {
		devs, err = a.d.Store.ListDevices(r.Context())
	} else {
		devs, err = a.d.Store.ListDevicesByUser(r.Context(), lower(u.Username))
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if devs == nil {
		devs = []core.Device{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devs})
}

func (a *API) getDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := a.loadDevice(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var owner *core.User
	if d.Username != "" {
		u, err := a.d.Store.GetUser(ctx, d.Username)
		switch {
		case err == nil:
			owner = &u
		case !isNotFound(err):
			a.fail(w, r, err)
			return
		}
	}
	plan, err := a.d.Reconciler.Plan(ctx, d.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if plan == nil {
		plan = []core.PlanEntry{}
	}
	cmds, err := a.d.Store.ListCommands(ctx, d.ID, 50)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if cmds == nil {
		cmds = []core.CommandRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": d, "owner": owner, "profiles": plan, "commands": cmds})
}

func (a *API) setOwner(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
	}
	if !decode(w, r, &body, false) {
		return
	}
	ctx := r.Context()
	d, err := a.d.Store.GetDevice(ctx, param(r, "id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	name := lower(body.Username)
	if name != "" {
		if _, err := a.d.Store.GetUser(ctx, name); err != nil {
			if isNotFound(err) {
				badRequest(w, "no such user")
				return
			}
			a.fail(w, r, err)
			return
		}
	}
	d.Username = name
	if err := a.d.Store.UpsertDevice(ctx, d); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(ctx, caller(r).Username, "device.owner", d.ID, "owner: "+name)
	a.d.Reconciler.Trigger(d.ID)
	noContent(w)
}

// targets are the MDM enrollment IDs to wake for a device.
func targets(d core.Device) []string {
	t := []string{d.ID}
	if d.UserChannelID != "" {
		t = append(t, d.UserChannelID)
	}
	return t
}

func (a *API) syncDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := a.loadDevice(w, r)
	if !ok {
		return
	}
	a.d.Reconciler.Trigger(d.ID)
	if err := a.d.MDM.Push(r.Context(), targets(d)...); err != nil {
		a.fail(w, r, err)
		return
	}
	noContent(w)
}

// record logs a command that was queued. The MDM engine may log it too;
// PutCommand replaces by UUID, so that is harmless.
func (a *API) record(r *http.Request, d core.Device, uuid, requestType string) {
	now := a.now().UTC()
	err := a.d.Store.PutCommand(r.Context(), core.CommandRecord{
		UUID: uuid, DeviceID: d.ID, Channel: core.ChannelDevice, RequestType: requestType,
		Status: core.CommandQueued, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		a.log.Error("cannot record command", "device", d.ID, "request_type", requestType, "error", err)
	}
}

// push wakes a device after a command was queued. The command stays queued
// and is fetched at the next check-in if this fails, so it is only logged.
func (a *API) push(r *http.Request, d core.Device) {
	if err := a.d.MDM.Push(r.Context(), targets(d)...); err != nil {
		a.log.Error("cannot wake device", "device", d.ID, "error", sanitize(err.Error(), a.d.Config))
	}
}

func notEnrolled(w http.ResponseWriter, d core.Device) bool {
	if d.Status == core.DeviceUnenrolled {
		writeError(w, http.StatusConflict, "the device is no longer enrolled")
		return true
	}
	return false
}

func (a *API) lockDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := a.loadDevice(w, r)
	if !ok {
		return
	}
	var body struct {
		PIN     string `json:"pin"`
		Message string `json:"message"`
	}
	if !decode(w, r, &body, true) {
		return
	}
	if len(body.Message) > 1000 {
		badRequest(w, "message is too long")
		return
	}
	cmd := map[string]any{}
	if d.Platform == core.PlatformMacOS {
		if !pinRE.MatchString(body.PIN) {
			badRequest(w, "a Mac needs a six-digit PIN to lock")
			return
		}
		cmd["PIN"] = body.PIN
	}
	if body.Message != "" {
		cmd["Message"] = body.Message
	}
	if notEnrolled(w, d) {
		return
	}
	uuid, err := a.d.MDM.Enqueue(r.Context(), d.ID, "DeviceLock", cmd)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.record(r, d, uuid, "DeviceLock")
	a.audit(r.Context(), caller(r).Username, "device.lock", d.ID, "command "+uuid)
	a.push(r, d)
	writeJSON(w, http.StatusOK, map[string]string{"command_uuid": uuid})
}

func (a *API) eraseDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Confirm string `json:"confirm"`
		PIN     string `json:"pin"`
	}
	if !decode(w, r, &body, false) {
		return
	}
	d, err := a.d.Store.GetDevice(r.Context(), param(r, "id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// A device that never reported a serial number is confirmed by its ID.
	want := d.SerialNumber
	if want == "" {
		want = d.ID
	}
	if body.Confirm == "" || body.Confirm != want {
		badRequest(w, "confirm must be the device's serial number")
		return
	}
	var cmd map[string]any
	resp := map[string]string{}
	if d.Platform == core.PlatformMacOS {
		pin := body.PIN
		if pin == "" {
			if pin, err = randomPIN(); err != nil {
				a.fail(w, r, err)
				return
			}
			// Whoever erases the Mac needs the PIN it will ask for at the
			// recovery screen; it is the only time it is shown.
			resp["pin"] = pin
		} else if !pinRE.MatchString(pin) {
			badRequest(w, "pin must be six digits")
			return
		}
		cmd = map[string]any{"PIN": pin}
	}
	if notEnrolled(w, d) {
		return
	}
	uuid, err := a.d.MDM.Enqueue(r.Context(), d.ID, "EraseDevice", cmd)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.record(r, d, uuid, "EraseDevice")
	a.audit(r.Context(), caller(r).Username, "device.erase", d.ID, "command "+uuid)
	a.push(r, d)
	resp["command_uuid"] = uuid
	writeJSON(w, http.StatusOK, resp)
}

func randomPIN() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func (a *API) deleteDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d, err := a.d.Store.GetDevice(ctx, param(r, "id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if d.Status == core.DeviceEnrolled {
		// Best effort: the device may be gone for good.
		uuid, err := a.d.MDM.RemoveProfile(ctx, d.ID, "openmdm.enrollment")
		if err != nil {
			a.log.Error("cannot queue removal of the MDM profile", "device", d.ID, "error", sanitize(err.Error(), a.d.Config))
		} else {
			a.record(r, d, uuid, "RemoveProfile")
			a.push(r, d)
		}
	}
	// Revoke the identity it enrolled with so that it cannot check in again.
	// Best effort, like the removal: a failure is logged and the device is
	// forgotten anyway.
	detail := "serial " + d.SerialNumber
	if d.CertSHA256 != "" {
		if err := a.d.Authority.Revoke(ctx, d.CertSHA256); err != nil {
			a.log.Error("cannot revoke the device certificate", "device", d.ID, "error", sanitize(err.Error(), a.d.Config))
			detail += "; certificate not revoked"
		} else {
			detail += "; certificate revoked"
		}
	}
	if err := a.d.Store.DeleteDevice(ctx, d.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(ctx, caller(r).Username, "device.deleted", d.ID, detail)
	noContent(w)
}
