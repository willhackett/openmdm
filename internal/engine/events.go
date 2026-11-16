package engine

import (
	"context"
	"errors"

	"openmdm/internal/core"
)

func (e *Engine) recoverEvent(what string) {
	if r := recover(); r != nil {
		e.log.Error("event handler panicked", "event", what, "panic", r)
	}
}

func platformOf(c core.Checkin) core.Platform {
	name := c.ProductName
	if name == "" {
		name = c.Model
	}
	return core.PlatformFromProductName(name)
}

// ownerOf finds who the device's certificate was issued to, and makes sure
// that person exists. ok is false if the certificate is not known.
func (e *Engine) ownerOf(ctx context.Context, c core.Checkin) (string, bool) {
	if c.CertSHA256 == "" {
		return "", false
	}
	ic, err := e.store.GetIssuedCertBySHA256(ctx, c.CertSHA256)
	if err != nil || ic.Username == "" {
		if err != nil && !errors.Is(err, core.ErrNotFound) {
			e.log.Error("looking up device certificate", "err", err)
		}
		return "", false
	}
	if _, err := e.store.GetUser(ctx, ic.Username); err != nil {
		if !errors.Is(err, core.ErrNotFound) {
			e.log.Error("looking up user", "user", ic.Username, "err", err)
			return ic.Username, true
		}
		if _, err := e.store.UpsertUser(ctx, core.User{Username: ic.Username, Role: core.RoleUser}); err != nil {
			e.log.Error("creating user", "user", ic.Username, "err", err)
		}
	}
	return ic.Username, true
}

func (e *Engine) clearProfiles(ctx context.Context, deviceID string) {
	rows, err := e.store.ListDeviceProfiles(ctx, deviceID)
	if err != nil {
		e.log.Error("listing device profiles", "device", deviceID, "err", err)
		return
	}
	for _, r := range rows {
		if err := e.store.DeleteDeviceProfile(ctx, deviceID, r.ProfileID); err != nil {
			e.log.Error("deleting device profile", "device", deviceID, "profile", r.ProfileID, "err", err)
		}
	}
}

// DeviceAuthenticated: a device that authenticates again has been wiped or
// re-enrolled, so nothing of ours is on it.
func (e *Engine) DeviceAuthenticated(ctx context.Context, c core.Checkin) {
	defer e.recoverEvent("authenticate")
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	d := core.Device{
		ID: c.DeviceID, SerialNumber: c.SerialNumber, Model: c.Model,
		DeviceName: c.DeviceName, OSVersion: c.OSVersion, Platform: platformOf(c),
		Status: core.DevicePending, EnrolledAt: now, LastSeenAt: now,
	}
	if old, err := e.store.GetDevice(ctx, c.DeviceID); err == nil {
		d.Username = old.Username
		d.CertSHA256 = old.CertSHA256
	}
	if c.CertSHA256 != "" {
		d.CertSHA256 = c.CertSHA256
	}
	if u, ok := e.ownerOf(ctx, c); ok {
		d.Username = u
	}
	if err := e.store.UpsertDevice(ctx, d); err != nil {
		e.log.Error("saving device", "device", c.DeviceID, "err", err)
		return
	}
	e.clearProfiles(ctx, c.DeviceID)
	e.audit(ctx, "device:"+c.DeviceID, "device.authenticated", c.DeviceID, d.DeviceName)
}

// DeviceTokenUpdated: the channel can be sent commands now.
func (e *Engine) DeviceTokenUpdated(ctx context.Context, c core.Checkin) {
	defer e.recoverEvent("token update")
	if e.tokenUpdated(ctx, c) {
		e.Trigger(c.DeviceID)
	}
}

func (e *Engine) tokenUpdated(ctx context.Context, c core.Checkin) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	d, err := e.store.GetDevice(ctx, c.DeviceID)
	if err != nil {
		if !errors.Is(err, core.ErrNotFound) {
			e.log.Error("loading device", "device", c.DeviceID, "err", err)
			return false
		}
		// The server lost its database; rebuild what we can.
		d = core.Device{
			ID: c.DeviceID, Platform: platformOf(c), Status: core.DevicePending, EnrolledAt: now,
		}
		if u, ok := e.ownerOf(ctx, c); ok {
			d.Username = u
		}
	}
	for _, f := range []struct {
		dst *string
		v   string
	}{
		{&d.SerialNumber, c.SerialNumber}, {&d.Model, c.Model},
		{&d.DeviceName, c.DeviceName}, {&d.OSVersion, c.OSVersion},
	} {
		if f.v != "" {
			*f.dst = f.v
		}
	}
	if d.CertSHA256 == "" {
		d.CertSHA256 = c.CertSHA256
	}
	d.LastSeenAt = now
	was := d.Status
	if c.UserID == "" {
		d.Status = core.DeviceEnrolled
	} else {
		d.UserChannelID = c.EnrollmentID
		if was != core.DeviceEnrolled && err != nil {
			d.Status = core.DeviceEnrolled
		}
	}
	if err := e.store.UpsertDevice(ctx, d); err != nil {
		e.log.Error("saving device", "device", c.DeviceID, "err", err)
		return false
	}
	if was != core.DeviceEnrolled && d.Status == core.DeviceEnrolled {
		e.audit(ctx, "device:"+c.DeviceID, "device.enrolled", c.DeviceID, d.DeviceName)
	}
	return true
}

// DeviceCheckedOut: the MDM profile is gone. A check-out on a user channel
// only forgets that channel.
func (e *Engine) DeviceCheckedOut(ctx context.Context, c core.Checkin) {
	defer e.recoverEvent("check out")
	e.mu.Lock()
	defer e.mu.Unlock()
	d, err := e.store.GetDevice(ctx, c.DeviceID)
	if err != nil {
		if !errors.Is(err, core.ErrNotFound) {
			e.log.Error("loading device", "device", c.DeviceID, "err", err)
		}
		return
	}
	d.LastSeenAt = e.now()
	if c.UserID != "" {
		if d.UserChannelID == c.EnrollmentID {
			d.UserChannelID = ""
		}
		if err := e.store.UpsertDevice(ctx, d); err != nil {
			e.log.Error("saving device", "device", c.DeviceID, "err", err)
		}
		return
	}
	d.Status = core.DeviceUnenrolled
	d.UserChannelID = ""
	if err := e.store.UpsertDevice(ctx, d); err != nil {
		e.log.Error("saving device", "device", c.DeviceID, "err", err)
		return
	}
	e.clearProfiles(ctx, c.DeviceID)
	e.audit(ctx, "device:"+c.DeviceID, "device.checked_out", c.DeviceID, d.DeviceName)
}

// CommandResulted records a device's answer and moves the profile it was
// about.
func (e *Engine) CommandResulted(ctx context.Context, r core.CommandResult) {
	defer e.recoverEvent("command result")
	if e.resulted(ctx, r) {
		e.Trigger(r.DeviceID)
	}
}

func (e *Engine) resulted(ctx context.Context, r core.CommandResult) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()

	deviceID := r.DeviceID
	if cmd, err := e.store.GetCommand(ctx, r.CommandUUID); err == nil {
		if deviceID == "" {
			deviceID = cmd.DeviceID
		}
		cmd.Status = r.Status
		cmd.Detail = r.ErrorText
		cmd.UpdatedAt = now
		if err := e.store.PutCommand(ctx, cmd); err != nil {
			e.log.Error("updating command", "err", err)
		}
	} else if !errors.Is(err, core.ErrNotFound) {
		e.log.Error("loading command", "err", err)
	}
	if deviceID != "" {
		if d, err := e.store.GetDevice(ctx, deviceID); err == nil {
			d.LastSeenAt = now
			if err := e.store.UpsertDevice(ctx, d); err != nil {
				e.log.Error("saving device", "device", deviceID, "err", err)
			}
		}
	}

	dp, err := e.store.GetDeviceProfileByCommand(ctx, r.CommandUUID)
	if err != nil || dp.CommandUUID != r.CommandUUID {
		return false // not about a profile, or a newer command replaced it
	}
	actor := "device:" + dp.DeviceID
	switch dp.State {
	case core.StateSent:
		switch r.Status {
		case core.CommandAcknowledged:
			dp.State, dp.Detail = core.StateInstalled, ""
			e.putRow(ctx, dp)
			e.audit(ctx, actor, "profile.installed", dp.DeviceID, dp.ProfileID)
			return true
		case core.CommandError:
			dp.State, dp.Detail = core.StateFailed, r.ErrorText
			e.putRow(ctx, dp)
			e.audit(ctx, actor, "profile.failed", dp.DeviceID, dp.ProfileID+": "+r.ErrorText)
			return true
		}
	case core.StateRemoving:
		switch r.Status {
		case core.CommandAcknowledged, core.CommandError:
			// Error means it was not there: the wanted end state.
			if err := e.store.DeleteDeviceProfile(ctx, dp.DeviceID, dp.ProfileID); err != nil {
				e.log.Error("deleting device profile", "err", err)
			}
			e.audit(ctx, actor, "profile.removed", dp.DeviceID, dp.ProfileID)
			return true
		}
	}
	return false
}

func (e *Engine) putRow(ctx context.Context, dp core.DeviceProfile) {
	if err := e.store.PutDeviceProfile(ctx, dp); err != nil {
		e.log.Error("saving device profile", "device", dp.DeviceID, "profile", dp.ProfileID, "err", err)
	}
}
