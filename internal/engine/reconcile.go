package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"openmdm/internal/core"
)

type action int

const (
	actNone    action = iota
	actInstall        // sign, install, record as sent
	actWrite          // write row as blocked or failed
	actRemove         // queue RemoveProfile, record removing
	actDelete         // nothing was ever sent: forget the row
)

// item is the decision about one profile on one device. Planning builds
// items without side effects; reconcile carries them out.
type item struct {
	profileID string
	name      string
	profile   *core.Profile
	row       *core.DeviceProfile
	wanted    bool
	reason    string
	act       action
	channel   core.Channel
	target    string
	state     core.ProfileState // the state it has or would get
	detail    string
	rendered  core.Rendered
	removeOld bool // identifier or channel changed: remove the old one first
}

func sentBefore(r *core.DeviceProfile) bool { return r != nil && r.CommandUUID != "" }

func (e *Engine) owner(ctx context.Context, d core.Device) (*core.User, error) {
	if d.Username == "" {
		return nil, nil
	}
	u, err := e.store.GetUser(ctx, d.Username)
	if errors.Is(err, core.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// whyAssigned gives the plain-words reason a profile is, or is not, for
// this owner.
func whyAssigned(a core.Assignment, u *core.User) (bool, string) {
	if a.Everyone {
		return true, "assigned to everyone"
	}
	if u == nil {
		return false, "not assigned to everyone and this device has no owner"
	}
	for _, name := range a.Users {
		if strings.EqualFold(name, u.Username) {
			return true, "assigned to " + u.Username
		}
	}
	for _, g := range a.Groups {
		if slices.Contains(u.Groups, g) {
			return true, "assigned to group " + g
		}
	}
	return false, "not assigned to " + u.Username
}

func channelFor(p core.Profile, d core.Device) (core.Channel, string) {
	if d.Platform == core.PlatformMacOS && p.MacOSChannel == core.ChannelUser {
		return core.ChannelUser, d.UserChannelID
	}
	return core.ChannelDevice, d.ID
}

func targetFor(ch core.Channel, d core.Device) string {
	if ch == core.ChannelUser {
		return d.UserChannelID
	}
	return d.ID
}

// plan decides, for every profile that is wanted or has a row, what to do.
func (e *Engine) plan(ctx context.Context, d core.Device) ([]item, error) {
	owner, err := e.owner(ctx, d)
	if err != nil {
		return nil, fmt.Errorf("loading owner: %w", err)
	}
	profiles, err := e.store.ListProfiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing profiles: %w", err)
	}
	rows, err := e.store.ListDeviceProfiles(ctx, d.ID)
	if err != nil {
		return nil, fmt.Errorf("listing device profiles: %w", err)
	}
	byProfile := map[string]*core.DeviceProfile{}
	for i := range rows {
		byProfile[rows[i].ProfileID] = &rows[i]
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })

	var items []item
	for i := range profiles {
		p := &profiles[i]
		row := byProfile[p.ID]
		delete(byProfile, p.ID)

		it := item{profileID: p.ID, name: p.Name, profile: p, row: row}
		switch {
		case !slices.Contains(p.Platforms, d.Platform):
			it.reason = "not for " + string(d.Platform)
		default:
			it.wanted, it.reason = whyAssigned(p.Assignment, owner)
		}
		if it.wanted {
			e.planWanted(ctx, d, owner, &it)
		} else if row == nil {
			continue
		} else {
			e.planUnwanted(d, &it)
		}
		items = append(items, it)
	}
	// Rows whose profile no longer exists.
	var gone []string
	for id := range byProfile {
		gone = append(gone, id)
	}
	sort.Strings(gone)
	for _, id := range gone {
		it := item{profileID: id, name: id, row: byProfile[id], reason: "profile no longer exists"}
		e.planUnwanted(d, &it)
		items = append(items, it)
	}
	return items, nil
}

func (e *Engine) planUnwanted(d core.Device, it *item) {
	row := it.row
	it.channel = row.Channel
	it.target = targetFor(row.Channel, d)
	it.state, it.detail = row.State, row.Detail
	switch {
	case row.State == core.StateRemoving:
		// already on its way out
	case !sentBefore(row):
		it.act = actDelete
	case it.target == "":
		// The user channel is gone; it can be removed when it comes back.
	default:
		it.act = actRemove
		it.state, it.detail = core.StateRemoving, ""
	}
}

func (e *Engine) planWanted(ctx context.Context, d core.Device, owner *core.User, it *item) {
	p := it.profile
	row := it.row
	it.channel, it.target = channelFor(*p, d)

	// blockOrFail records a state that needs no command.
	record := func(state core.ProfileState, detail string) {
		it.state, it.detail = state, detail
		if row != nil && row.State == state && row.Detail == detail && row.Channel == it.channel {
			return
		}
		it.act = actWrite
	}

	if it.channel == core.ChannelUser && it.target == "" {
		record(core.StateBlocked, "waiting for someone to log in to this Mac")
		return
	}
	r, err := e.renderer.Render(ctx, *p, d, owner)
	if err != nil {
		// Never log or show more than the error: it carries no secret values.
		record(core.StateFailed, "the profile's template is broken: "+err.Error())
		return
	}
	it.rendered = r
	if len(r.Missing) > 0 {
		record(core.StateBlocked, "waiting for "+strings.Join(r.Missing, ", "))
		return
	}

	send := row == nil ||
		row.State == core.StatePending || row.State == core.StateBlocked || row.State == core.StateRemoving ||
		row.ContentHash != r.Hash || row.Channel != it.channel
	if !send && row.State == core.StateFailed && e.now().Sub(row.UpdatedAt) >= failedRetry {
		send = true
	}
	if !send {
		it.state, it.detail = row.State, row.Detail
		return
	}
	it.act = actInstall
	it.state, it.detail = core.StatePending, ""
	it.removeOld = sentBefore(row) && row.State != core.StateRemoving && row.Identifier != "" &&
		(row.Identifier != r.Identifier || row.Channel != it.channel)
}

// reconcile makes one device match the profiles.
func (e *Engine) reconcile(ctx context.Context, deviceID string) error {
	d, err := e.store.GetDevice(ctx, deviceID)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil
		}
		return err
	}
	if d.Status != core.DeviceEnrolled {
		return nil
	}
	items, err := e.plan(ctx, d)
	if err != nil {
		return err
	}

	pushes := map[string]bool{}
	var order []string
	queue := func(target string) {
		if !pushes[target] {
			pushes[target] = true
			order = append(order, target)
		}
	}

	e.mu.Lock()
	acted := map[string]bool{}
	for i := range items {
		it := &items[i]
		if it.act != actNone {
			acted[it.profileID] = true
		}
		switch it.act {
		case actInstall:
			e.install(ctx, d, it, queue)
		case actWrite:
			dp := core.DeviceProfile{DeviceID: d.ID, ProfileID: it.profileID}
			if it.row != nil {
				dp = *it.row
			}
			dp.State, dp.Detail, dp.Channel = it.state, it.detail, it.channel
			if it.state == core.StateFailed {
				dp.ContentHash = "" // a fixed template must be sent at once
			}
			e.putRow(ctx, dp)
		case actRemove:
			e.remove(ctx, d, it, queue)
		case actDelete:
			if err := e.store.DeleteDeviceProfile(ctx, d.ID, it.profileID); err != nil {
				e.log.Error("deleting device profile", "device", d.ID, "profile", it.profileID, "err", err)
			}
		}
	}
	e.mu.Unlock()

	// A row stuck in sent or removing for a day: wake the device again.
	now := e.now()
	for i := range items {
		it := &items[i]
		if acted[it.profileID] || it.row == nil || it.target == "" {
			continue
		}
		if (it.row.State == core.StateSent || it.row.State == core.StateRemoving) &&
			now.Sub(it.row.UpdatedAt) > nudgeAfter {
			key := d.ID + "/" + it.profileID
			e.mu.Lock()
			last, ok := e.nudged[key]
			if !ok || now.Sub(last) > nudgeAfter {
				e.nudged[key] = now
				queue(it.target)
			}
			e.mu.Unlock()
		}
	}

	if len(order) > 0 {
		if err := e.mdm.Push(ctx, order...); err != nil {
			e.log.Error("pushing to device", "device", d.ID, "err", err)
		}
	}
	return nil
}

func (e *Engine) command(ctx context.Context, d core.Device, ch core.Channel, uuid, typ, profileID string) {
	now := e.now()
	err := e.store.PutCommand(ctx, core.CommandRecord{
		UUID: uuid, DeviceID: d.ID, Channel: ch, RequestType: typ, ProfileID: profileID,
		Status: core.CommandQueued, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		e.log.Error("recording command", "device", d.ID, "err", err)
	}
}

func (e *Engine) install(ctx context.Context, d core.Device, it *item, queue func(string)) {
	row := it.row
	r := it.rendered
	if it.removeOld {
		oldTarget := targetFor(row.Channel, d)
		if oldTarget != "" {
			uuid, err := e.mdm.RemoveProfile(ctx, oldTarget, row.Identifier)
			if err != nil {
				e.log.Error("queueing removal of old profile", "device", d.ID, "profile", it.profileID, "err", err)
			} else {
				e.command(ctx, d, row.Channel, uuid, "RemoveProfile", it.profileID)
				queue(oldTarget)
			}
		}
	}
	signed, err := e.renderer.Sign(r.Content)
	if err != nil {
		e.log.Error("signing profile", "device", d.ID, "profile", it.profileID, "err", err)
		return
	}
	uuid, err := e.mdm.InstallProfile(ctx, it.target, signed)
	if err != nil {
		e.log.Error("queueing profile", "device", d.ID, "profile", it.profileID, "err", err)
		return
	}
	e.putRow(ctx, core.DeviceProfile{
		DeviceID: d.ID, ProfileID: it.profileID, State: core.StateSent, Channel: it.channel,
		Identifier: r.Identifier, ContentHash: r.Hash, CommandUUID: uuid,
	})
	e.command(ctx, d, it.channel, uuid, "InstallProfile", it.profileID)
	queue(it.target)
}

func (e *Engine) remove(ctx context.Context, d core.Device, it *item, queue func(string)) {
	row := *it.row
	uuid, err := e.mdm.RemoveProfile(ctx, it.target, row.Identifier)
	if err != nil {
		e.log.Error("queueing removal", "device", d.ID, "profile", it.profileID, "err", err)
		return
	}
	row.State, row.CommandUUID, row.Detail = core.StateRemoving, uuid, ""
	e.putRow(ctx, row)
	e.command(ctx, d, row.Channel, uuid, "RemoveProfile", it.profileID)
	queue(it.target)
}

// Plan says what reconcile would do for a device, changing nothing.
func (e *Engine) Plan(ctx context.Context, deviceID string) ([]core.PlanEntry, error) {
	d, err := e.store.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	items, err := e.plan(ctx, d)
	if err != nil {
		return nil, err
	}
	out := make([]core.PlanEntry, 0, len(items))
	for _, it := range items {
		out = append(out, core.PlanEntry{
			ProfileID: it.profileID, Name: it.name, Wanted: it.wanted, Reason: it.reason,
			State: it.state, Channel: it.channel, Detail: it.detail,
		})
	}
	return out, nil
}
