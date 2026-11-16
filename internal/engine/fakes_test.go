package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"testing"
	"time"

	"openmdm/internal/core"
)

// clock is a controllable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// memStore is an in-memory core.Store. Methods the engine does not use are
// left to the embedded nil interface.
type memStore struct {
	core.Store
	mu       sync.Mutex
	clk      *clock
	users    map[string]core.User
	devices  map[string]core.Device
	profiles map[string]core.Profile
	dps      map[string]core.DeviceProfile // deviceID/profileID
	cmds     map[string]core.CommandRecord
	certs    map[string]core.IssuedCert
	events   []core.Event
	dpPuts   int
	cmdPuts  int
	listDevs int
}

func newMemStore(clk *clock) *memStore {
	return &memStore{
		clk: clk, users: map[string]core.User{}, devices: map[string]core.Device{},
		profiles: map[string]core.Profile{}, dps: map[string]core.DeviceProfile{},
		cmds: map[string]core.CommandRecord{}, certs: map[string]core.IssuedCert{},
	}
}

func nf(what string) error { return fmt.Errorf("%s: %w", what, core.ErrNotFound) }

func (s *memStore) UpsertUser(_ context.Context, u core.User) (core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.users[u.Username]; ok {
		u.CreatedAt = old.CreatedAt
	} else {
		u.CreatedAt = s.clk.Now()
	}
	s.users[u.Username] = u
	return u, nil
}
func (s *memStore) GetUser(_ context.Context, name string) (core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[name]
	if !ok {
		return u, nf("user")
	}
	return u, nil
}
func (s *memStore) UpsertDevice(_ context.Context, d core.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.devices[d.ID]; ok && d.EnrolledAt.IsZero() {
		d.EnrolledAt = old.EnrolledAt
	}
	s.devices[d.ID] = d
	return nil
}
func (s *memStore) GetDevice(_ context.Context, id string) (core.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return d, nf("device")
	}
	return d, nil
}
func (s *memStore) ListDevices(context.Context) ([]core.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listDevs++
	out := []core.Device{}
	for _, d := range s.devices {
		out = append(out, d)
	}
	return out, nil
}
func (s *memStore) PutProfile(_ context.Context, p core.Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.UpdatedAt = s.clk.Now()
	s.profiles[p.ID] = p
	return nil
}
func (s *memStore) DeleteProfile(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.profiles, id)
	return nil
}
func (s *memStore) ListProfiles(context.Context) ([]core.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.Profile{}
	for _, p := range s.profiles {
		out = append(out, p)
	}
	return out, nil
}
func (s *memStore) PutDeviceProfile(_ context.Context, dp core.DeviceProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dp.UpdatedAt = s.clk.Now()
	s.dps[dp.DeviceID+"/"+dp.ProfileID] = dp
	s.dpPuts++
	return nil
}
func (s *memStore) GetDeviceProfileByCommand(_ context.Context, uuid string) (core.DeviceProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, dp := range s.dps {
		if dp.CommandUUID == uuid && uuid != "" {
			return dp, nil
		}
	}
	return core.DeviceProfile{}, nf("device profile")
}
func (s *memStore) ListDeviceProfiles(_ context.Context, id string) ([]core.DeviceProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.DeviceProfile{}
	for _, dp := range s.dps {
		if dp.DeviceID == id {
			out = append(out, dp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProfileID < out[j].ProfileID })
	return out, nil
}
func (s *memStore) DeleteDeviceProfile(_ context.Context, dev, prof string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.dps, dev+"/"+prof)
	return nil
}
func (s *memStore) PutCommand(_ context.Context, c core.CommandRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cmds[c.UUID] = c
	s.cmdPuts++
	return nil
}
func (s *memStore) GetCommand(_ context.Context, uuid string) (core.CommandRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cmds[uuid]
	if !ok {
		return c, nf("command")
	}
	return c, nil
}
func (s *memStore) GetIssuedCertBySHA256(_ context.Context, h string) (core.IssuedCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.certs[h]
	if !ok {
		return c, nf("cert")
	}
	return c, nil
}
func (s *memStore) AppendEvent(_ context.Context, e core.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.ID = int64(len(s.events) + 1)
	s.events = append(s.events, e)
	return nil
}

func (s *memStore) row(dev, prof string) (core.DeviceProfile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.dps[dev+"/"+prof]
	return r, ok
}
func (s *memStore) kinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var k []string
	for _, e := range s.events {
		k = append(k, e.Kind)
	}
	return k
}
func (s *memStore) puts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dpPuts, s.cmdPuts
}

// fakeRenderer renders a template to "<template>|<device>|<owner>"; the
// identifier and the problems are set per profile by the test.
type fakeRenderer struct {
	mu      sync.Mutex
	idents  map[string]string
	missing map[string][]string
	errs    map[string]error
	renders int
}

func newRenderer() *fakeRenderer {
	return &fakeRenderer{idents: map[string]string{}, missing: map[string][]string{}, errs: map[string]error{}}
}

func (r *fakeRenderer) set(f func()) { r.mu.Lock(); f(); r.mu.Unlock() }

func (r *fakeRenderer) Render(_ context.Context, p core.Profile, d core.Device, u *core.User) (core.Rendered, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.renders++
	if err := r.errs[p.ID]; err != nil {
		return core.Rendered{}, err
	}
	id := r.idents[p.ID]
	if id == "" {
		id = "com.test." + p.ID
	}
	if m := r.missing[p.ID]; len(m) > 0 {
		return core.Rendered{Identifier: id, Missing: m}, nil
	}
	owner := ""
	if u != nil {
		owner = u.Username
	}
	content := []byte(fmt.Sprintf("%s|%s|%s|%s", p.Template, d.ID, owner, id))
	sum := sha256.Sum256(content)
	return core.Rendered{Content: content, Identifier: id, Hash: hex.EncodeToString(sum[:])}, nil
}
func (r *fakeRenderer) Validate(core.Profile) (core.TemplateInfo, error) {
	return core.TemplateInfo{}, nil
}
func (r *fakeRenderer) Sign(c []byte) ([]byte, error) { return append([]byte("signed:"), c...), nil }

type call struct{ Target, What string } // What: profile content or identifier

type fakeMDM struct {
	mu       sync.Mutex
	n        int
	installs []call
	removes  []call
	pushes   [][]string
	fail     error
}

func (m *fakeMDM) uuid() string { m.n++; return fmt.Sprintf("cmd-%d", m.n) }
func (m *fakeMDM) InstallProfile(_ context.Context, t string, p []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return "", m.fail
	}
	m.installs = append(m.installs, call{t, string(p)})
	return m.uuid(), nil
}
func (m *fakeMDM) RemoveProfile(_ context.Context, t, id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removes = append(m.removes, call{t, id})
	return m.uuid(), nil
}
func (m *fakeMDM) Enqueue(context.Context, string, string, map[string]any) (string, error) {
	return "", errors.New("unused")
}
func (m *fakeMDM) Push(_ context.Context, t ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pushes = append(m.pushes, append([]string(nil), t...))
	return nil
}
func (m *fakeMDM) PushInfo(context.Context) (core.PushInfo, error)   { return core.PushInfo{}, nil }
func (m *fakeMDM) SetPushCert(context.Context, []byte, []byte) error { return nil }

func (m *fakeMDM) counts() (int, int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.installs), len(m.removes), len(m.pushes)
}

// harness wires an Engine to the fakes.
type harness struct {
	t   *testing.T
	ctx context.Context
	clk *clock
	st  *memStore
	rn  *fakeRenderer
	md  *fakeMDM
	e   *Engine
}

func newHarness(t *testing.T) *harness {
	clk := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	h := &harness{t: t, ctx: context.Background(), clk: clk, st: newMemStore(clk), rn: newRenderer(), md: &fakeMDM{}}
	h.e = New(h.st, h.rn, h.md, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Now: clk.Now})
	return h
}

func (h *harness) device(id string, p core.Platform, owner string) core.Device {
	d := core.Device{ID: id, Platform: p, Username: owner, Status: core.DeviceEnrolled, EnrolledAt: h.clk.Now()}
	h.st.UpsertDevice(h.ctx, d)
	return d
}
func (h *harness) user(name string, groups ...string) {
	h.st.UpsertUser(h.ctx, core.User{Username: name, Role: core.RoleUser, Groups: groups})
}
func (h *harness) profile(id string, ch core.Channel, a core.Assignment, plats ...core.Platform) core.Profile {
	if len(plats) == 0 {
		plats = []core.Platform{core.PlatformMacOS, core.PlatformIOS, core.PlatformIPadOS}
	}
	p := core.Profile{ID: id, Name: id, Platforms: plats, MacOSChannel: ch, Assignment: a, Template: "v1"}
	h.st.PutProfile(h.ctx, p)
	return p
}
func (h *harness) reconcile(id string) {
	h.t.Helper()
	if err := h.e.reconcile(h.ctx, id); err != nil {
		h.t.Fatal(err)
	}
}
func (h *harness) state(dev, prof string) core.ProfileState {
	r, ok := h.st.row(dev, prof)
	if !ok {
		return "(none)"
	}
	return r.State
}
func (h *harness) result(uuid string, s core.CommandStatus, text string) {
	h.e.CommandResulted(h.ctx, core.CommandResult{CommandUUID: uuid, Status: s, ErrorText: text})
}

var everyone = core.Assignment{Everyone: true}
