package api

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"sync"
	"time"

	"openmdm/internal/core"
)

// memStore is a complete in-memory core.Store.
type memStore struct {
	mu       sync.Mutex
	users    map[string]core.User
	devices  map[string]core.Device
	profiles map[string]core.Profile
	dprofs   map[string]core.DeviceProfile // deviceID + "|" + profileID
	cmds     []core.CommandRecord
	enrolls  map[string]core.Enrollment
	events   []core.Event
	blobs    map[string][]byte
	serial   int64
	failPut  error
}

func newMemStore() *memStore {
	return &memStore{
		users: map[string]core.User{}, devices: map[string]core.Device{}, profiles: map[string]core.Profile{},
		dprofs: map[string]core.DeviceProfile{}, enrolls: map[string]core.Enrollment{}, blobs: map[string][]byte{},
	}
}

func nf(what, id string) error { return fmt.Errorf("%s %q: %w", what, id, core.ErrNotFound) }

func (s *memStore) UpsertUser(_ context.Context, u core.User) (core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.users[u.Username]; ok {
		u.CreatedAt = old.CreatedAt
		if u.LastLoginAt.IsZero() {
			u.LastLoginAt = old.LastLoginAt
		}
	} else {
		u.CreatedAt = time.Now().UTC()
	}
	s.users[u.Username] = u
	return u, nil
}
func (s *memStore) GetUser(_ context.Context, n string) (core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[n]; ok {
		return u, nil
	}
	return core.User{}, nf("user", n)
}
func (s *memStore) ListUsers(context.Context) ([]core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.User{}
	for _, u := range s.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}
func (s *memStore) UpsertDevice(_ context.Context, d core.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[d.ID] = d
	return nil
}
func (s *memStore) GetDevice(_ context.Context, id string) (core.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.devices[id]; ok {
		return d, nil
	}
	return core.Device{}, nf("device", id)
}
func (s *memStore) ListDevices(context.Context) ([]core.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.Device{}
	for _, d := range s.devices {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (s *memStore) ListDevicesByUser(_ context.Context, u string) ([]core.Device, error) {
	all, _ := s.ListDevices(context.Background())
	out := []core.Device{}
	for _, d := range all {
		if d.Username == u {
			out = append(out, d)
		}
	}
	return out, nil
}
func (s *memStore) DeleteDevice(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[id]; !ok {
		return nf("device", id)
	}
	delete(s.devices, id)
	return nil
}
func (s *memStore) PutProfile(_ context.Context, p core.Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failPut != nil {
		return s.failPut
	}
	p.UpdatedAt = time.Now().UTC()
	s.profiles[p.ID] = p
	return nil
}
func (s *memStore) GetProfile(_ context.Context, id string) (core.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.profiles[id]; ok {
		return p, nil
	}
	return core.Profile{}, nf("profile", id)
}
func (s *memStore) ListProfiles(context.Context) ([]core.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.Profile{}
	for _, p := range s.profiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (s *memStore) DeleteProfile(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.profiles[id]; !ok {
		return nf("profile", id)
	}
	delete(s.profiles, id)
	return nil
}
func (s *memStore) PutDeviceProfile(_ context.Context, dp core.DeviceProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dprofs[dp.DeviceID+"|"+dp.ProfileID] = dp
	return nil
}
func (s *memStore) GetDeviceProfileByCommand(_ context.Context, c string) (core.DeviceProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, dp := range s.dprofs {
		if dp.CommandUUID == c {
			return dp, nil
		}
	}
	return core.DeviceProfile{}, nf("command", c)
}
func (s *memStore) ListDeviceProfiles(_ context.Context, id string) ([]core.DeviceProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.DeviceProfile{}
	for _, dp := range s.dprofs {
		if dp.DeviceID == id {
			out = append(out, dp)
		}
	}
	return out, nil
}
func (s *memStore) ListDeviceProfilesByProfile(_ context.Context, id string) ([]core.DeviceProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.DeviceProfile{}
	for _, dp := range s.dprofs {
		if dp.ProfileID == id {
			out = append(out, dp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out, nil
}
func (s *memStore) DeleteDeviceProfile(_ context.Context, d, p string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.dprofs, d+"|"+p)
	return nil
}
func (s *memStore) PutCommand(_ context.Context, c core.CommandRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.cmds {
		if s.cmds[i].UUID == c.UUID {
			s.cmds[i] = c
			return nil
		}
	}
	s.cmds = append(s.cmds, c)
	return nil
}
func (s *memStore) GetCommand(_ context.Context, u string) (core.CommandRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.cmds {
		if c.UUID == u {
			return c, nil
		}
	}
	return core.CommandRecord{}, nf("command", u)
}
func (s *memStore) ListCommands(_ context.Context, id string, limit int) ([]core.CommandRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.CommandRecord{}
	for i := len(s.cmds) - 1; i >= 0; i-- {
		if s.cmds[i].DeviceID == id && len(out) < limit {
			out = append(out, s.cmds[i])
		}
	}
	return out, nil
}
func (s *memStore) CreateEnrollment(_ context.Context, e core.Enrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrolls[e.Token] = e
	return nil
}
func (s *memStore) GetEnrollment(_ context.Context, t string) (core.Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.enrolls[t]; ok {
		return e, nil
	}
	return core.Enrollment{}, nf("enrollment", "")
}
func (s *memStore) GetEnrollmentByChallenge(_ context.Context, c string) (core.Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.enrolls {
		if e.Challenge == c {
			return e, nil
		}
	}
	return core.Enrollment{}, nf("enrollment", "")
}
func (s *memStore) MarkEnrollmentDownloaded(_ context.Context, t string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.enrolls[t]
	if !ok {
		return nf("enrollment", "")
	}
	if e.DownloadedAt != nil {
		return fmt.Errorf("already downloaded: %w", core.ErrInvalid)
	}
	e.DownloadedAt = &at
	s.enrolls[t] = e
	return nil
}
func (s *memStore) MarkEnrollmentUsed(_ context.Context, c string, at time.Time) error {
	return nil
}
func (s *memStore) ListEnrollments(context.Context) ([]core.Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.Enrollment{}
	for _, e := range s.enrolls {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
func (s *memStore) PutIssuedCert(context.Context, core.IssuedCert) error { return nil }
func (s *memStore) GetIssuedCertBySHA256(context.Context, string) (core.IssuedCert, error) {
	return core.IssuedCert{}, core.ErrNotFound
}
func (s *memStore) ListIssuedCerts(context.Context) ([]core.IssuedCert, error) { return nil, nil }
func (s *memStore) NextSerial(context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serial++
	return s.serial, nil
}
func (s *memStore) GetBlob(_ context.Context, k string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.blobs[k]; ok {
		return b, nil
	}
	return nil, nf("blob", k)
}
func (s *memStore) PutBlob(_ context.Context, k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[k] = v
	return nil
}
func (s *memStore) AppendEvent(_ context.Context, e core.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.ID = int64(len(s.events) + 1)
	s.events = append(s.events, e)
	return nil
}
func (s *memStore) ListEvents(_ context.Context, limit int) ([]core.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.Event{}
	for i := len(s.events) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.events[i])
	}
	return out, nil
}
func (s *memStore) Close() error { return nil }

func (s *memStore) lastEvent() core.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 {
		return core.Event{}
	}
	return s.events[len(s.events)-1]
}

var oidUID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}

// fakeSecrets is an in-memory core.SecretStore.
type fakeSecrets struct {
	mu     sync.Mutex
	users  map[string]map[string]string
	global map[string]string
	health error
}

func newFakeSecrets() *fakeSecrets {
	return &fakeSecrets{users: map[string]map[string]string{}, global: map[string]string{}}
}
func (f *fakeSecrets) UserSecrets(_ context.Context, u string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for k, v := range f.users[u] {
		out[k] = v
	}
	return out, nil
}
func (f *fakeSecrets) SetUserSecret(_ context.Context, u, k, v string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.users[u] == nil {
		f.users[u] = map[string]string{}
	}
	f.users[u][k] = v
	return nil
}
func (f *fakeSecrets) DeleteUserSecret(_ context.Context, u, k string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.users[u], k)
	return nil
}
func (f *fakeSecrets) GlobalSecrets(context.Context) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for k, v := range f.global {
		out[k] = v
	}
	return out, nil
}
func (f *fakeSecrets) SetGlobalSecret(_ context.Context, k, v string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.global[k] = v
	return nil
}
func (f *fakeSecrets) DeleteGlobalSecret(_ context.Context, k string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.global, k)
	return nil
}
func (f *fakeSecrets) Health(context.Context) error { return f.health }

// fakeRenderer finds {{secret "x"}} and {{globalSecret "y"}} in a template;
// a template containing BROKEN does not validate.
type fakeRenderer struct{}

var (
	userSecRE = regexp.MustCompile(`\{\{\s*secret(?:Data)?\s+"([a-z0-9_]+)"`)
	globSecRE = regexp.MustCompile(`\{\{\s*globalSecret(?:Data)?\s+"([a-z0-9_]+)"`)
)

func uniq(re *regexp.Regexp, s string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

func (fakeRenderer) Render(context.Context, core.Profile, core.Device, *core.User) (core.Rendered, error) {
	return core.Rendered{}, nil
}
func (fakeRenderer) Validate(p core.Profile) (core.TemplateInfo, error) {
	if regexp.MustCompile(`BROKEN`).MatchString(p.Template) {
		return core.TemplateInfo{}, fmt.Errorf("%w: template does not parse", core.ErrInvalid)
	}
	return core.TemplateInfo{
		Identifier: "com.example." + p.ID, UserSecrets: uniq(userSecRE, p.Template),
		GlobalSecrets: uniq(globSecRE, p.Template), PayloadTypes: []string{"com.apple.test"},
	}, nil
}
func (fakeRenderer) Sign(c []byte) ([]byte, error) { return c, nil }

type fakeReconciler struct {
	mu        sync.Mutex
	triggered []string
	all       int
	planErr   error
}

func (f *fakeReconciler) Trigger(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.triggered = append(f.triggered, id)
}
func (f *fakeReconciler) TriggerAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.all++
}
func (f *fakeReconciler) Plan(_ context.Context, id string) ([]core.PlanEntry, error) {
	if f.planErr != nil {
		return nil, f.planErr
	}
	return []core.PlanEntry{{ProfileID: "p1", Name: "P1", Wanted: true, Reason: "assigned to everyone", State: core.StateInstalled, Channel: core.ChannelDevice}}, nil
}
func (f *fakeReconciler) snapshot() ([]string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.triggered...), f.all
}

type enqueued struct {
	Target, Type string
	Cmd          map[string]any
}

type fakeMDM struct {
	mu        sync.Mutex
	enqueued  []enqueued
	removed   [][2]string
	pushed    [][]string
	push      core.PushInfo
	pushErr   error
	removeErr error
	setErr    error
	setCalls  int
	n         int
	// strictPush makes SetPushCert check the pair like the real one does.
	strictPush bool
	lastKeyPEM []byte
}

func (f *fakeMDM) next() string {
	f.n++
	return fmt.Sprintf("cmd-%d", f.n)
}
func (f *fakeMDM) InstallProfile(context.Context, string, []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.next(), nil
}
func (f *fakeMDM) RemoveProfile(_ context.Context, t, id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removeErr != nil {
		return "", f.removeErr
	}
	f.removed = append(f.removed, [2]string{t, id})
	return f.next(), nil
}
func (f *fakeMDM) Enqueue(_ context.Context, t, rt string, c map[string]any) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enqueued = append(f.enqueued, enqueued{t, rt, c})
	return f.next(), nil
}
func (f *fakeMDM) Push(_ context.Context, t ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushed = append(f.pushed, t)
	return f.pushErr
}
func (f *fakeMDM) PushInfo(context.Context) (core.PushInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.push, nil
}
func (f *fakeMDM) SetPushCert(_ context.Context, c, k []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCalls++
	if f.setErr != nil {
		return f.setErr
	}
	if f.strictPush {
		// Like the real one: the key must belong to the certificate, which
		// must carry an APNs topic in its subject's UID.
		if _, err := tls.X509KeyPair(c, k); err != nil {
			return fmt.Errorf("%w: certificate and key do not match", core.ErrInvalid)
		}
		blk, _ := pem.Decode(c)
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return fmt.Errorf("%w: certificate: %v", core.ErrInvalid, err)
		}
		for _, n := range cert.Subject.Names {
			if n.Type.Equal(oidUID) {
				f.lastKeyPEM = append([]byte(nil), k...)
				f.push = core.PushInfo{Configured: true, Topic: fmt.Sprint(n.Value), NotAfter: cert.NotAfter.UTC()}
				return nil
			}
		}
		return fmt.Errorf("%w: not an APNs MDM push certificate", core.ErrInvalid)
	}
	f.push = core.PushInfo{Configured: true, Topic: "com.apple.mgmt.External.test", NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	return nil
}

type fakeEnroller struct {
	err error
}

func (f *fakeEnroller) EnrollmentProfile(_ context.Context, e core.Enrollment) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []byte("<plist>enrol for " + e.Username + "</plist>"), nil
}

type fakeAuthority struct {
	cert      *x509.Certificate
	mu        sync.Mutex
	revoked   []string
	revokeErr error
}

func newFakeAuthority() *fakeAuthority {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA", Organization: []string{"Test"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return &fakeAuthority{cert: c}
}
func (f *fakeAuthority) CACertificate() *x509.Certificate { return f.cert }
func (f *fakeAuthority) SigningIdentity() (*x509.Certificate, crypto.Signer) {
	return nil, nil
}
func (f *fakeAuthority) VerifyIssued(context.Context, *x509.Certificate) error { return nil }
func (f *fakeAuthority) Revoke(_ context.Context, sha string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, sha)
	return f.revokeErr
}
