// Package store implements core.Store on SQLite (modernc.org/sqlite, pure
// Go). One file, WAL mode, schema kept by numbered migrations embedded in
// the binary.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"openmdm/internal/core"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

var _ core.Store = (*Store)(nil)

// Store is a core.Store backed by one SQLite database.
//
// SQLite allows a single writer, so all writes go through one connection
// (database/sql queues the callers); on a file database reads use a separate
// pool, which WAL lets run alongside the writer. A ":memory:" database is
// private to its connection, so there one connection serves everything.
type Store struct {
	w *sql.DB // writes; exactly one connection
	r *sql.DB // reads; == w for ":memory:"
}

// Open opens (creating it if need be) the database at path and brings its
// schema up to date. path is a file path, or ":memory:" for a private
// in-memory database.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: empty database path")
	}
	s := &Store{}
	var err error
	if path == ":memory:" {
		db, err := sql.Open("sqlite", memoryDSN())
		if err != nil {
			return nil, err
		}
		limit(db, 1)
		s.w, s.r = db, db
	} else {
		if dir := filepath.Dir(path); dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, fmt.Errorf("store: %w", err)
			}
		}
		if s.w, err = sql.Open("sqlite", fileDSN(path, true)); err != nil {
			return nil, err
		}
		limit(s.w, 1)
		if s.r, err = sql.Open("sqlite", fileDSN(path, false)); err != nil {
			s.w.Close()
			return nil, err
		}
		limit(s.r, 4)
	}
	if err := s.migrate(context.Background()); err != nil {
		s.Close()
		return nil, fmt.Errorf("store: %w", err)
	}
	return s, nil
}

// limit keeps connections open for the life of the Store (an in-memory
// database vanishes with its last connection).
func limit(db *sql.DB, n int) {
	db.SetMaxOpenConns(n)
	db.SetMaxIdleConns(n)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)
}

const pragmas = "_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_pragma=journal_mode(WAL)"

func memoryDSN() string {
	return "file::memory:?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
}

func fileDSN(path string, writer bool) string {
	esc := strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(path)
	dsn := "file:" + esc + "?" + pragmas
	if writer {
		return dsn + "&_txlock=immediate"
	}
	return dsn + "&_pragma=query_only(1)"
}

// Close releases the database.
func (s *Store) Close() error {
	err := s.w.Close()
	if s.r != s.w {
		if e := s.r.Close(); err == nil {
			err = e
		}
	}
	return err
}

// ---- migrations ----

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		num, _, _ := strings.Cut(name, "_")
		v, err := strconv.Atoi(num)
		if err != nil {
			return nil, fmt.Errorf("migration %q: name must start with a number", name)
		}
		b, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{v, name, string(b)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i := 1; i < len(ms); i++ {
		if ms[i].version == ms[i-1].version {
			return nil, fmt.Errorf("duplicate migration number %d", ms[i].version)
		}
	}
	return ms, nil
}

func (s *Store) migrate(ctx context.Context) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	if _, err := s.w.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	applied := map[int]bool{}
	rows, err := s.w.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	known := map[int]bool{}
	for _, m := range ms {
		known[m.version] = true
	}
	for v := range applied {
		if !known[v] {
			return fmt.Errorf("database schema version %d is newer than this program understands", v)
		}
	}
	for _, m := range ms {
		if applied[m.version] {
			continue
		}
		err := s.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
				m.version, m.name, ts(time.Now()))
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
	}
	return nil
}

// tx runs fn in a write transaction.
func (s *Store) tx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ---- helpers ----

const tsLayout = "2006-01-02T15:04:05.000000000Z" // fixed width: sorts as text

// ts renders a time for storage; the zero time is "".
func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(tsLayout)
}

func tsPtr(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return ts(*t)
}

func parseTS(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("store: bad stored time %q: %w", s, err)
	}
	return t.UTC(), nil
}

func parseTSPtr(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid || ns.String == "" {
		return nil, nil
	}
	t, err := parseTS(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func notFound(what, key string) error {
	return fmt.Errorf("%s %q: %w", what, key, core.ErrNotFound)
}

func jsonStrings(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func parseStrings(s string) ([]string, error) {
	out := []string{}
	if s == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, fmt.Errorf("store: bad stored list %q: %w", s, err)
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func limitArg(n int) int {
	if n <= 0 {
		return -1 // SQLite: no limit
	}
	return n
}

type scanner interface{ Scan(dest ...any) error }

// one runs a query expected to yield one row and scans it with fn.
func one[T any](ctx context.Context, db *sql.DB, what, key string, fn func(scanner) (T, error), q string, args ...any) (T, error) {
	v, err := fn(db.QueryRowContext(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		var zero T
		return zero, notFound(what, key)
	}
	return v, err
}

// many runs a query and scans every row; the result is never nil.
func many[T any](ctx context.Context, db *sql.DB, fn func(scanner) (T, error), q string, args ...any) ([]T, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		v, err := fn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---- users ----

const userCols = `username, email, name, groups, role, created_at, last_login_at`

func scanUser(sc scanner) (core.User, error) {
	var u core.User
	var groups, role, created, login string
	if err := sc.Scan(&u.Username, &u.Email, &u.Name, &groups, &role, &created, &login); err != nil {
		return u, err
	}
	var err error
	u.Role = core.Role(role)
	if u.Groups, err = parseStrings(groups); err != nil {
		return u, err
	}
	if u.CreatedAt, err = parseTS(created); err != nil {
		return u, err
	}
	u.LastLoginAt, err = parseTS(login)
	return u, err
}

func (s *Store) UpsertUser(ctx context.Context, u core.User) (core.User, error) {
	name := lower(u.Username)
	if name == "" {
		return core.User{}, fmt.Errorf("username is required: %w", core.ErrInvalid)
	}
	role := u.Role
	if role == "" {
		role = core.RoleUser
	}
	created := u.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	var out core.User
	err := s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO users (`+userCols+`) VALUES (?,?,?,?,?,?,?)
			ON CONFLICT(username) DO UPDATE SET
				email = excluded.email, name = excluded.name,
				groups = excluded.groups, role = excluded.role,
				last_login_at = CASE WHEN excluded.last_login_at = '' THEN users.last_login_at
				                     ELSE excluded.last_login_at END`,
			name, u.Email, u.Name, jsonStrings(u.Groups), string(role), ts(created), ts(u.LastLoginAt))
		if err != nil {
			return err
		}
		out, err = scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, name))
		return err
	})
	return out, err
}

func (s *Store) GetUser(ctx context.Context, username string) (core.User, error) {
	return one(ctx, s.r, "user", username, scanUser,
		`SELECT `+userCols+` FROM users WHERE username = ?`, lower(username))
}

func (s *Store) ListUsers(ctx context.Context) ([]core.User, error) {
	return many(ctx, s.r, scanUser, `SELECT `+userCols+` FROM users ORDER BY username`)
}

// ---- devices ----

const deviceCols = `id, username, platform, serial_number, model, device_name, os_version, status, user_channel_id, enrolled_at, last_seen_at, cert_sha256`

func scanDevice(sc scanner) (core.Device, error) {
	var d core.Device
	var platform, status, enrolled, seen string
	if err := sc.Scan(&d.ID, &d.Username, &platform, &d.SerialNumber, &d.Model, &d.DeviceName,
		&d.OSVersion, &status, &d.UserChannelID, &enrolled, &seen, &d.CertSHA256); err != nil {
		return d, err
	}
	d.Platform, d.Status = core.Platform(platform), core.DeviceStatus(status)
	var err error
	if d.EnrolledAt, err = parseTS(enrolled); err != nil {
		return d, err
	}
	d.LastSeenAt, err = parseTS(seen)
	return d, err
}

func (s *Store) UpsertDevice(ctx context.Context, d core.Device) error {
	if d.ID == "" {
		return fmt.Errorf("device id is required: %w", core.ErrInvalid)
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO devices (`+deviceCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			username = excluded.username, platform = excluded.platform,
			serial_number = excluded.serial_number, model = excluded.model,
			device_name = excluded.device_name, os_version = excluded.os_version,
			status = excluded.status, user_channel_id = excluded.user_channel_id,
			enrolled_at = CASE WHEN excluded.enrolled_at = '' THEN devices.enrolled_at
			                   ELSE excluded.enrolled_at END,
			last_seen_at = excluded.last_seen_at, cert_sha256 = excluded.cert_sha256`,
		d.ID, lower(d.Username), string(d.Platform), d.SerialNumber, d.Model, d.DeviceName,
		d.OSVersion, string(d.Status), d.UserChannelID, ts(d.EnrolledAt), ts(d.LastSeenAt), d.CertSHA256)
	return err
}

func (s *Store) GetDevice(ctx context.Context, id string) (core.Device, error) {
	return one(ctx, s.r, "device", id, scanDevice, `SELECT `+deviceCols+` FROM devices WHERE id = ?`, id)
}

func (s *Store) ListDevices(ctx context.Context) ([]core.Device, error) {
	return many(ctx, s.r, scanDevice, `SELECT `+deviceCols+` FROM devices ORDER BY device_name, id`)
}

func (s *Store) ListDevicesByUser(ctx context.Context, username string) ([]core.Device, error) {
	return many(ctx, s.r, scanDevice, `SELECT `+deviceCols+` FROM devices WHERE username = ? ORDER BY device_name, id`, lower(username))
}

// DeleteDevice removes the device and its DeviceProfiles. Deleting a device
// that is not there is not an error.
func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM device_profiles WHERE device_id = ?`, id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
		return err
	})
}

// ---- profiles ----

const profileCols = `id, name, description, platforms, macos_channel, assignment, template, source, updated_at`

func scanProfile(sc scanner) (core.Profile, error) {
	var p core.Profile
	var platforms, channel, assignment, updated string
	if err := sc.Scan(&p.ID, &p.Name, &p.Description, &platforms, &channel, &assignment, &p.Template, &p.Source, &updated); err != nil {
		return p, err
	}
	p.MacOSChannel = core.Channel(channel)
	strs, err := parseStrings(platforms)
	if err != nil {
		return p, err
	}
	p.Platforms = make([]core.Platform, len(strs))
	for i, v := range strs {
		p.Platforms[i] = core.Platform(v)
	}
	if assignment != "" {
		if err := json.Unmarshal([]byte(assignment), &p.Assignment); err != nil {
			return p, fmt.Errorf("store: bad stored assignment: %w", err)
		}
	}
	if p.Assignment.Users == nil {
		p.Assignment.Users = []string{}
	}
	if p.Assignment.Groups == nil {
		p.Assignment.Groups = []string{}
	}
	p.UpdatedAt, err = parseTS(updated)
	return p, err
}

func (s *Store) PutProfile(ctx context.Context, p core.Profile) error {
	if p.ID == "" {
		return fmt.Errorf("profile id is required: %w", core.ErrInvalid)
	}
	platforms := make([]string, len(p.Platforms))
	for i, v := range p.Platforms {
		platforms[i] = string(v)
	}
	a := p.Assignment
	if a.Users == nil {
		a.Users = []string{}
	}
	if a.Groups == nil {
		a.Groups = []string{}
	}
	ab, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = s.w.ExecContext(ctx, `INSERT INTO profiles (`+profileCols+`) VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name, description = excluded.description,
			platforms = excluded.platforms, macos_channel = excluded.macos_channel,
			assignment = excluded.assignment, template = excluded.template,
			source = excluded.source, updated_at = excluded.updated_at`,
		p.ID, p.Name, p.Description, jsonStrings(platforms), string(p.MacOSChannel), string(ab),
		p.Template, p.Source, ts(time.Now()))
	return err
}

func (s *Store) GetProfile(ctx context.Context, id string) (core.Profile, error) {
	return one(ctx, s.r, "profile", id, scanProfile, `SELECT `+profileCols+` FROM profiles WHERE id = ?`, id)
}

func (s *Store) ListProfiles(ctx context.Context) ([]core.Profile, error) {
	return many(ctx, s.r, scanProfile, `SELECT `+profileCols+` FROM profiles ORDER BY name, id`)
}

// DeleteProfile removes the profile only; DeviceProfiles are left. Deleting
// a profile that is not there is not an error.
func (s *Store) DeleteProfile(ctx context.Context, id string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM profiles WHERE id = ?`, id)
	return err
}

// ---- device profiles ----

const dpCols = `device_id, profile_id, state, channel, identifier, content_hash, command_uuid, detail, updated_at`

func scanDP(sc scanner) (core.DeviceProfile, error) {
	var dp core.DeviceProfile
	var state, channel, updated string
	if err := sc.Scan(&dp.DeviceID, &dp.ProfileID, &state, &channel, &dp.Identifier,
		&dp.ContentHash, &dp.CommandUUID, &dp.Detail, &updated); err != nil {
		return dp, err
	}
	dp.State, dp.Channel = core.ProfileState(state), core.Channel(channel)
	var err error
	dp.UpdatedAt, err = parseTS(updated)
	return dp, err
}

func (s *Store) PutDeviceProfile(ctx context.Context, dp core.DeviceProfile) error {
	if dp.DeviceID == "" || dp.ProfileID == "" {
		return fmt.Errorf("device id and profile id are required: %w", core.ErrInvalid)
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO device_profiles (`+dpCols+`) VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(device_id, profile_id) DO UPDATE SET
			state = excluded.state, channel = excluded.channel,
			identifier = excluded.identifier, content_hash = excluded.content_hash,
			command_uuid = excluded.command_uuid, detail = excluded.detail,
			updated_at = excluded.updated_at`,
		dp.DeviceID, dp.ProfileID, string(dp.State), string(dp.Channel), dp.Identifier,
		dp.ContentHash, dp.CommandUUID, dp.Detail, ts(time.Now()))
	return err
}

func (s *Store) GetDeviceProfileByCommand(ctx context.Context, commandUUID string) (core.DeviceProfile, error) {
	if commandUUID == "" {
		return core.DeviceProfile{}, notFound("device profile for command", commandUUID)
	}
	return one(ctx, s.r, "device profile for command", commandUUID, scanDP,
		`SELECT `+dpCols+` FROM device_profiles WHERE command_uuid = ? ORDER BY updated_at DESC LIMIT 1`, commandUUID)
}

func (s *Store) ListDeviceProfiles(ctx context.Context, deviceID string) ([]core.DeviceProfile, error) {
	return many(ctx, s.r, scanDP, `SELECT `+dpCols+` FROM device_profiles WHERE device_id = ? ORDER BY profile_id`, deviceID)
}

func (s *Store) ListDeviceProfilesByProfile(ctx context.Context, profileID string) ([]core.DeviceProfile, error) {
	return many(ctx, s.r, scanDP, `SELECT `+dpCols+` FROM device_profiles WHERE profile_id = ? ORDER BY device_id`, profileID)
}

func (s *Store) DeleteDeviceProfile(ctx context.Context, deviceID, profileID string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM device_profiles WHERE device_id = ? AND profile_id = ?`, deviceID, profileID)
	return err
}

// ---- commands ----

const cmdCols = `uuid, device_id, channel, request_type, profile_id, status, detail, created_at, updated_at`

func scanCommand(sc scanner) (core.CommandRecord, error) {
	var c core.CommandRecord
	var channel, status, created, updated string
	if err := sc.Scan(&c.UUID, &c.DeviceID, &channel, &c.RequestType, &c.ProfileID, &status, &c.Detail, &created, &updated); err != nil {
		return c, err
	}
	c.Channel, c.Status = core.Channel(channel), core.CommandStatus(status)
	var err error
	if c.CreatedAt, err = parseTS(created); err != nil {
		return c, err
	}
	c.UpdatedAt, err = parseTS(updated)
	return c, err
}

// PutCommand creates or replaces by UUID. A zero CreatedAt keeps the
// existing row's (or is now, for a new one); a zero UpdatedAt is now.
func (s *Store) PutCommand(ctx context.Context, c core.CommandRecord) error {
	if c.UUID == "" {
		return fmt.Errorf("command uuid is required: %w", core.ErrInvalid)
	}
	now := time.Now()
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = now
	}
	keep := ts(c.CreatedAt) // "" means: keep the existing row's
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO commands (`+cmdCols+`) VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(uuid) DO UPDATE SET
			device_id = excluded.device_id, channel = excluded.channel,
			request_type = excluded.request_type, profile_id = excluded.profile_id,
			status = excluded.status, detail = excluded.detail,
			created_at = CASE WHEN ? = '' THEN commands.created_at ELSE ? END,
			updated_at = excluded.updated_at`,
		c.UUID, c.DeviceID, string(c.Channel), c.RequestType, c.ProfileID, string(c.Status), c.Detail,
		ts(c.CreatedAt), ts(c.UpdatedAt), keep, keep)
	return err
}

func (s *Store) GetCommand(ctx context.Context, uuid string) (core.CommandRecord, error) {
	return one(ctx, s.r, "command", uuid, scanCommand, `SELECT `+cmdCols+` FROM commands WHERE uuid = ?`, uuid)
}

func (s *Store) ListCommands(ctx context.Context, deviceID string, limit int) ([]core.CommandRecord, error) {
	return many(ctx, s.r, scanCommand, `SELECT `+cmdCols+` FROM commands WHERE device_id = ?
		ORDER BY created_at DESC, rowid DESC LIMIT ?`, deviceID, limitArg(limit))
}

// ---- enrollments ----

const enrCols = `token, challenge, username, created_by, created_at, expires_at, downloaded_at, used_at`

func scanEnrollment(sc scanner) (core.Enrollment, error) {
	var e core.Enrollment
	var created, expires string
	var down, used sql.NullString
	if err := sc.Scan(&e.Token, &e.Challenge, &e.Username, &e.CreatedBy, &created, &expires, &down, &used); err != nil {
		return e, err
	}
	var err error
	if e.CreatedAt, err = parseTS(created); err != nil {
		return e, err
	}
	if e.ExpiresAt, err = parseTS(expires); err != nil {
		return e, err
	}
	if e.DownloadedAt, err = parseTSPtr(down); err != nil {
		return e, err
	}
	e.UsedAt, err = parseTSPtr(used)
	return e, err
}

func (s *Store) CreateEnrollment(ctx context.Context, e core.Enrollment) error {
	if e.Token == "" || e.Challenge == "" {
		return fmt.Errorf("enrollment token and challenge are required: %w", core.ErrInvalid)
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO enrollments (`+enrCols+`) VALUES (?,?,?,?,?,?,?,?)`,
		e.Token, e.Challenge, lower(e.Username), e.CreatedBy, ts(e.CreatedAt), ts(e.ExpiresAt),
		tsPtr(e.DownloadedAt), tsPtr(e.UsedAt))
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return fmt.Errorf("enrollment token or challenge already exists: %w", core.ErrInvalid)
	}
	return err
}

func (s *Store) GetEnrollment(ctx context.Context, token string) (core.Enrollment, error) {
	// The token is a secret: keep it out of the error text.
	return one(ctx, s.r, "enrollment", "", scanEnrollment, `SELECT `+enrCols+` FROM enrollments WHERE token = ?`, token)
}

func (s *Store) GetEnrollmentByChallenge(ctx context.Context, challenge string) (core.Enrollment, error) {
	if challenge == "" {
		return core.Enrollment{}, notFound("enrollment", "")
	}
	return one(ctx, s.r, "enrollment", "", scanEnrollment, `SELECT `+enrCols+` FROM enrollments WHERE challenge = ?`, challenge)
}

// markEnrollment sets column col of the row where keyCol = key, if it is not
// set yet, in one statement.
func (s *Store) markEnrollment(ctx context.Context, col, keyCol, key string, at time.Time) error {
	res, err := s.w.ExecContext(ctx, `UPDATE enrollments SET `+col+` = ? WHERE `+keyCol+` = ? AND `+col+` IS NULL`, ts(at), key)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	var x int
	err = s.w.QueryRowContext(ctx, `SELECT 1 FROM enrollments WHERE `+keyCol+` = ?`, key).Scan(&x)
	if errors.Is(err, sql.ErrNoRows) {
		return notFound("enrollment", "")
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("enrollment already %s: %w", strings.TrimSuffix(col, "_at"), core.ErrInvalid)
}

func (s *Store) MarkEnrollmentDownloaded(ctx context.Context, token string, at time.Time) error {
	return s.markEnrollment(ctx, "downloaded_at", "token", token, at)
}

func (s *Store) MarkEnrollmentUsed(ctx context.Context, challenge string, at time.Time) error {
	if challenge == "" {
		return notFound("enrollment", "")
	}
	return s.markEnrollment(ctx, "used_at", "challenge", challenge, at)
}

func (s *Store) ListEnrollments(ctx context.Context) ([]core.Enrollment, error) {
	return many(ctx, s.r, scanEnrollment, `SELECT `+enrCols+` FROM enrollments ORDER BY created_at DESC, rowid DESC`)
}

// ---- issued certificates ----

const certCols = `serial, common_name, username, sha256, pem, not_after, issued_at, revoked_at`

func scanCert(sc scanner) (core.IssuedCert, error) {
	var c core.IssuedCert
	var notAfter, issued string
	var revoked sql.NullString
	if err := sc.Scan(&c.Serial, &c.CommonName, &c.Username, &c.SHA256, &c.PEM, &notAfter, &issued, &revoked); err != nil {
		return c, err
	}
	var err error
	if c.NotAfter, err = parseTS(notAfter); err != nil {
		return c, err
	}
	if c.IssuedAt, err = parseTS(issued); err != nil {
		return c, err
	}
	c.RevokedAt, err = parseTSPtr(revoked)
	return c, err
}

func (s *Store) PutIssuedCert(ctx context.Context, c core.IssuedCert) error {
	if c.Serial == "" {
		return fmt.Errorf("certificate serial is required: %w", core.ErrInvalid)
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = time.Now()
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO issued_certs (`+certCols+`) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(serial) DO UPDATE SET
			common_name = excluded.common_name, username = excluded.username,
			sha256 = excluded.sha256, pem = excluded.pem, not_after = excluded.not_after,
			issued_at = excluded.issued_at, revoked_at = excluded.revoked_at`,
		c.Serial, c.CommonName, lower(c.Username), lower(c.SHA256), c.PEM, ts(c.NotAfter), ts(c.IssuedAt), tsPtr(c.RevokedAt))
	return err
}

func (s *Store) GetIssuedCertBySHA256(ctx context.Context, sha256hex string) (core.IssuedCert, error) {
	return one(ctx, s.r, "certificate", sha256hex, scanCert,
		`SELECT `+certCols+` FROM issued_certs WHERE sha256 = ? ORDER BY issued_at DESC, rowid DESC LIMIT 1`, lower(sha256hex))
}

func (s *Store) ListIssuedCerts(ctx context.Context) ([]core.IssuedCert, error) {
	return many(ctx, s.r, scanCert, `SELECT `+certCols+` FROM issued_certs ORDER BY issued_at DESC, rowid DESC`)
}

// NextSerial returns the next certificate serial: 2, 3, 4, ... The counter
// is in the database, so it continues across restarts.
func (s *Store) NextSerial(ctx context.Context) (int64, error) {
	var n int64
	err := s.w.QueryRowContext(ctx, `UPDATE counters SET value = value + 1 WHERE name = 'serial' RETURNING value`).Scan(&n)
	return n, err
}

// ---- blobs ----

func (s *Store) GetBlob(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := s.r.QueryRowContext(ctx, `SELECT value FROM blobs WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("blob", key)
	}
	if err != nil {
		return nil, err
	}
	if v == nil {
		v = []byte{}
	}
	return v, nil
}

func (s *Store) PutBlob(ctx context.Context, key string, value []byte) error {
	if key == "" {
		return fmt.Errorf("blob key is required: %w", core.ErrInvalid)
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO blobs (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, append([]byte{}, value...))
	return err
}

// ---- events ----

func (s *Store) AppendEvent(ctx context.Context, e core.Event) error {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO events (at, actor, kind, subject, detail) VALUES (?,?,?,?,?)`,
		ts(e.At), e.Actor, e.Kind, e.Subject, e.Detail)
	return err
}

func (s *Store) ListEvents(ctx context.Context, limit int) ([]core.Event, error) {
	return many(ctx, s.r, func(sc scanner) (core.Event, error) {
		var e core.Event
		var at string
		if err := sc.Scan(&e.ID, &at, &e.Actor, &e.Kind, &e.Subject, &e.Detail); err != nil {
			return e, err
		}
		var err error
		e.At, err = parseTS(at)
		return e, err
	}, `SELECT id, at, actor, kind, subject, detail FROM events ORDER BY at DESC, id DESC LIMIT ?`, limitArg(limit))
}
