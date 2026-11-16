// Package core is the contract between every other package in OpenMDM: the
// domain types and the interfaces the parts talk through. It imports nothing
// from the rest of the module, and no package under internal/ imports
// another one except through the interfaces here (cmd/openmdm wires the
// concrete implementations together).
package core

import (
	"errors"
	"time"
)

// ErrNotFound is returned by every lookup that finds nothing. Wrap it; test
// with errors.Is.
var ErrNotFound = errors.New("not found")

// ErrForbidden: the caller is signed in but may not do this.
var ErrForbidden = errors.New("forbidden")

// ErrInvalid: the request is malformed. The wrapped message is safe to show.
var ErrInvalid = errors.New("invalid")

// Platform is the kind of Apple device.
type Platform string

const (
	PlatformMacOS  Platform = "macos"
	PlatformIOS    Platform = "ios"
	PlatformIPadOS Platform = "ipados"
)

// Role decides what a signed-in person may do. An admin manages everything;
// a user sees their own devices and sets their own secrets.
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// User is a person, as the identity provider describes them. Username is the
// key everywhere (OIDC preferred_username, lower-cased) and is also the name
// of their secrets in the secret store.
type User struct {
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	Groups      []string  `json:"groups"`
	Role        Role      `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
	LastLoginAt time.Time `json:"last_login_at"`
}

// DeviceStatus is where a device is in its life with this server.
type DeviceStatus string

const (
	// DeviceEnrolled: checked in and holding a push token.
	DeviceEnrolled DeviceStatus = "enrolled"
	// DevicePending: authenticated but no push token yet.
	DevicePending DeviceStatus = "pending"
	// DeviceUnenrolled: the MDM profile was removed, or an admin removed it.
	DeviceUnenrolled DeviceStatus = "unenrolled"
)

// Device is one enrolled Mac, iPhone or iPad. ID is its UDID, which is also
// the MDM engine's enrollment ID for the device channel.
type Device struct {
	ID           string       `json:"id"`
	Username     string       `json:"username"` // owner; "" until known
	Platform     Platform     `json:"platform"`
	SerialNumber string       `json:"serial_number"`
	Model        string       `json:"model"`
	DeviceName   string       `json:"device_name"`
	OSVersion    string       `json:"os_version"`
	Status       DeviceStatus `json:"status"`
	// UserChannelID is the MDM engine's enrollment ID of the Mac's user
	// channel ("<UDID>:<user GUID>"), over which user-scoped profiles are
	// sent. Empty on iPhone and iPad and on a Mac nobody has logged in to
	// since enrolling.
	UserChannelID string    `json:"user_channel_id"`
	EnrolledAt    time.Time `json:"enrolled_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}

// Channel is which MDM connection a command travels on.
type Channel string

const (
	ChannelDevice Channel = "device"
	ChannelUser   Channel = "user" // macOS only
)

// Assignment says who gets a profile. Everyone, or the named users, or the
// members of the named groups (the identity provider's groups). The three
// are OR-ed; an empty Assignment gives the profile to nobody.
type Assignment struct {
	Everyone bool     `json:"everyone" yaml:"everyone"`
	Users    []string `json:"users" yaml:"users"`
	Groups   []string `json:"groups" yaml:"groups"`
}

// Profile is a configuration profile template. One Profile serves every
// platform it lists: on a Mac it is sent on the channel MacOSChannel names,
// on an iPhone or iPad always on the device channel. Template is a
// .mobileconfig with template actions in it (see docs/PROFILES.md); it is
// rendered per device and per owner at the moment it is sent.
type Profile struct {
	ID           string     `json:"id"` // slug: [a-z0-9-]+
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Platforms    []Platform `json:"platforms"`
	MacOSChannel Channel    `json:"macos_channel"` // "device" (default) or "user"
	Assignment   Assignment `json:"assignment"`
	Template     string     `json:"template"`
	// Source is "file" for a profile loaded from the profiles directory
	// (read-only in the UI) and "ui" for one made in the UI.
	Source    string    `json:"source"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ProfileState is how one profile stands on one device.
type ProfileState string

const (
	// StatePending: should be on the device; not sent yet.
	StatePending ProfileState = "pending"
	// StateBlocked: cannot be rendered for this device; Detail says why
	// (a secret that is not set, no owner, no user channel yet).
	StateBlocked ProfileState = "blocked"
	// StateSent: the install command is queued or the device said NotNow.
	StateSent ProfileState = "sent"
	// StateInstalled: the device acknowledged the install.
	StateInstalled ProfileState = "installed"
	// StateFailed: the device refused it; Detail is the device's reason.
	StateFailed ProfileState = "failed"
	// StateRemoving: no longer wanted; the remove command is queued.
	StateRemoving ProfileState = "removing"
)

// DeviceProfile is the record of one profile on one device. A row exists
// while the profile is wanted there or still being removed; once a removal
// is acknowledged the row is deleted.
type DeviceProfile struct {
	DeviceID  string       `json:"device_id"`
	ProfileID string       `json:"profile_id"`
	State     ProfileState `json:"state"`
	Channel   Channel      `json:"channel"`
	// Identifier is the top-level PayloadIdentifier of what was sent, kept
	// so that it can be removed after the Profile itself is gone.
	Identifier string `json:"identifier"`
	// ContentHash is the hex SHA-256 of the rendered, unsigned profile last
	// sent. A different hash for the same device means it must be sent again.
	ContentHash string    `json:"content_hash"`
	CommandUUID string    `json:"command_uuid"`
	Detail      string    `json:"detail"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CommandStatus is the device's latest answer to a command.
type CommandStatus string

const (
	CommandQueued       CommandStatus = "queued"
	CommandAcknowledged CommandStatus = "acknowledged"
	CommandError        CommandStatus = "error"
	CommandNotNow       CommandStatus = "notnow"
)

// CommandRecord is the log of one MDM command.
type CommandRecord struct {
	UUID        string        `json:"uuid"`
	DeviceID    string        `json:"device_id"`
	Channel     Channel       `json:"channel"`
	RequestType string        `json:"request_type"` // InstallProfile, RemoveProfile, DeviceLock, ...
	ProfileID   string        `json:"profile_id"`   // "" unless about a profile
	Status      CommandStatus `json:"status"`
	Detail      string        `json:"detail"` // the device's error text, if any
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// Enrollment is an invitation to enrol one device for one person. Token is
// the unguessable part of the link (/enroll/<token>); Challenge is the SCEP
// challenge password written into the enrolment profile made from it. Both
// are single use: the token until the profile has been downloaded
// (DownloadedAt), the challenge until a certificate has been issued (UsedAt).
type Enrollment struct {
	Token        string     `json:"token"`
	Challenge    string     `json:"-"`
	Username     string     `json:"username"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	DownloadedAt *time.Time `json:"downloaded_at"`
	UsedAt       *time.Time `json:"used_at"`
}

// IssuedCert is a certificate the built-in CA issued over SCEP. For a device
// identity certificate Username is the person the enrolment was for, which
// is how a device that checks in is tied to its owner.
type IssuedCert struct {
	Serial     string     `json:"serial"` // decimal
	CommonName string     `json:"common_name"`
	Username   string     `json:"username"`
	SHA256     string     `json:"sha256"` // hex, of the DER
	PEM        string     `json:"-"`
	NotAfter   time.Time  `json:"not_after"`
	IssuedAt   time.Time  `json:"issued_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

// Event is one line of the audit log: who did what to what.
type Event struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`   // username, "device:<UDID>" or "system"
	Kind    string    `json:"kind"`    // e.g. "secret.set", "device.enrolled", "profile.installed"
	Subject string    `json:"subject"` // what it was done to
	Detail  string    `json:"detail"`  // never a secret value
}

// PushInfo describes the APNs push certificate in use.
type PushInfo struct {
	Configured bool      `json:"configured"`
	Topic      string    `json:"topic"`
	NotAfter   time.Time `json:"not_after"`
}
