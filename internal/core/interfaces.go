package core

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"
)

// Store is everything OpenMDM keeps of its own (SQLite; internal/store).
// The MDM engine's protocol state (push tokens, the command queue) is not
// here: the engine keeps that itself.
//
// Every method that looks one thing up returns ErrNotFound when it is not
// there. Lists are never nil. Times are UTC.
type Store interface {
	// Users. UpsertUser creates or updates by Username and returns the row;
	// it sets CreatedAt on creation and never clears LastLoginAt.
	UpsertUser(ctx context.Context, u User) (User, error)
	GetUser(ctx context.Context, username string) (User, error)
	ListUsers(ctx context.Context) ([]User, error)

	// Devices. UpsertDevice creates or replaces by ID, keeping EnrolledAt
	// from the existing row when the given one is zero.
	UpsertDevice(ctx context.Context, d Device) error
	GetDevice(ctx context.Context, id string) (Device, error)
	ListDevices(ctx context.Context) ([]Device, error)
	ListDevicesByUser(ctx context.Context, username string) ([]Device, error)
	DeleteDevice(ctx context.Context, id string) error // also its DeviceProfiles

	// Profiles. PutProfile creates or replaces by ID and sets UpdatedAt.
	PutProfile(ctx context.Context, p Profile) error
	GetProfile(ctx context.Context, id string) (Profile, error)
	ListProfiles(ctx context.Context) ([]Profile, error)
	DeleteProfile(ctx context.Context, id string) error // DeviceProfiles are left for the reconciler

	// The state of profiles on devices. PutDeviceProfile creates or replaces
	// by (DeviceID, ProfileID) and sets UpdatedAt.
	PutDeviceProfile(ctx context.Context, dp DeviceProfile) error
	GetDeviceProfileByCommand(ctx context.Context, commandUUID string) (DeviceProfile, error)
	ListDeviceProfiles(ctx context.Context, deviceID string) ([]DeviceProfile, error)
	ListDeviceProfilesByProfile(ctx context.Context, profileID string) ([]DeviceProfile, error)
	DeleteDeviceProfile(ctx context.Context, deviceID, profileID string) error

	// The command log. PutCommand creates or replaces by UUID.
	PutCommand(ctx context.Context, c CommandRecord) error
	GetCommand(ctx context.Context, uuid string) (CommandRecord, error)
	ListCommands(ctx context.Context, deviceID string, limit int) ([]CommandRecord, error) // newest first

	// Enrolments.
	CreateEnrollment(ctx context.Context, e Enrollment) error
	GetEnrollment(ctx context.Context, token string) (Enrollment, error)
	GetEnrollmentByChallenge(ctx context.Context, challenge string) (Enrollment, error)
	// MarkEnrollmentDownloaded and MarkEnrollmentUsed set the timestamp only
	// if it is not set yet, and return ErrInvalid if it already was (so two
	// callers racing cannot both win).
	MarkEnrollmentDownloaded(ctx context.Context, token string, at time.Time) error
	MarkEnrollmentUsed(ctx context.Context, challenge string, at time.Time) error
	ListEnrollments(ctx context.Context) ([]Enrollment, error) // newest first, expired included

	// Certificates the CA has issued.
	PutIssuedCert(ctx context.Context, c IssuedCert) error
	GetIssuedCertBySHA256(ctx context.Context, sha256hex string) (IssuedCert, error)
	ListIssuedCerts(ctx context.Context) ([]IssuedCert, error)
	// NextSerial returns a new certificate serial number, never repeating.
	NextSerial(ctx context.Context) (int64, error)

	// Blobs is a small key-value table for things that belong to the server
	// and not to a person: the CA certificate and its sealed key, the sealed
	// APNs key, the session key. GetBlob returns ErrNotFound if unset.
	GetBlob(ctx context.Context, key string) ([]byte, error)
	PutBlob(ctx context.Context, key string, value []byte) error

	// The audit log. AppendEvent sets ID and, if zero, At.
	AppendEvent(ctx context.Context, e Event) error
	ListEvents(ctx context.Context, limit int) ([]Event, error) // newest first

	Close() error
}

// SecretStore is where secret values live: OpenBao (internal/secrets), or a
// file or memory for development. OpenMDM holds no secret value in its own
// database. A person's secrets are one document of string fields, and there
// is one more document of global ones. An implementation must not be able
// to reach outside its configured prefix.
//
// Keys match [a-z0-9_]+. A value that is binary (a .p12) is stored
// base64-encoded; the template says which it expects.
type SecretStore interface {
	// UserSecrets returns every secret of one person; an empty map (not an
	// error) if they have none.
	UserSecrets(ctx context.Context, username string) (map[string]string, error)
	SetUserSecret(ctx context.Context, username, key, value string) error
	DeleteUserSecret(ctx context.Context, username, key string) error
	GlobalSecrets(ctx context.Context) (map[string]string, error)
	SetGlobalSecret(ctx context.Context, key, value string) error
	DeleteGlobalSecret(ctx context.Context, key string) error
	// Health reports whether the store can be reached and written to.
	Health(ctx context.Context) error
}

// Sealer encrypts what must be kept in the Store but not in the clear (the
// CA key, the APNs key). The key comes from the configuration.
type Sealer interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}

// Authority is the built-in certificate authority (internal/pki). It issues
// device identity certificates over SCEP and holds the identity profiles are
// signed with.
type Authority interface {
	// CACertificate is the root; it goes into the enrolment profile so that
	// devices trust the server's signatures.
	CACertificate() *x509.Certificate
	// SigningIdentity is what profiles are signed with: a certificate the CA
	// issued for the purpose, and its key.
	SigningIdentity() (*x509.Certificate, crypto.Signer)
	// VerifyIssued reports whether cert was issued by this CA, is within its
	// validity and has not been revoked.
	VerifyIssued(ctx context.Context, cert *x509.Certificate) error
}

// Rendered is a profile made ready for one device.
type Rendered struct {
	// Content is the unsigned .mobileconfig; nil if Missing is not empty.
	Content []byte
	// Identifier is its top-level PayloadIdentifier.
	Identifier string
	// Hash is the hex SHA-256 of Content.
	Hash string
	// Missing lists what could not be filled in, as text for a person:
	// `secret "fastmail_app_password"`, `global secret "wifi_psk"`,
	// "an owner". Non-empty means the profile is blocked for this device.
	Missing []string
}

// Renderer turns a Profile into what one device should receive
// (internal/profiles). It reads secrets through a SecretStore and never
// logs or returns a secret value in an error.
type Renderer interface {
	// Render fills in the template for device d owned by u (u is nil if the
	// device has no owner). A missing secret is not an error: it is reported
	// in Rendered.Missing. An error means the template itself is broken.
	Render(ctx context.Context, p Profile, d Device, u *User) (Rendered, error)
	// Validate checks a template without any device: that it parses, is a
	// property list once the actions are replaced by placeholders, and has a
	// PayloadIdentifier and PayloadUUID. It returns the secrets it names.
	Validate(p Profile) (TemplateInfo, error)
	// Sign wraps a rendered profile in a CMS signature by the Authority's
	// signing identity.
	Sign(content []byte) ([]byte, error)
}

// TemplateInfo is what a template refers to.
type TemplateInfo struct {
	Identifier    string   `json:"identifier"`
	UserSecrets   []string `json:"user_secrets"`
	GlobalSecrets []string `json:"global_secrets"`
	PayloadTypes  []string `json:"payload_types"`
}

// MDM is the protocol engine (internal/mdm, on top of NanoMDM): it queues
// commands for devices and wakes them through APNs. target is an MDM
// enrollment ID: Device.ID for the device channel, Device.UserChannelID for
// a Mac's user channel.
type MDM interface {
	// InstallProfile queues an InstallProfile command carrying the (signed)
	// profile and returns the command's UUID.
	InstallProfile(ctx context.Context, target string, profile []byte) (string, error)
	// RemoveProfile queues a RemoveProfile for a PayloadIdentifier.
	RemoveProfile(ctx context.Context, target, identifier string) (string, error)
	// Enqueue queues any other command. command is the "Command" dictionary
	// without RequestType, e.g. {"PIN": "123456"} for DeviceLock; nil if the
	// command takes no arguments.
	Enqueue(ctx context.Context, target, requestType string, command map[string]any) (string, error)
	// Push asks APNs to wake the targets so that they fetch their queue. It
	// is not an error for a target to have no push token yet.
	Push(ctx context.Context, targets ...string) error
	// PushInfo and SetPushCert manage the APNs certificate (PEM).
	PushInfo(ctx context.Context) (PushInfo, error)
	SetPushCert(ctx context.Context, certPEM, keyPEM []byte) error
}

// Checkin is what the MDM engine learned from a device checking in.
type Checkin struct {
	DeviceID     string // UDID
	UserID       string // the Mac user's GUID, on a user-channel check-in; else ""
	EnrollmentID string // the engine's ID for this channel
	SerialNumber string
	Model        string
	ProductName  string // "iPhone", "iPad", "MacBookPro18,3"...; the platform is derived from it
	DeviceName   string
	OSVersion    string
	// CertSHA256 is the hex SHA-256 of the identity certificate the device
	// presented, which GetIssuedCertBySHA256 ties to an owner.
	CertSHA256 string
}

// CommandResult is a device's answer to a command.
type CommandResult struct {
	CommandUUID  string
	EnrollmentID string
	DeviceID     string
	Status       CommandStatus
	// ErrorText is the device's ErrorChain, flattened to one line.
	ErrorText string
	// Raw is the whole response property list.
	Raw []byte
}

// Events is how the MDM engine reports what devices do. internal/engine
// implements it. Methods must return quickly and must not fail the device's
// request: they record and schedule, nothing more.
type Events interface {
	// DeviceAuthenticated: first message of an enrolment (or re-enrolment).
	DeviceAuthenticated(ctx context.Context, c Checkin)
	// DeviceTokenUpdated: the channel has a push token; the device (or the
	// Mac's user channel, if c.UserID is set) can now be sent commands.
	DeviceTokenUpdated(ctx context.Context, c Checkin)
	// DeviceCheckedOut: the MDM profile was removed from the device.
	DeviceCheckedOut(ctx context.Context, c Checkin)
	// CommandResulted: a device answered a command.
	CommandResulted(ctx context.Context, r CommandResult)
}

// Reconciler makes devices match what the profiles and assignments say
// (internal/engine). Trigger and TriggerAll only schedule; the work happens
// on the engine's own goroutine, one device at a time.
type Reconciler interface {
	Trigger(deviceID string)
	TriggerAll()
	// Plan says, without changing anything, what a device should have and
	// why: one entry per profile that is wanted or installed.
	Plan(ctx context.Context, deviceID string) ([]PlanEntry, error)
}

// PlanEntry is one profile's standing for one device, as the reconciler
// sees it now.
type PlanEntry struct {
	ProfileID string       `json:"profile_id"`
	Name      string       `json:"name"`
	Wanted    bool         `json:"wanted"`
	Reason    string       `json:"reason"` // why it is wanted or not: "assigned to everyone", "platform ios not listed", ...
	State     ProfileState `json:"state"`  // "" if not on the device and not wanted
	Channel   Channel      `json:"channel"`
	Detail    string       `json:"detail"`
}

// Enroller makes enrolment profiles (internal/profiles builds the property
// list; this is the interface the HTTP layer uses).
type Enroller interface {
	// EnrollmentProfile returns the signed enrolment .mobileconfig for an
	// Enrollment: the CA certificate, a SCEP payload carrying its Challenge,
	// and the MDM payload.
	EnrollmentProfile(ctx context.Context, e Enrollment) ([]byte, error)
}
