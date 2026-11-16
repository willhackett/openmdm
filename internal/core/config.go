package core

import "time"

// Config is the whole configuration, read from a YAML file (--config) with
// environment variables able to override the secrets in it
// (OPENMDM_MASTER_KEY, OPENMDM_OIDC_CLIENT_SECRET, OPENMDM_OPENBAO_TOKEN,
// OPENMDM_OPENBAO_SECRET_ID). cmd/openmdm loads and validates it.
type Config struct {
	// Listen is the address the one HTTP server binds, e.g. ":8080". TLS is
	// expected to be terminated in front of it.
	Listen string `yaml:"listen"`
	// PublicURL is what devices use, from anywhere: the base of /mdm, /scep
	// and /enroll, e.g. "https://mdm.example.com". Changing it later means
	// enrolling every device again.
	PublicURL string `yaml:"public_url"`
	// AdminURL is where people open the UI, if it is a different name
	// (e.g. an internal one); defaults to PublicURL.
	AdminURL string `yaml:"admin_url"`
	// DataDir holds the SQLite database and the MDM engine's own files.
	DataDir string `yaml:"data_dir"`
	// ProfilesDir, if set, is a directory of profiles loaded at start and
	// whenever a file in it changes (see docs/PROFILES.md).
	ProfilesDir string `yaml:"profiles_dir"`
	// MasterKey seals the CA key and the APNs key in the database: 32 bytes,
	// base64. Lose it and every device has to enrol again.
	MasterKey string `yaml:"master_key"`
	// Organization appears in profiles and in the CA's name.
	Organization string `yaml:"organization"`

	OIDC    OIDCConfig    `yaml:"oidc"`
	Secrets SecretsConfig `yaml:"secrets"`

	// ReconcileInterval is how often every device is looked at even if
	// nothing happened (default 15m).
	ReconcileInterval time.Duration `yaml:"reconcile_interval"`
	// EnrollmentTTL is how long an enrolment link works (default 1h).
	EnrollmentTTL time.Duration `yaml:"enrollment_ttl"`
}

// OIDCConfig is single sign-on. There are no local passwords.
type OIDCConfig struct {
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// AdminGroup: members are admins. Everyone else who can sign in is a user.
	AdminGroup string `yaml:"admin_group"`
	// GroupsClaim is the claim listing a person's groups (default "groups").
	GroupsClaim string `yaml:"groups_claim"`
	// UsernameClaim is the claim used as Username (default "preferred_username").
	UsernameClaim string `yaml:"username_claim"`
	// CAFile, if set, is a PEM bundle to trust for the issuer (an internal CA).
	CAFile string `yaml:"ca_file"`
}

// SecretsConfig chooses and configures the SecretStore.
type SecretsConfig struct {
	// Backend is "openbao" (also works with Vault), "file" or "memory".
	Backend string `yaml:"backend"`

	// openbao: a KV version 2 mount, and the path under it that is ours.
	// People's secrets are at <Mount>/<Prefix>/users/<username>, global ones
	// at <Mount>/<Prefix>/global. Nothing outside <Prefix> is ever read or
	// written; the token's policy should allow nothing else either.
	Address string `yaml:"address"`
	Mount   string `yaml:"mount"`  // default "secret"
	Prefix  string `yaml:"prefix"` // default "openmdm"
	// Either a token (Token, or TokenFile re-read when it changes) or
	// AppRole (RoleID with SecretID or SecretIDFile).
	Token        string `yaml:"token"`
	TokenFile    string `yaml:"token_file"`
	RoleID       string `yaml:"role_id"`
	SecretID     string `yaml:"secret_id"`
	SecretIDFile string `yaml:"secret_id_file"`
	CAFile       string `yaml:"ca_file"`

	// file: a JSON file, for development only (values in the clear).
	File string `yaml:"file"`
}
