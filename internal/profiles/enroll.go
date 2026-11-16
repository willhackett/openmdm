package profiles

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"howett.net/plist"

	"openmdm/internal/core"
)

var _ core.Enroller = (*Enroller)(nil)

// EnrollerOptions configures an Enroller.
type EnrollerOptions struct {
	// PublicURL is what devices use, e.g. "https://mdm.example.com".
	PublicURL    string
	Organization string
	// Topic returns the APNs topic of the push certificate. An empty topic or
	// an error means push is not set up yet.
	Topic func(ctx context.Context) (string, error)
}

// Enroller implements core.Enroller.
type Enroller struct {
	authority core.Authority
	renderer  core.Renderer
	opts      EnrollerOptions
}

// NewEnroller makes an Enroller. The renderer signs the profile it builds.
func NewEnroller(authority core.Authority, renderer core.Renderer, opts EnrollerOptions) *Enroller {
	return &Enroller{authority: authority, renderer: renderer, opts: opts}
}

func newUUID() string { return strings.ToUpper(uuid.NewString()) }

// EnrollmentProfile implements core.Enroller.
func (e *Enroller) EnrollmentProfile(ctx context.Context, en core.Enrollment) ([]byte, error) {
	var topic string
	if e.opts.Topic != nil {
		t, err := e.opts.Topic(ctx)
		if err == nil {
			topic = t
		}
	}
	if topic == "" {
		return nil, fmt.Errorf("%w: the APNs push certificate has not been uploaded yet, so devices cannot be enrolled", core.ErrInvalid)
	}
	ca := e.authority.CACertificate()
	if ca == nil {
		return nil, fmt.Errorf("the certificate authority has no certificate")
	}
	base := strings.TrimRight(e.opts.PublicURL, "/")
	fingerprint := sha1.Sum(ca.Raw)
	rnd := make([]byte, 4)
	if _, err := rand.Read(rnd); err != nil {
		return nil, err
	}
	scepUUID := newUUID()
	org := e.opts.Organization

	caPayload := map[string]any{
		"PayloadType":        "com.apple.security.root",
		"PayloadVersion":     1,
		"PayloadIdentifier":  "openmdm.enrollment.ca",
		"PayloadUUID":        newUUID(),
		"PayloadDisplayName": "OpenMDM certificate authority",
		"PayloadContent":     ca.Raw,
	}
	scepPayload := map[string]any{
		"PayloadType":        "com.apple.security.scep",
		"PayloadVersion":     1,
		"PayloadIdentifier":  "openmdm.enrollment.scep",
		"PayloadUUID":        scepUUID,
		"PayloadDisplayName": "OpenMDM device identity",
		"PayloadContent": map[string]any{
			"URL":           base + "/scep",
			"Name":          "OpenMDM",
			"Challenge":     en.Challenge,
			"Keysize":       2048,
			"Key Type":      "RSA",
			"Key Usage":     5,
			"Subject":       [][][]string{{{"O", org}}, {{"CN", "OpenMDM device identity " + hex.EncodeToString(rnd)}}},
			"CAFingerprint": fingerprint[:],
			"Retries":       3,
			"RetryDelay":    10,
		},
	}
	mdmPayload := map[string]any{
		"PayloadType":             "com.apple.mdm",
		"PayloadVersion":          1,
		"PayloadIdentifier":       "openmdm.enrollment.mdm",
		"PayloadUUID":             newUUID(),
		"PayloadDisplayName":      "OpenMDM",
		"ServerURL":               base + "/mdm",
		"CheckInURL":              base + "/mdm",
		"Topic":                   topic,
		"IdentityCertificateUUID": scepUUID,
		"SignMessage":             true,
		"AccessRights":            8191,
		"CheckOutWhenRemoved":     true,
		"ServerCapabilities":      []string{"com.apple.mdm.per-user-connections"},
	}
	top := map[string]any{
		"PayloadType":              "Configuration",
		"PayloadVersion":           1,
		"PayloadIdentifier":        "openmdm.enrollment",
		"PayloadUUID":              newUUID(),
		"PayloadDisplayName":       org + " device management",
		"PayloadOrganization":      org,
		"PayloadRemovalDisallowed": false,
		"PayloadContent":           []any{caPayload, scepPayload, mdmPayload},
	}
	var buf bytes.Buffer
	enc := plist.NewEncoder(&buf)
	enc.Indent("\t")
	if err := enc.Encode(top); err != nil {
		return nil, fmt.Errorf("building the enrolment profile: %w", err)
	}
	return e.renderer.Sign(buf.Bytes())
}
