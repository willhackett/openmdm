package profiles

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"testing"

	"github.com/smallstep/pkcs7"
	"howett.net/plist"

	"openmdm/internal/core"
)

func plistUnmarshal(b []byte, v any) (int, error) { return plist.Unmarshal(b, v) }

func TestSign(t *testing.T) {
	auth := newAuthority(t)
	r := NewRenderer(&fakeSecrets{}, auth, "Org")
	content := []byte("<plist>hello</plist>")
	der, err := r.Sign(content)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p7.Content, content) {
		t.Fatal("content not embedded")
	}
	if len(p7.Certificates) != 2 {
		t.Fatalf("want signer and CA certificates, got %d", len(p7.Certificates))
	}
	if err := p7.VerifyWithChain(auth.caPool); err != nil {
		t.Fatal(err)
	}
	// Tampering is caught.
	p7.Content = []byte("<plist>other</plist>")
	if err := p7.Verify(); err == nil {
		t.Fatal("tampered content verified")
	}
}

func okTopic(context.Context) (string, error) { return "com.apple.mgmt.External.test", nil }

func TestEnrollmentProfile(t *testing.T) {
	auth := newAuthority(t)
	r := NewRenderer(&fakeSecrets{}, auth, "Org")
	e := NewEnroller(auth, r, EnrollerOptions{PublicURL: "https://mdm.example.com/", Organization: "Example Org", Topic: okTopic})
	der, err := e.EnrollmentProfile(context.Background(), core.Enrollment{Challenge: "chal-123"})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := p7.VerifyWithChain(auth.caPool); err != nil {
		t.Fatal(err)
	}
	var top struct {
		PayloadType, PayloadIdentifier, PayloadUUID, PayloadDisplayName, PayloadOrganization string
		PayloadRemovalDisallowed                                                             bool
		PayloadContent                                                                       []map[string]any
	}
	if _, err := plist.Unmarshal(p7.Content, &top); err != nil {
		t.Fatal(err)
	}
	if top.PayloadType != "Configuration" || top.PayloadIdentifier != "openmdm.enrollment" ||
		top.PayloadDisplayName != "Example Org device management" || top.PayloadOrganization != "Example Org" ||
		top.PayloadRemovalDisallowed || top.PayloadUUID == "" || len(top.PayloadContent) != 3 {
		t.Fatalf("%+v", top)
	}
	ca, scep, mdm := top.PayloadContent[0], top.PayloadContent[1], top.PayloadContent[2]
	if ca["PayloadType"] != "com.apple.security.root" || !bytes.Equal(ca["PayloadContent"].([]byte), auth.ca.Raw) {
		t.Fatalf("ca: %v", ca)
	}
	if scep["PayloadType"] != "com.apple.security.scep" {
		t.Fatalf("scep: %v", scep)
	}
	sc := scep["PayloadContent"].(map[string]any)
	fp := sha1.Sum(auth.ca.Raw)
	if sc["URL"] != "https://mdm.example.com/scep" || sc["Challenge"] != "chal-123" || sc["Keysize"] != uint64(2048) ||
		sc["Key Type"] != "RSA" || sc["Key Usage"] != uint64(5) || !bytes.Equal(sc["CAFingerprint"].([]byte), fp[:]) {
		t.Fatalf("scep content: %v", sc)
	}
	subj := sc["Subject"].([]any)
	if len(subj) != 2 || subj[0].([]any)[0].([]any)[1] != "Example Org" {
		t.Fatalf("subject: %v", subj)
	}
	cn := subj[1].([]any)[0].([]any)[1].(string)
	if len(cn) != len("OpenMDM device identity ")+8 {
		t.Fatalf("cn: %q", cn)
	}
	if mdm["PayloadType"] != "com.apple.mdm" || mdm["ServerURL"] != "https://mdm.example.com/mdm" ||
		mdm["CheckInURL"] != "https://mdm.example.com/mdm" || mdm["Topic"] != "com.apple.mgmt.External.test" ||
		mdm["IdentityCertificateUUID"] != scep["PayloadUUID"] || mdm["SignMessage"] != true ||
		mdm["AccessRights"] != uint64(8191) || mdm["CheckOutWhenRemoved"] != true {
		t.Fatalf("mdm: %v", mdm)
	}
	if caps := mdm["ServerCapabilities"].([]any); len(caps) != 1 || caps[0] != "com.apple.mdm.per-user-connections" {
		t.Fatalf("caps: %v", caps)
	}
	// Two profiles differ in their random parts.
	der2, _ := e.EnrollmentProfile(context.Background(), core.Enrollment{Challenge: "x"})
	if bytes.Equal(der, der2) {
		t.Fatal("not fresh")
	}
}

func TestEnrollmentNeedsTopic(t *testing.T) {
	auth := newAuthority(t)
	r := NewRenderer(&fakeSecrets{}, auth, "Org")
	for name, topic := range map[string]func(context.Context) (string, error){
		"nil":   nil,
		"empty": func(context.Context) (string, error) { return "", nil },
		"err":   func(context.Context) (string, error) { return "", errors.New("boom") },
	} {
		e := NewEnroller(auth, r, EnrollerOptions{PublicURL: "https://x", Topic: topic})
		_, err := e.EnrollmentProfile(context.Background(), core.Enrollment{Challenge: "SECRETCHALLENGE"})
		if !errors.Is(err, core.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && bytes.Contains([]byte(err.Error()), []byte("SECRETCHALLENGE")) {
			t.Errorf("%s: challenge in error", name)
		}
	}
}
