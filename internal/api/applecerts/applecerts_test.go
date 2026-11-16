package applecerts

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// Apple's published SHA-256 fingerprint of the Apple Root CA.
const rootSHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"

func TestEmbeddedCertificates(t *testing.T) {
	root, wwdr := Root(), WWDRG3()

	if sum := sha256.Sum256(root.Raw); hex.EncodeToString(sum[:]) != rootSHA256 {
		t.Errorf("root fingerprint = %x", sum)
	}
	if root.Subject.CommonName != "Apple Root CA" || strings.Join(root.Subject.Organization, "") != "Apple Inc." {
		t.Errorf("root subject = %s", root.Subject)
	}
	// The root (2006) is signed with SHA-1, which crypto/x509 refuses to
	// verify, so check its self-signature by hand.
	pub, ok := root.PublicKey.(*rsa.PublicKey)
	if !ok || root.SignatureAlgorithm != x509.SHA1WithRSA {
		t.Fatalf("unexpected root key or algorithm: %T %v", root.PublicKey, root.SignatureAlgorithm)
	}
	h := sha1.Sum(root.RawTBSCertificate)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, h[:], root.Signature); err != nil || root.Subject.String() != root.Issuer.String() {
		t.Errorf("root is not self-signed: %v", err)
	}
	if !strings.Contains(wwdr.Subject.String(), "Worldwide Developer Relations") || !strings.Contains(wwdr.Subject.String(), "G3") {
		t.Errorf("intermediate subject = %s", wwdr.Subject)
	}
	if err := wwdr.CheckSignatureFrom(root); err != nil {
		t.Errorf("WWDR G3 is not signed by the root: %v", err)
	}
	// An expired embedded certificate must fail the build, not a customer.
	now := time.Now()
	if now.After(root.NotAfter) || now.Before(root.NotBefore) {
		t.Errorf("root is not valid now (until %s)", root.NotAfter)
	}
	if now.After(wwdr.NotAfter) || now.Before(wwdr.NotBefore) {
		t.Errorf("WWDR G3 is not valid now (until %s): update the embedded certificate", wwdr.NotAfter)
	}
	for _, p := range [][]byte{RootPEM(), WWDRG3PEM()} {
		for _, line := range strings.Split(strings.TrimSpace(string(p)), "\n") {
			if len(line) > 64 {
				t.Errorf("PEM line longer than 64 characters")
			}
		}
	}
}
