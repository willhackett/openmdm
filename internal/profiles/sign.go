package profiles

import (
	"bytes"
	"fmt"

	"github.com/smallstep/pkcs7"
)

// Sign implements core.Renderer: a CMS SignedData with the content embedded,
// the signing certificate and the CA certificate included, as DER. This is
// what a device accepts as a signed .mobileconfig.
func (r *Renderer) Sign(content []byte) ([]byte, error) {
	cert, key := r.authority.SigningIdentity()
	if cert == nil || key == nil {
		return nil, fmt.Errorf("signing identity is not available")
	}
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	if ca := r.authority.CACertificate(); ca != nil && !bytes.Equal(ca.Raw, cert.Raw) {
		sd.AddCertificate(ca)
	}
	out, err := sd.Finish()
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	return out, nil
}
