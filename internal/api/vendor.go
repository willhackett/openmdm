package api

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/pkcs12"
	"howett.net/plist"

	"openmdm/internal/api/applecerts"
)

// The MDM vendor route to a push certificate request: Apple's own. The owner
// is the MDM vendor, holding an "MDM Vendor CSR Signing Certificate" from
// Apple's developer portal; the push CSR is signed with its key here, and the
// result is the file Apple's push certificate portal accepts
// (https://developer.apple.com/documentation/devicemanagement/setting-up-push-notifications-for-your-device-management-customers).

const (
	blobVendorCert = "vendor/cert" // PEM
	blobVendorKey  = "vendor/key"  // sealed PEM

	vendorChainWarning = "The certificate does not chain to Apple's WWDR G3 intermediate, so the chain could not be verified against it. Apple's portal may reject requests signed with it."
)

type vendorCert struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func vendorInfo(c *x509.Certificate) map[string]any {
	if c == nil {
		return map[string]any{"configured": false}
	}
	sum := sha256.Sum256(c.Raw)
	return map[string]any{
		"configured": true,
		"subject":    c.Subject.String(),
		"not_after":  c.NotAfter.UTC(),
		"sha256":     hex.EncodeToString(sum[:]),
	}
}

// loadVendorCert returns the stored certificate alone; nil if there is none.
// Cleared blobs are empty (the Store has no delete), which counts as none.
func (a *API) loadVendorCert(ctx context.Context) (*x509.Certificate, error) {
	b, err := a.d.Store.GetBlob(ctx, blobVendorCert)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("the stored vendor certificate is damaged")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// loadVendor returns the certificate with its key; nil if none is configured.
func (a *API) loadVendor(ctx context.Context) (*vendorCert, error) {
	c, err := a.loadVendorCert(ctx)
	if err != nil || c == nil {
		return nil, err
	}
	keyPEM, err := a.openSealed(ctx, blobVendorKey)
	if err != nil {
		return nil, err
	}
	k, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, errors.New("the stored vendor key is damaged")
	}
	return &vendorCert{cert: c, key: k}, nil
}

func (a *API) getVendorCertificate(w http.ResponseWriter, r *http.Request) {
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	c, err := a.loadVendorCert(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vendor": vendorInfo(c)})
}

func (a *API) deleteVendorCertificate(w http.ResponseWriter, r *http.Request) {
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	ctx := r.Context()
	c, err := a.loadVendorCert(ctx)
	if err != nil {
		// A damaged one is exactly what a person wants to be rid of.
		a.log.Warn("deleting a damaged vendor certificate", "error", err)
	}
	if err := a.clearBlobs(ctx, []string{blobVendorCert, blobVendorKey}); err != nil {
		a.fail(w, r, err)
		return
	}
	if c != nil || err != nil {
		a.audit(ctx, caller(r).Username, "settings.vendor_certificate_deleted", "vendor-certificate", "")
	}
	noContent(w)
}

// parseCertificateText reads a certificate given as PEM or as base64 of a DER
// .cer. A PEM text may hold several certificates (a chain).
func parseCertificateText(s string) ([]*x509.Certificate, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("the certificate is empty")
	}
	var certs []*x509.Certificate
	if strings.Contains(s, "-----BEGIN") {
		rest := []byte(s)
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, errors.New("the certificate cannot be read: it is not a valid X.509 certificate")
			}
			certs = append(certs, c)
		}
		if len(certs) == 0 {
			return nil, errors.New("no certificate found in the PEM text")
		}
		return certs, nil
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, errors.New("the certificate is neither PEM nor base64 of a DER .cer file")
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("the certificate is neither PEM nor base64 of a DER .cer file")
	}
	return []*x509.Certificate{c}, nil
}

// parseVendorKey reads an RSA private key, with readable errors.
func parseVendorKey(s string) (*rsa.PrivateKey, error) {
	b := []byte(strings.TrimSpace(s))
	if len(b) == 0 {
		return nil, errors.New("the private key is empty")
	}
	if blk, _ := pem.Decode(b); blk != nil {
		if blk.Type == "ENCRYPTED PRIVATE KEY" || blk.Headers["DEK-Info"] != "" {
			return nil, errors.New("the private key is encrypted with a passphrase: remove the passphrase first, or upload a .p12 file instead")
		}
		if blk.Type == "EC PRIVATE KEY" {
			return nil, errors.New("the private key is not an RSA key: Apple's MDM vendor signing needs an RSA key")
		}
	} else {
		return nil, errors.New("the private key must be PEM text")
	}
	k, err := parseKeyPEM(b)
	if err != nil {
		return nil, errors.New("the private key is not an RSA private key in PEM form")
	}
	return k, nil
}

func keyMatches(c *x509.Certificate, k *rsa.PrivateKey) bool {
	pub, ok := c.PublicKey.(*rsa.PublicKey)
	return ok && pub.N.Cmp(k.N) == 0 && pub.E == k.E
}

// fromP12 opens a .p12: the RSA key and the certificate that belongs to it.
func fromP12(b64, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
	if err != nil || len(der) == 0 {
		return nil, nil, errors.New("p12 must be the base64 text of a .p12 file")
	}
	blocks, err := safeToPEM(der, password)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return nil, nil, errors.New("the .p12 file could not be opened: the password is wrong")
		}
		return nil, nil, errors.New("the .p12 file could not be read: " + sanitizeP12Error(err))
	}
	var certs []*x509.Certificate
	var keys []*rsa.PrivateKey
	for _, blk := range blocks {
		switch blk.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, nil, errors.New("the .p12 file holds a certificate that cannot be read")
			}
			certs = append(certs, c)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
			if err != nil {
				return nil, nil, errors.New("the private key in the .p12 file is not an RSA key: Apple's MDM vendor signing needs an RSA key")
			}
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, nil, errors.New("the .p12 file holds no private key")
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("the .p12 file holds no certificate")
	}
	for _, k := range keys {
		for _, c := range certs {
			if keyMatches(c, k) {
				return c, k, nil
			}
		}
	}
	return nil, nil, errors.New("the private key in the .p12 file does not belong to any certificate in it")
}

// safeToPEM wraps pkcs12.ToPEM: the library may panic on junk.
func safeToPEM(der []byte, password string) (blocks []*pem.Block, err error) {
	defer func() {
		if recover() != nil {
			blocks, err = nil, errors.New("not a PKCS#12 file")
		}
	}()
	return pkcs12.ToPEM(der, password)
}

func sanitizeP12Error(err error) string {
	m := err.Error()
	if strings.Contains(m, "algorithm") || strings.Contains(m, "unknown") {
		return "it uses an encryption this server cannot read; export it again with the legacy (3DES) option"
	}
	return "it is not a valid PKCS#12 file"
}

// chainsToWWDR reports whether the certificate was issued by Apple's WWDR G3
// intermediate (embedded in the binary).
func chainsToWWDR(c *x509.Certificate) bool {
	return c.CheckSignatureFrom(applecerts.WWDRG3()) == nil
}

func (a *API) putVendorCertificate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CertificatePEM string `json:"certificate_pem"`
		KeyPEM         string `json:"key_pem"`
		P12            string `json:"p12"`
		Password       string `json:"password"`
	}
	if !decode(w, r, &body, false) {
		return
	}
	usePEM := body.CertificatePEM != "" || body.KeyPEM != ""
	useP12 := body.P12 != ""
	switch {
	case usePEM && useP12:
		badRequest(w, "send either certificate_pem and key_pem, or p12 and password, not both")
		return
	case !usePEM && !useP12:
		badRequest(w, "send either certificate_pem and key_pem, or p12 and password")
		return
	case usePEM && (body.CertificatePEM == "" || body.KeyPEM == ""):
		badRequest(w, "both certificate_pem and key_pem are required")
		return
	}
	if body.Password != "" && !useP12 {
		badRequest(w, "password is only for a p12 file")
		return
	}

	var cert *x509.Certificate
	var key *rsa.PrivateKey
	if useP12 {
		var err error
		if cert, key, err = fromP12(body.P12, body.Password); err != nil {
			badRequest(w, err.Error())
			return
		}
	} else {
		certs, err := parseCertificateText(body.CertificatePEM)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		if key, err = parseVendorKey(body.KeyPEM); err != nil {
			badRequest(w, err.Error())
			return
		}
		for _, c := range certs {
			if keyMatches(c, key) {
				cert = c
				break
			}
		}
		if cert == nil {
			if _, ok := certs[0].PublicKey.(*rsa.PublicKey); !ok {
				badRequest(w, "the certificate does not have an RSA key: Apple's MDM vendor signing needs an RSA key")
			} else {
				badRequest(w, "the private key does not belong to the certificate")
			}
			return
		}
	}
	now := a.now()
	if now.After(cert.NotAfter) {
		badRequest(w, "the certificate expired on "+cert.NotAfter.UTC().Format("2006-01-02"))
		return
	}
	if now.Before(cert.NotBefore) {
		badRequest(w, "the certificate is not valid until "+cert.NotBefore.UTC().Format("2006-01-02"))
		return
	}
	if a.d.Sealer == nil {
		a.fail(w, r, errors.New("no sealer configured"))
		return
	}
	sealed, err := a.d.Sealer.Seal(pemKey(key))
	if err != nil {
		a.fail(w, r, err)
		return
	}

	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	ctx := r.Context()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := errors.Join(a.d.Store.PutBlob(ctx, blobVendorKey, sealed), a.d.Store.PutBlob(ctx, blobVendorCert, certPEM)); err != nil {
		_ = a.clearBlobs(ctx, []string{blobVendorCert, blobVendorKey})
		a.fail(w, r, err)
		return
	}
	info := vendorInfo(cert)
	a.audit(ctx, caller(r).Username, "settings.vendor_certificate_set", "vendor-certificate", cert.Subject.String())
	out := map[string]any{"vendor": info}
	if !chainsToWWDR(cert) {
		out["warning"] = vendorChainWarning
	}
	writeJSON(w, http.StatusOK, out)
}

// pemChain is the vendor certificate, the WWDR G3 intermediate and the Apple
// root, in that order, each PEM block with 64-character lines.
func pemChain(vendor *x509.Certificate) string {
	var sb strings.Builder
	for _, c := range []*x509.Certificate{vendor, applecerts.WWDRG3(), applecerts.Root()} {
		sb.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return sb.String()
}

// signPushRequest builds Apple's push certificate request for a CSR (PEM):
// a property list with the DER CSR, its SHA256WithRSA signature and the
// certificate chain, as XML, base64-encoded.
func signPushRequest(csrPEM []byte, v *vendorCert) (string, error) {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil {
		return "", errors.New("the pending CSR is damaged")
	}
	sum := sha256.Sum256(blk.Bytes)
	sig, err := rsa.SignPKCS1v15(rand.Reader, v.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	if err := rsa.VerifyPKCS1v15(v.cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, sum[:], sig); err != nil {
		return "", errors.New("the vendor key does not match the vendor certificate")
	}
	xml, err := plist.MarshalIndent(map[string]string{
		"PushCertRequestCSR":       base64.StdEncoding.EncodeToString(blk.Bytes),
		"PushCertSignature":        base64.StdEncoding.EncodeToString(sig),
		"PushCertCertificateChain": pemChain(v.cert),
	}, plist.XMLFormat, "\t")
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(xml), nil
}

func (a *API) postVendorSign(w http.ResponseWriter, r *http.Request) {
	if a.d.Sealer == nil {
		a.fail(w, r, errors.New("no sealer configured"))
		return
	}
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	ctx := r.Context()

	v, err := a.loadVendor(ctx)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if v == nil {
		badRequest(w, "no MDM vendor certificate is configured: add one first")
		return
	}
	if a.now().After(v.cert.NotAfter) {
		badRequest(w, "the MDM vendor certificate expired on "+v.cert.NotAfter.UTC().Format("2006-01-02")+": replace it")
		return
	}

	// Use the pending key and CSR; make them only if there are none.
	m, pending, err := a.loadPending(ctx)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var csrPEM []byte
	if pending {
		csrPEM, err = a.pendingCSR(ctx)
		if err != nil && !isNotFound(err) {
			a.fail(w, r, err)
			return
		}
	}
	if csrPEM == nil {
		if m, csrPEM, err = a.newPending(ctx); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	content, err := signPushRequest(csrPEM, v)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	sum := sha256.Sum256(v.cert.Raw)
	a.audit(ctx, caller(r).Username, "settings.push_vendor_sign", "push-certificate", fmt.Sprintf("vendor certificate %x", sum[:8]))
	writeJSON(w, http.StatusOK, map[string]any{
		"filename": decryptedFilename, "content": content, "request": pendingJSON(m, true),
	})
}
