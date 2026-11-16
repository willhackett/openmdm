package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/smallstep/pkcs7"

	"openmdm/internal/core"
)

// A push certificate request goes through the free signing service
// mdmcert.download, the way micromdm's mdmctl does it
// (cmd/mdmctl/mdmcert.download.go). The service countersigns the CSR as an
// MDM vendor and emails the result, encrypted to a certificate we send it.

const (
	// DefaultSigningURL is the service's endpoint.
	DefaultSigningURL = "https://mdmcert.download/api/v1/signrequest"
	// signingAPIKey is the service's fixed, public API key (the one mdmctl
	// and commandment use); it identifies the client program, not a person.
	signingAPIKey = "f847aea2ba06b41264d587b229e2712c89b1490a1208b7ff1aafab5bb40d47bc"
	// signingUserAgent is what mdmctl sends; the service may refuse others.
	signingUserAgent = "micromdm/certhelper"

	blobPendingKey     = "push/pending-key"         // sealed PEM, the push key
	blobPendingEncKey  = "push/pending-encrypt-key" // sealed PEM, the key the answer is encrypted to
	blobPendingEncCert = "push/pending-encrypt-cert"
	blobPendingMeta    = "push/pending-meta"
	blobPendingCSR     = "push/pending-csr" // the PEM CSR for the pending key

	csrFilename = "openmdm-push.csr"

	decryptedFilename = "push-certificate-request.plist.b64"
)

var pendingBlobs = []string{blobPendingKey, blobPendingCSR, blobPendingEncKey, blobPendingEncCert, blobPendingMeta}

// encryptionBlobs exist only while a countersigning request is out.
var encryptionBlobs = []string{blobPendingEncKey, blobPendingEncCert}

type pendingMeta struct {
	Email       string    `json:"email"`
	RequestedAt time.Time `json:"requested_at"`
}

// signRequest is the service's request body.
type signRequest struct {
	CSR     string `json:"csr"` // base64 of the PEM CSR
	Email   string `json:"email"`
	Key     string `json:"key"`
	Encrypt string `json:"encrypt"` // base64 of the PEM certificate to encrypt the answer to
}

// loadPending returns the pending request, if there is one. Cleared blobs
// are empty (the Store has no delete), which counts as none.
func (a *API) loadPending(ctx context.Context) (pendingMeta, bool, error) {
	raw, err := a.d.Store.GetBlob(ctx, blobPendingMeta)
	if err != nil {
		if isNotFound(err) {
			return pendingMeta{}, false, nil
		}
		return pendingMeta{}, false, err
	}
	if len(raw) == 0 {
		return pendingMeta{}, false, nil
	}
	var m pendingMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return pendingMeta{}, false, fmt.Errorf("pending request is damaged: %w", err)
	}
	return m, true, nil
}

// clearPending forgets the request and its keys.
func (a *API) clearPending(ctx context.Context) error { return a.clearBlobs(ctx, pendingBlobs) }

func (a *API) clearBlobs(ctx context.Context, keys []string) error {
	var errs []error
	for _, k := range keys {
		if _, err := a.d.Store.GetBlob(ctx, k); err != nil && isNotFound(err) {
			continue
		}
		errs = append(errs, a.d.Store.PutBlob(ctx, k, []byte{}))
	}
	return errors.Join(errs...)
}

func pendingJSON(m pendingMeta, pending bool) map[string]any {
	if !pending {
		return map[string]any{"pending": false}
	}
	return map[string]any{"pending": true, "email": m.Email, "requested_at": m.RequestedAt}
}

func (a *API) getPushRequest(w http.ResponseWriter, r *http.Request) {
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	m, pending, err := a.loadPending(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"request": pendingJSON(m, pending)})
}

func (a *API) deletePushRequest(w http.ResponseWriter, r *http.Request) {
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	ctx := r.Context()
	_, pending, err := a.loadPending(ctx)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.clearPending(ctx); err != nil {
		a.fail(w, r, err)
		return
	}
	if pending {
		a.audit(ctx, caller(r).Username, "settings.push_request_deleted", "push-certificate", "")
	}
	noContent(w)
}

func pemKey(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

// parseKeyPEM reads what pemKey wrote (or a bare DER key).
func parseKeyPEM(b []byte) (*rsa.PrivateKey, error) {
	der := b
	if blk, _ := pem.Decode(b); blk != nil {
		der = blk.Bytes
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("not an RSA private key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rk, nil
}

// openSealedPEM returns the PEM of a sealed key blob.
func (a *API) openSealed(ctx context.Context, blob string) ([]byte, error) {
	sealed, err := a.d.Store.GetBlob(ctx, blob)
	if err != nil {
		return nil, err
	}
	if len(sealed) == 0 {
		return nil, core.ErrNotFound
	}
	return a.d.Sealer.Open(sealed)
}

// newPending makes a push key and its CSR, replacing whatever was pending.
// Only the pending blobs change: a push certificate already in use is not
// touched until a new one is uploaded and accepted.
func (a *API) newPending(ctx context.Context) (pendingMeta, []byte, error) {
	pushKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return pendingMeta{}, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "OpenMDM push certificate", Organization: orgList(a.d.Config.Organization)},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, pushKey)
	if err != nil {
		return pendingMeta{}, nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	sealed, err := a.d.Sealer.Seal(pemKey(pushKey))
	if err != nil {
		return pendingMeta{}, nil, err
	}
	m := pendingMeta{RequestedAt: a.now().UTC()}
	if err := a.clearPending(ctx); err != nil {
		return pendingMeta{}, nil, err
	}
	if err := a.putMeta(ctx, blobPendingKey, sealed, blobPendingCSR, csrPEM, m); err != nil {
		_ = a.clearPending(ctx)
		return pendingMeta{}, nil, err
	}
	return m, csrPEM, nil
}

func (a *API) putMeta(ctx context.Context, k1 string, v1 []byte, k2 string, v2 []byte, m pendingMeta) error {
	meta, err := json.Marshal(m)
	if err != nil {
		return err
	}
	for _, kv := range []struct {
		k string
		v []byte
	}{{k1, v1}, {k2, v2}, {blobPendingMeta, meta}} {
		if err := a.d.Store.PutBlob(ctx, kv.k, kv.v); err != nil {
			return err
		}
	}
	return nil
}

func (a *API) putMetaOnly(ctx context.Context, m pendingMeta) error {
	meta, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return a.d.Store.PutBlob(ctx, blobPendingMeta, meta)
}

// pendingCSR returns the pending CSR, or ErrNotFound.
func (a *API) pendingCSR(ctx context.Context) ([]byte, error) {
	b, err := a.d.Store.GetBlob(ctx, blobPendingCSR)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, core.ErrNotFound
	}
	return b, nil
}

func csrJSON(csr []byte, m pendingMeta) map[string]any {
	return map[string]any{"filename": csrFilename, "csr_pem": string(csr), "request": pendingJSON(m, true)}
}

func (a *API) postPushCSR(w http.ResponseWriter, r *http.Request) {
	if a.d.Sealer == nil {
		a.fail(w, r, errors.New("no sealer configured"))
		return
	}
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	m, csr, err := a.newPending(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r.Context(), caller(r).Username, "settings.push_csr", "push-certificate", "")
	writeJSON(w, http.StatusOK, csrJSON(csr, m))
}

func (a *API) getPushCSR(w http.ResponseWriter, r *http.Request) {
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	ctx := r.Context()
	m, pending, err := a.loadPending(ctx)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !pending {
		writeError(w, http.StatusNotFound, "no certificate signing request is pending")
		return
	}
	csr, err := a.pendingCSR(ctx)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, csrJSON(csr, m))
}

func (a *API) postPushRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &body, false) {
		return
	}
	email := strings.TrimSpace(body.Email)
	if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email || len(email) > 254 || strings.ContainsAny(email, "\r\n") {
		badRequest(w, "a valid email address is required: the signing service emails the request to it")
		return
	}
	if a.d.Sealer == nil {
		a.fail(w, r, errors.New("no sealer configured"))
		return
	}
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	ctx := r.Context()

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

	encKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	now := a.now().UTC()
	encTmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "OpenMDM mdmcert.download exchange"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	encDER, err := x509.CreateCertificate(rand.Reader, encTmpl, encTmpl, &encKey.PublicKey, encKey)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	encCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encDER})
	sealedEnc, err := a.d.Sealer.Seal(pemKey(encKey))
	if err != nil {
		a.fail(w, r, err)
		return
	}

	// Keep everything first, so that the emailed answer can always be read.
	m.Email, m.RequestedAt = email, now
	if err := a.putMeta(ctx, blobPendingEncKey, sealedEnc, blobPendingEncCert, encCertPEM, m); err != nil {
		_ = a.clearBlobs(ctx, encryptionBlobs)
		a.fail(w, r, err)
		return
	}

	if err := a.callSigningService(ctx, signRequest{
		CSR:     base64.StdEncoding.EncodeToString(csrPEM),
		Email:   email,
		Key:     signingAPIKey,
		Encrypt: base64.StdEncoding.EncodeToString(encCertPEM),
	}); err != nil {
		// The key and CSR stay: they can be tried again or used another way.
		m.Email = ""
		if cerr := errors.Join(a.clearBlobs(ctx, encryptionBlobs), a.putMetaOnly(ctx, m)); cerr != nil {
			a.log.Error("cannot tidy the failed push certificate request", "error", cerr)
		}
		a.log.Warn("push certificate request refused", "error", sanitize(err.Error(), a.d.Config))
		writeError(w, http.StatusBadGateway, sanitize(err.Error(), a.d.Config))
		return
	}
	a.audit(ctx, caller(r).Username, "settings.push_request", "push-certificate", "email "+email)
	writeJSON(w, http.StatusOK, map[string]any{"request": pendingJSON(m, true)})
}

func orgList(o string) []string {
	if o == "" {
		return nil
	}
	return []string{o}
}

// callSigningService posts the request. The error is a message for a person.
func (a *API) callSigningService(ctx context.Context, sr signRequest) error {
	payload, err := json.Marshal(sr)
	if err != nil {
		return err
	}
	url := a.d.SigningURL
	if url == "" {
		url = DefaultSigningURL
	}
	client := a.d.SigningClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", signingUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("the signing service (mdmcert.download) could not be reached; try again later")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	// The service answers {"result": "success"|"failure", "reason": "..."}.
	var out struct {
		Result string `json:"result"`
		Reason string `json:"reason"`
		Error  string `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	reason := strings.TrimSpace(out.Reason)
	if reason == "" {
		reason = strings.TrimSpace(out.Error)
	}
	if resp.StatusCode == http.StatusOK && strings.EqualFold(out.Result, "success") {
		return nil
	}
	if reason != "" {
		return fmt.Errorf("the signing service (mdmcert.download) refused the request: %s", reason)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the signing service (mdmcert.download) answered with status %d", resp.StatusCode)
	}
	return errors.New("the signing service (mdmcert.download) did not accept the request")
}

func (a *API) decryptPushRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Encrypted string `json:"encrypted"`
	}
	if !decode(w, r, &body, false) {
		return
	}
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	ctx := r.Context()
	if m, pending, err := a.loadPending(ctx); err != nil {
		a.fail(w, r, err)
		return
	} else if !pending || m.Email == "" {
		badRequest(w, "there is no pending request to the signing service; make one first")
		return
	}
	// The file is hex; it may have been pasted with line breaks around it.
	hexText := strings.Join(strings.Fields(body.Encrypted), "")
	if hexText == "" {
		badRequest(w, "paste the text of the file the signing service emailed")
		return
	}
	der, err := hex.DecodeString(hexText)
	if err != nil {
		badRequest(w, "that is not the text of the emailed file: it should be hexadecimal characters only")
		return
	}
	keyPEM, err1 := a.openSealed(ctx, blobPendingEncKey)
	certPEM, err2 := a.d.Store.GetBlob(ctx, blobPendingEncCert)
	if err := errors.Join(err1, err2); err != nil {
		a.fail(w, r, err)
		return
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		a.fail(w, r, errors.New("pending encryption certificate is damaged"))
		return
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	content, err := decryptPKCS7(der, cert, key)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	a.audit(ctx, caller(r).Username, "settings.push_request_decrypted", "push-certificate", "")
	writeJSON(w, http.StatusOK, map[string]any{"filename": decryptedFilename, "content": string(content)})
}

// decryptPKCS7 opens an enveloped message; the library may panic on junk.
func decryptPKCS7(der []byte, cert *x509.Certificate, key *rsa.PrivateKey) (out []byte, err error) {
	defer func() {
		if recover() != nil {
			out, err = nil, errors.New("that file is not a PKCS#7 message")
		}
	}()
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, errors.New("that file is not a PKCS#7 message")
	}
	out, err = p7.Decrypt(cert, key)
	if err != nil {
		return nil, errors.New("that file cannot be decrypted with the key of the pending request: was it sent for a different request?")
	}
	return out, nil
}

// pairWithPending returns the PEM of the pending push key.
func (a *API) pendingPushKey(ctx context.Context) ([]byte, error) {
	keyPEM, err := a.openSealed(ctx, blobPendingKey)
	if err != nil {
		return nil, err
	}
	k, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return pemKey(k), nil
}
