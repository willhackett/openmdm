// Package mdm is OpenMDM's MDM protocol layer. It embeds NanoMDM as a
// library: NanoMDM decodes check-ins, keeps enrolments, push tokens and the
// command queue, and sends APNs wake-ups; this package wires it up, checks
// the device's identity against our own CA, and reports what devices do to
// core.Events.
package mdm

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/micromdm/nanomdm/cryptoutil"
	httpmdm "github.com/micromdm/nanomdm/http/mdm"
	"github.com/micromdm/nanomdm/push"
	"github.com/micromdm/nanomdm/push/nanopush"
	pushsvc "github.com/micromdm/nanomdm/push/service"
	"github.com/micromdm/nanomdm/service"
	"github.com/micromdm/nanomdm/service/certauth"
	"github.com/micromdm/nanomdm/service/nanomdm"
	"github.com/micromdm/nanomdm/storage/file"

	"openmdm/internal/core"
)

// maxBodyBytes bounds a request body. Check-ins are a few KiB; command
// results (a profile list, a certificate list) can be larger. NanoMDM itself
// reads whatever it is sent, so the limit is ours.
const maxBodyBytes = 10 << 20

// Options configures New.
type Options struct {
	// DataDir is OpenMDM's data directory. NanoMDM keeps its state in
	// <DataDir>/nanomdm, created 0700. That includes the APNs push
	// certificate's PRIVATE KEY, which NanoMDM's file storage writes in the
	// clear (mode 0600), so the directory must be private to the server.
	DataDir   string
	Authority core.Authority
	Events    core.Events
	Logger    *slog.Logger

	// PushProviders replaces the APNs client; nil means NanoMDM's nanopush
	// (HTTP/2 to Apple). It exists so that tests never reach Apple.
	PushProviders push.PushProviderFactory
}

// Service is the MDM engine. Handler serves devices; the core.MDM methods
// serve the rest of OpenMDM.
type Service struct {
	log     *slog.Logger
	dir     string // <DataDir>/nanomdm
	store   *file.FileStorage
	pusher  *pushsvc.PushService
	handler http.Handler

	// pushMu keeps a push from reading a half-written certificate/key pair
	// while SetPushCert replaces it.
	pushMu sync.RWMutex
}

var _ core.MDM = (*Service)(nil)

// New builds the service. ctx is not retained.
func New(ctx context.Context, opts Options) (*Service, error) {
	if opts.DataDir == "" {
		return nil, errors.New("mdm: DataDir is required")
	}
	if opts.Authority == nil {
		return nil, errors.New("mdm: Authority is required")
	}
	if opts.Events == nil {
		return nil, errors.New("mdm: Events is required")
	}
	lg := opts.Logger
	if lg == nil {
		lg = slog.New(slog.DiscardHandler)
	}
	dir := filepath.Join(opts.DataDir, "nanomdm")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mdm: creating %s: %w", dir, err)
	}
	// MkdirAll leaves an existing directory as it is; make sure it is private.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mdm: securing %s: %w", dir, err)
	}
	store, err := file.New(dir)
	if err != nil {
		return nil, fmt.Errorf("mdm: opening storage: %w", err)
	}

	nlog := slogAdapter{l: lg}

	// UserAuthenticate: NanoMDM's default declines user management (410),
	// and then a Mac never opens a user channel. With the zero-length digest
	// challenge (NanoMDM's -ua-zl-dc) the Mac accepts and sends user-channel
	// TokenUpdates, which is how profiles reach a Mac's user.
	core1 := nanomdm.New(store,
		nanomdm.WithUserAuthenticate(nanomdm.NewUAService(store, true)),
		nanomdm.WithLogger(nlog.With("service", "nanomdm")),
	)

	var svc service.CheckinAndCommandService = core1
	svc = &reporter{CheckinAndCommandService: svc, events: opts.Events, log: lg.With("service", "events")}
	// certauth ties each certificate to the one device that first used it.
	svc = certauth.New(svc, store, certauth.WithLogger(nlog.With("service", "certauth")))
	svc = idGuard{next: svc}

	verifier := authorityVerifier{a: opts.Authority}
	var h http.Handler = httpmdm.CheckinAndCommandHandler(svc, nlog.With("handler", "checkin-command"))
	h = httpmdm.CertVerifyMiddleware(h, verifier, nlog.With("handler", "cert-verify"))
	h = httpmdm.CertExtractMdmSignatureMiddleware(h,
		httpmdm.MdmSignatureVerifierFunc(cryptoutil.VerifyMdmSignature),
		httpmdm.SigLogWithLogger(nlog.With("handler", "cert-extract")))
	h = limitBody(h)

	factory := opts.PushProviders
	if factory == nil {
		factory = nanopush.NewFactory()
	}
	return &Service{
		log:     lg,
		dir:     dir,
		store:   store,
		pusher:  pushsvc.New(store, store, factory, nlog.With("service", "push")),
		handler: h,
	}, nil
}

// Handler is the single endpoint devices use, to be mounted at /mdm.
// Check-ins and command polls share the URL. TLS is terminated in front of
// it, so the device's identity is the certificate that signed the request
// (the Mdm-Signature header), which must have been issued by our CA and not
// be revoked.
func (s *Service) Handler() http.Handler { return s.handler }

// authorityVerifier adapts core.Authority to NanoMDM's CertVerifier.
type authorityVerifier struct{ a core.Authority }

func (v authorityVerifier) Verify(ctx context.Context, cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("missing MDM certificate")
	}
	return v.a.VerifyIssued(ctx, cert)
}

// limitBody allows only PUT and POST, and reads at most maxBodyBytes of the
// body (413 beyond that), handing the rest of the chain a body it can reread.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			w.Header().Set("Allow", "PUT, POST")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		if r.ContentLength > maxBodyBytes {
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytesReader(body))
		next.ServeHTTP(w, r)
	})
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
