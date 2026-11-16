package mdm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/cryptoutil"
	pushsvc "github.com/micromdm/nanomdm/push/service"

	"openmdm/internal/core"
)

// topicRE is what an MDM push topic looks like. NanoMDM's file storage
// builds file names from it, so nothing else may through.
var topicRE = regexp.MustCompile(`^com\.apple\.mgmt[A-Za-z0-9._-]*$`)

// Push wakes the targets through APNs. A target without a push token yet,
// or no push certificate at all, is not an error; a failure to reach APNs,
// or APNs refusing a token, is.
func (s *Service) Push(ctx context.Context, targets ...string) error {
	seen := make(map[string]bool, len(targets))
	ids := make([]string, 0, len(targets))
	for _, t := range targets {
		if t == "" || seen[t] {
			continue
		}
		if err := s.checkTargetName(t); err != nil {
			return err
		}
		seen[t] = true
		ids = append(ids, t)
	}
	if len(ids) == 0 {
		return nil
	}

	s.pushMu.RLock()
	defer s.pushMu.RUnlock()

	info, err := s.pushInfo()
	if err != nil {
		return err
	}
	if !info.Configured {
		s.log.Debug("push skipped: no push certificate configured", "targets", len(ids))
		return nil
	}

	responses, err := s.pusher.Push(ctx, ids)
	var errs []error
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// A certificate exists, but not for the topic the device holds.
			err = fmt.Errorf("no push certificate for the topic the device enrolled with (have %q): %w", info.Topic, err)
		}
		errs = append(errs, err)
	}
	for _, id := range ids {
		resp := responses[id]
		switch {
		case resp == nil:
		case errors.Is(resp.Err, pushsvc.ErrIdNotFound):
			s.log.Debug("push skipped: no push token yet", "target", id)
		case resp.Err != nil:
			errs = append(errs, fmt.Errorf("push to %s: %w", id, resp.Err))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) checkTargetName(t string) error {
	parts := strings.Split(t, ":")
	if len(parts) > 2 {
		return fmt.Errorf("%w: malformed enrollment ID", core.ErrInvalid)
	}
	for _, p := range parts {
		if p == "" || !validIDPart(p) {
			return fmt.Errorf("%w: malformed enrollment ID", core.ErrInvalid)
		}
	}
	return nil
}

// SetPushCert validates and stores the APNs MDM push certificate and its
// key, and later pushes use it. The key is kept by NanoMDM's file storage,
// unencrypted, in <DataDir>/nanomdm (mode 0600, in a 0700 directory).
func (s *Service) SetPushCert(ctx context.Context, certPEM, keyPEM []byte) error {
	cert, err := cryptoutil.DecodePEMCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("%w: certificate: %v", core.ErrInvalid, err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("%w: certificate and key do not match: %v", core.ErrInvalid, err)
	}
	topic, err := cryptoutil.TopicFromCert(cert)
	if err != nil {
		return fmt.Errorf("%w: not an APNs MDM push certificate: %v", core.ErrInvalid, err)
	}
	if !topicRE.MatchString(topic) {
		return fmt.Errorf("%w: unusable push topic", core.ErrInvalid)
	}
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("%w: certificate expired on %s", core.ErrInvalid, cert.NotAfter.UTC().Format("2006-01-02"))
	}

	s.pushMu.Lock()
	defer s.pushMu.Unlock()
	if err := s.store.StorePushCert(ctx, certPEM, keyPEM); err != nil {
		return fmt.Errorf("mdm: storing push certificate: %w", err)
	}
	// PushInfo reports the newest certificate file; touch this one so that
	// it wins even on a file system with coarse timestamps.
	now := time.Now()
	_ = os.Chtimes(filepath.Join(s.dir, topic+".pem"), now, now)
	s.log.Info("push certificate stored", "topic", topic, "not_after", cert.NotAfter.UTC())
	return nil
}

// PushInfo describes the stored push certificate: the most recently stored
// one if (after a topic change) there are several.
func (s *Service) PushInfo(ctx context.Context) (core.PushInfo, error) {
	s.pushMu.RLock()
	defer s.pushMu.RUnlock()
	return s.pushInfo()
}

func (s *Service) pushInfo() (core.PushInfo, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return core.PushInfo{}, fmt.Errorf("mdm: reading %s: %w", s.dir, err)
	}
	var (
		best    core.PushInfo
		bestMod time.Time
	)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".pem") {
			continue
		}
		topic := strings.TrimSuffix(name, ".pem")
		if !topicRE.MatchString(topic) {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.dir, topic+".key")); err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.dir, name))
		if err != nil {
			continue
		}
		cert, err := cryptoutil.DecodePEMCertificate(raw)
		if err != nil {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if !best.Configured || fi.ModTime().After(bestMod) {
			best = core.PushInfo{Configured: true, Topic: topic, NotAfter: cert.NotAfter.UTC()}
			bestMod = fi.ModTime()
		}
	}
	return best, nil
}
