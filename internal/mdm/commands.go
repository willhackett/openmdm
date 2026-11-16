package mdm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"howett.net/plist"

	nmdm "github.com/micromdm/nanomdm/mdm"

	"openmdm/internal/core"
)

// InstallProfile queues an InstallProfile command carrying profile.
func (s *Service) InstallProfile(ctx context.Context, target string, profile []byte) (string, error) {
	if len(profile) == 0 {
		return "", fmt.Errorf("%w: empty profile", core.ErrInvalid)
	}
	return s.enqueue(ctx, target, "InstallProfile", map[string]any{"Payload": profile})
}

// RemoveProfile queues a RemoveProfile for a PayloadIdentifier.
func (s *Service) RemoveProfile(ctx context.Context, target, identifier string) (string, error) {
	if identifier == "" {
		return "", fmt.Errorf("%w: empty profile identifier", core.ErrInvalid)
	}
	return s.enqueue(ctx, target, "RemoveProfile", map[string]any{"Identifier": identifier})
}

// Enqueue queues any other command; command is merged into the Command
// dictionary beside RequestType (which always wins).
func (s *Service) Enqueue(ctx context.Context, target, requestType string, command map[string]any) (string, error) {
	if requestType == "" {
		return "", fmt.Errorf("%w: empty request type", core.ErrInvalid)
	}
	return s.enqueue(ctx, target, requestType, command)
}

// checkTarget makes sure target is a plain enrollment ID that NanoMDM has
// seen. NanoMDM's file storage would happily create a queue for any name.
func (s *Service) checkTarget(target string) error {
	if target == "" {
		return fmt.Errorf("%w: empty target", core.ErrInvalid)
	}
	parts := strings.Split(target, ":")
	if len(parts) > 2 {
		return fmt.Errorf("%w: malformed enrollment ID", core.ErrInvalid)
	}
	for _, p := range parts {
		if p == "" || !validIDPart(p) {
			return fmt.Errorf("%w: malformed enrollment ID", core.ErrInvalid)
		}
	}
	fi, err := os.Stat(filepath.Join(s.dir, target))
	if err != nil || !fi.IsDir() {
		return fmt.Errorf("%w: enrollment %q", core.ErrNotFound, target)
	}
	return nil
}

func (s *Service) enqueue(ctx context.Context, target, requestType string, params map[string]any) (string, error) {
	if err := s.checkTarget(target); err != nil {
		return "", err
	}
	cmd := make(map[string]any, len(params)+1)
	for k, v := range params {
		cmd[k] = v
	}
	cmd["RequestType"] = requestType
	id := strings.ToUpper(uuid.NewString())
	raw, err := plist.Marshal(map[string]any{"CommandUUID": id, "Command": cmd}, plist.XMLFormat)
	if err != nil {
		return "", fmt.Errorf("%w: encoding command: %v", core.ErrInvalid, err)
	}
	c, err := nmdm.DecodeCommand(raw)
	if err != nil {
		return "", fmt.Errorf("mdm: built an invalid command: %w", err)
	}
	failures, err := s.store.EnqueueCommand(ctx, []string{target}, c)
	if err != nil {
		return "", fmt.Errorf("mdm: queueing %s: %w", requestType, err)
	}
	if ferr := failures[target]; ferr != nil {
		return "", fmt.Errorf("mdm: queueing %s: %w", requestType, ferr)
	}
	s.log.Debug("command queued", "target", target, "request_type", requestType, "command_uuid", id)
	return id, nil
}
