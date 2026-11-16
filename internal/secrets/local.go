package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"openmdm/internal/core"
)

// memoryBackend keeps everything in a map. For tests and demos.
type memoryBackend struct {
	mu   sync.Mutex
	docs map[string]map[string]string
}

func newMemoryBackend() *memoryBackend {
	return &memoryBackend{docs: map[string]map[string]string{}}
}

func (m *memoryBackend) get(ctx context.Context, doc string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return copyMap(m.docs[doc]), nil
}

func (m *memoryBackend) update(ctx context.Context, doc string, fn func(map[string]string) bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := copyMap(m.docs[doc])
	if fn(cur) {
		m.docs[doc] = cur
	}
	return nil
}

func (m *memoryBackend) health(ctx context.Context) error { return ctx.Err() }

// fileBackend keeps everything in one JSON file:
//
//	{"users": {"name": {"key": "value"}}, "global": {"key": "value"}}
//
// FOR DEVELOPMENT ONLY: values are in the clear on disk, and the whole file
// is rewritten on every change. It is written atomically (temp file, then
// rename) with mode 0600. Only one process may use the file.
type fileBackend struct {
	mu   sync.Mutex
	path string
}

type fileDoc struct {
	Users  map[string]map[string]string `json:"users"`
	Global map[string]string            `json:"global"`
}

func newFileBackend(path string) (*fileBackend, error) {
	if path == "" {
		return nil, invalid("secrets backend \"file\" needs a file path")
	}
	return &fileBackend{path: path}, nil
}

func (f *fileBackend) load() (fileDoc, error) {
	var d fileDoc
	b, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return d, fmt.Errorf("secrets file: %w", err)
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &d); err != nil {
			// The decoder's message can quote file content; say only that it failed.
			return fileDoc{}, errors.New("secrets file: not valid JSON")
		}
	}
	return d, nil
}

func (f *fileBackend) save(d fileDoc) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".secrets-*.tmp")
	if err != nil {
		return fmt.Errorf("secrets file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("secrets file: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("secrets file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("secrets file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("secrets file: %w", err)
	}
	if err := os.Rename(name, f.path); err != nil {
		return fmt.Errorf("secrets file: %w", err)
	}
	return nil
}

// pick returns the map for a doc name inside d (creating it for users).
func pick(d *fileDoc, doc string) map[string]string {
	if doc == globalDoc {
		return d.Global
	}
	return d.Users[doc[len("users/"):]]
}

func (f *fileBackend) get(ctx context.Context, doc string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	d, err := f.load()
	if err != nil {
		return nil, err
	}
	return copyMap(pick(&d, doc)), nil
}

func (f *fileBackend) update(ctx context.Context, doc string, fn func(map[string]string) bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	d, err := f.load()
	if err != nil {
		return err
	}
	cur := copyMap(pick(&d, doc))
	if !fn(cur) {
		return nil
	}
	if doc == globalDoc {
		d.Global = cur
	} else {
		if d.Users == nil {
			d.Users = map[string]map[string]string{}
		}
		d.Users[doc[len("users/"):]] = cur
	}
	return f.save(d)
}

func (f *fileBackend) health(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.load(); err != nil {
		return err
	}
	// The directory must be writable for a later Set to work.
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".secrets-health-*.tmp")
	if err != nil {
		return fmt.Errorf("secrets file directory is not writable: %w", core.ErrInvalid)
	}
	tmp.Close()
	os.Remove(tmp.Name())
	return nil
}
