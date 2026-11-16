package profiles

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	"openmdm/internal/core"
)

const sourceFile = "file"

// Loader keeps the store's "file" profiles equal to a directory of
// <id>.mobileconfig and <id>.yaml pairs.
type Loader struct {
	dir      string
	store    core.Store
	renderer core.Renderer
	onChange func()
	logger   *slog.Logger

	debounce time.Duration
	retry    time.Duration
	mu       sync.Mutex
}

// NewLoader makes a Loader. onChange may be nil.
func NewLoader(dir string, store core.Store, renderer core.Renderer, onChange func(), logger *slog.Logger) *Loader {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	return &Loader{
		dir: dir, store: store, renderer: renderer, onChange: onChange, logger: logger,
		debounce: time.Second, retry: 10 * time.Second,
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// meta is the .yaml file.
type meta struct {
	Name         string          `yaml:"name"`
	Description  string          `yaml:"description"`
	Platforms    []core.Platform `yaml:"platforms"`
	MacOSChannel core.Channel    `yaml:"macos_channel"`
	Assign       core.Assignment `yaml:"assign"`
}

// normalise makes two profiles comparable: nil and empty slices are the
// same, and UpdatedAt (set by the store) is ignored.
func normalise(p core.Profile) core.Profile {
	p.UpdatedAt = time.Time{}
	if p.Platforms == nil {
		p.Platforms = []core.Platform{}
	}
	if p.Assignment.Users == nil {
		p.Assignment.Users = []string{}
	}
	if p.Assignment.Groups == nil {
		p.Assignment.Groups = []string{}
	}
	return p
}

// Sync does one pass over the directory.
func (l *Loader) Sync(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries, err := os.ReadDir(l.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			l.logger.Info("profiles directory does not exist; nothing loaded", "dir", l.dir)
			return nil
		}
		return fmt.Errorf("reading profiles directory: %w", err)
	}

	// ids with at least one file, and which have which.
	haveTemplate := map[string]bool{}
	haveMeta := map[string]bool{}
	present := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		switch ext := filepath.Ext(name); ext {
		case ".mobileconfig":
			id := strings.TrimSuffix(name, ext)
			haveTemplate[id], present[id] = true, true
		case ".yaml":
			id := strings.TrimSuffix(name, ext)
			haveMeta[id], present[id] = true, true
		}
	}

	stored, err := l.store.ListProfiles(ctx)
	if err != nil {
		return fmt.Errorf("listing profiles: %w", err)
	}
	byID := map[string]core.Profile{}
	for _, p := range stored {
		byID[p.ID] = p
	}

	var errs []error
	changed := false

	ids := make([]string, 0, len(present))
	for id := range present {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !haveTemplate[id] || !haveMeta[id] {
			l.logger.Warn("profile skipped: it needs both a .mobileconfig and a .yaml file", "id", id)
			continue
		}
		if old, ok := byID[id]; ok && old.Source != sourceFile {
			l.logger.Warn("profile file skipped: a profile made in the UI has the same ID", "id", id)
			continue
		}
		p, err := l.read(id)
		if err != nil {
			l.logger.Warn("profile skipped", "id", id, "error", err.Error())
			continue
		}
		if _, err := l.renderer.Validate(p); err != nil {
			l.logger.Warn("profile skipped: it is not valid", "id", id, "error", err.Error())
			continue
		}
		if old, ok := byID[id]; ok && reflect.DeepEqual(normalise(old), normalise(p)) {
			continue
		}
		if err := l.store.PutProfile(ctx, p); err != nil {
			l.logger.Error("saving profile failed", "id", id, "error", err.Error())
			errs = append(errs, fmt.Errorf("saving profile %q: %w", id, err))
			continue
		}
		l.logger.Info("profile loaded", "id", id)
		changed = true
	}

	for _, p := range stored {
		if p.Source != sourceFile || present[p.ID] {
			continue
		}
		if err := l.store.DeleteProfile(ctx, p.ID); err != nil {
			l.logger.Error("removing profile failed", "id", p.ID, "error", err.Error())
			errs = append(errs, fmt.Errorf("removing profile %q: %w", p.ID, err))
			continue
		}
		l.logger.Info("profile removed: its files are gone", "id", p.ID)
		changed = true
	}

	if changed && l.onChange != nil {
		l.onChange()
	}
	return errors.Join(errs...)
}

func (l *Loader) read(id string) (core.Profile, error) {
	tpl, err := os.ReadFile(filepath.Join(l.dir, id+".mobileconfig"))
	if err != nil {
		return core.Profile{}, err
	}
	raw, err := os.ReadFile(filepath.Join(l.dir, id+".yaml"))
	if err != nil {
		return core.Profile{}, err
	}
	var m meta
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return core.Profile{}, fmt.Errorf("%s.yaml: %w", id, err)
	}
	return core.Profile{
		ID:           id,
		Name:         m.Name,
		Description:  m.Description,
		Platforms:    m.Platforms,
		MacOSChannel: m.MacOSChannel,
		Assignment:   m.Assign,
		Template:     string(tpl),
		Source:       sourceFile,
	}, nil
}

// Run syncs, then watches the directory until ctx is done.
func (l *Loader) Run(ctx context.Context) error {
	if err := l.Sync(ctx); err != nil {
		l.logger.Error("profiles sync failed", "error", err.Error())
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watching profiles directory: %w", err)
	}
	defer w.Close()

	watching := false
	var retry <-chan time.Time
	tryAdd := func() {
		if err := w.Add(l.dir); err != nil {
			if !watching {
				retry = time.After(l.retry)
			}
			return
		}
		watching = true
		retry = nil
	}
	tryAdd()

	var timer *time.Timer
	var fire <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case <-retry:
			tryAdd()
			if watching {
				l.syncLogged(ctx)
			}
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if ev.Name == l.dir && ev.Has(fsnotify.Remove|fsnotify.Rename) {
				watching = false
				_ = w.Remove(l.dir)
				retry = time.After(l.retry)
			}
			if timer == nil {
				timer = time.NewTimer(l.debounce)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(l.debounce)
			}
			fire = timer.C
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			l.logger.Warn("watching profiles directory", "error", err.Error())
		case <-fire:
			fire = nil
			l.syncLogged(ctx)
		}
	}
}

func (l *Loader) syncLogged(ctx context.Context) {
	if err := l.Sync(ctx); err != nil && ctx.Err() == nil {
		l.logger.Error("profiles sync failed", "error", err.Error())
	}
}
