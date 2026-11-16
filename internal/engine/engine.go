// Package engine reacts to what devices do and makes them match the
// profiles. Events (core.Events) record what a device told us and schedule a
// reconcile; one worker goroutine reconciles one device at a time.
package engine

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"openmdm/internal/core"
)

const (
	defaultInterval = 15 * time.Minute
	failedRetry     = time.Hour
	nudgeAfter      = 24 * time.Hour
)

// Options tunes an Engine. The zero value is fine.
type Options struct {
	// Interval is how often every device is reconciled (default 15 minutes).
	Interval time.Duration
	// Now is the clock; time.Now if nil. For tests.
	Now func() time.Time
}

// Engine implements core.Events and core.Reconciler.
type Engine struct {
	store    core.Store
	renderer core.Renderer
	mdm      core.MDM
	log      *slog.Logger
	opts     Options

	// mu serialises the engine's own writes to the store, so that a command
	// result cannot interleave with the reconciler recording a command.
	mu sync.Mutex

	// qmu guards the queue.
	qmu    sync.Mutex
	queue  []string
	queued map[string]bool
	all    bool
	busy   bool
	wake   chan struct{}

	// nudged remembers when a stuck row last got a nudge push.
	nudged map[string]time.Time
}

var (
	_ core.Events     = (*Engine)(nil)
	_ core.Reconciler = (*Engine)(nil)
)

// New makes an Engine. Nothing happens until Run is called, but Trigger may
// be used before that: it is remembered.
func New(store core.Store, renderer core.Renderer, mdm core.MDM, logger *slog.Logger, opts Options) *Engine {
	if opts.Interval <= 0 {
		opts.Interval = defaultInterval
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	return &Engine{
		store: store, renderer: renderer, mdm: mdm, log: logger, opts: opts,
		queued: map[string]bool{},
		wake:   make(chan struct{}, 1),
		nudged: map[string]time.Time{},
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func (e *Engine) now() time.Time { return e.opts.Now().UTC() }

// Trigger schedules a reconcile of one device. It never blocks.
func (e *Engine) Trigger(deviceID string) {
	if deviceID == "" {
		return
	}
	e.qmu.Lock()
	if !e.queued[deviceID] {
		e.queued[deviceID] = true
		e.queue = append(e.queue, deviceID)
	}
	e.qmu.Unlock()
	e.poke()
}

// TriggerAll schedules a reconcile of every device. The devices are listed
// by the worker, so this never blocks either.
func (e *Engine) TriggerAll() {
	e.qmu.Lock()
	e.all = true
	e.qmu.Unlock()
	e.poke()
}

func (e *Engine) poke() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Run is the worker. It returns nil when ctx is done.
func (e *Engine) Run(ctx context.Context) error {
	e.TriggerAll()
	ticker := time.NewTicker(e.opts.Interval)
	defer ticker.Stop()
	for {
		for {
			id, ok := e.next(ctx)
			if !ok {
				break
			}
			if ctx.Err() != nil {
				e.finish()
				return nil
			}
			e.reconcileSafe(ctx, id)
			e.finish()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-e.wake:
		case <-ticker.C:
			e.TriggerAll()
		}
	}
}

// next pops the next device to reconcile, expanding a pending TriggerAll
// first. busy stays true until finish, so tests can tell when it is idle.
func (e *Engine) next(ctx context.Context) (string, bool) {
	e.qmu.Lock()
	all := e.all
	e.all = false
	if all {
		e.busy = true
	}
	e.qmu.Unlock()

	if all {
		devs, err := e.store.ListDevices(ctx)
		if err != nil {
			e.log.Error("listing devices to reconcile", "err", err)
		}
		e.qmu.Lock()
		for _, d := range devs {
			if !e.queued[d.ID] {
				e.queued[d.ID] = true
				e.queue = append(e.queue, d.ID)
			}
		}
		e.busy = false
		e.qmu.Unlock()
	}

	e.qmu.Lock()
	defer e.qmu.Unlock()
	if len(e.queue) == 0 {
		return "", false
	}
	id := e.queue[0]
	e.queue = e.queue[1:]
	delete(e.queued, id)
	e.busy = true
	return id, true
}

func (e *Engine) finish() {
	e.qmu.Lock()
	e.busy = false
	e.qmu.Unlock()
}

// idle reports whether nothing is queued or running (for tests).
func (e *Engine) idle() bool {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	return len(e.queue) == 0 && !e.busy && !e.all
}

func (e *Engine) reconcileSafe(ctx context.Context, id string) {
	defer func() {
		if r := recover(); r != nil {
			e.log.Error("reconcile panicked", "device", id, "panic", r)
		}
	}()
	if err := e.reconcile(ctx, id); err != nil {
		e.log.Error("reconcile failed", "device", id, "err", err)
	}
}

func (e *Engine) audit(ctx context.Context, actor, kind, subject, detail string) {
	err := e.store.AppendEvent(ctx, core.Event{At: e.now(), Actor: actor, Kind: kind, Subject: subject, Detail: detail})
	if err != nil {
		e.log.Error("writing audit event", "kind", kind, "err", err)
	}
}
