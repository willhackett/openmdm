package mdm

import (
	"context"
	"fmt"
	"log/slog"

	nanolog "github.com/micromdm/nanolib/log"
)

// slogAdapter lets NanoMDM log through slog. NanoMDM logs alternating
// key/value pairs, with "msg" as the message.
type slogAdapter struct {
	l *slog.Logger
}

var _ nanolog.Logger = slogAdapter{}

func (a slogAdapter) Info(args ...interface{})  { a.log(slog.LevelInfo, args) }
func (a slogAdapter) Debug(args ...interface{}) { a.log(slog.LevelDebug, args) }

func (a slogAdapter) With(args ...interface{}) nanolog.Logger {
	return slogAdapter{l: a.l.With(kvAttrs(args)...)}
}

func (a slogAdapter) log(level slog.Level, args []interface{}) {
	ctx := context.Background()
	if !a.l.Enabled(ctx, level) {
		return
	}
	msg := ""
	rest := make([]interface{}, 0, len(args))
	for i := 0; i < len(args); i += 2 {
		if k, ok := args[i].(string); ok && k == "msg" && i+1 < len(args) {
			msg = fmt.Sprint(args[i+1])
			continue
		}
		rest = append(rest, args[i])
		if i+1 < len(args) {
			rest = append(rest, args[i+1])
		}
	}
	a.l.Log(ctx, level, msg, kvAttrs(rest)...)
}

// kvAttrs turns alternating keys and values into slog arguments, tolerating
// an odd count and keys that are not strings.
func kvAttrs(args []interface{}) []any {
	out := make([]any, 0, len(args))
	for i := 0; i < len(args); i += 2 {
		key := fmt.Sprint(args[i])
		if i+1 < len(args) {
			out = append(out, key, args[i+1])
		} else {
			out = append(out, "!BADKEY", key)
		}
	}
	return out
}
