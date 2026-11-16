package core

import (
	"context"
	"strings"
)

type ctxKey int

const userKey ctxKey = iota

// WithUser returns a context carrying the signed-in person. internal/auth
// sets it; internal/api reads it.
func WithUser(ctx context.Context, u User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

// UserFrom returns the signed-in person, if the request has one.
func UserFrom(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userKey).(User)
	return u, ok
}

// PlatformFromProductName derives the platform from what a device calls
// itself when it checks in ("iPhone15,2", "iPad13,4", "Mac14,7",
// "MacBookPro18,3", "iMac21,1", "VirtualMac2,1"). Anything that is not an
// iPhone, iPod or iPad is taken to be a Mac.
func PlatformFromProductName(productName string) Platform {
	p := strings.ToLower(productName)
	switch {
	case strings.HasPrefix(p, "iphone"), strings.HasPrefix(p, "ipod"):
		return PlatformIOS
	case strings.HasPrefix(p, "ipad"):
		return PlatformIPadOS
	default:
		return PlatformMacOS
	}
}

// Wants reports whether a profile with this assignment goes to a person.
// u is nil for a device with no owner, which only Everyone reaches.
func (a Assignment) Wants(u *User) bool {
	if a.Everyone {
		return true
	}
	if u == nil {
		return false
	}
	for _, name := range a.Users {
		if strings.EqualFold(name, u.Username) {
			return true
		}
	}
	for _, g := range a.Groups {
		for _, have := range u.Groups {
			if g == have {
				return true
			}
		}
	}
	return false
}
