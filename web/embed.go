// Package web carries the built UI (web/dist, made by `npm run build`).
package web

import "embed"

// Dist is the built single-page application.
//
//go:embed all:dist
var Dist embed.FS
