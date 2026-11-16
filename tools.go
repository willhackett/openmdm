//go:build tools

// Keeps the module's dependencies in go.mod while the packages that use
// them are being written.
package tools

import (
	_ "github.com/coreos/go-oidc/v3/oidc"
	_ "github.com/go-chi/chi/v5"
	_ "github.com/google/uuid"
	_ "github.com/gorilla/securecookie"
	_ "github.com/micromdm/nanomdm/service/nanomdm"
	_ "github.com/micromdm/nanomdm/storage/file"
	_ "github.com/micromdm/nanomdm/push/nanopush"
	_ "github.com/micromdm/nanomdm/push/service"
	_ "github.com/micromdm/nanomdm/service/certauth"
	_ "github.com/micromdm/nanomdm/http/mdm"
	_ "github.com/micromdm/scep/v2/server"
	_ "github.com/micromdm/scep/v2/depot"
	_ "github.com/smallstep/pkcs7"
	_ "github.com/smallstep/scep"
	_ "golang.org/x/oauth2"
	_ "gopkg.in/yaml.v3"
	_ "howett.net/plist"
	_ "modernc.org/sqlite"
	_ "github.com/fsnotify/fsnotify"
	_ "golang.org/x/crypto/pkcs12"
)
