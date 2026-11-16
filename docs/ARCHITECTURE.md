# Architecture

One Go program, one HTTP server, one data directory.

```
                    ┌────────────────────────── openmdm ──────────────────────────┐
 device ── /mdm ───▶│ internal/mdm      NanoMDM: check-in, command queue, APNs    │
 device ── /scep ──▶│ internal/pki      the CA, SCEP, the profile-signing identity│
 device ── /enroll ▶│ internal/api      REST API for the UI; the enrolment link   │
 person ── /auth ──▶│ internal/auth     OIDC sign-in, sessions                    │
 person ── /api ───▶│ internal/engine   reacts to devices; makes them match       │
 person ── /  ─────▶│ web/              the UI (Preact), embedded in the binary   │
                    │ internal/profiles templates → per-device profiles, signing  │
                    │ internal/secrets  OpenBao (or file, memory)                 │
                    │ internal/store    SQLite: everything OpenMDM keeps itself   │
                    └─────────────────────────────────────────────────────────────┘
```

## The rule that keeps the parts apart

`internal/core` holds the domain types and the interfaces. Every package
under `internal/` imports `openmdm/internal/core` and **no other package of
this module**. `cmd/openmdm/main.go` is the only place that knows the
concrete types; it builds each part and hands it the interfaces it needs.

| Package | Implements | Is given |
|---|---|---|
| `internal/store` | `core.Store` | a path |
| `internal/secrets` | `core.SecretStore` | `core.SecretsConfig` |
| `internal/pki` | `core.Authority`, the SCEP HTTP handler | `core.Store`, `core.Sealer` |
| `internal/profiles` | `core.Renderer`, `core.Enroller`, the profiles-directory loader | `core.SecretStore`, `core.Authority`, `core.Store` |
| `internal/mdm` | `core.MDM`, the `/mdm` HTTP handler | `core.Authority`, `core.Events`, `core.Store`, `core.Sealer` |
| `internal/engine` | `core.Events`, `core.Reconciler` | `core.Store`, `core.Renderer`, `core.MDM` |
| `internal/auth` | sign-in routes, the session middleware | `core.OIDCConfig`, `core.Store` |
| `internal/api` | the `/api/v1` and `/enroll` handlers | everything above, as interfaces |
| `web/` | the UI | `docs/API.md` |

## How a device comes to have a profile

1. **Enrolment.** A signed-in person asks for an enrolment
   (`POST /api/v1/enrollments`), which makes a `core.Enrollment` with a
   one-hour link. Opening the link on the device returns a signed enrolment
   profile: the CA certificate, a SCEP payload with a one-time challenge,
   and the MDM payload (`SignMessage` on, so the device's identity survives
   a TLS-terminating proxy).
2. **Identity.** The device asks `/scep` for a certificate. `internal/pki`
   checks the challenge against the store, issues the certificate, and
   records it (`core.IssuedCert`) with the username the enrolment was for.
3. **Check-in.** The device talks to `/mdm`. `internal/mdm` verifies the
   message signature against the CA, lets NanoMDM handle the protocol, and
   reports to `core.Events`: authenticated, token updated, checked out,
   command result.
4. **The engine** (`internal/engine`) keeps `core.Device` rows up to date
   from those events, ties a device to its owner through the certificate it
   presented, and reconciles.
5. **Reconcile**, one device at a time: every profile whose platforms
   include the device's and whose assignment wants its owner is *wanted*.
   Each is rendered (`core.Renderer`); a profile that cannot be rendered is
   `blocked` with the reason. A wanted profile whose hash differs from what
   the device has is signed and queued (`core.MDM.InstallProfile`) on the
   right channel; a profile the device has that is no longer wanted is
   removed. Then the device is woken through APNs.
6. **Results** come back as events and move the `core.DeviceProfile` to
   `installed` or `failed`.

## Channels on a Mac

A Mac has two MDM connections: the device channel and, once someone logs
in, a user channel. Accounts (mail, calendars, contacts) and personal
certificates only install on the user channel. A profile says which with
`macos_channel`. On iPhone and iPad there is only the device channel, so
the same profile simply goes there. That is how one profile serves both.

## Secrets

OpenMDM never stores a secret value. `core.SecretStore` reads and writes
OpenBao KV v2 under one prefix: `<mount>/<prefix>/users/<username>` and
`<mount>/<prefix>/global`. The API never returns a value, only which keys
are set. The only things sealed in SQLite are the server's own keys (the CA
key, the APNs key), with the master key from the configuration.

## Conventions

- Go: standard library first. `log/slog` for logs, never a secret value or a
  whole profile in a log line. Errors wrap `core.ErrNotFound`,
  `core.ErrInvalid`, `core.ErrForbidden` where they apply.
- Every package has tests that run with `go test ./internal/<pkg>/...` and
  need no network, no Docker and no other package's implementation: fake
  the `core` interfaces you are given, in your own `_test.go` files.
- Comments say why, in plain words.
