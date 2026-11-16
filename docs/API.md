# HTTP API

One server. JSON in and out under `/api/v1`. Times are RFC 3339 UTC. The
objects are the `core` types (`internal/core/types.go`), with the JSON names
given there.

Errors are `{"error": "<message a person can read>"}` with the status:
400 invalid, 401 not signed in, 403 not allowed, 404 not found, 409
conflict, 500 otherwise (the message is then generic; the cause is logged).

## Who may do what

Every `/api/v1` route needs a session (cookie, set by `/auth`). A request
that changes anything (not GET or HEAD) must carry the header
`X-Requested-With: openmdm`, or it is refused with 403: that is the CSRF
protection.

- An **admin** may do everything.
- A **user** may read themselves, their own devices and those devices'
  profiles and commands; set and delete their own secrets; make an
  enrolment for themselves; and ask for one of their devices to be synced
  or locked. Anything else is 403. A user asking for someone else's device
  gets 404, not 403.

## Sign-in

| | |
|---|---|
| `GET /auth/login?next=/path` | starts OIDC; `next` must be a local path |

Sign-in works on both names the server is known by, `admin_url` and `public_url`: the redirect address given to the identity provider is `<the name the request came in on>/auth/callback`, and a request on any other name is refused. The session cookie belongs to the name it was set on.
| `GET /auth/callback` | finishes it, sets the session cookie, redirects to `next` |
| `POST /auth/logout` | ends the session; 204 |

## Device-facing (no session, except the enrolment link)

| | |
|---|---|
| `PUT /mdm` | MDM check-in and commands (signed by the device) |
| `GET, POST /scep` | SCEP |
| `GET /enroll/{token}` | needs a session like any page (not signed in: redirect to `/auth/login?next=/enroll/{token}`), so even an invited person signs in first. Then: the signed enrolment profile for that enrolment, as `application/x-apple-aspen-config`, once. 404 if unknown or expired; 403 (a short plain-text page) if the person signed in is neither the one the enrolment is for nor an admin; 410 if already downloaded |
| `GET /healthz` | `{"status":"ok"}`; 503 with `{"status":"degraded","problems":[...]}` if the secret store cannot be reached |

## `/api/v1`

### Me

`GET /me` → `{"user": User, "push": PushInfo, "public_url": "...", "version": "..."}`

### Users (admin, except oneself)

- `GET /users` → `{"users": [User]}`
- `GET /users/{username}` → `{"user": User, "devices": [Device]}`

People appear here once they have signed in, or once an admin has made an
enrolment or set a secret for them.

### Secrets

Values are write-only: no route returns one.

- `GET /users/{username}/secrets` → `{"secrets": [{"key": "fastmail_app_password", "set": true, "used_by": ["personal-mail"]}]}`.
  The list is every key that is set, plus every key a profile assigned to
  this person names that is not set (`"set": false`): what they still
  have to supply.
- `PUT /users/{username}/secrets/{key}` with `{"value": "..."}` → 204.
  `"encoding": "base64"` may be given to say the value is already base64
  (a certificate file); the UI sends files that way.
- `DELETE /users/{username}/secrets/{key}` → 204
- `GET /secrets/global`, `PUT /secrets/global/{key}`, `DELETE /secrets/global/{key}`: the same for global secrets (admin).

Setting or deleting a secret triggers a reconcile of the devices it affects.

### Devices

- `GET /devices` → `{"devices": [Device]}` (a user sees their own)
- `GET /devices/{id}` → `{"device": Device, "owner": User|null, "profiles": [PlanEntry], "commands": [CommandRecord]}` (the 50 newest commands)
- `PUT /devices/{id}/owner` with `{"username": "george"}` (admin) → 204; `""` clears it
- `POST /devices/{id}/sync` → 204: reconcile now and wake the device
- `POST /devices/{id}/lock` with `{"pin": "123456", "message": "..."}` → `{"command_uuid": "..."}`. `pin` is required for a Mac (six digits) and ignored otherwise.
- `POST /devices/{id}/erase` with `{"confirm": "<the device's serial number>"}` (admin) → `{"command_uuid": "..."}`; 400 if the serial number does not match
- `DELETE /devices/{id}` (admin) → 204: removes the MDM profile from the device if it can still be reached (which removes everything OpenMDM installed) and forgets it, and revokes the identity certificate it enrolled with so that it cannot check in again

### Profiles

- `GET /profiles` → `{"profiles": [Profile + {"info": TemplateInfo, "counts": {"installed": 2, "pending": 0, "blocked": 1, "failed": 0}}]}` (admin; `template` omitted in the list)
- `GET /profiles/{id}` → `{"profile": Profile, "info": TemplateInfo, "devices": [{"device": Device, "state": DeviceProfile}]}` (admin)
- `PUT /profiles/{id}` with a Profile (`id` from the path; `source` ignored) → `{"profile": Profile, "info": TemplateInfo}` (admin). Creates or replaces a UI profile; 409 if a profile with that ID came from a file; 400 with the template's error if it does not validate.
- `DELETE /profiles/{id}` (admin) → 204; 409 for a file profile
- `POST /profiles/validate` with a Profile → `{"info": TemplateInfo}` or 400 (admin): checks a template without saving it

Changing or deleting a profile triggers a reconcile of every device.

### Enrolments

- `POST /enrollments` with `{"username": "george"}` (omit for oneself; someone else needs admin) → `{"enrollment": Enrollment, "url": "https://<public_url>/enroll/<token>"}`
- `GET /enrollments` → `{"enrollments": [Enrollment]}` (admin; a user sees their own)

### Settings (admin)

- `GET /settings` → `{"push": PushInfo, "ca": {"subject": "...", "not_after": "...", "sha256": "..."}, "secrets": {"backend": "openbao", "healthy": true, "error": ""}, "public_url": "...", "organization": "..."}`
- `PUT /settings/push-certificate` with `{"certificate_pem": "...", "key_pem": "..."}` → `{"push": PushInfo}`; 400 if they do not match or the certificate is not an MDM push certificate
- `PUT /settings/push-certificate` with only `{"certificate_pem": "..."}` when a request (below) is pending: the certificate is paired with the key made for that request, and the request is then cleared. 400 if they do not match.

Getting a push certificate from Apple needs a request countersigned by an MDM vendor; Apple's portal does not take a plain CSR. OpenMDM uses the free signing service mdmcert.download for that, in three steps:

- `POST /settings/push-certificate/request` with `{"email": "you@your-company.example"}` → `{"request": {"pending": true, "email": "...", "requested_at": "..."}}`. Makes a new private key and CSR and a one-off encryption certificate, keeps the keys sealed in the database, and sends the CSR, the encryption certificate and the email address to `https://mdmcert.download/api/v1/signrequest`. The service emails a file to that address. 502 with the service's message if it refuses (it does not accept free-mail addresses). A new request replaces a pending one.
- `GET /settings/push-certificate/request` → `{"request": {"pending": false}}` or the pending one as above.
- `POST /settings/push-certificate/request/decrypt` with `{"encrypted": "<the text of the emailed .p7 file>"}` → `{"filename": "push-certificate-request.plist.b64", "content": "<text>"}`: the countersigned request, to be uploaded at https://identity.apple.com/pushcert. 400 if it cannot be decrypted with the pending request's key. Apple then gives a `.pem`, which goes to `PUT /settings/push-certificate` as `certificate_pem`.
- `DELETE /settings/push-certificate/request` → 204: forget a pending request.

- `GET /settings/ca.pem` → the CA certificate (PEM)

### Audit log (admin)

- `GET /events?limit=200` → `{"events": [Event]}`
