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

A push certificate starts with a certificate signing request (CSR) for a key that never leaves the server:

- `POST /settings/push-certificate/csr` → `{"filename": "openmdm-push.csr", "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----…", "request": {"pending": true, "requested_at": "…", "email": ""}}`. Makes a new private key (kept sealed in the database) and its CSR, replacing any pending one. No network call. This is also how the certificate is renewed each year: a new CSR, a new key, the same Apple ID at Apple's portal.
- `GET /settings/push-certificate/csr` → the pending CSR again, same shape; 404 if none is pending.

The resulting certificate, however it was obtained, goes to `PUT /settings/push-certificate` as `certificate_pem`.

- `GET /settings/ca.pem` → the CA certificate (PEM)

Apple's portal (https://identity.apple.com/pushcert) is documented as taking only a request countersigned by an MDM vendor, not a plain CSR. OpenMDM can do that itself, with an MDM vendor certificate of your own, or use the free signing service mdmcert.download.

#### Signing it yourself: the MDM vendor certificate

Apple's route (https://developer.apple.com/documentation/devicemanagement/setting-up-push-notifications-for-your-device-management-customers): the Account Holder of an Apple Developer Program or Enterprise Program membership asks Apple for access to the "MDM Vendor CSR Signing Certificate" (https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate), creates it in the developer portal and exports it with its private key. OpenMDM keeps the certificate (PEM) in the blob `vendor/cert` and the key, sealed, in `vendor/key`; no route returns the key.

- `GET /settings/vendor-certificate` → `{"vendor": {"configured": true, "subject": "...", "not_after": "...", "sha256": "..."}}`, or `{"vendor": {"configured": false}}`. An expired certificate is still shown, so that it can be replaced.
- `PUT /settings/vendor-certificate` with either `{"certificate_pem": "...", "key_pem": "..."}` or `{"p12": "<base64 of a .p12 file>", "password": "..."}` → `{"vendor": {...}}`. The certificate may be PEM (a chain is fine: the one that matches the key is used) or the base64 of a DER `.cer` file. The key must be an RSA key in PEM (PKCS#1 or PKCS#8, no passphrase). A .p12 (as exported from Keychain Access) is opened with its password; it must be in the legacy 3DES form that Keychain Access writes, and its key must be RSA. 400 with a message if the key does not match the certificate, the key is not RSA, the certificate has expired or is not yet valid, or the input cannot be read. The password is never stored.
  If the certificate was not issued by Apple's WWDR G3 intermediate (the one embedded in OpenMDM) it is still accepted, and the answer carries a warning: `{"vendor": {...}, "warning": "The certificate does not chain to Apple's WWDR G3 intermediate, ... Apple's portal may reject requests signed with it."}`.
- `DELETE /settings/vendor-certificate` → 204: forgets the certificate and its key.
- `POST /settings/push-certificate/vendor-sign` → `{"filename": "push-certificate-request.plist.b64", "content": "<base64 text>", "request": {"pending": true, "requested_at": "…", "email": ""}}`. Uses the pending CSR and key (making them first if none is pending, as `POST /settings/push-certificate/csr` does; an existing pending request is reused, not replaced). The CSR in DER is signed with the vendor key (SHA256WithRSA, PKCS#1 v1.5), and a property list with exactly three keys is built: `PushCertRequestCSR` (base64 of the DER CSR), `PushCertSignature` (base64 of the signature) and `PushCertCertificateChain` (the PEM of the vendor certificate, then Apple's WWDR G3 intermediate, then the Apple root, each with 64-character lines). `content` is the base64 of that XML property list: the file to upload at https://identity.apple.com/pushcert, with an Apple ID (the same one every year). 400 if no vendor certificate is configured or it has expired; nothing is changed then. The request stays pending; the `.pem` certificate Apple returns goes to `PUT /settings/push-certificate` as `certificate_pem` only.

The two Apple certificates are part of the program (`internal/api/applecerts`); a test checks that the root is Apple's (SHA-256 `B0:B1:73:0E:CB:C7:FF:45:05:14:2C:49:F1:29:5E:6E:DA:6B:CA:ED:7E:2C:68:C5:BE:91:B5:A1:10:01:F0:24`), that the intermediate is signed by it and that neither has expired. Audit events: `settings.vendor_certificate_set`, `settings.vendor_certificate_deleted` and `settings.push_vendor_sign`, none with key material.

#### Signing it with mdmcert.download

The service's JSON API was deprecated in 2026: the live server answers "This API has been deprecated; please visit https://mdmcert.download/". The UI therefore no longer calls these routes; it sends people to the website, where the CSR (from `GET /settings/push-certificate/csr`) is uploaded by hand, and shows the decrypt step only if a request made earlier is still pending (`request.email` is not empty). The routes below are kept for compatible services reachable through the configurable signing URL, and `POST .../request` passes the service's message on (502) when it refuses. In three steps:

- `POST /settings/push-certificate/request` with `{"email": "you@your-company.example"}` → `{"request": {"pending": true, "email": "...", "requested_at": "..."}}`. Uses the pending CSR (making a key and CSR first if none is pending), makes a one-off encryption certificate, keeps the keys sealed in the database, and sends the CSR, the encryption certificate and the email address to `https://mdmcert.download/api/v1/signrequest`. The service emails a file to that address. 502 with the service's message if it refuses (it does not accept free-mail addresses); the pending key and CSR are kept, so it can be tried again or the CSR used another way.
- `GET /settings/push-certificate/request` → `{"request": {"pending": false}}` or the pending one as above.
- `POST /settings/push-certificate/request/decrypt` with `{"encrypted": "<the text of the emailed .p7 file>"}` → `{"filename": "push-certificate-request.plist.b64", "content": "<text>"}`: the countersigned request, to be uploaded at https://identity.apple.com/pushcert. 400 if it cannot be decrypted with the pending request's key. Apple then gives a `.pem`, which goes to `PUT /settings/push-certificate` as `certificate_pem`.
- `DELETE /settings/push-certificate/request` → 204: forget a pending request.

### Audit log (admin)

- `GET /events?limit=200` → `{"events": [Event]}`
