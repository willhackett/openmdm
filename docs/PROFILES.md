# Writing a profile

A profile is a `.mobileconfig` (an XML property list) with template actions
where something differs between people or devices, plus a few lines saying
who it is for.

## In the profiles directory

Two files per profile, named by its ID (`[a-z0-9-]+`):

    profiles/personal-mail.mobileconfig     the template
    profiles/personal-mail.yaml             who it is for

```yaml
name: Personal mail
description: Fastmail mail, calendars and contacts
platforms: [macos, ios, ipados]
macos_channel: user        # "device" (default) or "user"
assign:
  everyone: true           # or: users: [will, george]   groups: [family]
```

The directory is read at start and again whenever a file in it changes. A
profile from a file shows in the UI as read-only (`source: file`). Removing
the files removes the profile, and so removes it from devices.

## The template

Go's `text/template`, with `{{` and `}}`. Everything a template prints is
XML-escaped, except `secretData`/`globalSecretData`, whose values are
already base64 and go inside `<data>`.

| Action | Gives |
|---|---|
| `{{ .User.Username }}`, `.User.Email`, `.User.Name` | the device's owner |
| `{{ .Device.ID }}`, `.Device.SerialNumber`, `.Device.DeviceName`, `.Device.Model`, `.Device.OSVersion`, `.Device.Platform` | the device |
| `{{ .Organization }}` | from the configuration |
| `{{ secret "fastmail_app_password" }}` | the owner's secret of that name |
| `{{ globalSecret "wifi_psk" }}` | a global secret |
| `{{ secretData "smime_p12" }}`, `{{ globalSecretData "…" }}` | a secret whose value is base64, for a `<data>` element |
| `{{ uuid "mail" }}` | a UUID that is always the same for this profile, device and label |

A profile that names a secret its owner has not set, or uses `.User` on a
device with no owner, is not sent: it shows on the device as **blocked**,
with what is missing. It goes by itself once that is supplied.

The top-level `PayloadIdentifier` must be a constant: it is how the profile
is recognised on the device and removed from it.

`if`, `range`, `eq` and the rest of `text/template` work: a profile can
include a payload only on one platform with
`{{ if eq .Device.Platform "macos" }}…{{ end }}`.
