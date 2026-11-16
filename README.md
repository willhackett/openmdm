# OpenMDM

A small MDM server for Apple devices: enrol a Mac, iPhone or iPad, and push
configuration profiles to it through Apple's push service.

*Created out of pure frustration that this doesn't exist without some
fucking paywall.*

What it does, with nothing held back for a paid edition:

- **One profile for every platform.** A profile says which platforms it is
  for and, on a Mac, whether it belongs to the machine or to the user.
  Nothing is sent to a device it was not written for.
- **Profiles are per person.** Assign a profile to everyone, to people or to
  groups. It is rendered for each device's owner when it is sent: their
  name, their address, their secrets.
- **Secrets live in OpenBao** (or Vault), never in OpenMDM's database: one
  document per person under a prefix that is all OpenMDM's token can reach.
  A person sets their own from the UI; a profile that needs one that is not
  set yet waits, and says which.
- **Single sign-on only** (OIDC). No local passwords.
- **Its own certificate authority and SCEP server**, so every device gets
  its own identity certificate at enrolment and every profile is signed.
- **One binary, one data directory.** SQLite, no other database. Runs
  natively on arm64 and amd64.

It is built on [NanoMDM](https://github.com/micromdm/nanomdm), which does
the MDM protocol itself.

Not in it: automatic enrolment through Apple Business Manager, installing
apps, enforcing OS updates, software inventory.

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): the parts and how they meet
- [docs/PROFILES.md](docs/PROFILES.md): writing a profile
- [docs/API.md](docs/API.md): the HTTP API
