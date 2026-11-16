# Secrets in OpenBao

OpenMDM keeps people's secrets (and global ones) in OpenBao, or HashiCorp
Vault, KV version 2. Nothing else is stored there, and OpenMDM's token should
be able to reach nothing else.

Layout, with the defaults `mount: secret` and `prefix: openmdm`:

| Secret | KV path |
|---|---|
| one person's secrets, all keys in one document | `secret/openmdm/users/<username>` |
| global secrets | `secret/openmdm/global` |

Usernames are lower-cased and limited to `a-z 0-9 . _ @ -`; keys to
`a-z 0-9 _`. OpenMDM refuses anything else before it makes a request, so a
name cannot point outside the prefix.

Setting a key reads the document and writes it back with KV v2
check-and-set (`cas`), and tries again if someone else wrote in between. Two
people saving different keys at once both keep them. Deleting the last key
writes an empty document; old versions stay in KV's history. Nothing is
destroyed.

## Policy

OpenMDM only reads and writes the data paths. It never lists, deletes or
reads metadata, so it needs no `metadata/` path and no `delete` or `list`.
Save as `openmdm.hcl`:

```hcl
# Everything under the prefix: users/<name> and global.
path "secret/data/openmdm/*" {
  capabilities = ["create", "read", "update"]
}

# The health check asks what the token may do on its own paths. Every token
# gets this from the default policy; keep it if you attach tokens without it.
path "sys/capabilities-self" {
  capabilities = ["update"]
}
```

If you change `mount` or `prefix`, change the path to match
(`<mount>/data/<prefix>/*`). If you want to look at version history yourself
as an operator, do it with your own token; do not widen this one.

```sh
bao policy write openmdm openmdm.hcl
```

(`vault` instead of `bao` for HashiCorp Vault.)

## A token

```sh
bao token create -policy=openmdm -period=768h -orphan -display-name=openmdm
```

A periodic token lives as long as it is renewed, and OpenMDM does not renew
it, so renew it yourself or prefer AppRole below. Put it in the config as
`token`, in `OPENMDM_OPENBAO_TOKEN`, or in a file named by `token_file`. The
file is read again when it changes, so you can rotate it without a restart.

## AppRole (recommended)

OpenMDM logs in itself, keeps the token until shortly before it expires, and
logs in again if a request is refused with 403.

```sh
bao auth enable approle
bao write auth/approle/role/openmdm \
    token_policies=openmdm \
    token_ttl=1h token_max_ttl=24h \
    secret_id_ttl=0

bao read  -field=role_id   auth/approle/role/openmdm/role-id
bao write -f -field=secret_id auth/approle/role/openmdm/secret-id
```

The secret ID is a password: keep it in a file with mode 0600
(`secret_id_file`, re-read at each login) or in
`OPENMDM_OPENBAO_SECRET_ID`.

## OpenMDM config

```yaml
secrets:
  backend: openbao
  address: https://bao.example.com:8200
  mount: secret          # default
  prefix: openmdm        # default
  role_id: 4d2c0c3e-0000-0000-0000-000000000000
  secret_id_file: /etc/openmdm/secret-id
  ca_file: /etc/openmdm/bao-ca.pem   # only for a private CA; added to the system roots
```

With a plain token instead of AppRole, replace the `role_id` and
`secret_id_file` lines with one of:

```yaml
  token_file: /etc/openmdm/bao-token
  # or: token: s.xxxxxxxx   (better: OPENMDM_OPENBAO_TOKEN)
```

Give one method only: `token`, else `token_file`, else `role_id` with
`secret_id` or `secret_id_file` is used, in that order.

## Checking it

`GET /healthz` and the settings page call `sys/capabilities-self` for
`secret/data/openmdm/global`. They report unhealthy if the token is refused or
lacks `read`, `create` or `update` there. This writes nothing.

## Development

`backend: file` with `file: ./secrets.json` keeps the same documents in one
JSON file (mode 0600, values in the clear), and `backend: memory` forgets them
on exit. Neither is for production.
