# OpenBao / Vault

The module can read the secrets of KumoMTA from an OpenBao or HashiCorp
Vault KV version 2 store instead of local files.

## What lives where

| Secret | Local file (OpenBao off) | OpenBao path (OpenBao on) |
|---|---|---|
| DKIM private key | `state/dkim/<domain>/<selector>.key` (0600) | `<mount>/<path>/dkim/<domain>/<selector>` |
| Smarthost password | `state/secrets/smarthost_password` (0600) | `<mount>/<path>/smarthost` |
| Webhook bearer token | `state/secrets/webhook_token` (0600) | `<mount>/<path>/webhook` |
| Password of a manual cluster throttle store | `state/secrets/cluster_redis_password` (0600) | `<mount>/<path>/cluster_redis`, shared by the instances using the same path ([cluster.md](cluster.md)) |

Each OpenBao secret holds the value in the field named by `vault_key`
(`key` when empty). `VAULT_ADDR` and `VAULT_TOKEN` are stored in
`state/openbao.env` (0600) and passed to kumod through its environment;
they are never written in the policy or returned by an action
(`get-configuration` returns `vault_token_set` only).

The module's own credentials (HTTP API, SMTP AUTH hashes, metrics
password, integration credentials) always stay local, so the MTA keeps
working when OpenBao is unreachable.

## Turn it on

OpenBao page, or:

```
api-cli run module/kumomta1/configure-module --data '{
  "vault_enabled": true,
  "vault_address": "https://openbao.example.org",
  "vault_token": "s.xxxx",
  "vault_mount": "secret",
  "vault_path": "kumomta",
  "vault_key": ""
}'
```

New secrets saved from the UI are written to OpenBao (the token needs write
access). `generate-dkim-key` writes new keys to OpenBao, and moves an
existing local key there: the private key then leaves the volume, only the
public key stays on disk for the DNS record.

## Turn it off

A secret that exists only in OpenBao is lost to KumoMTA when OpenBao is
turned off: DKIM signing of that domain stops (messages leave unsigned,
`key_location` becomes `missing`) and the smarthost password or webhook
token stop working until they are set again.

1. `list-openbao-only-secrets` (reader) lists those secrets: kind, name
   and OpenBao path, plus whether the current token can read each one. It
   never returns the values.

   ```
   api-cli run module/kumomta1/list-openbao-only-secrets
   {"vault_enabled": true, "copyable": true, "items": [
     {"kind": "dkim_key", "name": "kumo1._domainkey.example.org",
      "domain": "example.org", "selector": "kumo1",
      "path": "kumomta/dkim/example.org/kumo1", "readable": true},
     {"kind": "smarthost_password", "name": "smarthost_password",
      "path": "kumomta/smarthost", "readable": true}]}
   ```

2. `copy-openbao-to-local` (admin) reads them with the current token and
   writes the local 0600 files. A DKIM key is copied only when it matches
   the published public key. The output lists the copied and the failed
   items, without values; the action fails if any item failed.

3. `configure-module` with `"vault_enabled": false`. If secrets still
   exist only in OpenBao, the action goes on and returns a warning:

   ```
   {"warnings": [{"id": "openbao_items_unavailable",
                  "items": ["kumo1._domainkey.example.org"]}]}
   ```

The OpenBao page does this for you: when OpenBao was on and you turn it
off, it shows the list in a warning and offers "Copy to local storage and
turn off" (when the token can read every item) or "Turn off anyway".

## Discovery

[geniusdynamics/ns8-openbao](https://github.com/geniusdynamics/ns8-openbao)
publishes `module/<id>/srv/http/openbao` when its "Cluster network API"
setting is on. `list-openbao-servers` returns those instances in
`servers` (the UI choice "OpenBao of this cluster" sets `VAULT_ADDR` to
one of them) and the other openbao instances of the cluster in
`unpublished`: the UI names them with the setting to turn on. "Other
OpenBao or Vault" takes any URL.
