# ns8-kumomta

[KumoMTA](https://docs.kumomta.com/) for [NethServer 8](https://github.com/NethServer/ns8-core):
a high performance outbound and inbound mail transfer agent, relay and
smarthost. KumoMTA has no web interface of its own: the NS8 module UI is
its administration interface.

- SMTP listeners: inbound (MX, port 25) and submission (STARTTLS + SMTP
  AUTH, port 587), both optional and on configurable ports
- relaying for trusted networks, authenticated clients and, optionally,
  the whole cluster (NS8 smarthost provider)
- sending domains with DKIM signing, key generation and the DNS TXT record
  to publish
- inbound routes: domains accepted from anyone and relayed to an internal
  server
- optional upstream smarthost with authentication
- traffic shaping per destination, over the KumoMTA default rules
- optional webhook of the delivery log records, with an HMAC-SHA256
  signature
- **sending platforms**: integration credentials separate from the admin
  user, HTTPS injection API (`/api/inject/v1`) and domain management API
  (`/api/v1/domains`) through Traefik, customer domains with DKIM keys,
  DNS records and validation, tenants and campaigns, bounce
  classification, return path and feedback-loop domain
- optional **OpenBao / Vault** key sources for the secrets, with a copy
  back to local storage before turning it off
- optional **sink mode** for testing: accept and discard all outbound mail
- live views: queue summary, top destinations, delivery statistics, recent
  bounces and deliveries
- optional Prometheus metrics route through Traefik, behind authentication

## Documentation

- [docs/integration.md](docs/integration.md): integrating a sending
  platform: SMTP or HTTP injection, credentials, tenants and campaigns
- [docs/domains-and-dkim.md](docs/domains-and-dkim.md): sending domains,
  DKIM, DNS records, validation and status
- [docs/webhooks.md](docs/webhooks.md): event types, payload, signature
- [docs/api.md](docs/api.md): reference of the HTTPS API and the actions,
  with curl examples
- [docs/sink-mode.md](docs/sink-mode.md): sink mode for testing
- [docs/openbao.md](docs/openbao.md): OpenBao/Vault secrets, turning OpenBao off

## Install

    add-module ghcr.io/geniusdynamics/kumomta:latest 1

The output returns the instance name, for example `kumomta1`.

## Configure

Every `configure-module` field is optional: a missing field keeps its
current value, so each UI page sends only its own fields. The first call
needs `hostname`.

```
api-cli run configure-module --agent module/kumomta1 --data - <<EOF
{
  "hostname": "mx.example.org",
  "lets_encrypt": false,
  "inbound_enabled": true,
  "inbound_port": 25,
  "submission_enabled": true,
  "submission_port": 587,
  "relay_networks": ["192.168.1.0/24"],
  "cluster_relay": true,
  "smtp_users": [{"username": "app1", "password": "Secret,1234"}],
  "domains": [{"domain": "example.org", "selector": "kumo1"}],
  "inbound_routes": [{"domain": "example.org", "host": "10.5.4.1", "port": 25}],
  "smarthost_enabled": false,
  "shaping": [{"domain": "gmail.com", "connection_limit": 5, "max_message_rate": "100/min"}],
  "retry_interval": "20m",
  "max_age": "5d"
}
EOF
```

See `imageroot/actions/configure-module/validate-input.json` for every
field. Secrets (`smtp_users[].password`, `smarthost_password`,
`webhook_token`, `webhook_signing_secret`, `vault_token`,
`metrics_password`, `integrations[].password`) are write only:
`get-configuration` returns `*_set` markers instead, and SMTP user
passwords are kept as salted SHA-256 hashes.

Integration settings: `integrations`, `api_host`, `api_allowlist`,
`require_verified_domains`, `spf_include`, `bounce_domain`,
`webhook_signing_secret` (see [docs/api.md](docs/api.md)).

Other actions:

| Action | Role | Purpose |
|---|---|---|
| `get-configuration` | reader | settings, DKIM TXT records, no secrets |
| `get-queue-status` | reader | totals, scheduled messages by domain, delivery counters by destination |
| `list-recent-events` | reader | recent bounces, deferrals, expirations and deliveries from the logs |
| `list-openbao-servers` | reader | OpenBao instances published in the cluster |
| `generate-dkim-key` | admin | generate or rotate a DKIM key, or move a local key to OpenBao |
| `list-domains` | reader | sending domains, owner, DNS status, records to publish |
| `add-domain` | admin | add a sending domain (optionally owned by an integration), generate or import its DKIM key |
| `validate-domain` | admin | check the DNS of one or all sending domains: pending, verified, failed |
| `remove-domain` | admin | remove a sending domain and its local key |
| `list-openbao-only-secrets` | reader | secrets that exist only in OpenBao, and whether the token reads them (no values) |
| `copy-openbao-to-local` | admin | copy those secrets to local 0600 files before turning OpenBao off |

`configure-module` returns `{"warnings": [...]}`: `sink_mode_enabled`
while sink mode is on, `openbao_items_unavailable` (with the item names)
when OpenBao is turned off while secrets exist only there.

## Design

### Rootless, with the network of the host

The module is rootless, like ns8-mail. NS8 sets
`net.ipv4.ip_unprivileged_port_start=23`, so the module user binds 25, 465
and 587 itself. kumod runs with `--network=host`: it sees the real client
addresses, which relaying decisions and logs need, with neither pasta nor a
slirp4netns port handler involved. Nothing requires root: kumod runs as the
`kumod` user of the image, mapped to the module user with
`--userns=keep-id:uid=999,gid=999`, so it reads the 0600 secrets of the
state directory and owns its spool.

The KumoMTA HTTP API listens on `127.0.0.1:${TCP_PORT}` only. Its ACL
(`acl.toml`) replaces the product default: no address is trusted, every
request needs HTTP basic authentication. The module actions use their own
credentials (0600, `state/secrets/api.env`).

### Ports and other mail modules

The listener ports are configurable and the inbound listener is optional,
so KumoMTA can run as an outbound-only relay on a non-standard submission
port next to another MTA. `configure-module` refuses a port that another
NS8 mail module of the node uses (ns8-mail, ns8-mailcow, ns8-postal,
another kumomta), or that another service holds. The enabled ports are
opened with `add-public-service` (`node:fwadm`).

Port 465 (implicit TLS, SMTPS) is not offered yet. KumoMTA added it on
2026-10-16 (commit `7ac08291`, "smtp_server: Add implicit TLS listener
mode", issues #199 and #200): `kumo.start_esmtp_listener` takes
`tls_mode = 'ImplicitTls'` (and `kumo.make_egress_path` the same option for
outbound SMTPS). The reference pages carry `since('dev')` and the entry is
in `docs/changelog/main.md`, the unreleased changelog: the newest stable
release, `2026.09.29-b90d8bc1`, predates it, and ghcr.io has no newer dated
tag, only the floating `main`/`dev`/`latest` and per-commit `sha-*`
images. The module does not run development builds, so the Settings page
shows the 465 listener as a disabled option until a stable release brings
`tls_mode`; then the listener needs the pin upgrade, a third optional
listener in `INIT.listeners` with `tls_mode`, its firewall port and the
same port conflict check as 25 and 587.

### Sending platforms

An integration credential (Integrations page, `integrations` of
`configure-module`) is a user name and a password with scopes: `inject`
(HTTP injection), `smtp` (SMTP AUTH) and `domains` (domain API), an
optional tenant and sending rate. Its salted SHA-256 hash is in
`state/secrets/integrations.*` (0600); kumod checks it in
`http_server_validate_auth_basic` and `smtp_server_auth_plain`, and the
rendered `acl.toml` grants it `/api/inject` only. The `ns8-admin` user of
the module stays on the loopback.

With `api_host`, `configure-module` publishes two Traefik routes on that
host name, HTTPS only: `/api/inject` to kumod and `/api/v1` to
`kumomta-api.service`, a small Python daemon on the second TCP port of the
module (127.0.0.1) that serves the domain API with the same credentials.
The daemon, the domain actions and `configure-module` share the settings
under a file lock; a change re-renders the policy and bumps the
configuration epoch.

Messages of an integration must come `From:` a sending domain of the MTA,
owned by it or by the administrator, and verified (DKIM and SPF found in
the DNS) while `require_verified_domains` is on. `X-Tenant` and
`X-Campaign` set the KumoMTA tenant and campaign (per-customer queues), a
tenant bound to the credential wins, and `max_message_rate` throttles the
tenant. The log records and the webhook carry `meta.tenant`,
`meta.campaign` and the per-recipient injection `metadata` (`meta.extra`),
with the IANA `bounce_classification`. With `bounce_domain`, the inbound
listener accepts mail for it and for `bounces.<sending domain>` and logs
DSNs and ARF reports as `OOB` and `Feedback` records instead of relaying
them. See [docs/integration.md](docs/integration.md).

### Configuration and reload

`configure-module` stores the settings in `state/settings.json` (no
secrets) and renders the KumoMTA policy in `state/kumomta`, mounted on
`/opt/kumomta/etc/policy`:

| File | Content |
|---|---|
| `init.lua` | the policy: listeners, HTTP API, ACL, SMTP AUTH, relaying, DKIM signing, queues, egress paths, webhook; generated `INIT` and `KEYS` tables |
| `acl.toml` | HTTP API access control |
| `listener_domains.toml` | inbound domains (`relay_to`), format of `policy-extras.listener_domains` |
| `relay_hosts.toml` | trusted networks |
| `sources.toml` | egress source and pool, format of `policy-extras.sources` |
| `dkim_data.toml` | DKIM signing data, format of `policy-extras.dkim_sign` (plus `vault_key`) |
| `queues.toml` | retention, inbound routes, smarthost |
| `shaping.toml` | per-destination limits, merged over the KumoMTA `shaping.toml` |
| `webhook.toml` | webhook URL, token and signature flags |
| `platform.toml` | domain policy of the integrations, bounce and feedback domains |

The data files are read through `kumo.memoize` with
`invalidate_with_epoch`. After a change the module bumps the KumoMTA
configuration epoch (`POST /api/admin/bump-config-epoch`): the new settings
apply to the next sessions and queues without dropping connections or
restarting kumod. Only the settings of the `init` event (listener ports,
host name, message size, webhook on/off) and the OpenBao environment need a
restart; the module tracks them in a hash and restarts kumod only when they
change. The unit reports started only once the API and every listener
answer with a 220 banner.

### TLS

Like ns8-mail: the certificate of the host name comes from Traefik
(`traefik@node:fulladm`) through the core `get-certificate` helper into
`state/tls`, with a self-signed certificate until Traefik has one. With
`lets_encrypt` the module requests it with `set-certificate`; the
`certificate-changed` event replaces the files and KumoMTA re-reads them.

### OpenBao / Vault

The OpenBao page turns on KumoMTA key sources from a KV v2 store, OpenBao
or Vault. `VAULT_ADDR` and `VAULT_TOKEN` are stored in `state/openbao.env`
(0600) and loaded by `kumomta.service` with
`EnvironmentFile=-%S/state/openbao.env`; they are never written in the
policy nor returned by `get-configuration` (`vault_token_set` instead).
With OpenBao on, the policy renders vault blocks (`vault_mount`,
`vault_path`, optional `vault_key`) for:

- DKIM private keys: `<path>/dkim/<domain>/<selector>`
- the smarthost password: `<path>/smarthost`
- the webhook bearer token: `<path>/webhook`

When the UI receives a new secret it writes it to OpenBao itself (the
token then needs write access to the path); `generate-dkim-key` generates a
key in OpenBao or moves the local one there, so the private key leaves the
volume. With OpenBao off, the same secrets are local 0600 files. The
module's own credentials (HTTP API, SMTP AUTH hashes, metrics password)
stay local: the module must keep working when OpenBao is unreachable.

Turning OpenBao off leaves the secrets that exist only in OpenBao behind:
`list-openbao-only-secrets` (reader, names and paths only) lists them, and
the UI shows them in a warning before saving. It offers to copy them back
to local 0600 files first with `copy-openbao-to-local`, when the token can
still read them, or to turn OpenBao off anyway. `configure-module` returns
an `openbao_items_unavailable` warning with the same list. See
[docs/openbao.md](docs/openbao.md).

[geniusdynamics/ns8-openbao](https://github.com/geniusdynamics/ns8-openbao)
publishes `module/<id>/srv/http/openbao` when its cluster network API is
enabled: the UI lists those instances and offers the first one as default,
and the manual URL remains the fallback.

### Cluster smarthost

The core "Email notifications" settings (`cluster/get-smarthost`) list the
modules publishing `module/<id>/srv/tcp/submission`, and configure the
chosen one with its host, port 25, no TLS and no authentication. With
`cluster_relay` the module publishes that key with the VPN address of the
node and trusts the cluster network for relaying. This works only with the
inbound listener on port 25; in outbound-only mode or on another port the
key is removed, since the core would configure a port nobody listens on.
Other applications can use the same address, or a submission user.

The cluster relay is on by default. The "Offer as smarthost to the
cluster" toggle of the Settings page (`"cluster_relay": false`) turns it
off: the cluster network leaves `relay_hosts.toml` and the
`srv/tcp/submission` key is deleted, so `cluster/get-smarthost` no longer
lists the module and unauthenticated mail from the cluster addresses can
only reach the inbound domains.

### Sink mode (testing)

`"sink_enabled": true` (Settings, "Sink mode (testing)", off by default)
makes KumoMTA accept every message and discard it instead of delivering
it, like the KumoMTA
[smart-sink example](https://github.com/KumoCorp/kumomta/tree/main/examples/smart-sink-docker):
every scheduled queue gets a `custom_lua` delivery protocol that logs a
`Delivery` record. A recipient local part containing `tempfail` or
`permfail` simulates a deferral or a bounce. While it is on, the UI shows
a warning banner on every page and `get-configuration` returns a
`sink_mode_enabled` warning. See [docs/sink-mode.md](docs/sink-mode.md).

### Live views

`get-queue-status` reads `/metrics.json` of the local API.
`list-recent-events` decodes the closed KumoMTA log segments (a segment
closes every minute) with the `tailer` tool of the image. Log segments are
kept 7 days (`kumomta-logs-cleanup.timer`).

### Backup

`state-include.conf` covers `settings.json`, `secrets/`, `openbao.env`,
`dkim/` (the integration credentials are under `secrets/`), the rendered
policy and the `kumomta-spool` volume. Before the
backup `module-dump-state` asks kumod to flush its RocksDB spool. Restore
and clone call `configure-module` with every setting and `lets_encrypt`
off.

### Image

`ghcr.io/kumocorp/kumomta`, pinned to the newest stable release. KumoMTA
publishes dated stable releases (`2026.09.29-b90d8bc1`) matching its
GitHub releases; `latest`, `main` and `dev` are floating and are not used.
`renovate.json` compares these tags with a regex versioning. No Redis: no
implemented feature needs it (the traffic shaping automation daemon and
shared throttles are not configured).

## Uninstall

    remove-module --no-preserve kumomta1

## Testing

Test the module using the `test-module.sh` script:

    ./test-module.sh <NODE_ADDR> ghcr.io/geniusdynamics/kumomta:latest

The tests are made using [Robot Framework](https://robotframework.org/)
