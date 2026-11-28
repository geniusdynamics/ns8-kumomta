# Guardrails for customer submission

KumoMTA can enforce admission limits, isolate new tenants on sandbox sending
IPs, pause a tenant, and check a suppression service and Rspamd. Configure
these controls through the NS8 administrator action `configure-module`. They
apply to authenticated integration credentials on SMTP submission and HTTP
injection. Use those credentials for customer traffic. The cluster smarthost,
trusted relays, ordinary SMTP users, and the internal admin API are for
administrator traffic.

## Configure tenants and sending IPs

Set `guarded_integrations` to the names of integration credentials that must
use a configured tenant. Each credential in this list needs a fixed tenant or
a tenant prefix. Use fixed-tenant credentials for direct customer access. Use
a prefix-scoped credential in a trusted platform that submits for multiple
tenants. The domain policy resolves and validates the tenant before admission.

Set `tenant_policies` to a map keyed by the exact KumoMTA tenant label. Any
integration that submits under one of these labels uses the corresponding
policy. Each entry requires `admission_per_hour`. It can also set `pool` to
`default` or `sandbox`, and `paused` to `true` or `false`.

```json
{
  "guarded_integrations": ["platform"],
  "tenant_policies": {
    "customer-trial": {"admission_per_hour": 100, "pool": "sandbox"},
    "customer-approved": {"admission_per_hour": 2500, "pool": "default"},
    "customer-paused": {"admission_per_hour": 100, "paused": true}
  },
  "sending_ips": [
    {"address": "192.0.2.10", "per_hour": 2500},
    {"address": "192.0.2.11", "per_hour": 100}
  ],
  "sandbox_ips": ["192.0.2.11"]
}
```

Example addresses are reserved for documentation. Use addresses assigned to
the node and an existing integration named `platform`. Sandbox addresses must
be explicit entries in `sending_ips`. Reserve at least one other explicit
address for the default pool. Pool isolation requires direct SMTP delivery.
Keep IP settings local to each node and distribute tenant policies and
credential settings to every node that accepts traffic for those tenants.

Setting `paused` defers new submissions with `451` and assigns queued mail
for the tenant to a pool without sending IPs. Changing a pool assignment or
pause restarts kumod to rebuild ready queues from the spool. Wait for the
configuration action to finish on each node. SMTP transactions already in
progress during the restart may complete. Paused messages remain subject to
the normal queue retention period. Clear the pause to resume delivery.

The admission limit uses KumoMTA's replenishing hourly throttle with the
default burst allowance. It counts envelope recipients across both submission
protocols. Rejected recipients can consume capacity because the module charges
the budget before calling external services. A rejected SMTP batch may have
used part of its budget. For a clustered module, protected submissions defer
with `451` when the shared throttle store is unavailable, even when the module
has fallen back to local delivery throttles. On a standalone module the
admission counter is local. The existing `max_message_rate` is a delivery
throttle and applies independently.

The NS8 action replaces the entire map or list for any supplied field. Omit a
field to keep its current value. Read the applied policy with
`get-configuration`.

## Check a platform suppression service

Set `suppression_url` to a trusted HTTPS endpoint with a valid certificate.
Set the write-only `suppression_token` to its bearer credential. Endpoints
are configured by the module administrator. Use a final URL and configure the
service without redirects.

For each submission under a tenant policy, KumoMTA POSTs JSON containing
`tenant`, `integration` and `recipients` (an array of envelope addresses).
The request carries the token in the Authorization header and contains no
message body or subject. The service must authorize the integration and tenant,
apply the current recipient policy, and respond within three seconds.

| Response | Module behavior |
|---|---|
| `204` | Continue only when every recipient passes |
| `403` | Reject the affected submission with `550` |
| Other status, timeout or connection failure | Defer with `451` |

SMTP may submit several recipients in one transaction. Treat the request as an
all-or-nothing decision. HTTP injection reports failures per recipient in its
normal response. Connect this service wherever customers submit directly, so
they cannot bypass the platform's suppression checks.

## Scan with Rspamd

Set `rspamd_url` to the full `/checkv2` URL of a private Rspamd worker
reachable from the sending node. Set `rspamd_password` if the worker requires
the Rspamd Password header. Use a trusted link to the scanner as it receives
the message content. A worker bundled with a mail server can be used if it is
configured to serve this endpoint to KumoMTA.

The module scans messages under a tenant policy after admission and suppression
checks and before DKIM signing. `no action` and `accept` continue, `reject`
produces `550`, and `soft reject`, other actions, skipped scans and service
failures defer with `451`. Tune the worker to return these delivery decisions.
When a guarded message cannot be DKIM-signed, it also defers with `451`.

Endpoint tokens and passwords are private files backed up with module secrets.
`get-configuration` returns only whether each credential is set. To remove a
secret use `suppression_token_clear` or `rspamd_password_clear`. Clear the URL
when removing the suppression token.

See the [sending platform responsibilities](platform-responsibilities.md),
[KumoMTA throttle reference](https://docs.kumomta.com/reference/kumo/make_throttle/)
and [Rspamd integration guide](https://docs.kumomta.com/userguide/integrations/rspamd/).
