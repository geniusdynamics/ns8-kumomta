# Sink mode (testing)

Sink mode turns the MTA into a mail sink: KumoMTA accepts every message,
signs it as usual, and then discards it instead of delivering it. Use it
to test a sending platform end to end (SMTP or HTTP injection, queues,
DKIM, webhooks) without sending a single message to the Internet.

**Never leave it on in production: while it is on, no message leaves the
server.**

## Turn it on and off

From the UI: Settings, "Testing", "Sink mode (testing)". Or:

```
api-cli run module/kumomta1/configure-module --data '{"sink_enabled": true}'
api-cli run module/kumomta1/configure-module --data '{"sink_enabled": false}'
```

The change applies at once, without a restart: the module bumps the
KumoMTA configuration epoch and every scheduled queue re-reads its
configuration.

While sink mode is on:

- the UI shows a warning banner on every page;
- `get-configuration` returns `"sink_enabled": true` and a warning
  `{"id": "sink_mode_enabled", "message": "..."}` in `warnings`;
- `configure-module` returns the same warning id in its output.

## What it does

It follows the policy of the KumoMTA
[smart-sink example](https://github.com/KumoCorp/kumomta/tree/main/examples/smart-sink-docker),
with one difference: the example is a separate receiving server that
rejects at SMTP time, while here the sink replaces the delivery of this MTA,
so the platform sees the same asynchronous records it sees in production.

Every scheduled queue (outbound destinations, inbound routes and the
smarthost, messages already queued included) gets the `custom_lua`
delivery protocol `ns8_sink`. Its `send` method returns success, so KumoMTA
logs a `Delivery` record with the response
`ns8-kumomta sink: accepted and discarded, not delivered`, removes the
message from the spool and counts it as delivered.

The recipient local part selects a simulated outcome:

| Local part contains | Outcome | Log record |
|---|---|---|
| `tempfail` | `451 4.3.0 ... simulated transient failure`, retried later | `TransientFailure` |
| `permfail` | `550 5.1.1 ... simulated bounce` | `Bounce` |
| anything else | accepted and discarded | `Delivery` |

The records reach the webhook (see [webhooks.md](webhooks.md)) and the
recent events of the Queue page like real ones, so a platform can test its
delivery, deferral and bounce handling.

Sink mode does not change reception: relaying rules, authentication, DKIM
signing, tenants and domain checks apply as usual.

## Capture

The sink discards the messages. To look at the signed messages, send them
to a mailbox you control with sink mode off, or inspect a queued message
with the KumoMTA admin API before it is delivered.
