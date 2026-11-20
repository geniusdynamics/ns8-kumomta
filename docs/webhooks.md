# Event webhooks

KumoMTA can POST each of its log records to a URL: delivery, deferral,
bounce, expiration, out-of-band bounce and complaint events. Configure it
on the Delivery page, or:

```
api-cli run module/kumomta1/configure-module --data '{
  "webhook_enabled": true,
  "webhook_url": "https://platform.example.com/hooks/kumomta",
  "webhook_record_types": ["Delivery", "Bounce", "TransientFailure",
                           "Expiration", "OOB", "Feedback"],
  "webhook_token": "optional-bearer-token",
  "webhook_signing_secret": "optional-hmac-secret-16+-chars"
}'
```

## Delivery

- One HTTP `POST` per record, `Content-Type: application/json`, the body
  is the record (below).
- A `2xx` answer acknowledges the record. Anything else (or no answer) is
  retried: first after 1 minute, then with back-off up to 20 minutes,
  until the record expires with the default queue retention. The receiver
  must therefore be **idempotent**: the same record can arrive more than
  once. Use `id` + `type` + `event_time` as the deduplication key.
- Records are queued in the spool: they survive a restart, and they are
  not lost while the receiver is down.
- Order is not guaranteed.

## Authentication

Two optional, independent mechanisms; both secrets are write only, stored
in 0600 files or in OpenBao:

- **Bearer token** (`webhook_token`): `Authorization: Bearer <token>`.
- **Signature** (`webhook_signing_secret`): every request carries

  ```
  X-KumoMTA-Signature: t=1763280000,v1=5f2b...e9
  ```

  where `t` is the Unix time of the request and `v1` the lowercase hex
  HMAC-SHA256 of the string `<t>.<raw request body>` with the secret as
  key. Verify it on the raw body, before parsing it, with a constant time
  comparison, and reject a `t` older than a few minutes (replay):

  ```python
  import hashlib, hmac, time

  def verify(secret: bytes, header: str, body: bytes, tolerance=300) -> bool:
      fields = dict(item.split("=", 1) for item in header.split(","))
      ts, sig = fields.get("t", ""), fields.get("v1", "")
      if not ts.isdigit() or abs(time.time() - int(ts)) > tolerance:
          return False
      expected = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
      return hmac.compare_digest(expected, sig)
  ```

  ```go
  mac := hmac.New(sha256.New, secret)
  mac.Write([]byte(ts + "."))
  mac.Write(body)
  ok := hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(sig))
  ```

## Event types

| `type` | Meaning | Platform action |
|---|---|---|
| `Delivery` | accepted by the destination server (`response.code` 2xx) | mark delivered |
| `TransientFailure` | deferred (4xx or connection problem), will be retried | record the last response, keep waiting |
| `Bounce` | permanently rejected (5xx) during delivery | mark bounced; suppress the address for a hard bounce (see `bounce_classification`) |
| `Expiration` | still undelivered after the retention time (`max_age`) | mark failed |
| `AdminBounce` | removed by an administrator | mark failed |
| `OOB` | an asynchronous bounce (DSN) received on the return path domain | mark bounced, suppress |
| `Feedback` | an ARF complaint report (feedback loop) | mark complained, suppress |
| `Reception` | the message was accepted by the MTA | optional |
| `Rejection` | a message was refused at reception | optional |

## Record format

The body is a KumoMTA log record
([reference](https://docs.kumomta.com/reference/log_record/)). The fields
a platform needs:

```json
{
  "type": "Bounce",
  "id": "1d98076abbbc11ed940250ebf67f93bd",
  "sender": "bounce-123@bounces.customer.example",
  "recipient": "user@destination.example",
  "queue": "newsletter-42:customer-7@destination.example",
  "site": "destination.example->mx.destination.example",
  "size": 4211,
  "response": {
    "code": 550,
    "enhanced_code": {"class": 5, "subject": 1, "detail": 1},
    "content": "5.1.1 The email account that you tried to reach does not exist",
    "command": "."
  },
  "peer_address": {"name": "mx.destination.example.", "addr": "192.0.2.25"},
  "timestamp": 1763280000,
  "event_time": "2026-11-16T08:00:00.123456789Z",
  "created": 1763279990,
  "num_attempts": 1,
  "bounce_classification": "InvalidRecipient",
  "egress_pool": "default",
  "egress_source": "default",
  "feedback_report": null,
  "headers": {"Subject": "Your invoice", "Message-ID": "<abc@customer.example>"},
  "meta": {
    "tenant": "customer-7",
    "campaign": "newsletter-42",
    "extra": {"message_id": "msg_01H..."}
  },
  "delivery_protocol": "ESMTP",
  "reception_protocol": "HTTP",
  "nodeid": "..."
}
```

| Field | |
|---|---|
| `type` | event type, above |
| `id` | KumoMTA spool id of the message (one per recipient) |
| `sender`, `recipient` | envelope addresses |
| `queue` | `campaign:tenant@domain` (parts absent when unset) |
| `response` | last SMTP response; `code` 2xx/4xx/5xx |
| `bounce_classification` | classification by the IANA enhanced status code rules of KumoMTA: `InvalidRecipient`, `InactiveMailbox`, `BadDomain`, `DNSFailure`, `QuotaIssues`, `PolicyRelated`, `AuthenticationFailed`, `MessageExpired`, `RoutingErrors`, `TransientFailure`, `Uncategorized`... Hard bounces for suppression: `InvalidRecipient`, `InactiveMailbox`, `BadDomain` |
| `timestamp`, `event_time`, `created` | Unix time and RFC 3339 time of the event, Unix time of the reception |
| `num_attempts` | delivery attempts so far |
| `headers` | `Subject` and `Message-ID` of the message |
| `meta.tenant`, `meta.campaign` | from the assigned tenant and the accepted campaign header |
| `meta.extra` | the per-recipient `metadata` of the HTTP injection, unchanged: put the platform's own message id here to correlate |
| `meta.x_message_ref` | the `X-Message-Ref` header of the message, if any |
| `feedback_report` | for `Feedback`: the parsed ARF report (`feedback_type`, `user_agent`, `original_mail_from`, `original_rcpt_to`, `reported_domain`, the original message headers...) |

Correlation: for HTTP injection, set `recipients[].metadata` (for example
`{"message_id": "<platform id>"}`) and read `meta.extra.message_id`. For
SMTP, add an `X-Message-Ref:` header (imported as `meta.x_message_ref`) or
use the `Message-ID` in `headers`. `OOB` and `Feedback` records describe a
report about an earlier message: the original recipient is in the report
(`feedback_report.original_rcpt_to`, or the `recipient` of the OOB record),
the original `Message-ID` in the report headers.

## Tests

Turn on [sink mode](sink-mode.md) on a test instance: injected messages
produce `Delivery` records, and recipients containing `tempfail` or
`permfail` produce `TransientFailure` and `Bounce` records, without
delivering anything.
