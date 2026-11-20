# Integrating a sending platform

This module can be the MTA of a sending platform: a transactional or
marketing email service that sends on behalf of many customers, each with
their own sending domains. This page is the overview; the details are in:

- [domains-and-dkim.md](domains-and-dkim.md): customer domains, DKIM, DNS records, validation
- [webhooks.md](webhooks.md): delivery, bounce and complaint events
- [api.md](api.md): reference of the endpoints and the NS8 actions, with curl examples
- [sink-mode.md](sink-mode.md): end-to-end tests without delivering mail
- [openbao.md](openbao.md): keeping DKIM keys in OpenBao or Vault

## Building blocks

```
 platform ──HTTPS──► Traefik ── /api/inject/v1 ──► kumod (HTTP injection)
     │                     └── /api/v1/domains ──► kumomta-api (domains, DKIM, DNS checks)
     ├──SMTP 587 (STARTTLS + AUTH)──────────────► kumod (submission)
     ◄──HTTPS POST (webhook, optionally signed)── kumod log hook
```

| Need | Use |
|---|---|
| Send a message | HTTP injection (`POST /api/inject/v1`) or SMTP submission |
| Add a customer domain, get its DNS records | `POST /api/v1/domains` |
| Check the customer's DNS | `POST /api/v1/domains/<domain>/validate` |
| Learn what happened to a message | the webhook: `Delivery`, `Bounce`, `TransientFailure`, `Expiration`, `OOB`, `Feedback` records |
| Separate customers in queues, rates and logs | KumoMTA tenants and campaigns |

## Integration credentials

The platform authenticates with an **integration credential**, never with
the module's own admin API user (`ns8-admin`, which stays on the loopback
and is never routed). Create one per platform on the **Integrations** page,
or with `configure-module`:

```json
{
  "api_host": "mta-api.example.org",
  "integrations": [{
    "name": "platform1",
    "password": "a-long-random-secret-of-16+-chars",
    "tenant": "",
    "scopes": ["inject", "domains"],
    "max_message_rate": ""
  }]
}
```

- `name` is the user name, `password` the secret: HTTP basic
  authentication for the HTTP API, SMTP AUTH PLAIN for submission. The
  module stores a scrypt verifier in a 0600 file. The UI can generate the
  password in the browser and shows it once. On upgrade, existing
  verifiers are wrapped in scrypt and keep accepting the same passwords.
  Setting a new password creates a direct scrypt verifier.
- `scopes`:
  - `inject`: `POST /api/inject/v1` (KumoMTA's ACL grants this credential
    nothing else);
  - `smtp`: SMTP AUTH on the submission listener;
  - `domains`: the domain management API `/api/v1/*`.
- `tenant`: when set, every message of the credential gets this KumoMTA
  tenant, whatever the headers say: use it when one credential is one
  customer. Leave it empty to use the administrator-assigned domain
  tenant or a tenant derived from the credential name.
- `max_message_rate`: optional sending rate, e.g. `1000/h`. Credentials
  bound to the same tenant share the strictest configured rate. An unbound
  credential has a separate rate across its domains and campaigns.
  Messages over the rate wait in their queue.

`api_host` publishes two Traefik routes on that host name, HTTPS only
(HTTP redirects), with Let's Encrypt when the Settings page asks for it:
`/api/inject` to kumod and `/api/v1` to the domain API. `api_allowlist`
restricts them to some networks. Without `api_host`, the platform can use
SMTP only. Traefik has no rate limiting option for module routes: the
domain API limits each credential to 120 requests per minute and blocks a
known user name after 20 failed authentications in a minute. Domain
mutations have separate rate limits and active domain quotas. KumoMTA
rejects invalid injection credentials with 401. Changing, revoking or
rotating a credential restarts kumod to clear its authentication cache.

## SMTP or HTTP injection?

| | SMTP submission (587) | HTTP injection |
|---|---|---|
| Client | any SMTP library, connection pooling | one HTTPS POST per message or per batch of recipients |
| Credential | integration with `smtp` scope (or an SMTP user) | integration with `inject` scope |
| Message | complete RFC 5322 message | complete message, or built by KumoMTA from `from`, `subject`, `text_body`, `html_body`, `headers`, `attachments` |
| Per-recipient data | headers only | `substitutions` (templating) and `metadata` (echoed in the webhook) |
| Result | SMTP reply per recipient | JSON `success_count`, `fail_count`, `errors` |

HTTP injection is the better fit for a platform: one request carries many
recipients with their own substitutions, and the per-recipient `metadata`
comes back in every webhook event, which is how the platform correlates
events with its own message records. See [api.md](api.md#http-injection).

## Tenants and campaigns

KumoMTA queues messages by `campaign:tenant@destination-domain`, so each
customer (tenant) and each campaign gets its own queues: a customer with a
bad list does not slow down the others, and an administrator can suspend
or bounce one tenant's queues.

- `X-Campaign` can select a campaign for SMTP or HTTP injection. Use up to
  64 letters, digits, dots, underscores or hyphens.
- For integrations, the tenant comes from the credential, an
  administrator-assigned sending domain, or `ns8-integration-<name>`, in
  that order. Create a credential per tenant when you need explicit tenant
  boundaries. After upgrading, tenant labels previously supplied through
  the domain API give way to this assignment.
- SMTP users, clients in trusted relay networks and the internal HTTP
  administrator can set `X-Tenant` using the same syntax as a campaign.
- The module strips both routing headers from submitted messages before delivery. The assigned
  tenant and campaign appear in webhooks and queue names.

## Sending domain policy

Messages of an integration (HTTP injection, or SMTP AUTH with an
integration credential) are accepted only when the `From:` domain:

1. is a sending domain of this MTA: added by this integration through the
   API, or by the administrator; a domain of another integration is
   refused;
2. is **verified** (DKIM and SPF records found and correct), unless
   `require_verified_domains` is off (Integrations page). Turn it off only
   for tests.

A refused message gets `550 5.7.1 ...`: a failed recipient in the JSON
reply of the injection, an SMTP error at the end of DATA.

SMTP users and trusted networks of the Settings and Users pages are
administrator clients: the domain policy does not apply to them.

## Bounces and feedback loops

KumoMTA classifies every bounce and deferral with the IANA rules
(`bounce_classification` in the records, e.g. `InvalidRecipient`,
`InactiveMailbox`, `BadDomain`, `QuotaIssues`, `PolicyRelated`,
`MessageExpired`).

Asynchronous bounces and complaints come back as email. Set a **return
path and feedback domain** (`bounce_domain`, Integrations page), e.g.
`bounces.mta.example.org`, with an MX record pointing to this server and
the inbound listener on port 25. Then:

- each customer domain publishes `bounces.<domain> CNAME <bounce_domain>`
  (the module lists it with the other records), and the platform uses an
  envelope sender `<anything>@bounces.<domain>` (SPF and DMARC aligned on
  the customer domain);
- bounces (DSN) sent to those addresses are logged as `OOB` records;
- ARF complaint reports sent to any address of `bounce_domain` (register
  e.g. `fbl@bounces.mta.example.org` with the mailbox providers' feedback
  loops) are logged as `Feedback` records;
- neither is relayed anywhere; both go to the webhook.

Gmail has no per-message feedback loop: use Google Postmaster Tools.

## Checklist for a platform

1. Create an integration credential with the scopes it needs; set `api_host`.
2. For each customer domain: `POST /api/v1/domains`, show the returned
   records to the customer, then call `.../validate` until it is
   `verified` (for example every few minutes for a day).
3. Send with `POST /api/inject/v1`, `From:` on a verified domain,
   the `X-Campaign` header and per-recipient `metadata` with the
   platform's message id.
4. Configure the webhook (Delivery page) with a signing secret, verify the
   signature, and update the message status from `type` and
   `meta.extra`.
5. Use sink mode on a test instance to exercise all of it without sending.
