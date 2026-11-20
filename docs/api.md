# API reference

Two surfaces:

- the **HTTPS API** for sending platforms, on the API host name
  (`api_host`), authenticated with an integration credential;
- the **NS8 actions** of the module, for administrators and automation
  inside the cluster (`api-cli`, the UI).

In the examples: `API=https://mta-api.example.org`, credential
`platform1` / `$SECRET`, module `kumomta1`.

## HTTPS API

Every request uses HTTP basic authentication with an integration
credential. Plain HTTP redirects to HTTPS.

| Status | Meaning |
|---|---|
| 401 | missing or wrong credential |
| 403 | the credential lacks the scope of the endpoint |
| 404 | unknown path, or a domain that does not exist or belongs to someone else |
| 409 | the domain already exists or its selector has a conflicting key |
| 422 | invalid input (`error` says which) |
| 429 | over 120 requests per minute, or too many failed authentications |

Errors of the domain API are `{"error": "<code>", "detail": "<value>"}`.

### HTTP injection

`POST /api/inject/v1`, scope `inject`. This is the KumoMTA injection API,
reached through Traefik; the module only adds authentication, the sending
domain policy and tenants. Full request reference:
[KumoMTA inject API](https://docs.kumomta.com/reference/http/kumod/api_inject_v1_post/).

```
curl -u platform1:$SECRET -H 'Content-Type: application/json' -d '{
  "envelope_sender": "bounce-1234@bounces.customer.example",
  "content": {
    "from": {"email": "news@customer.example", "name": "Customer"},
    "subject": "Hello {{ name }}",
    "text_body": "Hi {{ name }}, ...",
    "html_body": "<p>Hi {{ name }}, ...</p>",
    "headers": {
      "X-Campaign": "welcome",
      "List-Unsubscribe": "<https://platform.example.com/u/abc>",
      "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"
    }
  },
  "recipients": [
    {"email": "ann@example.net", "name": "Ann",
     "substitutions": {"name": "Ann"},
     "metadata": {"message_id": "msg_001"}},
    {"email": "bob@example.org", "name": "Bob",
     "substitutions": {"name": "Bob"},
     "metadata": {"message_id": "msg_002"}}
  ]
}' $API/api/inject/v1
```

```json
{"success_count": 2, "fail_count": 0, "failed_recipients": [], "errors": []}
```

`content` can also be a complete RFC 5322 message as a string. A refused
recipient is counted in `fail_count`, with the reason in `errors`, e.g.
`550 5.7.1 sending domain customer.example is not verified`. The answer is
`200` as long as the request is valid; check `fail_count`.

`metadata` is echoed in every webhook record of that recipient as
`meta.extra` ([webhooks.md](webhooks.md)).

### Who am I

`GET /api/v1/whoami`, scope `domains`.

```
curl -u platform1:$SECRET $API/api/v1/whoami
{"name": "platform1", "tenant": "", "scopes": ["inject", "domains"], "max_message_rate": ""}
```

### List the domains

`GET /api/v1/domains`: the domains of this credential.

```
curl -u platform1:$SECRET $API/api/v1/domains
{"domains": [{"domain": "customer.example", "status": "verified", ...}],
 "require_verified_domains": true}
```

### Add a domain

`POST /api/v1/domains` → `201` and the domain object.

```
curl -u platform1:$SECRET -H 'Content-Type: application/json' \
  -d '{"domain": "customer.example", "selector": "s1"}' \
  $API/api/v1/domains
```

| Field | Required | |
|---|---|---|
| `domain` | yes | lowercase is applied |
| `selector` | no | default `kumo1` |
| `tenant` | no | omit to use the credential tenant. An explicit value must equal a fixed tenant on the credential |
| `dkim_private_key` | no | PEM key to import instead of generating one |

In a cluster using local DKIM storage, supply the common key or provision
it first. With a shared OpenBao path, concurrent requests adopt the same
stored key. [Cluster DKIM setup](cluster.md#dkim-keys-in-a-cluster)

### Get a domain

`GET /api/v1/domains/<domain>` → the domain object.

### Validate a domain

`POST /api/v1/domains/<domain>/validate` → the domain object with the new
`status`, `last_checked` and `checks`.

### Remove a domain

`DELETE /api/v1/domains/<domain>` → `{"domain": "...", "removed": true}`.

### The domain object

```json
{
  "domain": "customer.example",
  "selector": "s1",
  "owner": "platform1",
  "tenant": "customer-7",
  "status": "pending",
  "last_checked": "2026-11-16T08:00:00Z",
  "checks": [
    {"name": "dkim", "required": true, "status": "missing",
     "detail": "s1._domainkey.customer.example: no TXT record (nxdomain)"},
    {"name": "spf", "required": true, "status": "pass", "detail": "SPF authorizes a:mx.example.org"},
    {"name": "dmarc", "required": false, "status": "missing", "detail": "..."}
  ],
  "key_location": "local",
  "dkim_record": {"name": "s1._domainkey.customer.example", "type": "TXT", "value": "v=DKIM1; k=rsa; p=..."},
  "records": [{"check": "dkim", "required": true, "type": "TXT", "name": "...", "value": "...", "purpose": "..."}]
}
```

`status`: `pending`, `verified` or `failed`; see
[domains-and-dkim.md](domains-and-dkim.md).

### SMTP

Submission listener (default port 587), STARTTLS then `AUTH PLAIN` with a
credential that has the `smtp` scope. Same domain policy and tenant rules
as HTTP injection. `X-Campaign` selects the campaign and
`X-Message-Ref` supports message correlation.

The domain API allows 120 authenticated requests per integration per minute.
Domain creates, deletes and DNS validations share a separate limit of 12 per
integration and 60 per instance per minute. The API caps active owned domains
at 100 per integration and 1,000 per instance. Exceeding a limit returns 429.
OpenBao retains shared DKIM keys after a domain is deleted.

## NS8 actions

Run with `api-cli run module/kumomta1/<action> --data '<json>'`. Readers
of the module can run `get-*` and `list-*` actions: they never return
secrets.

| Action | Role | Input | Output |
|---|---|---|---|
| `configure-module` | admin | settings, see `validate-input.json` | `{"warnings": [...]}` |
| `get-configuration` | reader | | settings, domains with records and status, integrations without passwords, `warnings` |
| `list-domains` | reader | `{"owner": "platform1"}` optional | `{"domains": [...]}` |
| `add-domain` | admin | `{"domain", "selector", "owner", "tenant", "dkim_private_key"}` | the domain object |
| `validate-domain` | admin | `{"domain"}`, or `{}` for all | `{"domains": [...]}` |
| `remove-domain` | admin | `{"domain"}` | `{"domain", "removed": true}` |
| `generate-dkim-key` | admin | `{"domain", "rotate", "source", "private_key", "peer"}` | `{"domain", "selector", "key_location", "dkim_record"}` |
| `list-openbao-only-secrets` | reader | | see [openbao.md](openbao.md) |
| `copy-openbao-to-local` | admin | | `{"copied": [...], "failed": [...]}` |
| `set-peer-access` | admin on the source | `{"peer":"kumomta2","allowed":true}` | selected peer and effective approval |
| `reveal-dkim-key` | approved clusterpeer | `{"domain", "selector"}` | DKIM private key for the receiving instance |
| `reveal-cluster-settings` | approved clusterpeer | | cluster store settings and the manual store password, see [cluster.md](cluster.md) |
| `get-queue-status` | reader | | queue and delivery counters |
| `list-recent-events` | reader | `{"types", "limit", "segments"}` | recent log records |

Integration credentials and the API host name are `configure-module`
settings:

```
api-cli run module/kumomta1/configure-module --data '{
  "api_host": "mta-api.example.org",
  "api_allowlist": [],
  "require_verified_domains": true,
  "spf_include": "include:_spf.example.org",
  "bounce_domain": "bounces.mta.example.org",
  "integrations": [
    {"name": "platform1", "password": "<16+ characters>",
     "tenant": "customer-7", "scopes": ["inject", "smtp", "domains"],
     "max_message_rate": "5000/h"}
  ]
}'
```

`integrations` replaces the list: an integration left out is removed; an
entry without `password` keeps its current password.

Examples from a cluster node:

```
api-cli run module/kumomta1/add-domain --data '{"domain": "customer.example", "owner": "platform1"}'
api-cli run module/kumomta1/validate-domain --data '{"domain": "customer.example"}'
api-cli run module/kumomta1/list-domains --data '{}'
api-cli run module/kumomta1/remove-domain --data '{"domain": "customer.example"}'
```
