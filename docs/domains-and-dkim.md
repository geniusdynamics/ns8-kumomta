# Sending domains, DKIM and DNS validation

Every message leaving the MTA is signed with the DKIM key of its `From:`
domain, when the domain is a sending domain of the module. Sending domains
come from two places:

- the administrator, on the Domains page (`configure-module` `domains`);
- an integration, through the domain API (`/api/v1/domains`) or the
  `add-domain` action with `owner`. Such a domain belongs to that
  integration: only it can see, validate, use or remove it through the API
  (the administrator can remove it from the UI).

## Add a domain

```
curl -u platform1:$SECRET -H 'Content-Type: application/json' \
  -d '{"domain": "customer.example", "selector": "s1"}' \
  https://mta-api.example.org/api/v1/domains
```

| Field | |
|---|---|
| `domain` | the customer domain (required) |
| `selector` | DKIM selector, default `kumo1` |
| `tenant` | tenant of the messages from this domain when the credential has none and no `X-Tenant` is set. A credential bound to a tenant can only use its own |
| `dkim_private_key` | optional PEM private key to import (RSA), instead of generating a 2048-bit RSA key. Never returned |

The module generates the key, stores the private key in a 0600 file (or in
OpenBao when enabled, see [openbao.md](openbao.md)) and answers `201` with
the domain and the records to publish. The domain starts as `pending`.

## DNS records

```json
{
  "domain": "customer.example", "selector": "s1",
  "owner": "platform1", "tenant": "", "status": "pending",
  "last_checked": "", "checks": [], "key_location": "local",
  "records": [
    {"check": "dkim", "required": true, "type": "TXT",
     "name": "s1._domainkey.customer.example",
     "value": "v=DKIM1; k=rsa; p=MIIBIjANBg...", "purpose": "..."},
    {"check": "spf", "required": true, "type": "TXT",
     "name": "customer.example",
     "value": "v=spf1 a:mx.example.org ~all", "purpose": "..."},
    {"check": "dmarc", "required": false, "type": "TXT",
     "name": "_dmarc.customer.example",
     "value": "v=DMARC1; p=none; rua=mailto:dmarc@customer.example", "purpose": "..."},
    {"check": "return_path", "required": false, "type": "CNAME",
     "name": "bounces.customer.example",
     "value": "bounces.mta.example.org.", "purpose": "..."}
  ]
}
```

| Record | Required | Notes |
|---|---|---|
| DKIM TXT `<selector>._domainkey.<domain>` | yes | the public key of the selector. Long values must be split in strings of 255 characters by the DNS provider (most do it) |
| SPF TXT on `<domain>` | yes | the SPF mechanism of this MTA: `a:<host name>` by default, or the **SPF mechanism** of the Integrations page (`spf_include`, e.g. `include:_spf.example.org`). A domain with an SPF record already adds the mechanism to it: one SPF record per domain |
| DMARC TXT `_dmarc.<domain>` | recommended | start with `p=none`, then `quarantine` or `reject` |
| Return path CNAME `bounces.<domain>` | recommended, only with a `bounce_domain` | brings bounces and complaint reports back, see [integration.md](integration.md#bounces-and-feedback-loops) |

## Validation and status

```
curl -u platform1:$SECRET -X POST \
  https://mta-api.example.org/api/v1/domains/customer.example/validate
```

The module queries the DNS (from the node, 5 second timeout per query) and
stores, per domain, a status, the time of the check (`last_checked`, ISO
8601 UTC) and the result of each check:

| Check | `pass` | `fail` | `missing` |
|---|---|---|---|
| `dkim` | the TXT record has the same `p=` key | a DKIM record with another key | no record (or DNS error) |
| `spf` | one SPF record containing the mechanism | no mechanism, or several SPF records | no SPF record |
| `dmarc` | a `v=DMARC1` record | | no record |
| `return_path` | CNAME to `bounce_domain` | CNAME elsewhere | no CNAME |

The status considers the required checks only (DKIM and SPF):

| Status | Meaning |
|---|---|
| `pending` | not validated yet, or a required record is not published yet |
| `verified` | every required check passes: the integrations can send from it |
| `failed` | a required record is published but wrong |

A domain is checked only when asked: through the API, the **Check DNS**
button of the Domains page, or the `validate-domain` action (all domains
when no `domain` is given). A platform typically polls `validate` while a
customer sets up the DNS, and again from time to time: a verified domain
whose records are removed goes back to `pending` or `failed` at the next
check, and its mail is refused again.

Sending from a domain that is not `verified` is refused for the
integrations while `require_verified_domains` is on (default).

## Remove a domain

```
curl -u platform1:$SECRET -X DELETE \
  https://mta-api.example.org/api/v1/domains/customer.example
```

The local key files are deleted. A key stored in OpenBao is left there.

## Rotate a key

The `generate-dkim-key` action (admin, "Rotate key" on the Domains page)
replaces the key of the selector: the published record stops matching at
once, so publish the new record right away and validate again. The domain
API has no rotation endpoint yet: a platform rotates by removing the domain
and adding it again with a new selector (or an imported key), then
publishing the new record.
