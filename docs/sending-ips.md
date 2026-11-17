# Sending IPs and their limits

The *Sending IPs* page lists the addresses KumoMTA sends from. Each IP
has:

- **overall limits**, for all destinations together: messages per minute,
  per hour and per day, and a maximum number of concurrent connections;
- **limits per destination**: the same four limits for one of the large
  providers (Gmail and Google Workspace, Outlook.com and Hotmail,
  Microsoft 365, Yahoo and AOL, iCloud), a domain, or an MX host name
  suffix. One provider then cannot use the whole budget of the IP: an IP
  allowed 1000 messages per minute can be capped at 200 per minute towards
  Gmail.

`0` means no limit. Without any IP on the page, KumoMTA sends from the
address of the default route, with no per-IP limit, as before.

Changing addresses, EHLO names or weights restarts kumod so active queues
pick up the new egress pool. Queued messages stay on disk. Rate and
connection limit edits reload live when the egress pool stays the same.

*Add the large providers* fills in conservative starting points (per IP:
Gmail 2000/h and 5 connections, Outlook.com 1000/h and 3, Microsoft 365
2000/h and 5, Yahoo 1000/h and 3, iCloud 500/h and 3). Raise them as the
reputation of the IP grows, and follow the provider's guidance.

```
api-cli run module/kumomta1/configure-module --data '{"sending_ips": [
  {"address": "203.0.113.5", "ehlo_domain": "", "weight": 1,
   "per_minute": 1000, "per_hour": 0, "per_day": 100000, "max_connections": 50,
   "providers": [
     {"provider": "google", "per_minute": 200, "per_hour": 0, "per_day": 0, "max_connections": 5},
     {"provider": "domain", "match": "example.com", "per_minute": 0, "per_hour": 500, "per_day": 0, "max_connections": 2},
     {"provider": "mx", "match": "mx.example.net", "per_minute": 0, "per_hour": 1000, "per_day": 0, "max_connections": 0}
   ]}
]}'
```

| Field | |
|---|---|
| `address` | a local IPv4 or IPv6 address of the node (checked), or empty for the address of the default route |
| `ehlo_domain` | EHLO name of the IP, default the host name of the module |
| `weight` | share of the messages of the IP in the pool (weighted round robin) |
| `per_minute`, `per_hour`, `per_day` | message rates, `0` for none |
| `max_connections` | concurrent connections, `0` for none |
| `providers[].provider` | `google`, `outlook`, `office365`, `yahoo`, `apple`, `domain` or `mx` |
| `providers[].match` | with `domain`: the destination domain; with `mx`: the MX host name suffix |

## How KumoMTA applies them

Only native KumoMTA mechanisms of the pinned release are used; the module
keeps no counter of its own.

- Each IP is an **egress source** (`source_address`, `ehlo_domain`) of the
  `default` pool, with its weight (`sources.toml`, the
  `policy-extras.sources` helper). Messages pick a source by weighted round
  robin.
- **Overall limits** are named throttles added to every egress path of the
  source by `get_egress_path_config`:
  `additional_message_rate_throttles` (`ns8-<source>-min`, `-h`, `-d`, specs
  like `1000/min`, `5000/h`, `100000/d`) and `additional_connection_limits`
  (`ns8-<source>-conn`). A named limit is shared by every path that carries
  the same name, here all the destinations of that source
  (`ip_limits.toml`).
- **Limits per destination** are source blocks of `shaping.toml`, with the
  same named limits:
  - a provider: `[provider."google".sources."<source>"]`, merged into the
    provider block of the KumoMTA default `shaping.toml`, which matches its
    MX host names; the limit applies to every site of the provider;
  - an MX suffix: a provider block `ns8-mx-<suffix>` with
    `match = [{MXSuffix = ".<suffix>"}]`;
  - a domain: `["<domain>".sources."<source>"]` (`mx_rollup = false`).

  KumoMTA merges the `additional_*` tables of the default, provider, domain
  and source levels, so the overall and the per-destination limits all
  apply; the lowest one wins.
- A message over a rate waits in its ready queue; a source over its
  connection limit opens no more connections. Nothing is rejected.

The per-site limits of the *Delivery* page (`shaping`) still apply on top,
per source and site.

The overall limits skip the internal queues of the TSA and webhook log
hooks: only mail counts against the budget of an IP.

## In a cluster

With a shared throttle store ([cluster.md](cluster.md)), named throttles
and connection limits are kept in the store, so the limits of an IP hold
across the instances. The names carry the source, so the limits are **per
IP**, never global per destination:

- an IP listed on this page is the source `ip-<address>`;
- the default route of a clustered instance is the source `node-<node ID>`
  (on a standalone instance it keeps the name `default`), so even the
  shaping rules of the *Delivery* page are per node IP in a cluster.

List on each instance the IPs of its own node. Two instances that send
from the same address (behind a proxy, for example) share its limits.
