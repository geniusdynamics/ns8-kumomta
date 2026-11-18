# Multi-node cluster

Several ns8-kumomta instances, normally one per node, can send as one
MTA cluster:

- a **shared throttle store** (Valkey or Redis) makes the throttles,
  connection limits and tenant rates global: every instance counts against
  the same limits;
- each instance can run the **traffic shaping automation daemon**
  (`tsa-daemon`), and every kumod sends its log records to the daemons of
  all the instances that share the store, so the automation reacts to the
  responses seen by the whole cluster.

A single instance needs none of this. The default store is `none`
(standalone) and the policy of a standalone instance is exactly the one of
the earlier versions.

Every instance is a **peer**: there is no coordinator instance. The store
is the shared state; the cluster records of NS8 are the membership.

## Architecture

```
                 inbound mail: several MX records or a load balancer
                     │                     │                     │
 node 1              ▼        node 2       ▼        node 3       ▼
┌──────────────────────────┐ ┌──────────────────────────┐ ┌──────────────────────────┐
│ kumomta1                 │ │ kumomta2                 │ │ kumomta3                 │
│  kumod ── spool (local)  │ │  kumod ── spool (local)  │ │  kumod ── spool (local)  │
│   │ ▲                    │ │   │ ▲                    │ │   │ ▲                    │
│   │ └─ suspensions,      │ │   │ └─ ...               │ │   │ └─ ...               │
│   │    shaping overrides │ │   │                      │ │   │                      │
│   ▼                      │ │   ▼                      │ │   ▼                      │
│  tsa-daemon              │ │  tsa-daemon              │ │  (no TSA)                │
│  10.5.4.1:<3rd TCP port> │ │  10.5.4.2:<3rd TCP port> │ │                          │
└────────▲─────────▲───────┘ └────────▲─────────▲───────┘ └──────────────────────────┘
         │ log records (publish_log_v1) from every kumod to every tsa-daemon
         │         │ (cluster VPN, firewalld trusted zone)
         ▼         ▼
     ┌─────────────────────────────────────────────────┐
     │ shared throttle store                           │
     │  ns8-valkey instance (own credentials per peer) │
     │  or any Redis / Valkey: single node or          │
     │  Redis Cluster (no Sentinel, see below)         │
     └─────────────────────────────────────────────────┘

 cluster Redis of NS8 (no secrets):
   module/<valkey id>/srv/tcp/valkey             Valkey endpoints
   module/kumomtaN/srv/tcp/kumomta-cluster       peer records:
       host (VPN address), port (tsa-daemon), tsa, store, store_type,
       node, hostname, mode
 events: kumomta-cluster-changed, module-removed, valkey-changed
```

Each kumod keeps its own spool. The store holds throttle counters and
connection leases only; it never holds messages.

## Set up

1. Install ns8-kumomta on each node, and configure each instance (host
   name, listeners, users, domains) as usual.
2. On the first instance, *Cluster* page:
   - **Shared throttle store**: choose a **Valkey instance of this cluster**
     (ns8-valkey) from the list, or **Other Redis or Valkey** with its URLs,
     user name and password;
   - turn on **Run the automation daemon** if you want traffic shaping
     automation (recommended on at least one instance; on every instance it
     survives the loss of any node).
3. On the first instance's **Cluster** page, grant the joining instance
   access to its secrets. On the joining instance, use **Join another
   KumoMTA instance** and select the first one. The grant authorizes copying
   its store settings, including a manual store password, and importing
   its DKIM keys. Grant access only to an instance serving the same mail
   organization.
4. Spread the inbound mail: several MX records with the same preference,
   or a load balancer in front of the inbound and submission ports.
   Outbound limits are global because every instance uses the same store.

Command line:

```
api-cli run module/kumomta1/configure-module --data '{
  "cluster_store": "manual",
  "cluster_redis_nodes": ["redis://10.5.4.10:6379"],
  "cluster_redis_password": "...",
  "tsa_enabled": true
}'
api-cli run module/kumomta1/set-peer-access --data '{"peer":"kumomta2","allowed":true}'
api-cli run module/kumomta2/configure-module --data '{"cluster_join": "kumomta1"}'
api-cli run module/kumomta3/configure-module --data '{"cluster_store": "valkey", "cluster_valkey": "valkey1"}'
```

| Field | |
|---|---|
| `cluster_store` | `none` (default), `valkey` or `manual` |
| `cluster_valkey` | module ID of the ns8-valkey instance |
| `cluster_redis_nodes` | manual: `redis://host:port` or `rediss://host:port` (TLS) URLs, without credentials. More than one URL means a Redis Cluster |
| `cluster_redis_cluster` | manual: Redis Cluster protocol with a single URL |
| `cluster_redis_username` | manual: ACL user, empty for the default user |
| `cluster_redis_password` | manual: write only (`cluster_redis_password_set` in `get-configuration`); `cluster_redis_password_clear` removes it |
| `cluster_join` | copy the store settings of this kumomta instance (input only) |
| `tsa_enabled` | run tsa-daemon |

`get-configuration` adds `cluster_status` (`mode`: `standalone`, `shared`
or `local`, `reason`, `store`, `nodes`, `tsa_listen`, `tsa_peers`),
`valkey_instances`, `cluster_peers` and `tsa_port`, and the warning
`cluster_degraded` while the store is not used.

## Stores

### ns8-valkey

[geniusdynamics/ns8-valkey](https://github.com/geniusdynamics/ns8-valkey)
publishes `module/<id>/srv/tcp/valkey`; the *Cluster* page lists those
instances. The module follows the ns8-valkey consumer contract
(`docs/integration.md` of ns8-valkey):

- Credentials: each kumomta instance calls the guarded action
  `grant-client` of the chosen instance (role `valkeyclient`, requested
  by the `valkey@any:valkeyclient` authorization), with no input: the
  Valkey user is `ns8c-<kumomta module ID>`. The password goes to
  `state/secrets/cluster_redis_password` (0600); the user name and the
  `cluster_id` to `state/cluster/store.json`. Every call rotates the
  password, so the module calls it only when it has no credentials, when
  the instance changes, or when the credentials are refused, and then
  restarts kumod (it reads the password in its init event only).
- Endpoints: the record `host`/`port`, its `nodes` seed list and the
  `nodes` of the `grant-client` output are all passed as seeds;
  `ha_mode` `cluster` (or `cluster` `true`) sets `cluster = true`, also
  with a single seed.
- Permissions: the ns8-valkey client user (`+@all -@admin -@dangerous`)
  covers every command KumoMTA sends: `COMMAND INFO` (redis-cell
  detection), `EVALSHA`/`EVAL`/`SCRIPT LOAD`, `GET`/`SET`/`TIME` and the
  sorted set commands inside the scripts, `ZADD`/`ZREM`, `PING`, and
  `CLUSTER SLOTS` for the cluster client. The CI runs the manual store
  tests with a user restricted the same way. Client connections run on the cluster VPN without TLS
  (`tls` is `false`): WireGuard encrypts them.
- Events: `valkey-changed` of the configured instance, or of another member
  of its cluster, makes the module read the record again. When the
  configured instance is removed (`module-removed`), the module uses
  another record with the same `cluster_id`: the credentials stay valid.
- `revoke-client` is called (best effort) when the instance leaves the
  store, or is removed; ns8-valkey also drops the user on
  `module-removed`.
- No `key_prefix`: KumoMTA throttle keys have no configurable prefix.
- ns8-valkey offers standalone (no failover) and cluster mode (automatic
  failover with 3 or more members). Sentinel is not offered, as KumoMTA has
  no Sentinel client.

KumoMTA gets the user name and the password as the `username` and
`password` parameters of `configure_redis_throttles`, never inside the URL,
so that the password stays out of the policy files. The KumoMTA
documentation says these parameters apply to clusters only; the source of
the pinned release (`crates/mod-redis/src/lib.rs`, `build_client`) applies
them to a single node too.

### Other Redis or Valkey

Any store you run, with its own failover. KumoMTA's Redis client
(`kumo.configure_redis_throttles`, `redis.open`) supports:

| Mode | How |
|---|---|
| single node | one URL |
| Redis Cluster (Valkey cluster) | several URLs, or one URL and `cluster_redis_cluster` |
| TLS | `rediss://` URLs |
| ACL user | `cluster_redis_username` |
| **Sentinel** | **not supported**: the client of the pinned KumoMTA release (redis-rs with the `cluster` features only, `NodeSpec` single or cluster) has no Sentinel mode. Put a Redis Cluster, or a proxy that follows the Sentinel primary, behind a single URL |

The password is a 0600 file, or, while OpenBao is on, the shared secret
`<vault_path>/cluster_redis` (field `vault_key`): every instance that uses
the same OpenBao path reads the same password, and kumod loads it with a
KeySource. It is listed by `list-openbao-only-secrets` and copied back by
`copy-openbao-to-local` like the other secrets ([openbao.md](openbao.md)).

KumoMTA needs `EVAL` (it falls back to a Lua GCRA script when the
`redis-cell` module is absent) and keeps short-lived keys only: no
persistence is needed.

## Traffic shaping automation

tsa-daemon runs from the KumoMTA image (`/opt/kumomta/sbin/tsa-daemon`, user
`kumod`, uid/gid 999 in the pinned image), unit `kumomta-tsa.service`, with
its state (`tsa.db`) on the `kumomta-tsa` volume. It loads the same shaping
files as kumod: the KumoMTA defaults, with the automation rules of the
large mailbox providers, and the per-domain settings of the module.

- Standalone (`tsa_enabled`): it listens on `127.0.0.1:<3rd TCP port>`, and
  kumod publishes to it and subscribes to it.
- Clustered: `tsa_enabled` makes the instance a **designated TSA host**,
  chosen when the store is set up or when the instance joins (a join does
  not copy it: it is off unless checked). Only designated hosts run
  tsa-daemon, on the cluster VPN address, trusting the cluster network.
  Every kumod of the store publishes its log records to all the
  designated hosts (from the peer records) and subscribes to its own
  daemon, or to one designated host when it is not one, as in the KumoMTA
  "multiple node" deployment. The daemons compute the same suspensions and
  overrides from the same records; they do not share state.

KumoMTA reads the list of daemons in its `init` event only
(`configure_log_hook` and the subscriber tasks of `setup_publish`): a
configuration epoch bump does not change it. When a peer joins, leaves or
changes, it publishes `kumomta-cluster-changed`; each peer of the store
computes its list again and restarts kumod **only if the list changed**.
So peers that are not TSA hosts join and leave without restarting anyone
(the CI checks the PID of kumod).

**Changing the designation later is allowed**: it changes the list of
every peer of the store, so KumoMTA restarts once on each of them (a
graceful restart: queues stay in the spools, SMTP clients retry). The
*Cluster* page names those peers before saving, and `configure-module`
returns `tsa_peers_restart` with them; removing the last designated host
returns `tsa_no_host`. It is allowed rather than locked: a restart
per peer is the same cost as a TSA host joining or leaving, which
the cluster must handle anyway.

While designated hosts exist and none answers (TCP check of the health
check), `get-configuration` returns the warning `tsa_unreachable`: the
automation is paused, the shaping limits still apply. Records queued for
the daemon of a peer that left are discarded instead of being delivered.

## DKIM keys in a cluster

Peers serving the same domain and selector must sign with the same key.
The **Domains** page shows the public DNS record for comparison.

- **With OpenBao**, point the peers at the same KV v2 path. The first
  successful create establishes the key. Concurrent creates use a
  create-only write and subsequent requests reuse the stored key.
  An existing local key can seed an empty path. An import that conflicts
  with an established key fails and the operator can compare fingerprints.
- **With local keys**, configure the domain and selector on each peer.
  On the source, use its existing key or run `generate-dkim-key` once.
  Grant the receiving instance access on the source, then use **Import key**
  on the receiver with the source instance selected. Repeating the import
  with the same key is safe. For a domain created through `add-domain`
  or the HTTPS API, supply the common PEM or provision the matching key
  before creating the domain.
- A clustered instance refuses in-place rotation. Each domain has one
  active selector. To roll over, prepare the new key separately, publish
  its DNS record, allow time for DNS propagation, and coordinate activation
  of the prepared selector and key on the peers. Keep the old DNS record
  available while messages signed with the old selector are in flight.

## Failure modes

| Failure | Effect | What the module does |
|---|---|---|
| store unreachable at runtime | kumod cannot get connection leases nor apply throttles: deliveries stall (KumoMTA has no fallback) | the health check (`kumomta-cluster-check.timer`, every minute) renders local throttles and restarts kumod after 2 failed checks; warning `cluster_degraded` on every page; back to the store when it answers |
| store unreachable when kumod starts | `configure_redis_throttles` pings the store in `init`: kumod would not start | `ExecStartPre` checks the store first and renders local throttles |
| ns8-valkey instance removed | | `module-removed`: another member of the same Valkey cluster, else local throttles at once, warning `store_not_found` |
| credentials refused or revoked | | new `grant-client` request and a restart of kumod, then local throttles if it fails |
| a tsa-daemon down | its log records queue on every kumod and are retried; the shaping overrides of that daemon are ignored (`remote_load` = Ignore) | nothing: the other daemons keep working; the records of a removed peer are discarded |
| a node down | its spool (queued messages) stays on that node until it comes back | nothing automatic: see below |
| node without cluster VPN address | | `cluster_store: valkey` refused; a clustered tsa-daemon does not run |

While throttles are local, each instance applies the limits on its own: N
instances can send up to N times the configured rates.

### The spool is per node

KumoMTA does not replicate queued messages. When a node is lost, its
queued messages wait in its `kumomta-spool` volume:

- planned maintenance: stop the injections to that node (MX, load
  balancer), then drain it, for example with `kcli rebind` towards another
  instance, or wait for its queues to empty (Queue page);
- unplanned loss: bring the node back, or restore its backup (the spool
  volume is in the backup) on another node.

KumoMTA's message transfer API (`/api/admin/xfer/v1`, since 2026.03.04)
can move queued messages between nodes, but needs the kumod HTTP listener
reachable from the other nodes; the module keeps it on the loopback, so it
is not offered yet.

## Security

- No secret is published in cluster Redis: the peer records and the
  Valkey records hold addresses, ports and flags only.
- The store password is a 0600 file (`state/secrets`, in the backup), or
  an OpenBao secret, and it is passed to kumod through a KeySource, never in
  the policy, argv or environment. Store URLs with credentials are refused.
- The source administrator grants access per peer. Both
  `reveal-cluster-settings` and `reveal-dkim-key` check the authenticated
  calling module against these grants in addition to the NS8 `clusterpeer`
  role. Grants are directional and tied to the installed module's UUID.
  A new installation starts with an empty grant list. Inspect each peer's
  `secret_access` in `get-configuration` on the source. After cloning or
  restoring a source instance, review the peers and grant access again.
- Revoke future reads on the source with
  `api-cli run module/kumomta1/set-peer-access --data '{"peer":"kumomta2","allowed":false}'`.
  A peer can retain keys and store credentials it already received.
  Rotate those credentials when retiring a peer that should lose their use.
  NS8 stores reveal task results under the source module for eight hours,
  accessible to cluster administrators.
- tsa-daemon has no authentication: kumod's TSA client sends no
  credentials, so the access is by source address (the cluster network).
  The port listens on the VPN address only and NS8 accepts the cluster
  network in firewalld's `trusted` zone: no port is opened to the public
  zone. Any node of the NS8 cluster can reach it.

## Restore, clone, upgrade, removal

- Restore and clone keep the cluster settings: the instance rejoins the
  same store. ns8-valkey credentials are requested again by the new
  instance; the manual password comes back from the backup.
- Upgrade from an earlier version: nothing changes until a store is
  chosen. The TSA port is allocated when TSA is turned on.
- Ports and permissions on a new install: NS8 allocates the whole
  `org.nethserver.tcp-ports-demand` (3) when the module is added, and its
  `allocate-ports` refuses more than the demand, so the third port cannot
  be allocated later: it is reserved at install, with nothing listening on
  it and no firewall rule until TSA is turned on. The authorizations
  (`node:portsadm`, `kumomta@any:clusterpeer`, `valkey@any:valkeyclient`)
  come only from the image label at install or update; a module cannot
  grant itself a role later, so they are always declared. They give access
  only to the guarded cluster actions and to the module's own ports. The `clusterpeer` role is defined by the upgrade;
  NS8 grants it to the other instances when a module is added or the core
  is updated, until then use the store settings instead of `cluster_join`.
- Removal: the peer record is deleted and the peers drop its daemon.

## Not implemented

- Sharing the domains and the integration credentials between instances:
  each instance is configured on its own (DKIM keys: see above).
- Draining a node to another one from the UI.
