# KumoMTA High-Volume Architecture, Throughput & Deliverability Guide

While KumoMTA supports high-volume throughput spanning millions of transactions per hour (and up to a million per minute on high-core hardware), a lot of considerations need to be factored in to make sure your emails reach the desired inbox destinations.

In production environments, raw Mail Transfer Agent (MTA) speed is rarely the true bottleneck. Real-world sending capacity is governed by receiving ISP rate limits, IP and domain reputation, connection concurrency caps, DNS authentication alignment, and strict mail-stream isolation ([Mailflow Authority — KumoMTA Setup Guide](https://mailflowauthority.com)).

---

## Table of Contents
1. [Single-Node Hardware Throughput Benchmarks](#1-single-node-hardware-throughput-benchmarks)
2. [Safe Daily Volume Ceilings per Warmed IP](#2-safe-daily-volume-ceilings-per-warmed-ip)
3. [Warmed IP Pool Sizing by Hardware & Mail Type](#3-warmed-ip-pool-sizing-by-hardware--mail-type)
4. [B2C vs. B2B Deliverability & Filtering Dynamics](#4-b2c-vs-b2b-deliverability--filtering-dynamics)
5. [IP & Domain Warmup Schedule (4 to 6 Weeks)](#5-ip--domain-warmup-schedule-4-to-6-weeks)
6. [Anti-Blacklisting & Reputation Protection Rules](#6-anti-blacklisting--reputation-protection-rules)
7. [Production KumoMTA Configuration (Pools & Per-ISP Shaping)](#7-production-kumomta-configuration-pools--per-isp-shaping)
8. [Pre-Flight DNS & Diagnostics Checklist](#8-pre-flight-dns--diagnostics-checklist)
9. [Complete Reference & Further Reading](#9-complete-reference--further-reading)

---

## 1. Single-Node Hardware Throughput Benchmarks

Written in Rust with an asynchronous, event-driven engine, KumoMTA scales vertically on multi-core servers and horizontally across clusters ([KumoMTA Server Environment Tutorial](https://kumomta.com)). The table below breaks down single-node capacities derived from official benchmarks ([KumoMTA Performance Update](https://kumomta.com)):

| Hardware Tier | Hourly Throughput | Per Minute | Per Second | Architectural Role |
| :--- | :--- | :--- | :--- | :--- |
| **8 cores / 21 GB RAM** (`c5n.2xlarge`) | ~3,300,000 | ~55,000 / min | ~917 / sec | Entry-level high-volume node |
| **16 cores / 42 GB RAM** | ~4,600,000 | ~76,667 / min | ~1,278 / sec | Practical baseline (4M–6M/hr recommended) |
| **36 cores / 96 GB RAM** (`c5n.9xlarge`) | ~6,300,000 | ~105,000 / min | ~1,750 / sec | High-concurrency enterprise node |
| **96 cores** (`dev/null` sink benchmark) | ~60,000,000 | ~1,000,000 / min | ~16,667 / sec | Theoretical engine ceiling without ISP throttling |

### Infrastructure & Hardware Nuances
* **Sustained vs. Theoretical Speed:** While a 96-core system can ingest or drop 16,667 messages per second against a `dev/null` sink, live delivery speeds are constrained by TLS handshakes, DNS MX resolution latency, and receiving ISP throttling ([InboxTooling — KumoMTA vs. PowerMTA](https://inboxtooling.com)).
* **Network Bandwidth:** Delivering 1 million messages with an average payload of 50 KB over an 8-hour window transfers roughly **50 GB/hour (~111 Mbps)**, fitting comfortably inside standard 1 Gbps+ cloud networking ([KumoMTA Server Environment Tutorial](https://kumomta.com)).
* **Storage I/O:** KumoMTA spools message data and metadata using RocksDB. Use dedicated NVMe SSDs so disk write latency does not bottleneck high-concurrency bursts.
* **Real-World Handoff Latency:** In high-volume production migrations, KumoMTA's modern async queue handling has demonstrated rapid SMTP handoffs across major providers, averaging ~1.2s to Gmail, ~2.8s to Microsoft, and ~3.2s to Yahoo ([Postmark — Migrating to KumoMTA](https://postmarkapp.com)).

---

## 2. Safe Daily Volume Ceilings per Warmed IP

Even when running dedicated IPs with established reputations, mailbox providers and corporate security gateways enforce dynamic connection and velocity ceilings ([SMTP.com — Dedicated IP Addresses](https://smtp.com)). Pushing beyond these limits triggers temporary `421`/`451` deferrals or `5xx` blocks.

| Mail Stream Category | B2C Ceiling (Gmail, Yahoo, Outlook.com) | B2B Ceiling (Corporate Gateways) | Operational Notes |
| :--- | :--- | :--- | :--- |
| **Transactional Mail** *(OTPs, Receipts, Alerts)* | Up to **500,000 / day** per IP | Up to **250,000 / day** per IP | High open rates and near-zero complaints sustain higher velocity. |
| **Opt-In Marketing** *(Newsletters, Promos)* | **150,000 – 250,000 / day** per IP | **75,000 – 125,000 / day** per IP | Corporate gateways throttle promotional blasts faster than consumer ISPs. |
| **Cold Outreach** *(Unsolicited B2B)* | **Not Recommended** | **50 – 200 / day** per IP/mailbox | High-throughput MTAs are unsuited for cold mail; corporate filters block high-velocity cold blasts immediately. |

---

## 3. Warmed IP Pool Sizing by Hardware & Mail Type

To run KumoMTA hardware at peak capacity without saturating per-IP ISP limits, distribute traffic across a properly sized pool of warmed dedicated IPs ([KumoMTA Sending IPs Guide](https://kumomta.com)).

### Required Warmed IPs (8-Hour Daily Campaign Window)

| Hardware Tier (8h Volume) | Transactional: B2C (Gmail/Yahoo) | Transactional: B2B (Corporate) | Marketing: B2C (Gmail/Yahoo) | Marketing: B2B (Corporate) |
| :--- | :--- | :--- | :--- | :--- |
| **8 cores** (26.4M / day) | **53 IPs** | **106 IPs** | **106 – 176 IPs** | **212 – 352 IPs** |
| **16 cores** (36.8M / day) | **74 IPs** | **148 IPs** | **148 – 246 IPs** | **295 – 491 IPs** |
| **36 cores** (50.4M / day) | **101 IPs** | **202 IPs** | **202 – 336 IPs** | **404 – 672 IPs** |
| **96 cores** (480.0M / day) | **960 IPs** | **1,920 IPs** | **1,920 – 3,200 IPs** | **3,840 – 6,400 IPs** |

> **Scaling to 24/7 Continuous Sending:** If your application dispatches mail continuously across a full 24-hour cycle rather than an 8-hour campaign window, multiply the IP counts above by **3** (e.g., 159 to 1,056 IPs on an 8-core node; 222 to 1,473 IPs on a 16-core node).

---

## 4. B2C vs. B2B Deliverability & Filtering Dynamics

### B2C Mailbox Providers (Gmail, Yahoo, Outlook.com)
* **Engagement-Weighted Filtering:** Consumer mailbox providers measure positive recipient signals (opens, clicks, replies, moving out of spam) against negative signals (deletes without reading, spam reports). High engagement unlocks higher per-IP daily throughput.
* **Mandatory Bulk Sender Compliance:** Google and Yahoo enforce strict **SPF, DKIM, and DMARC** alignment, valid forward/reverse DNS (`PTR` records), and one-click unsubscribe headers (`List-Unsubscribe-Post: List-Unsubscribe=One-Click`) for senders exceeding 5,000 messages/day ([Google Email Sender Guidelines](https://google.com)).
* **Spam Complaint Ceilings:** Maintain user-reported spam rates below **0.08%**, and never cross Google/Yahoo's **0.3%** hard enforcement threshold ([Google Email Sender Guidelines](https://google.com)).

### B2B Corporate Gateways (Microsoft 365, Proofpoint, Mimecast, Barracuda)
* **Velocity & Connection Sensitivity:** Enterprise perimeter appliances evaluate traffic heuristically. Sudden bursts of concurrent SMTP connections or high message rates from a single IP look identical to spam floods or denial-of-service attacks.
* **Subnets & Concurrency:** B2B delivery requires spreading traffic across clean subnets with conservative concurrent connection caps (typically 2 to 10 connections per domain) and steady pacing ([Mailflow Authority — KumoMTA Architecture Guide](https://mailflowauthority.com)).

---

## 5. IP & Domain Warmup Schedule (4 to 6 Weeks)

Brand-new dedicated IPs and newly registered sending domains start with neutral/zero reputation. Sending full KumoMTA volume on Day 1 results in immediate deferrals or blacklisting ([SMTP.com — What is IP Warming?](https://smtp.com)).

### Sample Per-IP Warmup Progression
Send strictly to your most engaged, recently active subscribers during Weeks 1–3 before introducing broader segments ([Mailflow Authority — Complete Email & IP Warmup Guide](https://mailflowauthority.com)):

| Warmup Stage | Days | Daily Volume per IP | Target Audience Segment | KumoMTA Pool Weight Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Week 1** | Days 1–7 | 50 → 500 | 15-day clickers/openers | Weight `1` (vs. `20–50` on warmed IPs) |
| **Week 2** | Days 8–14 | 1,000 → 5,000 | 30-day engaged subscribers | Weight `2` |
| **Week 3** | Days 15–21 | 10,000 → 25,000 | 60-day engaged subscribers | Weight `5` |
| **Week 4** | Days 22–28 | 40,000 → 80,000 | 90-day active subscribers | Weight `10` |
| **Weeks 5–6** | Days 29–42 | 100,000 → Target Cap | Full opted-in mailing list | Full parity weight (`10–20`) |

> **Warmup Circuit-Breaker Rule:** Pause volume increases or step back one tier if hard bounces exceed **2%**, spam complaints exceed **0.08%**, or ISP logs return reputation-based `421`/`550` deferrals ([Mailflow Authority — Email Warmup Guide](https://mailflowauthority.com)).

---

## 6. Anti-Blacklisting & Reputation Protection Rules

1. **Never "Snowshoe" IPs:** Acquiring large blocks of IPs just to spread out low-engagement bulk mail or evade per-IP volume caps triggers automated snowshoe spam detection, resulting in entire `/24` or `/22` netblock listings. Every IP in a pool must maintain a consistent daily sending baseline rather than sitting idle between spikes.
2. **Isolate Domains & Subdomains:** Modern spam filters track **domain reputation** independently of IP reputation—meaning rotating IPs will not rescue a burned domain ([SMTP.com — IP Warming PDF Guide](https://smtp.com)). Separate traffic across distinct subdomains (e.g., `://yourdomain.com` for receipts/OTPs vs. `://yourdomain.com` for marketing) paired with separate KumoMTA egress pools.
3. **Automate Backoff with TSA:** Enable KumoMTA's **Traffic Shaping Automation (TSA)** daemon so the MTA reads SMTP deferral codes in real time and automatically reduces connection concurrency or pauses queues when an ISP pushes back ([KumoMTA Traffic Shaping Documentation](https://kumomta.com)).
4. **Enforce List Hygiene:** Suppress hard bounces immediately and sunset unengaged recipients (e.g., no opens or clicks in 90–180 days) to prevent hitting recycled spam traps.

---

## 7. Production KumoMTA Configuration (Pools & Per-ISP Shaping)

Use KumoMTA's built-in Lua policy helpers (`sources.lua` and `shaping.lua`) to enforce pool isolation, gradual IP warmup weights, and per-ISP throttling ([KumoMTA Policy Helpers Docs](https://kumomta.com)).

### Step 1: Egress Sources & Warmup Weights (`/opt/kumomta/etc/policy/sources.toml`)
```toml
# Individual Egress IPs (Must have matching forward A and reverse PTR records)
[source."ip-tx-01"]
source_address = "192.0.2.10"
ehlo_domain = "://yourdomain.com"

[source."ip-mkt-01"]
source_address = "192.0.2.20"
ehlo_domain = "://yourdomain.com"

[source."ip-mkt-02-warming"]
source_address = "192.0.2.21"
ehlo_domain = "://yourdomain.com"

# Isolated Egress Pools
[pool."pool-transactional"]
[pool."pool-transactional"."ip-tx-01"]
weight = 10

[pool."pool-marketing"]
[pool."pool-marketing"."ip-mkt-01"]
weight = 10

# Weight 1 vs 10 routes ~9% of marketing traffic to the warming IP
[pool."pool-marketing"."ip-mkt-02-warming"]
weight = 1
```

### Step 2: Per-ISP Connection & Rate Limits (`/opt/kumomta/etc/policy/shaping.toml`)
```toml
# Conservative fallback for B2B corporate gateways & unknown MX hosts
["default"]
connection_limit = 5
max_deliveries_per_connection = 20
max_message_rate = "60/min"

# B2C: Gmail (Tolerates higher concurrency once warmed)
["gmail.com"]
connection_limit = 20
max_deliveries_per_connection = 50
max_message_rate = "600/min"

# B2C: Yahoo / AOL
["yahoo.com"]
connection_limit = 10
max_deliveries_per_connection = 20
max_message_rate = "300/min"

# B2B / Enterprise: Microsoft 365 (Strict connection & velocity thresholds)
["outlook.com"]
connection_limit = 10
max_deliveries_per_connection = 25
max_message_rate = "200/min"
```

### Step 3: Queue Routing & TSA Integration (`/opt/kumomta/etc/policy/init.lua`)
```lua
local kumo = require 'kumo'
local sources = require 'policy-extras.sources'
local shaping = require 'policy-extras.shaping'

sources:setup { '/opt/kumomta/etc/policy/sources.toml' }

local shaper = shaping:setup_with_automation {
  publish = { 'http://127.0.0.1:8008' }, -- TSA Daemon endpoint
  subscribe = { 'http://127.0.0.1:8008' },
  extra_files = { '/opt/kumomta/etc/policy/shaping.toml' },
}

kumo.on('init', function()
  kumo.define_spool { name = 'data', path = '/var/spool/kumomta/data', kind = 'RocksDB' }
  kumo.define_spool { name = 'meta', path = '/var/spool/kumomta/meta', kind = 'RocksDB' }

  kumo.start_esmtp_listener {
    listen = '0.0.0.0:25',
    relay_hosts = { '127.0.0.1', '10.0.0.0/8' },
  }
end)

-- Isolate transactional vs. marketing traffic based on Tenant metadata
kumo.on('get_queue_config', function(domain, tenant, campaign, routing_domain)
  local pool = 'pool-marketing'
  if tenant == 'transactional' then
    pool = 'pool-transactional'
  end

  return kumo.make_queue_config {
    egress_pool = pool,
  }
end)

kumo.on('get_egress_path_config', shaper.get_egress_path_config)
```

---

## 8. Pre-Flight DNS & Diagnostics Checklist

Before routing live traffic through new KumoMTA nodes or IP pools, validate your DNS and authentication posture using diagnostic tools such as [InboxTooling](https://inboxtooling.com):

- [ ] **Forward-Confirmed Reverse DNS (FCrDNS):** Every egress IP resolves via `PTR` to its `ehlo_domain` (e.g., `://yourdomain.com`), and that hostname resolves back via an `A` record to the exact same IP.
- [ ] **SPF Record:** Authorized sending IPs/includes are published without exceeding the 10-DNS-lookup limit.
- [ ] **DKIM Signing:** 2048-bit RSA (or Ed25519) keys are active and aligned with the `From:` header domain.
- [ ] **DMARC Policy:** Published at `_://yourdomain.com` with at least `p=none` during initial monitoring, progressing to `p=quarantine` or `p=reject` once alignment is verified.
- [ ] **Feedback Loops & Postmaster Tools:** Registered with **Google Postmaster Tools**, **Microsoft SNDS**, and **Yahoo Sender Hub** to monitor IP/domain reputation and complaint spikes.

---

## 9. Complete Reference & Further Reading

### KumoMTA Official Documentation & Benchmarks
* **KumoMTA Official Documentation:** [://kumomta.com](https://://kumomta.com/)
* **Server Environment & Hardware Sizing:** [KumoMTA Server Environment Tutorial](https://://kumomta.com/tutorial/server_environment/)
* **Configuring Sending IPs & Egress Pools:** [KumoMTA Sending IPs Guide](https://://kumomta.com/userguide/configuration/sendingips/)
* **Lua Policy Helpers Reference:** [KumoMTA Policy Helpers Documentation](https://kumomta.com)
* **Traffic Shaping & Automation (TSA):** [KumoMTA Traffic Shaping Documentation](https://kumomta.com)
* **Official Hardware Benchmarks:** [KumoMTA Performance Update](https://kumomta.com)
* **High-Volume Production Case Study:** [Postmark Engineering — Why We Migrated to KumoMTA](https://postmarkapp.com)

### IP Warmup, Deliverability & Infrastructure Guides
* **SMTP.com — IP Warming Fundamentals:** [What is IP Warming and Why is it Essential?](https://smtp.com)
* **SMTP.com — Dedicated IP Ramping:** [What Are Dedicated IP Addresses?](https://smtp.com)
* **SMTP.com — Domain vs. IP Reputation:** [IP Warming for Better Email Deliverability (PDF)](https://smtp.com)
* **Mailflow Authority — Warmup Schedules:** [Complete Email & IP Warmup Guide](https://mailflowauthority.com)
* **Mailflow Authority — Self-Hosted KumoMTA Guide:** [High-Volume Self-Hosted Sending with KumoMTA](https://mailflowauthority.com)
* **Mailflow Authority — Architecture & Shaping:** [KumoMTA Architecture & Traffic Shaping Guide](https://mailflowauthority.com)
* **InboxTooling — MTA Comparison & Automation:** [KumoMTA vs. PowerMTA: A Deep Comparison](https://inboxtooling.comblog/kumomta-vs-powermta/)
* **InboxTooling — DNS & Auth Diagnostics:** [SPF, DKIM, DMARC & PTR Verification Suite](https://inboxtooling.com)
* **Google & Yahoo Sender Requirements:** [Google Email Sender Guidelines](https://google.com)
