# Sending platform responsibilities

The NS8 module accepts and delivers mail under the configured tenant policy.
The SaaS platform owns tenant onboarding, subscriber data, analytics and
customer-facing callbacks.

- **Suppression.** Consume the module's [signed events](webhooks.md). Deduplicate
  deliveries and correlate asynchronous bounces and complaints to original
  messages using platform message IDs, envelope identifiers and tenant context.
  Suppress confirmed invalid addresses and reliably attributed complaints.
  Keep unsubscribe and complaint records within the relevant tenant or list.
  Apply global blocks only according to explicit platform policy. Avoid
  suppressing recipients after temporary failures or provider-wide policy
  bounces. Check the durable list before accepting a send, and expose the
  [suppression decision endpoint](submission-guardrails.md#check-a-platform-suppression-service)
  for direct KumoMTA submissions.
- **One-click unsubscribe.** Apply it to the applicable subscription traffic.
  Generate an HTTPS link with an opaque token scoped to the recipient, tenant
  and list. Set `List-Unsubscribe` and
  `List-Unsubscribe-Post: List-Unsubscribe=One-Click` before injection. Handle
  the RFC 8058 POST idempotently and update suppression. Keep GET requests from
  changing subscription state. KumoMTA covers both fields in its DKIM signing
  policy. Verify the signed headers of a delivered sample.
  [RFC 8058](https://www.rfc-editor.org/rfc/rfc8058.html)
- **Open and click tracking.** If offered, apply link rewriting and insert
  tracking pixels in the platform before submission and DKIM signing.
  Record events under the right tenant, use opaque tracking IDs, and keep
  unsubscribe links independent of the click redirect. Treat privacy-proxy
  opens and security-scanner clicks as approximate signals.
- **Customer webhooks.** Receive the module's webhook at one controlled
  platform endpoint. Verify signatures on the raw body and durably record
  events before acknowledgement. Filter events by tenant, combine them with
  platform engagement events, then sign and retry callbacks separately for
  each customer's endpoint. Validate callback URLs and keep delivery history
  and failures available to the tenant.
- **Onboarding and reputation.** Verify account and domain ownership, assign a
  low admission cap and a sandbox pool, review sustained delivery evidence,
  and update the tenant policy on every KumoMTA node. Use bounce and complaint
  rates as review signals with minimum sample sizes. Provide account suspension
  and a route for operator review.
- **Inbound parse.** When offering it, configure an
  [inbound SMTP route](../README.md) to a separate MIME parser. The worker
  validates the receiving domain and maps it to a tenant, parses MIME and
  attachments with size limits, and delivers signed, retried webhooks. Keep
  attachment storage private to that tenant.
- **DMARC and abuse mailboxes.** Receive `dmarc@`, `abuse@` and `postmaster@`
  through `ns8-mail` or an external mailbox service. Point
  [ns8-parsedmarc](https://github.com/geniusdynamics/ns8-parsedmarc) at the DMARC
  report inbox and monitor the abuse addresses. Keep DSNs and ARF complaints
  on the [KumoMTA bounce and feedback domain](integration.md#bounces-and-feedback-loops).
  Give each service its intended MX destination when both receive inbound mail.
