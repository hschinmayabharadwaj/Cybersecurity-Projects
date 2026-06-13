<!-- © AngelaMos | 2026 | 04-CHALLENGES.md -->

# Challenges

This document proposes extensions to the canary token generator, organised by difficulty. Each challenge is sized to be a self-contained project on top of the existing codebase. The point is to deepen your understanding of the architecture by pushing it in directions the current design did or did not anticipate.

You don't need to do these in order. Pick ones that interest you.

---

## Easy (1-3 evenings each)

### 1. Add a Slack alert channel

Right now the project supports `telegram` and `webhook`. Slack has a different message format (rich attachments with colour-coded sidebars) and a different auth model (incoming webhook URLs, not bot tokens). Adding it cleanly means:

- New file `backend/internal/notify/slack/sender.go` implementing `notify.Sender` with `Channel() string { return "slack" }` and `Send(ctx, info, evt) error`.
- Extend `token.AlertChannel` validation in `backend/internal/token/dto.go` (validator tag is `oneof=telegram webhook`).
- Extend the React form on the landing page to render a Slack incoming-webhook URL field when the operator picks "Slack".
- Add a config field for an optional `SLACK_WEBHOOK_DEFAULT` if you want default routing.
- Register the sender in `backend/cmd/canary/main.go::buildEventStack`.

The natural test is `sender_test.go` with a `httptest.NewServer` that captures the POST body and asserts the rich-attachment JSON shape matches what Slack expects.

**Stretch:** add per-token Slack channel routing (the operator picks a channel suffix at token creation time, e.g. `#security-alerts` vs `#oncall`).

### 2. Per-token webhook signing secret

Currently the HMAC secret for webhook signing is a global env var (`WEBHOOK_HMAC_SECRET`). For multi-tenant deployments — or any deployment where different operators receive webhooks at different receivers — the secret should be per-token.

- Add a `webhook_hmac_secret` column to `tokens` (migration in `backend/internal/core/migrations/`).
- Plumb it through `event.NotifyInfo` and the webhook sender's `Send`.
- Generate a random secret automatically at token creation if `alert_channel = webhook`, and surface it once in the create response (operator copies it into their receiver configuration).
- Update the README to document the verification flow on the receiving side.

The interesting bit is the rotation story: if a secret leaks, how does the operator rotate it without redeploying the artifacts (whose URLs are immutable)? The cleanest answer is a `POST /api/m/{manageId}/rotate-secret` endpoint that issues a new secret and returns it once.

### 3. Filter events on the manage page

The manage page paginates events but doesn't filter. Common filter dimensions:

- By source IP (find all events from one IP)
- By country (find events from a specific country)
- By time range (last 24h, last 7d, custom)
- By notify status (show only `failed` to triage delivery problems)

The backend already has the data — `events` table is indexed on `triggered_at`. Add query params to `GET /api/m/{manageId}` and matching UI controls on the manage page. Use the same cursor-pagination pattern; just narrow the `WHERE` clause.

**Why this matters:** in a real deployment, a single canary token can fire hundreds of events over its lifetime (especially if it's a `webbug` planted in a public-ish location). The current "show me the most recent 20" view becomes useless quickly.

### 4. Event retention policy per-token

`event.Service.RunRetentionLoop` prunes events to a per-token global limit (`EVENT_RETENTION_PER_TOKEN`). In practice, different tokens want different retention. A `webbug` planted on a public link might fire frequently and need a rolling 30-day window; a `kubeconfig` planted on a service account might fire rarely and want forever-retention.

- Add a `retention_event_count` column (nullable) and a `retention_max_age` interval column to `tokens`.
- Modify `repo.PruneToLimit` (and consider renaming it `PruneByPolicy`) to honour per-token settings, falling back to the global default.
- Update the create form to optionally set retention.

This is a good exercise in handling SQL `NULL` cleanly in Go with `*int` / `*time.Duration` fields and `IS NOT NULL OR ...` in queries.

---

## Medium (a weekend each)

### 5. New token type: DNS resolution canary

A DNS canary fires when a unique subdomain is resolved. The artifact is the hostname; the trigger mechanism is *any* DNS query for that hostname hitting an authoritative server you control.

This requires:

- An authoritative DNS server, either delegated NS-records to your canary infrastructure for `*.canary.example.com`, or a separate listening port that you delegate from a public DNS host. Easiest path: a `miekg/dns` Go server on UDP/53 alongside the HTTP listener.
- A new generator `backend/internal/token/generators/dnscanary/` that:
  - `Generate` returns a `KindURL` artifact containing the hostname.
  - `Trigger` is unused on the HTTP side; the DNS server records the event directly via `event.Service.Record` when a query lands.
- A new handler that the DNS server calls per-query, extracting the token ID from the leftmost subdomain label.

**The clever part:** DNS queries are very chatty and most of them come from recursive resolvers, not the original querier. The event record should capture both the resolver's IP (from the query packet) and any EDNS Client Subnet (ECS) data, which leaks a /24 of the original querier in many cases. Most real-world canary tokens for DNS use this.

**Why it matters:** DNS canaries catch attackers using `nslookup` or `dig` against hostnames they find in a `.env` or config file. They also catch a class of pre-authentication enumeration tooling that resolves before connecting. Thinkst Canary's DNS token is one of their highest-value primitives.

### 6. New token type: AWS credential canary

A real AWS credential canary is a real `AKIA*` access key + matching secret. The "trigger" is a CloudTrail event for the IAM principal using that key. Real Thinkst tokens use AWS API Gateway + Lambda to detect the access attempts.

For this project, the simplified version is:

- Issue real (but heavily-permission-restricted) AWS access keys via the AWS SDK, scoped to a single IAM user that has no permissions except `sts:GetCallerIdentity` on its own ARN.
- Poll CloudTrail (or use EventBridge if the operator's account supports it) for `GetCallerIdentity` events using that key.
- Convert detected events into trigger events on your canary backend.

This is operationally heavier than the other tokens because it requires AWS API access from your canary infrastructure. The challenge is partly the AWS integration and partly the design decision about how the operator supplies their AWS credentials — direct keys, an assumed role, or a separate "AWS adapter" service.

**The cleaner alternative** for an educational project: generate a *fake* AKIA-style key, document the limitation that it only catches attackers who try to use it (not attackers who just exfiltrate it), and rely on a separate sub-token URL embedded in the key's "description" field that fires on retrieval.

### 7. JA3/JA4 fingerprinting on HTTPS trigger requests

Browser fingerprinting (the slowredirect type) requires JS to run. JA3/JA4 fingerprinting works at the TLS handshake level and catches every HTTPS client — including curl, wget, Python `requests`, and headless tools that won't run JS.

- Replace nginx in front with an HTTPS listener that exposes the TLS ClientHello bytes to the application layer. Options: terminate TLS in Go directly with `crypto/tls` (`GetClientHelloInfo` callback) or front with a JA-aware proxy like `Suricata` / `ja4-fingerprinter` / `caddy-tlsmonitor`.
- Extend the event payload's `extra` JSONB with `ja3_hash`, `ja4_hash`, and `tls_version`.
- Surface them in the manage page.

The forensic value is large: JA3/JA4 hashes are much harder to spoof than `User-Agent`, and they correlate the same attacker across multiple campaigns. The downside is that running your own TLS termination loses Cloudflare Tunnel as an option (Cloudflare terminates TLS at their edge before forwarding) — you'd need to deploy directly.

### 8. Bulk token operations

Power users want to mint 50 tokens at once with the same alert channel but different memos (one per workstation, say). Right now they have to click 50 times.

- Add `POST /api/tokens/bulk` accepting an array of `CreateRequest` objects.
- Rate-limit it independently from single-token creation (lower per-minute, but allow larger bursts of bulk requests).
- Frontend: a "Bulk" tab on the landing page with a CSV upload + per-row form.
- Return a zip of all artifacts in one response so the operator gets one download.

The interesting backend design problem is partial failure: if 49 tokens succeed and 1 fails, what's the response? Either you persist nothing on any failure (atomic) or you persist what succeeded and return a per-row status (best-effort). The codebase's domain layout suggests best-effort with per-row status is cleaner.

---

## Hard (a week or more each)

### 9. Detection-resistant artifact generation

Every artifact in this project has fingerprintable properties. The PDF placeholder padding produces a URL with a recognisable `?p=__________` query. The webbug pixel is byte-identical across all tokens of that type. The envfile canary uses a fixed `INTERNAL_METRICS_ENDPOINT` key.

A determined attacker who studies one of your tokens can identify others. Hardening:

- **PDF:** randomise the padding chars per-token (use printable URL-safe chars), or rotate among multiple template PDFs with placeholders in different fields (footer text, embedded form action, JS, etc.).
- **Webbug:** vary the pixel slightly per token. JPEG quantisation noise is enough to produce different SHA256 hashes for a "1x1 JPEG that looks the same".
- **Envfile:** randomise the canary key name from a list of plausible alternatives (`INTERNAL_METRICS_ENDPOINT`, `OBSERVABILITY_PUSH_URL`, `TELEMETRY_GATEWAY`, etc.). Randomise the position of the canary line within the file.
- **DOCX:** rotate among several footer styles or embed the URL in different document parts (settings.xml, footnotes, comments, etc.).

The exercise: pick one artifact type and design a configuration system that lets the operator dial how unique the per-token artifact should be (uniform vs randomised). Track the randomisation seed per token so you can reproduce the artifact later if needed.

**Why it matters:** Thinkst's commercial product is hardened against attacker fingerprinting in exactly this way. Open-source canaries are easier to fingerprint by definition (the source code is public), so this kind of work is the bridge between "educational project" and "operational deployment".

### 10. Operator-side retry pipeline for failed notifications

Right now if `notify_status = failed` (queue full, webhook receiver down, transient Telegram error), the event stays at that status forever. Operators have no built-in way to retry.

Build a retry pipeline:

- A new background goroutine (similar to the retention loop) that scans for `notify_status = failed` events with `notified_at IS NULL` and re-queues them on the notify service.
- Exponential backoff per event — first retry at 1 minute, then 5, then 30 — with a configurable max retry count.
- A new `retry_count` column on `events` to track attempts.
- Optional: a manual "retry" button on the manage page that bumps `retry_count = 0` and re-queues immediately.

The hardest design decision is when to give up. After N retries, do you alert the operator via a secondary channel (system-level email, dead-letter file write)? Do you just stop and require manual intervention? The right answer depends on the deployment model.

### 11. Multi-tenant deployment

The current architecture is single-operator. Multi-tenancy means:

- An auth model for token creation (not Turnstile — actual user accounts). Plug in WebAuthn for passwordless or use Cloudflare Access for SSO.
- A `users` table and a `user_id` foreign key on `tokens`.
- Manage routes (`/api/m/{manageId}`) become authorisation-aware: the requester must own the token (or use the public manage URL, which becomes a sharing primitive).
- Admin routes split into "global admin" (the deployment operator) and "per-user admin" (each tenant's view of their own tokens).
- Per-tenant rate limits — a tenant shouldn't be able to DOS others by exhausting the shared budget.
- Maybe per-tenant alert channel config (one tenant uses Telegram, another uses webhook, with separate validation).

This is a significant project — multi-tenancy is famously the rewrite that small services try to retrofit and end up rewriting twice. Doing it cleanly means starting from a clear data model and threading the tenant context through every layer.

### 12. Distributed deployment with leader election

The MySQL listener and the retention loop are designed assuming one process. If you want to run multiple `canary` instances behind a load balancer for HA, you need:

- **Leader election** for the retention loop (only one instance should be pruning). Easiest: a Redis key with `SETNX` + TTL renewal as the leader heartbeat. Slightly more robust: use `etcd` or `Consul`.
- **A shared MySQL listener address.** Each instance can bind to the same `0.0.0.0:3306` if you front them with an NLB; or they all bind to ephemeral ports and a service mesh routes by token-ID hash.
- **Shared dedup gate** — already works because the gate is in Redis.
- **Shared notification queue** — currently in-memory per process. Moving it to a Redis stream or a real broker (NATS, Kafka) is the right answer for actual scale.

This is the project where you'd genuinely benefit from running the existing one in production for a while first, hitting the limits, and then designing the shared infrastructure based on what actually breaks rather than what you imagine might.

---

## Defensive Drills (one-off exercises, hours each)

Not really "challenges" in the build-something sense; these are exercises to deepen your understanding by using the canary against yourself.

### A. Pwn-your-own-PDF

Generate a PDF token, save it, then open it in:

1. Chrome (built-in PDF viewer)
2. Firefox (PDF.js)
3. Acrobat Reader
4. macOS Preview
5. `pdftotext` (Poppler)

Which ones fire? Predict before checking the manage page. The answer is informative about how brittle PDF-based tokens are in practice.

### B. Pwn-your-own-DOCX

Same drill with a DOCX:

1. Microsoft Word (on Windows, on Mac)
2. LibreOffice
3. Pages
4. Google Docs (upload + view)
5. Office Online (upload + view)
6. `docx2txt` or `pandoc`

Which fire? What does the resulting fingerprint look like for each?

### C. Trace your own MySQL trigger

Connect to your local instance with the `mysql` CLI from a `canary_*` username. Watch the connection in Wireshark or `tcpdump -A -i lo0 -s 0 -X 'tcp port 3306'`. Identify each packet:

1. Server `HandshakeV10` (the server sends this first)
2. Client `HandshakeResponse`
3. Server `ERR_PACKET`

The point is to see how protocol-level the implementation really is. Read the bytes against the [MySQL Internals — Client/Server Protocol](https://dev.mysql.com/doc/internals/en/client-server-protocol.html) documentation.

### D. Try to enumerate

Set up the service. Mint one valid `webbug` token. Then write a script that hits `/c/{random}` URLs with random 12-char IDs and try to detect which ones are real based on:

- Response timing
- Response headers
- Response body bytes

If the script can reliably tell real from fake, the enumeration-resistance design has a hole. Find it. Fix it.

### E. Try to DOS the alert channel

Mint a token with a webhook alert channel pointing at a URL you control. Then write a script that hits the trigger URL from many source IPs (use a SOCKS pool, or just hit it from multiple cloud VMs).

How many concurrent IPs does it take before:

1. The notify queue fills up and starts dropping?
2. The webhook receiver gives up?
3. The operator notices?

Use the answer to inform the worker pool sizing for your real deployment.

---

## Reading List

If you want to deepen the conceptual side rather than the implementation side, these are the resources that informed the design of this project:

- **Thinkst Canary Tokens** documentation and Haroon Meer's talks (DEFCON, BSidesLV) — the modern canary canon.
- **MITRE Engage** matrix and example deployments — defensive deception taxonomy.
- **Tom Limoncelli's "How Complex Systems Fail"** — relevant when designing the dedup gate and failure modes.
- **The MySQL Internals docs** (Oracle) — needed if you want to extend the MySQL token to support more protocol features.
- **PDF 1.7 reference (ISO 32000-1)** — needed if you want to extend the PDF token beyond the URI page-open action.
- **Office Open XML format (ECMA-376)** — needed if you want to extend the DOCX token beyond the footer URI.
- **2024 Mandiant M-Trends report** and **2024 Verizon DBIR** — dwell-time numbers that make the case for deception.

---

Done. If you build any of these, the project is open to PRs — and if you build #5 (DNS canary) or #9 (detection-resistant artifacts), the maintainers want to talk to you.
