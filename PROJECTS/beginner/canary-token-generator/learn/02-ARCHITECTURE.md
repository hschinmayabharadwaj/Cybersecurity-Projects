<!-- © AngelaMos | 2026 | 02-ARCHITECTURE.md -->

# Architecture

This document covers the system design. It walks through the request lifecycle for both token creation and token triggering, the schema, the dedup gate, the notification pipeline, and the deployment topology. Read time is roughly 20-25 minutes.

The point is not to recap the code — that's [03 - Implementation](03-IMPLEMENTATION.md) — but to explain *why* each piece exists and why it sits where it does. Architecture decisions only make sense once you understand the constraints they're optimising against.

---

## High-Level Topology

```
                                   ┌────────────────────────────┐
                                   │  Cloudflare Tunnel         │
                                   │  (optional, public ingress)│
                                   └─────────────┬──────────────┘
                                                 │
                                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  nginx (reverse proxy)                                              │
│    - Serves /  → frontend static bundle (prod) or Vite (dev)        │
│    - Proxies /api/* → canary backend                                │
│    - Proxies /c/*, /k/*, /healthz → canary backend                  │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  canary (Go binary, internal port 8080)                             │
│                                                                     │
│   chi router with middleware chain:                                 │
│     CleanPath → StripSlashes → RequestID → Logger → Recovery →      │
│     SecurityHeaders → (route-specific: CORS, rate limit, Turnstile, │
│                        operator bearer)                             │
│                                                                     │
│   Domains:                                                          │
│     internal/token/     CRUD + trigger handler + generator registry │
│     internal/event/     ingestion service with dedup gate           │
│     internal/notify/    async worker pool                           │
│     internal/admin/     bearer-gated operator endpoints             │
│     internal/health/    /healthz                                    │
│                                                                     │
│   Background goroutines:                                            │
│     MySQL TCP listener  (bound to MYSQL_FAKE_ADDR, accepts conns)   │
│     Retention loop      (prunes events to a per-token limit)        │
└──────┬───────────────────────────────────────┬──────────────────────┘
       │                                       │
       ▼                                       ▼
┌──────────────────┐                  ┌───────────────────────────┐
│ PostgreSQL 18    │                  │ Redis 7                   │
│  tokens          │                  │  dedup:trigger:{id}:{ip}  │
│  events          │                  │  dedup:active:{id}        │
│  goose_db_version│                  │  ratelimit:{scope}:{key}  │
└──────────────────┘                  └───────────────────────────┘
                                                 │
                                                 ▼
                                       ┌───────────────────────┐
                                       │ External destinations │
                                       │  - Telegram Bot API   │
                                       │  - Webhook receivers  │
                                       │  - Jaeger (OTLP/gRPC) │
                                       └───────────────────────┘
```

The shape is conventional for a Go web service: nginx in front, single Go binary in the middle, Postgres and Redis behind. The interesting parts are the dedup gate, the async notification pipeline, and the MySQL listener that lives next to the HTTP server in the same process.

---

## Request Lifecycle 1: Creating a Token

This is the request that runs when the operator clicks "Generate" in the web UI.

```
Operator (browser)
  │
  │  POST /api/tokens
  │  Content-Type: application/json
  │  Body: { "type": "envfile", "memo": "team-laptops",
  │           "alert_channel": "telegram",
  │           "telegram_bot": "...", "telegram_chat": "...",
  │           "metadata": { "include_keys": ["aws", "github"] },
  │           "cf_turnstile_response": "..." }
  │
  ▼
nginx → canary:8080
  │
  ▼
chi middleware chain (in order, see backend/cmd/canary/main.go:298-308):
  CleanPath, StripSlashes                     normalise URL
  RequestID                                   attach uuid to ctx
  Logger                                      slog request_start / request_end
  Recovery                                    catch panics → 500 + structured log
  SecurityHeaders                             CSP, HSTS, X-Frame-Options
  CORS (per-route, /api/* only)               allowed origins from config
  RateLimiter (per-fingerprint)               token bucket via Redis (KeyByFingerprint)
  RateLimiter (per-minute, create scope)      separate bucket for token creation
  RateLimiter (per-hour, create scope)        slow-bleed budget for creation
  TurnstileVerify                             POST cf-turnstile-response to Cloudflare siteverify
  │
  ▼
token.Handler.CreateToken
  │
  │  - validator/v10 on the CreateRequest DTO
  │  - extract fingerprint = sha256(RealIP + UserAgent)[:16]
  │
  ▼
token.Service.Create
  │
  ├─► generator.Generator(type) → e.g. envfile.Generator
  │      │
  │      └─► Generate(ctx, token, baseURL) → Artifact
  │          (envfile picks recipes, shuffles, injects canary line)
  │
  ├─► token.Repository.Insert → PostgreSQL
  │      INSERT INTO tokens (id, manage_id, type, memo, filename,
  │        alert_channel, telegram_bot, telegram_chat, webhook_url,
  │        created_at, created_ip, created_fp, enabled, metadata)
  │      VALUES (...)
  │
  └─► Return CreateResponse { token, artifact }
  │
  ▼
HTTP 201 Created
  Body: {
    "success": true,
    "data": {
      "token": {
        "id": "abc123xyz789",
        "manage_id": "9b1d...",
        "type": "envfile",
        "trigger_url": "https://canary.example.com/c/abc123xyz789",
        "manage_url":  "https://canary.example.com/m/9b1d...",
        ...
      },
      "artifact": {
        "kind": "file",
        "filename": ".env",
        "content_b64": "..."
      }
    }
  }
```

Notes on the chain that aren't obvious from the diagram:

- **Two separate rate limiters on creation.** The fingerprint limiter is wide (default 100/min) and applies to every `/api/*` request — it's there to keep a single tab from hammering the API. The create-min / create-hour limiters are tighter and apply *only* to `POST /api/tokens`. The hour budget exists because a script could happily spread its requests across many minutes and burn through unlimited token IDs if there were no longer-window cap.
- **Turnstile is verified last in the create chain.** That's so the cheap checks (rate limit) reject obvious abuse before we pay for the Cloudflare round-trip on every request.
- **The fingerprint is for rate limiting, not authentication.** It's `sha256(RealIP + UserAgent)[:16]` — trivially forgeable by an attacker who knows it exists. The point is to make casual abuse harder, not to bind identity. Authentication for admin endpoints is a separate concern (constant-time bearer compare).

---

## Request Lifecycle 2: Triggering a Token

This is the path that runs when an attacker opens the artifact. It's deliberately fast and free of synchronous side effects.

```
Attacker (or attacker's tool)
  │
  │  GET /c/abc123xyz789
  │  User-Agent: curl/8.0   (or Acrobat, or Word, or kubectl, or ...)
  │
  ▼
nginx → canary:8080
  │
  ▼
Middleware chain (NO CORS, NO Turnstile, NO operator bearer — trigger routes are root-mounted)
  │
  ▼
token.Handler.HandleTrigger (backend/internal/token/handler.go)
  │
  │  - Extract tokenID from URL param
  │  - Look up token via Repository.GetByID (or treat as "fake" if not found)
  │  - Resolve Generator by Type
  │
  ▼
generator.Trigger(ctx, token, request) → Event, TriggerResponse, error
  │
  │  Generator-specific behaviour:
  │   webbug       → returns embedded JPEG + cache-control:no-store
  │   pixel-using  → returns embedded 1x1 GIF + cache-control:no-store
  │   slowredirect → renders HTML interstitial; later POST /c/{id}/fingerprint
  │                  attaches fingerprint to the SAME event row's `extra` column
  │   kubeconfig   → same as webbug response
  │   mysql        → unreachable here (TCP listener handles MySQL triggers)
  │
  │  In every case: returns an Event{ TokenID, SourceIP, UserAgent, Referer, ... }
  │  with no ID yet (DB assigns BIGSERIAL on insert)
  │
  ▼
Handler writes the HTTP response IMMEDIATELY
  │  (the attacker's browser gets its bytes before the next steps run)
  │
  ▼
Handler dispatches event.Service.Record asynchronously (or inline, see note)
  │
  ▼
event.Service.Record (backend/internal/event/service.go)
  │
  ├─► geoip.Lookuper.Lookup(SourceIP) → enriches evt.Geo* fields
  │
  ├─► Repository.Insert → PostgreSQL (assigns evt.ID)
  │
  ├─► tokens.IncrementTriggerCount(tokenID) → atomic UPDATE
  │
  ├─► dedupGate(tokenID, sourceIP):
  │      key = "dedup:trigger:{tokenID}:{sourceIP}"
  │      ok, _ = redis.SetNX(key, 1, 15min)
  │      if ok:   return true (first hit, will notify)
  │      if !ok:  redis.Incr(key)
  │               redis.SAdd("dedup:active:{tokenID}", sourceIP)
  │               redis.Expire("dedup:active:{tokenID}", 15min)
  │               return false (suppress notification)
  │
  ├─► if dedup says "first hit":
  │      notify.Service.Notify(notifyInfo, evt) → enqueue dispatchJob
  │      (returns immediately; worker pool handles delivery)
  │
  └─► if dedup says "duplicate":
         repo.UpdateNotifyStatus(eventID, NotifyDeduped, nil)
         (the event row stays in the DB for forensics; alert is suppressed)
```

An important subtlety in the codebase: the trigger handler records the event *synchronously* (DB insert + dedup + notify enqueue) before writing the HTTP response. That keeps the code paths simple and means we don't lose events if the process exits between response and DB insert. The bet is that the insert is fast enough (sub-10ms on a healthy Postgres) that the attacker's client doesn't notice the latency.

The notification *delivery* is async — `event.Service.Record` only *enqueues* a `dispatchJob` and returns immediately. The actual HTTP call to Telegram or the webhook receiver runs on a worker goroutine, so a slow alert destination cannot stall the trigger response. If you wanted to push event recording onto a background queue as well (to absorb DB latency spikes during a flood), the `notify` package's worker-pool pattern would be the model — apply it to event ingestion.

---

## Request Lifecycle 3: MySQL Trigger (TCP, not HTTP)

The MySQL token is special. The artifact is a connection string, not a URL. When the attacker connects, they speak the MySQL v10 wire protocol, not HTTP. So we run a separate TCP listener inside the same process.

```
Attacker
  │
  │  mysql -h db.canary.example.com -P 3306 \
  │        -u canary_abc123xyz789 -p internal_db
  │
  ▼
TCP listener (backend/internal/token/generators/mysql/server.go)
  │
  │  net.Listen("tcp", cfg.MySQL.FakeAddr)
  │  accept loop spawns a goroutine per connection
  │
  ▼
ConnectionHandler.HandleConnection
  │
  │  1. Generate random connection ID + auth-plugin-data
  │     (crypto/rand for both — must look real to MySQL clients)
  │
  │  2. Write HandshakeV10 packet
  │     (server version "5.7.40-canary", caps 0xf7ff/0x81ff, utf8mb4,
  │      auth plugin "mysql_native_password")
  │
  │  3. Read ClientAuth response
  │     (32-bit caps, 32-bit max-packet, 1-byte charset, 23-byte filler,
  │      null-terminated username)
  │
  │  4. Extract token ID from username  (strip "canary_" prefix)
  │
  │  5. Look up token in DB
  │     - if found and enabled: build Event, dispatch via event.Service.Record
  │     - if not found:        still respond with Access denied (enumeration resistance)
  │
  │  6. Write ERR packet with sql state 28000
  │     "Access denied for user 'canary_...'@'attacker-ip' (using password: YES)"
  │
  │  7. Close TCP connection
  │
  ▼
Attacker's terminal:
  ERROR 1045 (28000): Access denied for user 'canary_abc123xyz789'@'1.2.3.4' (using password: YES)
```

A few design notes:

- **Same `event.Service.Record` path.** The MySQL listener doesn't bypass dedup, GeoIP, or notification. It builds the same `event.Event` struct with `extra = {"client_capabilities": ..., "client_charset": ...}` for forensic data, then hands off to the event service. That keeps the trigger logic uniform across all 7 token types.
- **No password verification, ever.** We never try to validate the password (we don't have one to validate against). We always return `Access denied`. If we *did* accept the connection, the attacker would expect to be able to run SQL, and we'd have to fake an entire MySQL server — out of scope.
- **Public vs internal address.** `MYSQL_FAKE_ADDR` is what the listener binds to (e.g. `0.0.0.0:3306` in the container). `MYSQL_PUBLIC_HOST` and `MYSQL_PUBLIC_PORT` are what go into the connection string we hand to the operator (e.g. `db.canary.example.com:3306`). Separating these is what lets the same instance be reachable through a reverse proxy or Cloudflare Tunnel that does port translation.

---

## The Dedup Gate

```
Attacker repeatedly opens /c/abc123xyz789 from IP 1.2.3.4
  │
  │  Hit 1 at T+0s:
  │     SetNX("dedup:trigger:abc123xyz789:1.2.3.4", 1, 15min) → set=true
  │     → record event, notify operator
  │     event.notify_status = sent
  │
  │  Hit 2 at T+5s:
  │     SetNX(...) → set=false (key already exists)
  │     Incr("dedup:trigger:abc123xyz789:1.2.3.4") → 2
  │     SAdd("dedup:active:abc123xyz789", "1.2.3.4")
  │     Expire("dedup:active:abc123xyz789", 15min)
  │     → record event in DB, mark notify_status = deduped
  │     → no notification fired
  │
  │  Hit 3..N at T+5s..T+900s:
  │     same as hit 2
  │
  │  Hit at T+901s:
  │     SetNX(...) → set=true again (TTL expired)
  │     → notify operator (fresh alert)
```

The dedup gate has three deliberate properties:

**It fails open.** If Redis is unreachable, `dedupGate` returns `true` and the event notifies. The reasoning: a Redis outage shouldn't suppress real attacker activity. The cost is alert noise during a Redis outage, which is preferable to silent failure.

**Per-`{token, source_ip}` not per-token.** Two different attackers hitting the same token from different IPs both fire notifications. That matters for shared honeyfile placements (e.g. a wiki page seen by multiple attackers in the same campaign) — you want each attacker to register as a fresh signal, not be suppressed by an earlier one.

**Events are still recorded.** The `events` table gets the row regardless of dedup outcome. The dedup gate only affects whether a notification is *fired*. The manage page displays a "N duplicate triggers silenced" badge so the operator knows there's quiet activity to investigate.

The `dedup:active:{tokenID}` Redis Set exists purely so the manage page can count distinct silenced IPs. `event.Service.CountActiveDedup` reads it via `SCARD`.

---

## The Notification Pipeline

```
event.Service.Record (decides to notify)
  │
  ▼
notify.Service.Notify(info, evt)
  │
  │  - increment jobWg
  │  - non-blocking send on s.queue (buffered chan dispatchJob, cap 256)
  │  - if queue full: drop, mark NotifyFailed, decrement jobWg
  │
  ▼
queue chan dispatchJob  ◄── 8 worker goroutines consume
  │
  ▼
worker.dispatch
  │
  │  ctx, cancel := context.WithTimeout(bg, 30s)
  │
  ├─► sender = s.senders[info.AlertChannel]
  │
  ├─► if not registered: log warn, mark NotifyFailed, return
  │
  ├─► sender.Send(ctx, info, evt):
  │     telegram.Send → POST api.telegram.org/bot{token}/sendMessage
  │     webhook.Send  → POST {webhook_url}  (HMAC-signed if WEBHOOK_HMAC_SECRET set,
  │                                          exponential backoff via cenkalti/backoff/v5)
  │
  ├─► on error: log warn, mark NotifyFailed
  │
  └─► on success: mark NotifySent with notified_at = now
```

The pipeline has three knobs in config: worker count (default 8), queue size (default 256), and per-job timeout (default 30s). The defaults are sized for a single host with low-to-moderate trigger volume. If you operate a wide canary deployment that fires hundreds of events per minute, raise the worker count and queue size.

The bounded queue is important. An unbounded queue means a slow notification destination (e.g. a webhook receiver that hangs) eventually consumes all process memory. With the bounded queue, a hung sender backs up to the queue cap, then `Notify` starts dropping jobs and marking them `NotifyFailed`. The operator sees those in the manage UI and can decide what to do — typically: switch alert channels, kill the broken receiver, or scale up the worker pool.

The 30-second per-job timeout is what eventually unsticks a hung sender. Even if a webhook receiver TCP-accepts and then never reads, the worker abandons after 30s and moves on.

---

## Schema

### `tokens`

```sql
CREATE TABLE tokens (
  id              VARCHAR(12) PRIMARY KEY,
  manage_id       UUID UNIQUE NOT NULL,
  type            VARCHAR(32) NOT NULL,
  memo            TEXT NOT NULL DEFAULT '',
  filename        TEXT,
  alert_channel   VARCHAR(16) NOT NULL,
  telegram_bot    TEXT,
  telegram_chat   TEXT,
  webhook_url     TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_ip      INET NOT NULL,
  created_fp      CHAR(16) NOT NULL,
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  trigger_count   BIGINT NOT NULL DEFAULT 0,
  last_triggered  TIMESTAMPTZ,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb
);
```

A few schema decisions worth flagging:

- **`id` is a 12-char base62 string, not a UUID.** This is the value that goes into the trigger URL (`/c/{id}`) and the artifact body (e.g. the PDF placeholder substitution). UUIDs are 36 chars and would push the PDF placeholder to >76 bytes, breaking the byte-exact substitution. 12 chars at base62 gives ~71 bits of entropy — comfortably non-guessable.
- **`manage_id` is a UUID v4.** This is the *operator-facing* identifier, used in `/api/m/{manageId}` for viewing token + events. Splitting it from `id` means an attacker who triggers a token cannot also enumerate to the manage page from the trigger URL.
- **`created_ip` is `INET`.** Native Postgres type for IPv4/IPv6. Makes geographic queries via `INET <<= cidr` easy if you want to add them later.
- **`metadata` is `JSONB`.** Type-specific config lives here (e.g. `{"destination_url": "..."}` for slowredirect, `{"include_keys": ["aws","db"]}` for envfile). Keeping it out of typed columns means new token types don't need migrations.

### `events`

```sql
CREATE TABLE events (
  id              BIGSERIAL PRIMARY KEY,
  token_id        VARCHAR(12) NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
  triggered_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  source_ip       INET NOT NULL,
  user_agent      TEXT,
  referer         TEXT,
  geo_country     CHAR(2),
  geo_region      VARCHAR(64),
  geo_city        VARCHAR(64),
  geo_asn         INT,
  geo_asn_org     VARCHAR(128),
  extra           JSONB NOT NULL DEFAULT '{}'::jsonb,
  notify_status   VARCHAR(16) NOT NULL DEFAULT 'pending',
  notified_at     TIMESTAMPTZ
);
```

- **`id` is BIGSERIAL.** Monotonic, dense, and ideal for cursor pagination. The manage page paginates with `WHERE id < cursor ORDER BY id DESC LIMIT N`.
- **`extra` is JSONB.** Two uses: (a) `slowredirect` token fingerprints get stored here as the raw JS-produced JSON blob; (b) MySQL events carry `{"client_capabilities": 0x..., "client_charset": 0x21}` so investigators can profile the attacking client.
- **`notify_status` ∈ {pending, sent, failed, deduped}.** The state machine: row inserted as `pending` → dedup decides → either `deduped` (skip notify) or queue for worker → worker writes `sent` or `failed` on completion. The status is what the manage UI uses to badge each row in the table.

### Indexes (migration `0003_indexes.sql`)

- `tokens.manage_id` is UNIQUE NOT NULL — implicit unique index.
- `events.token_id` — supports the manage page's `WHERE token_id = $1` filter.
- `events.triggered_at DESC` — supports admin "recent activity" queries.
- `events.notify_status` — supports filtering pending/failed for retry tooling.

---

## Frontend ↔ Backend Contract

The frontend is a single-page React 19 app. It has two routes:

```
/                  Landing page (token creation form, artifact reveal after success)
/m/:manageId       Manage page (token detail + paginated event feed)
```

State management is **TanStack Query only** — there's no Redux, no Zustand. Every server interaction is a query or mutation:

```typescript
useTokenTypes()         // GET /api/tokens/types
useCreateToken()        // POST /api/tokens
useManageToken(id)      // GET /api/m/:id (cursor-paginated)
useDeleteToken(id)      // DELETE /api/m/:id
```

Each hook validates the response body against a Zod schema before handing it to the component. That means the frontend types are the *actual* shape the backend returns, not what we hope it returns — Zod throws if the contract drifts.

The API client (`frontend/src/api/client.ts`) is a thin Axios wrapper with three job-specific behaviours:

1. **Turnstile injection.** If the user has completed the Turnstile widget, `POST /api/tokens` automatically gets the response token in the `CF-Turnstile-Response` header and the JSON body's `cf_turnstile_response` field (the backend accepts either).
2. **Error normalisation.** HTTP errors are mapped to typed error codes (`VALIDATION_ERROR`, `RATE_LIMITED`, `TURNSTILE_FAILED`, etc.) before being thrown, so components can branch on `err.code` instead of pattern-matching status codes.
3. **Timeout.** 15 seconds per request. Generation can take a couple of seconds for the PDF/DOCX types because of the embedded-template manipulation, but 15s is generous.

There is no WebSocket and no Server-Sent Events. The manage page polls (via TanStack Query's `refetchInterval`) every few seconds. For a low-volume canary deployment, this is plenty — events fire seconds-to-minutes apart, not milliseconds.

---

## Deployment Topology

### Production (`compose.yml`)

```
nginx ─┬─→ canary (Go binary)
       │     ├─→ Postgres
       │     └─→ Redis
       │
       │  static assets from frontend build (mounted in nginx image)
```

Four services, no Vite, no Air, no Jaeger. The Go binary is built with `CGO_ENABLED=0 -trimpath -ldflags="-s -w"` so the resulting image is a `gcr.io/distroless/static-debian12` with the single binary. The image is around 20 MB.

The `canary` container's `/healthz` is wired into the Docker healthcheck via the tiny `cmd/healthcheck` binary, which is a 1.2 MB statically-linked Go HTTP client. We ship that instead of putting `curl` in the image because distroless doesn't have curl.

### Production with Cloudflare Tunnel (`cloudflared.compose.yml`)

```
cloudflared (tunnel client) ─→ Cloudflare edge ─→ public internet
       │
       └─→ nginx (internal only, no exposed port)
```

The tunnel overlay swaps the nginx port-mapping for a `cloudflared` sidecar that maintains an outbound TLS connection to Cloudflare's edge. The instance becomes publicly reachable through `your-tunnel-name.your-domain` without opening any inbound port. That's especially useful for self-hosted deployments on residential connections or behind NAT.

### Development (`dev.compose.yml`)

```
nginx ─┬─→ frontend (Vite HMR)
       │
       └─→ canary (Air-reloaded Go)
             ├─→ Postgres
             ├─→ Redis
             └─→ Jaeger  (OTLP/gRPC + UI at :16686)
```

The dev compose:

- Mounts `frontend/` and `backend/` into the containers so file changes trigger reloads.
- Runs the backend with `air` (https://github.com/cosmtrek/air) for hot reload on `.go` file changes.
- Boots Jaeger so OpenTelemetry traces from the backend can be inspected at `http://localhost:16686`.
- Uses a separate compose project name (`canary-token-generator-dev`) so it doesn't conflict with a running production stack on the same host.

### Why Both Compose Files

A common pitfall is using a single compose file with optional services. The result is fragile: developers have to remember which `--profile` to pass, and CI scripts diverge from local commands. Two files keeps the boundary crisp — `just dev-up` is unambiguously the dev stack, `just up` is unambiguously prod. The `compose.yml` + `cloudflared.compose.yml` override is a separate concern (production with vs without public exposure).

---

## Configuration

The service is configured via `config.yaml` (defaults) overridden by environment variables, loaded with [koanf](https://github.com/knadh/koanf) (see `backend/internal/config/config.go`). The pattern is:

1. Load `config.yaml` for defaults.
2. Overlay env vars (matching the key path with `__` separators, e.g. `SERVER__PORT=8080` overrides `server.port`).
3. Validate the resulting struct against `validator/v10` tags.

The interesting env vars:

| Variable | Purpose |
|----------|---------|
| `PUBLIC_BASE_URL` | The hostname token URLs are minted against. **This is the thing that goes into your artifacts.** |
| `OPERATOR_TOKEN` | Bearer token for `/api/admin/*`. Unset → admin routes don't register. |
| `TURNSTILE_SECRET` | Cloudflare Turnstile server-side secret. Unset → Turnstile middleware is a no-op. |
| `WEBHOOK_HMAC_SECRET` | Used to sign outbound webhooks with HMAC-SHA256 in `X-Canary-Signature`. |
| `GEOLITE_PATH` | Path to the GeoLite2-City MMDB. Unset → GeoIP lookups are nop. |
| `MYSQL_FAKE_ENABLED` | Boolean. If false, the MySQL token type is hidden from `/api/tokens/types` and the listener doesn't spawn. |
| `MYSQL_FAKE_ADDR` | TCP listener bind address, e.g. `0.0.0.0:3306`. |
| `MYSQL_PUBLIC_HOST` / `MYSQL_PUBLIC_PORT` | What gets baked into the artifact connection string. |
| `EVENT_DEDUP_TTL` | Per-`{token, ip}` silence window. Default 15m. |
| `EVENT_RETENTION_PER_TOKEN` | The retention loop prunes events past this count per token. 0 = no pruning. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Where to send OpenTelemetry traces. Unset → tracing disabled. |
| `LOG_LEVEL` / `LOG_FORMAT` | `debug|info|warn|error` and `json|text`. |
| `TRUSTED_PROXY_CIDRS` | Required for correct `RealIP` extraction behind nginx/Cloudflare. |

The `TRUSTED_PROXY_CIDRS` value matters more than people expect. The `RealIP` middleware reads `X-Forwarded-For` only if the immediate peer is in the trusted CIDR list. If you forget to set it for your reverse proxy, every event will show the proxy's IP as the source IP. If you set it too widely, an attacker can spoof their IP by forging `X-Forwarded-For`.

---

## What Isn't In This Architecture (And Why)

A few omissions are deliberate.

**No multi-tenancy.** A single deployment is one operator's canary deployment. If you want per-team isolation, run multiple deployments (cheap, since the binary is small and Postgres/Redis can be shared). Adding multi-tenancy would require auth on token creation, which adds a lot of complexity for a beginner project.

**No alert routing rules.** Every token has a single alert channel chosen at creation. No "if envfile then PagerDuty, else Telegram" routing. That kind of routing is something a real ops team builds on top of the webhook receiver, not in the canary itself.

**No replay or backfill.** If the worker pool drops jobs to `NotifyFailed`, there's no built-in retry loop. The data is in the DB; you can write a one-off script to re-process failed events through a fresh notification call. A cron-style retry job is in `04-CHALLENGES.md` as an extension exercise.

**No clustering.** One process, one host. The dedup gate uses Redis which is shareable, so multi-instance is *possible*, but the MySQL TCP listener and the retention loop aren't designed for leader election. If you genuinely need to scale this past one host, you've outgrown the project's intended audience.

The next document, [03 - Implementation](03-IMPLEMENTATION.md), takes the architecture above and points you at the exact code that implements each piece.
