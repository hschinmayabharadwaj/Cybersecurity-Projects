<!-- © AngelaMos | 2026 | 03-IMPLEMENTATION.md -->

# Implementation Walkthrough

This document walks through the actual code that implements the architecture in [02 - Architecture](02-ARCHITECTURE.md). For each major piece I'll cite the file paths, the relevant function/type names, and the design decisions baked into the implementation. The point is not to read every line — it's to know exactly where to look when you want to extend or debug a specific behaviour. Read time is roughly 25-30 minutes.

---

## Wiring (`backend/cmd/canary/main.go`)

This is the file you read first to understand how the pieces connect. `run()` does the following, in order:

1. **Load config.** `config.Load(configPath)` reads `config.yaml`, overlays env vars via koanf, validates with `validator/v10`, returns a `*config.Config`.
2. **Set up logger.** `setupLogger(cfg.Log)` builds a `*slog.Logger` configured for JSON or text output at the configured level, then `slog.SetDefault(logger)` makes it the package-default.
3. **Configure trusted proxies.** `middleware.SetTrustedProxyCIDRs(cfg.Server.TrustedProxyCIDRs)` parses and stores the CIDRs that `RealIP` is allowed to trust.
4. **Initialise telemetry.** `initTelemetry(ctx, cfg, logger)` builds the OpenTelemetry SDK + OTLP gRPC exporter if `OTEL_EXPORTER_OTLP_ENDPOINT` is set; otherwise returns a nop tracer.
5. **Open Postgres.** `core.NewDatabase(ctx, cfg.Database)` creates the connection pool (pgx + sqlx). `core.RunMigrations(db.SQLDB())` runs the goose migrations in `backend/internal/core/migrations/`.
6. **Open Redis.** `core.NewRedis(ctx, cfg.Redis)` returns a `*redis.Client` with health-check ping at startup.
7. **Open GeoIP.** `openGeoIP(cfg, logger)` returns a `geoip.Lookuper` and a closer. If `GEOLITE_PATH` is unset or the MMDB fails to open, it returns `geoip.NopService()` so the event service keeps working with empty geo fields.
8. **Build event + notify stacks.** `buildEventStack` constructs the `notify.Service` worker pool, registers Telegram and webhook senders, and builds the `event.Service` that ties everything together.
9. **Build HTTP deps.** `buildHTTPDeps` constructs the Turnstile verifier, the health handler, the token service (with the generator registry), and the token HTTP handler.
10. **Mount the router.** `mountRouter` builds the `*server.Server` (chi router shell) and registers every route under the right middleware chain.
11. **Spawn the MySQL listener.** `spawnMySQLListener` opens a TCP listener if `cfg.MySQL.FakeEnabled` is true and runs the accept loop in a goroutine.
12. **Spawn the retention loop.** `spawnRetentionLoop` starts the periodic `event.Service.RunRetentionLoop` goroutine if `cfg.Event.RetentionPerToken > 0`.
13. **Serve.** `srv.Start()` runs in a goroutine; the main goroutine waits on the signal context (`signal.NotifyContext(SIGINT, SIGTERM)`).
14. **Graceful shutdown.** When a signal arrives, `srv.Shutdown(ctx, drainDelay)` flips the health endpoint to not-ready, waits `drainDelay` for load balancers to stop sending traffic, then shuts down the HTTP server. The MySQL listener and retention loop bound to the same context exit on their own.

If you only read one file in the codebase, this is the one.

---

## Generator Interface (`backend/internal/token/generators/generator.go`)

Every token type implements this interface:

```go
type Generator interface {
    Type() token.Type
    Generate(ctx context.Context, t *token.Token, baseURL string) (Artifact, error)
    Trigger(ctx context.Context, t *token.Token, r *http.Request) (*event.Event, *TriggerResponse, error)
}

type Artifact struct {
    Kind             ArtifactKind  // KindURL | KindFile | KindText | KindConnectionString
    URL              string
    Filename         string
    Content          []byte
    ContentType      string
    ConnectionString string
}

type TriggerResponse struct {
    StatusCode   int
    ContentType  string
    Body         []byte
    ExtraHeaders map[string]string
}
```

Generators are stateless beyond a few config values baked at construction (e.g. `mysql.Generator` keeps `publicHost`/`publicPort`/`database`). The registry at `backend/internal/token/generators/registry/registry.go` is just a `map[token.Type]Generator` populated at startup.

The same generator handles both creation (`Generate`) and trigger (`Trigger`). That keeps each type's logic in one file. The exceptions are `mysql` (HTTP `Trigger` returns `ErrHTTPTriggerNotSupported`; real triggering happens via TCP) and `slowredirect` (which adds a separate `POST /c/{id}/fingerprint` handler for capturing the fingerprint JSON after the interstitial).

---

## Generators, One By One

### `webbug` (the simplest one)

**File:** `backend/internal/token/generators/webbug/generator.go`

```go
//go:embed asset/pixel.jpg
var pixelBytes []byte
```

`Generate` returns a `KindURL` artifact pointing at `{baseURL}/c/{t.ID}`. `Trigger` returns the embedded JPEG with `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` and `Pragma: no-cache`. The event captures `SourceIP` (via `middleware.RealIP(r)`), `UserAgent`, and `Referer`.

If `t == nil` (unknown token ID), `Trigger` still returns the pixel response but with no event — that's the enumeration-resistance behaviour described in 01-CONCEPTS.md.

This is the template every other HTTP-triggered generator follows.

### `pixel` (the shared helper)

**File:** `backend/internal/token/generators/pixel/pixel.go`

Not a generator; a shared 43-byte transparent GIF that every "visited" response body uses (PDF, DOCX, envfile, slowredirect-after-fingerprint, kubeconfig). The package exposes `ContentType = "image/gif"` and a `Clone()` helper that returns a fresh `[]byte` copy so handlers don't accidentally mutate the shared slice.

Why separate from webbug's JPEG? Two-pixel hygiene: the visible web bug is JPEG because some content-blocking heuristics treat 1x1 GIFs specifically as advertiser pixels; the "you opened a file" response is GIF because it's already an HTTP image response and nobody is going to render it anyway.

### `pdf` (byte-exact substitution)

**File:** `backend/internal/token/generators/pdf/generator.go`

The key constants:

```go
const (
    placeholderRoot   = "HONEY_TRACK_URL_PADDED_TO_FIXED_WIDTH"
    PlaceholderLength = 76
    padChar           = "_"
    queryPadPrefix    = "?p="
)

//go:embed template/template.pdf
var pdfTemplate []byte
```

The template (built by `cmd/buildpdftemplate/main.go` with pdfcpu) has the literal `HONEY_TRACK_URL_PADDED_TO_FIXED_WIDTH___________________________________________________` (76 bytes) baked into a `/AA /O /URI` page-open action.

`Generate` builds `triggerURL`, refuses to proceed if it exceeds 76 bytes, pads it with `?p=____...` to be exactly 76 bytes, and runs `bytes.Replace(pdfTemplate, placeholder, padded, 1)`. Two defensive checks then guard against template corruption:

```go
if len(out) != len(pdfTemplate) {
    return ..., fmt.Errorf("pdf: substitution changed byte length")
}
if !bytes.Contains(out, []byte(triggerURL)) {
    return ..., fmt.Errorf("pdf: substitution did not embed trigger URL")
}
```

Both should be unreachable if the template is correct, but they catch a class of regressions where someone updates the template without re-running `buildpdftemplate`.

`padTriggerURL` is worth flagging because the padding strategy has a corner case: if the URL is exactly 75 bytes (one short of the placeholder length), `?p=` plus zero padding chars is impossible because `?p=` is 3 bytes itself. The function falls back to padding with underscores directly:

```go
case needed >= len(queryPadPrefix):
    return triggerURL + queryPadPrefix +
        strings.Repeat(padChar, needed-len(queryPadPrefix))
default:
    return triggerURL + strings.Repeat(padChar, needed)
```

The plain-underscore tail is technically a malformed URL but PDF readers won't fetch it as a URL anyway — the page-open action invokes the URL via the `/URI` value verbatim, so the underscore-padded one resolves to the same path on our server with garbage trailing chars that we ignore.

### `docx` (ZIP rewrite)

**File:** `backend/internal/token/generators/docx/generator.go`

The whole thing is `patchTemplate(docxTemplate, triggerURL)`. It:

1. Opens the embedded `template.docx` as a `zip.Reader`.
2. Opens a `bytes.Buffer` and a `zip.Writer` writing into it.
3. Iterates every entry in the input ZIP.
4. If the entry name is `word/footer2.xml`, does a single `bytes.Replace(body, "HONEY_TRACK_URL", triggerURL, 1)` on its contents. Otherwise leaves the body alone.
5. Calls `w.CreateHeader(&zip.FileHeader{Name: f.Name, Method: f.Method})` and writes the body.
6. Closes the writer (which finalises the central directory).

The `Method: f.Method` part matters. ZIP entries can be `Store` (no compression) or `Deflate` (DEFLATE-compressed). DOCX uses Deflate for most XML entries. If you accidentally rewrite an entry under a different method, Word can usually open it but loses the streaming-decompress fast-path. Preserving the original method keeps the output byte-shape close to a normal DOCX.

Why no length check like in PDF? DOCX is forgiving — the central directory records sizes per-entry, so changing one entry's length doesn't break offsets in other entries. The `zip.Writer` recomputes the central directory from scratch. Word doesn't care.

### `envfile` (recipes + canary line)

**File:** `backend/internal/token/generators/envfile/generator.go`

`Generate` workflow:

```
keys      = ExtractIncludeKeys(t.Metadata)    // default ["aws", "db"] if absent
trigger   = baseURL + "/c/" + t.ID
sections  = BuildSections(keys, trigger)      // per-recipe blocks + canary block
shuffle   = ShuffleSections(sections)         // crypto/rand Fisher-Yates
body      = RenderSections(sections)          // adds NODE_ENV=production header
```

The canary block is:

```go
sections = append(sections, []recipes.EnvLine{
    {Comment: "Internal monitoring (Datadog-style integration)"},
    {Key: "INTERNAL_METRICS_ENDPOINT", Value: triggerURL},
    {Key: "INTERNAL_METRICS_TOKEN",
     Value: "tok_live_" + recipes.RandomAlnumMixed(32)},
})
```

Note that the comment uses "Datadog-style integration" specifically — the burn-in is the comment that explains *why* this `.env` would contain a `INTERNAL_METRICS_ENDPOINT`, so an attacker reading the file accepts it as a plausible production config detail and tries to ping it.

**Recipes** (`backend/internal/token/generators/envfile/recipes/`):

| File | Produces |
|------|----------|
| `aws.go` | `AWS_ACCESS_KEY_ID=AKIA...` (20 chars), `AWS_SECRET_ACCESS_KEY=` (40 base64-ish chars), `AWS_REGION=us-east-1` etc. |
| `db.go` | `DATABASE_URL=postgresql://...:5432/...`, `REDIS_URL=redis://...`, etc. |
| `github.go` | `GITHUB_TOKEN=ghp_...` (36-char personal access token shape) |
| `stripe.go` | `STRIPE_SECRET_KEY=sk_live_...`, `STRIPE_PUBLISHABLE_KEY=pk_live_...` |

The fake values are deliberately constructed to *look* legitimate (AKIA-prefix for AWS, ghp_-prefix for GitHub, sk_live_-prefix for Stripe) without being valid credentials. An attacker who validates them against the real service gets a 401 from the real provider — which actually helps the deception, because their next move is usually "the creds are stale, let me try the next one in this file" and the next one is our canary.

`shuffleSections` is a crypto/rand-driven Fisher-Yates over the section slice. Using crypto/rand instead of `math/rand` is overkill for this purpose, but it gives an unpredictable section order that doesn't reveal a generator seed if an attacker collected many sample artifacts and pattern-analysed them.

### `kubeconfig` (text/template render)

**File:** `backend/internal/token/generators/kubeconfig/generator.go`, with template at `template.yaml.tmpl`

The template (simplified):

```yaml
apiVersion: v1
kind: Config
clusters:
- name: {{.ClusterName}}
  cluster:
    server: {{.APIServerURL}}
    insecure-skip-tls-verify: true
contexts:
- name: {{.ContextName}}
  context:
    cluster: {{.ClusterName}}
    user: {{.UserName}}
current-context: {{.ContextName}}
users:
- name: {{.UserName}}
  user:
    token: {{.Token}}
```

`Generate` fills in `ClusterName` (default `prod-cluster`, overridable via metadata), `UserName` (default `svc-backup-reader`), `APIServerURL = baseURL + "/k/" + t.ID`, and `Token = t.ID`. The default user name is the burn-in — `svc-backup-reader` sounds like a real service account, not "honeypot-user".

**The wildcard handler** (`handler.go` + `token/handler.go`):

```go
// in token/handler.go RegisterTriggerRoutes:
r.HandleFunc("/k/{tokenID}", h.HandleTrigger)
r.HandleFunc("/k/{tokenID}/*", h.HandleTrigger)
```

kubectl with a kubeconfig pointing at `https://canary.example.com/k/abc123xyz789` won't hit that path directly — it'll hit `https://canary.example.com/k/abc123xyz789/api/v1/namespaces/default/pods` or similar, depending on the command. The `/*` wildcard catches everything kubectl appends. The kubeconfig generator's `Trigger` returns the same pixel response as webbug (just to satisfy the contract — kubectl ignores the response body once it gets a non-2xx).

Actually, look at the response status more carefully: the handler returns 200 OK with a GIF body. kubectl typically expects JSON; it'll fail to parse and emit a connection error. From the attacker's perspective, the kubeconfig "works" enough to suggest the cluster is real but their auth is being rejected — same trick as the MySQL token.

### `mysql` (real wire protocol)

**Files:** `backend/internal/token/generators/mysql/protocol.go`, `server.go`, `handler.go`, `generator.go`

The four files split cleanly:

- `protocol.go` — pure functions: `BuildHandshakeV10`, `ReadClientAuth`, `BuildAccessDeniedErr`, `wrapPacket`, `readPacket`. No I/O dependencies; everything takes `io.Reader`/`io.Writer` or `[]byte`. This is testable in isolation and the test file (`protocol_test.go`) does exactly that — round-trips packets and checks every field.
- `server.go` — `Server.Run(ctx)` is the accept loop. It dials `net.Listen("tcp", addr)`, then loops `listener.Accept()` and spawns `go handler.HandleConnection(ctx, conn)` per connection. Shutdown is via `listener.Close()` from the parent goroutine.
- `handler.go` — `Handler.HandleConnection(ctx, conn)` is the per-connection logic.
- `generator.go` — `Generate` produces the connection string artifact. `Trigger` returns `ErrHTTPTriggerNotSupported` because MySQL doesn't go through the HTTP trigger path.

**The handshake sequence** in `handler.go`:

```go
func (h *Handler) HandleConnection(ctx context.Context, conn net.Conn) {
    defer conn.Close()
    conn.SetDeadline(time.Now().Add(10 * time.Second))

    h.writeHandshake(conn)                  // send HandshakeV10
    auth, _ := ReadClientAuth(conn)         // read client auth response

    if !strings.HasPrefix(auth.Username, "canary_") {
        return                              // not our token, just drop
    }
    tokenID := strings.TrimPrefix(auth.Username, "canary_")

    tok, _ := h.tokens.GetByID(ctx, tokenID)
    if tok == nil {
        return                              // unknown token, just drop
    }

    sourceHost := remoteHost(conn)
    h.recordEvent(ctx, tok, sourceHost, auth)
    h.writeAccessDenied(conn, auth.Username, sourceHost)
}
```

Notice the `canary_` prefix gate. Any client that doesn't send a `canary_*` username gets dropped silently — no handshake response, no error. That keeps generic MySQL scanners from extracting our `5.7.40-canary` server version banner via casual probing.

The `extra` JSONB stored on the event records the client's reported capabilities (e.g. `0x81bea285` for a typical `mysql` CLI) and charset (`0x21` for utf8mb4). Different attackers' tools have different capability fingerprints — a `mysql-cli` connection from a Linux host looks different from a Python `mysql-connector` connection looks different from a Go `database/sql` connection. The capability fingerprint is forensic gold.

**The error packet** in `protocol.go`:

```go
func BuildAccessDeniedErr(username, sourceHost string) ([]byte, error) {
    msg := fmt.Sprintf(
        `Access denied for user '%s'@'%s' (using password: YES)`,
        username, sourceHost,
    )
    var payload bytes.Buffer
    payload.WriteByte(0xff)                           // ERR packet marker
    binary.LittleEndian.PutUint16(buf[:], 1045)       // MySQL error 1045
    payload.Write(buf[:])
    payload.WriteByte('#')                            // SQL state marker
    payload.WriteString("28000")                      // SQL state for auth fail
    payload.WriteString(msg)
    return wrapPacket(payload.Bytes(), seqIDServerErr)
}
```

Error code 1045 with SQL state 28000 is the standard MySQL auth-failure code. The message format is verbatim what a real MySQL server emits. If you ran a real MySQL and connected with a wrong password, you'd see the same text byte-for-byte.

### `slowredirect` (HTML interstitial + fingerprint)

**Files:** `backend/internal/token/generators/slowredirect/generator.go`, `fingerprint_handler.go`

**`Generate`** builds a `KindURL` artifact pointing at `/c/{tokenID}` (same as webbug). The interesting part is `Trigger`.

**`Trigger`** renders an HTML template (not embedded as a `[]byte` — embedded as `text/template.Template` parsed at startup) with:

```
{
  "FingerprintURL": "/c/{tokenID}/fingerprint",
  "Destination":    "<operator-supplied destination URL>"
}
```

The template includes inline JS that:

1. Collects browser fingerprint signals (canvas, WebGL, fonts, timezone, etc.) using a small fingerprinting helper.
2. POSTs the JSON blob to `{FingerprintURL}`.
3. Waits a few seconds (template constant) so the fingerprint POST has time to complete.
4. Runs `window.location.replace(Destination)`.

The CSP header is set explicitly:

```
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'
```

This locks the page down so that even if the destination is an attacker-controlled URL passed through the operator's `metadata.destination_url`, the interstitial cannot be coerced into loading external scripts or making cross-origin XHRs.

**`fingerprint_handler.go`** is the POST handler:

```go
func (g *Generator) HandleFingerprint(w http.ResponseWriter, r *http.Request) {
    tokenID := chi.URLParam(r, urlParamTokenID)

    body, _ := io.ReadAll(io.LimitReader(r.Body, maxFingerprintBytes))

    // Sanity-check that it's valid JSON; we don't parse the structure.
    var dummy json.RawMessage
    if err := json.Unmarshal(body, &dummy); err != nil {
        w.WriteHeader(http.StatusNoContent)
        return
    }

    g.fingerprintRecorder.AttachFingerprint(
        r.Context(), tokenID, middleware.RealIP(r), body,
    )
    w.WriteHeader(http.StatusNoContent)
}
```

The fingerprint always returns 204 No Content — even on error. That's deliberate: if the attacker's network panel shows the fingerprint POST returning 400 or 500, they might notice. 204 with empty body is the most boring response possible.

`AttachFingerprint` writes the JSON blob to the *same event row* that the original trigger created, by updating `events.extra` for the most recent event matching `(token_id, source_ip)` within a short time window. That's why the manage page can show a fingerprint column alongside the trigger event: it's the same row.

**Enumeration resistance for slowredirect:** if the token ID is unknown, the response still renders a slowredirect HTML page — but with `Destination = "/"`. The attacker sees a redirect-to-root, which is indistinguishable from a token whose operator chose `/` as the destination. They can't tell the token is fake without seeing our alert side.

---

## The Trigger Handler (`backend/internal/token/handler.go`)

`HandleTrigger` is the function called for every `GET /c/{id}` and `* /k/{id}`. The shape:

```go
func (h *Handler) HandleTrigger(w http.ResponseWriter, r *http.Request) {
    id := strings.TrimRight(chi.URLParam(r, urlParamTokenID), "_")
    if id == "" {
        http.NotFound(w, r)
        return
    }

    tok, _ := h.svc.GetByID(r.Context(), id)
    if tok != nil && !tok.Enabled {
        tok = nil   // treat disabled tokens like unknown ones
    }

    gen, ok := h.resolveGenerator(tok, r)   // picks generator by path (/c/ vs /k/)
    if !ok {
        http.NotFound(w, r)
        return
    }

    evt, resp, _ := gen.Trigger(r.Context(), tok, r)
    if resp == nil {
        http.NotFound(w, r)
        return
    }

    if tok != nil && evt != nil {
        h.events.Record(r.Context(), tok, evt)
    }

    h.writeTriggerResponse(w, r, resp)
}
```

Several things to note:

**Trailing underscore trim.** `strings.TrimRight(id, "_")` handles the PDF padded URL — recall that PDF tokens have `?p=____` padding appended. Most readers strip the query string but some malformed readers send the underscores as part of the path. Trimming `_` is a tolerance for that.

**Disabled tokens look unknown.** When the operator soft-disables a token (`DELETE /api/m/{manageId}`), the row stays in the DB but `enabled=false`. The trigger handler sets `tok = nil` for disabled tokens, which causes `resolveGenerator` to pick the default (webbug) and produces a pixel response with no event recorded — exactly the same behaviour as for a completely unknown token. From the attacker's perspective, there's no way to tell if a token was never minted or was minted-then-disabled.

**`resolveGenerator` picks by path prefix.** If `r.URL.Path` starts with `/k/`, the kubeconfig generator handles it. Otherwise the generator is looked up by `tok.Type`. This is how the wildcard `/k/.../*` route plumbs through to the kubeconfig generator without an explicit type lookup.

**Event recording is synchronous.** As covered in the architecture doc, `h.events.Record` runs *before* `writeTriggerResponse`. The trade-off is bounded by Postgres insert latency (typically sub-10ms).

---

## Event Service (`backend/internal/event/service.go`)

`Service.Record` is the choreographer. The flow:

```go
func (s *Service) Record(ctx context.Context, info NotifyInfo, evt *Event) error {
    s.enrichGeo(evt)                              // attach GeoIP if available
    s.repo.Insert(ctx, evt)                       // assigns evt.ID
    s.tokens.IncrementTriggerCount(ctx, info.TokenID)
    first := s.dedupGate(ctx, info.TokenID, evt.SourceIP)
    if !first {
        s.repo.UpdateNotifyStatus(ctx, evt.ID, NotifyDeduped, nil)
        return nil
    }
    if s.notifier != nil {
        s.notifier.Notify(info, evt)              // enqueue, returns immediately
    }
    return nil
}
```

A subtle correctness property: the event row is inserted *before* the dedup gate check. That means even duplicate-suppressed events are persisted (with `notify_status = deduped`). The manage page can show "3 silenced triggers from 1.2.3.4" because the rows exist; it's just that no alerts fired for them.

The `dedupGate` function uses Redis `SETNX` for atomic first-acquire semantics:

```go
key := DedupKey(tokenID, sourceIP)           // "dedup:trigger:abc:1.2.3.4"
set, _ := s.rdb.SetNX(ctx, key, 1, 15*time.Minute).Result()
if set { return true }                       // first hit
s.rdb.Incr(ctx, key)
s.rdb.SAdd(ctx, "dedup:active:"+tokenID, sourceIP)
s.rdb.Expire(ctx, "dedup:active:"+tokenID, 15*time.Minute)
return false                                 // duplicate
```

The second Redis operation (`Incr` + `SAdd` + `Expire`) only runs on duplicates. The active-tracking set lets `CountActiveDedup` return a meaningful "N duplicate triggers silenced" badge to the manage page via `SCARD`.

The retention loop runs in its own goroutine (`RunRetentionLoop`) on a ticker. On each tick it calls `repo.PruneToLimit(perTokenLimit)` which deletes oldest events past the limit for each token. That bounds Postgres storage for high-volume tokens.

---

## Notification Service (`backend/internal/notify/service.go`)

The structure:

```go
type Service struct {
    senders     map[string]Sender   // "telegram" → telegramSender, "webhook" → webhookSender
    status      StatusWriter        // writes back to event.notify_status
    sendTimeout time.Duration       // 30s default
    workers     int                 // 8 default
    queue       chan dispatchJob    // 256 buffered
    workerWg    sync.WaitGroup      // tracks running workers
    jobWg       sync.WaitGroup      // tracks in-flight + queued jobs
}
```

`Notify` is non-blocking:

```go
func (s *Service) Notify(info event.NotifyInfo, evt *event.Event) {
    s.jobWg.Add(1)
    select {
    case s.queue <- dispatchJob{info, evt}:
        // queued
    default:
        s.jobWg.Done()
        s.markStatus(ctx, evt.ID, NotifyFailed, nil)
    }
}
```

The non-blocking send is the load-shedding mechanism. If the queue is full (suggesting all 8 workers are stuck on slow senders), we drop the job and mark it failed rather than block the trigger handler.

Each worker is a simple consumer:

```go
func (s *Service) worker() {
    defer s.workerWg.Done()
    for job := range s.queue {
        s.dispatch(job.info, job.evt)
        s.jobWg.Done()
    }
}

func (s *Service) dispatch(info, evt) {
    ctx, cancel := context.WithTimeout(bg, 30*time.Second)
    defer cancel()
    sender, ok := s.senders[info.AlertChannel]
    if !ok { mark failed; return }
    if err := sender.Send(ctx, info, evt); err != nil { mark failed; return }
    mark sent, time.Now().UTC()
}
```

The `closeOnce.Do(func() { close(s.queue) })` pattern in `Shutdown` ensures the queue is closed exactly once even if shutdown is called twice. After `close(queue)`, workers drain remaining jobs and exit when the channel reads return zero values.

`Wait()` is provided for test code to flush all pending notifications before assertions, via `jobWg.Wait()`.

### Webhook Sender (`backend/internal/notify/webhook/sender.go`)

POSTs a JSON body with `token_id`, `event_id`, `triggered_at`, `source_ip`, `user_agent`, GeoIP fields, and `extra`. If `WEBHOOK_HMAC_SECRET` is set in env, the body is signed with HMAC-SHA256 and the signature goes into `X-Canary-Signature: sha256={hex}`. Retries are via `cenkalti/backoff/v5` — exponential backoff with jitter, max 3 attempts within the 30-second timeout window, only retrying on transient errors (5xx, network errors, but not 4xx).

### Telegram Sender (`backend/internal/notify/telegram/sender.go`)

POSTs to `https://api.telegram.org/bot{TelegramBot}/sendMessage` with `chat_id={TelegramChat}` and a Markdown-formatted message. Retries are limited because Telegram returns proper status codes — a 403 means the bot doesn't have access to the chat, no amount of retries will help.

---

## Middleware (`backend/internal/middleware/`)

Each file is small and single-purpose:

| File | What It Does |
|------|--------------|
| `request_id.go` | Generates a UUID per request, attaches to context, exposes via `RequestID(ctx)` |
| `logging.go` | slog request_start / request_end with method, path, status, duration |
| `recovery.go` | `defer recover()` panic catcher; logs stack + returns 500 |
| `headers.go` | CSP, HSTS (prod only), X-Frame-Options, Referrer-Policy, X-Content-Type-Options; CORS middleware reads `cfg.CORS` |
| `realip.go` | Parses `X-Forwarded-For` and `X-Real-IP` only if the immediate peer is in `TRUSTED_PROXY_CIDRS` |
| `fingerprint.go` | `ExtractFingerprint(r) = sha256(RealIP(r) + r.UserAgent())[:16]` hex |
| `ratelimit.go` | Token bucket via Redis (`go-redis/redis_rate`) keyed by a `KeyFunc`; fail-open if Redis is down |
| `turnstile.go` | Reads response token from header `CF-Turnstile-Response` or JSON body field; calls `Verifier.Verify` |
| `operator_bearer.go` | Constant-time compare against `OPERATOR_TOKEN`; returns 404 on miss (not 401, to avoid revealing the endpoint exists) |

A few patterns worth absorbing:

**`OptionalHeader`** in `realip.go` (or wherever) returns `*string` — `nil` if empty, pointer to the value otherwise. This is for nullable DB columns (`user_agent`, `referer`) where an empty string is semantically different from "header was absent".

**Bearer middleware returns 404, not 401.** This is a small but deliberate choice. A 401 confirms the endpoint exists and just rejects your credentials. A 404 makes the endpoint look like it doesn't exist at all. An attacker scanning your service for admin endpoints can't distinguish "no admin endpoint here" from "I don't have the bearer". The cost is that legitimate operator typos look like 404s in logs — but operators don't make many typos on the admin endpoint URL.

**Rate limit fail-open.** If Redis is unreachable, the rate limiter logs a warning and lets the request through. The alternative (fail-closed) would mean a Redis outage immediately produces a service outage. For a canary service the trade-off is the right way around: a Redis outage shouldn't suppress real attacker activity.

---

## Frontend (`frontend/src/`)

The shape is two routes:

```
/                  pages/landing/index.tsx
/m/:manageId       pages/manage/index.tsx
```

**State management:** TanStack Query for *everything* server-touching. Each hook in `api/hooks/` validates with Zod:

```typescript
// frontend/src/api/hooks/useManageToken.ts
export function useManageToken(manageId: string, cursor?: number) {
  return useQuery({
    queryKey: ['manage', manageId, cursor],
    queryFn: async () => {
      const res = await api.get(`/m/${manageId}`, { params: { cursor } });
      return ManageResponseSchema.parse(res.data);
    },
    refetchInterval: 5_000,            // poll every 5s for new events
  });
}
```

The Zod schema is the source of truth for the response shape. If the backend drifts, Zod throws on parse and the component error-boundary catches it — much better than silent type mismatches.

**Form state on the landing page** is plain `useState` per field. There's no `react-hook-form` or formal validation library; the input controls are typed (`<input type="url">`) and the backend re-validates on submit anyway. Beginner-readable.

**The artifact reveal** after `useCreateToken` mutates is conditional rendering on the artifact `kind`:

- `kind: "url"` → render `<CopyField>` with the URL
- `kind: "file"` → render a base64 → Blob download link
- `kind: "text"` → render an `<textarea readonly>` with the content plus a download button
- `kind: "connection_string"` → render `<CopyField>` with the connection string

**The manage page** is a single TanStack Query reading the paginated event feed. Pagination is cursor-based — the response includes `page.next_cursor` and `page.has_more`, and the "load more" button calls the same query with a higher cursor. Each event row renders source IP, GeoIP (country flag + city), user agent, timestamp, and `notify_status` as a coloured badge.

---

## Tests

The test stack is opinionated:

- **`stretchr/testify`** for assertions.
- **`miniredis/v2`** for in-memory Redis. Every test that touches Redis spins up a fresh miniredis on a random port — no shared state across tests.
- **`testcontainers-go` + `modules/postgres`** for Postgres integration tests. Tests that need a real Postgres get a real Postgres in Docker, migrated fresh per test package.
- **`testdata/` directories** alongside production code for fixture files (e.g. `backend/internal/token/generators/pdf/testdata/sample.pdf`).

Each generator package has both a unit test (`generator_test.go`) that exercises the pure logic against fixtures and an integration test where applicable. The MySQL package has the most thorough protocol tests — `protocol_test.go` builds packets from spec values and reads them back, asserting on every byte.

The `server` package has an `e2e_test.go` that spins up a real HTTP server with the full middleware chain and exercises the whole CRUD-and-trigger flow. That's the test you run to catch routing/middleware integration bugs.

---

## Where to Look First When Debugging

A short cheat-sheet:

| Symptom | First file |
|---------|------------|
| Token creation 400s with a strange message | `backend/internal/token/dto.go` (validator tags) |
| Token created but trigger 404s | `backend/internal/token/handler.go::HandleTrigger`, `resolveGenerator` |
| Trigger fires but no event in DB | `backend/internal/event/service.go::Record`, then `repository.go::Insert` |
| Event in DB but `notify_status = pending` forever | Worker pool is stuck. Check logs for `notify: send failed`. |
| Event in DB but `notify_status = failed` | Look at sender logs. Webhook URL bad? Telegram chat ID wrong? |
| Trigger response is the wrong content type | Generator's `Trigger` function — every type sets `ContentType` differently. |
| Manage page shows 0 events but they're in the DB | Cursor pagination bug. Check `parseCursor` in the handler and the `WHERE id < cursor` in `event/repository.go::ListByToken`. |
| `RealIP` middleware returns the proxy IP | `TRUSTED_PROXY_CIDRS` env var isn't set or is wrong. |
| PDF token won't open in Acrobat | Did the template change without re-running `cmd/buildpdftemplate`? Check `Generate`'s byte-length and contains-URL assertions. |
| DOCX opens but doesn't fire | Check the footer XML actually contains the placeholder. Different Word templates use different footer paths. |
| MySQL listener won't bind | Port collision. `MYSQL_FAKE_ADDR` is what the listener binds to. |

The next document, [04 - Challenges](04-CHALLENGES.md), proposes extensions you can build on top of this codebase.
