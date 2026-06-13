<!-- © AngelaMos | 2026 | 01-CONCEPTS.md -->

# Honeytoken Concepts

This document covers the security theory behind canary tokens — what they are, why they work, how they fit into the broader deception-defense playbook, and how each of the seven token types in this project maps to attacker behaviour we see in real incident reports. Read time is roughly 20-25 minutes.

---

## Deception-Based Defense

### The Core Idea

The standard mental model for defense is a perimeter: walls, gates, guards. Stop the attacker at the edge. The problem is that real adversaries get past the edge routinely. Phishing works. Vulnerable web apps get pwned. Insiders go rogue. By the time a sophisticated attacker is in your network, the perimeter is no longer the question — the question is how long they get to wander around before someone notices.

The industry numbers on that question are bad. The 2024 IBM "Cost of a Data Breach" report puts the global mean time to identify a breach at 194 days. The 2024 Verizon DBIR shows that for breaches involving stolen credentials — the most common pattern — the median time from compromise to detection is measured in months. The 2024 Mandiant M-Trends report puts the global median dwell time at 10 days, which is the first time it's dropped below two weeks, and even that improvement is mostly attributed to ransomware actors who detonate quickly enough to be loud. For stealthy financially-motivated and state-sponsored intrusions, dwell times of 6-12 months are still routine.

That gap is what deception is designed to close. The pitch is straightforward: plant artifacts that no legitimate user has any reason to touch, then watch them. If anyone touches one, you have a high-confidence signal that someone is in your environment who shouldn't be, and you have it independent of whether your EDR, SIEM, or NIDS produced anything.

The first formal articulation of this idea in modern security is usually credited to Clifford Stoll's 1989 book *The Cuckoo's Egg*, where he tracked a KGB-affiliated attacker through Lawrence Berkeley National Lab by leaving fake military documents on accessible systems and waiting for the attacker to read them. The contemporary commercial version is Thinkst Canary, which Haroon Meer started shipping in 2015 and which has had a noticeably outsized impact on how mature security programs think about detection.

### Honeypots vs Honeytokens

These get conflated a lot. They're related but operationally distinct.

A **honeypot** is a fake system — a fake SSH server, a fake industrial control device, a fake database. You stand it up somewhere, attackers find it, you watch what they do. The point is usually intelligence: understanding what the attacker tries, what tools they use, what credentials they have. Cowrie, T-Pot, and Conpot are well-known open-source honeypots.

A **honeytoken** is a fake artifact — a fake credential, a fake document, a fake URL. It lives inside your real environment. The point is usually detection: nobody has any reason to touch it, so the moment somebody does, you know they shouldn't be there.

The two complement each other. Honeypots tell you who's at your perimeter. Honeytokens tell you who's already inside. The tradeoff is mostly operational complexity — a honeypot is a system you have to maintain, monitor, and isolate from the rest of your network. A honeytoken is a file. You drop it where it belongs and forget about it until it fires.

This project builds honeytokens.

### Why Honeytokens Have Near-Zero False Positives

This is the killer feature. A typical EDR alert has a non-trivial false positive rate — legitimate admin behaviour looks weird, IT tools trigger heuristics, edge cases happen. SOC analysts spend a lot of their time chasing alerts that turn out to be benign, which creates alert fatigue, which is one of the ways real breaches go unnoticed.

Canary tokens are designed so that the false-positive rate is structurally close to zero. The token is something nobody has any reason to touch. The `payroll-q3.pdf` on the file share is a file that exists only as bait — no employee was told about it, no automated process indexes it, no backup job opens it. So when the page-open action fires from a workstation in Belarus at 2am, you don't argue with the alert. You wake up the on-call.

The qualifier "structurally close to zero" matters because the rate isn't actually zero. You get false positives when:

- An automated DLP or backup tool *does* open the file (DLP tools that "render" document previews are the classic offender). The fix is to exclude your tooling explicitly or to plant tokens where those tools won't reach.
- A search-engine crawler hits a URL token that leaked into a public page. The fix is to either tag the page `noindex` or accept the crawler as a benign trigger you've categorized.
- A staff member stumbles across the bait file out of curiosity. This is rare and is itself useful signal — it tells you a human is browsing places they don't belong.

The dedup gate in this project (15-minute Redis silence per `{token, source_ip}`) is partly a defense against the first two cases. If a crawler hits a URL token, you get one alert, not 200.

### MITRE Engage

MITRE Engage is the defensive companion to ATT&CK. ATT&CK is a taxonomy of what attackers do; Engage is a taxonomy of what defenders can do to deceive, deny, disrupt, and direct adversaries. It launched in 2021 (replacing the older Shield project) and lives at [https://engage.mitre.org/](https://engage.mitre.org/).

The relevant Engage activities for this project:

| Activity ID | Name | What It Means |
|-------------|------|---------------|
| EAC0002 | Detect | Get visibility into adversary activity through deception |
| EAC0003 | Direct | Steer the adversary toward a deception artifact you control |
| SAC0011 | Lures | Use artifacts to lure adversaries toward deceptive content |
| SAC0007 | Burn-In | Make deception artifacts look authentic enough to attract interest |

Every token type in this project maps to **SAC0011 Lures**. The `slowredirect` token additionally implements **EAC0003 Direct** by sending the attacker to a controlled destination after the fingerprint capture. Burn-in (SAC0007) — making the artifact look real — is the part of the work that's *not* in the code; it's in how you name your `.env` file, what you put in the memo of your kubeconfig, and how convincingly you place the `customer-list.docx` on the share.

---

## Honeytoken Mechanics

Each token type relies on a specific behaviour of a specific format or protocol. Understanding the mechanism makes it clear *why* the token works and which adversaries it catches.

### 1. Web Bug (HTTP-fetched pixel)

**File:** `backend/internal/token/generators/webbug/generator.go`

**Mechanism:** Any HTTP client that fetches the URL fires the token. The artifact is a URL pointing at a 1x1 JPEG. The response includes `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` and `Pragma: no-cache` so that proxies and the browser cache don't suppress a second fetch.

**Why JPEG instead of the classic 1x1 GIF:** JPEGs are slightly larger and triggered some older anti-tracking heuristics less often during testing. The internal pixel helper in `backend/internal/token/generators/pixel/pixel.go` does provide a GIF, which is used by other generators that just need a non-empty "you visited" body (PDF, DOCX, envfile, slowredirect after fingerprint POST).

**Who you catch:** Anyone who renders an HTML email that contains the URL, anyone who follows a link from a Slack/Teams preview-bot, anyone running a vulnerability scanner that follows URLs. The technique is exactly the same as marketing email pixel-trackers — both sides of the deception/surveillance fence use it.

**Real-world parallel:** In 2016, Mossack Fonseca (the Panama Papers law firm) was breached, and one of the post-mortem recommendations from multiple sources was deploying tracker pixels on internal documents so that exfiltrated copies would phone home when the attackers opened them. Web bugs in the Thinkst Canary product fire this signal routinely in customer environments.

### 2. Slow Redirect (HTML interstitial with fingerprint capture)

**Files:** `backend/internal/token/generators/slowredirect/generator.go` and `fingerprint_handler.go`

**Mechanism:** The artifact is a URL the attacker clicks expecting a normal redirect. The server returns an HTML page (`template.html`) instead. That page runs a fingerprinting script that POSTs back to `/c/{tokenID}/fingerprint` with a JSON payload (canvas hash, WebGL renderer, font list, time-zone offset, CPU cores, etc.). After a 3-5 second delay the page redirects to the operator-specified destination so the attacker doesn't realise anything weird happened.

**Why a delay:** Two reasons. First, the JS needs time to run — fingerprinting is synchronous-ish and finishes in milliseconds, but networks aren't always fast. Second, an instantaneous redirect would feel suspicious; users expect link-shorteners and URL-cleaners to take a beat.

**Why CSP:** The response sets `Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'` so the inline fingerprinting JS can run but the attacker's browser can't be coerced into loading external resources from our trigger page. Even though *we* control the HTML, treating it like an XSS sink is hygiene that matters when the page is technically attacker-influenced.

**Who you catch:** Anyone who clicks a phishing-bait link in a planted document, in a fake admin panel URL, in a "leaked" Slack message. The fingerprint is the differentiator — for the other URL-based token types you only get IP and User-Agent, both trivially spoofable. Canvas hashes, WebGL renderer strings, and font lists are much harder to spoof reliably and let you correlate the same attacker across multiple fires.

**Real-world parallel:** Browser fingerprinting is the technique advertising networks use to track users across sites without cookies. Same primitive, pointed at adversaries. Mozilla's research at [https://wiki.mozilla.org/Security/Fingerprinting](https://wiki.mozilla.org/Security/Fingerprinting) catalogues the surface in detail.

### 3. PDF (page-open URI action)

**File:** `backend/internal/token/generators/pdf/generator.go`, with embedded template at `template/template.pdf`

**Mechanism:** The PDF spec allows a page to declare an "Additional Action" (`/AA`) dictionary. The `/O` key inside that dictionary specifies an action to take when the page is opened. One legal action type is `/URI`, which causes the PDF reader to fetch a URL. When Acrobat opens the document, it follows the URI; that fires our trigger.

**Why a byte-exact substitution:** A PDF is fundamentally a stream of objects with byte-offset cross-references. If you rewrite a string and accidentally change the file length, every offset in the xref table is wrong and most readers will refuse to open the file. The trick: bake a fixed-width placeholder (`HONEY_TRACK_URL_PADDED_TO_FIXED_WIDTH`, 76 bytes) into the template, then replace it with a URL padded with `?p=____...` until it's exactly 76 bytes. Same length, same offsets, file still valid.

**Why 76 bytes:** Long enough to hold `https://canary.example.com/c/abc123xyz789` plus some headroom for longer hostnames. If the operator's `PUBLIC_BASE_URL` makes the URL exceed 76 characters, the generator returns `ErrTriggerURLTooLong` rather than corrupt the file.

**Caveat:** Chrome and Firefox's built-in PDF viewers (PDFium and PDF.js) deliberately strip Action objects. So this token type only fires when the attacker opens the document in Acrobat, Foxit, Preview, or any other "real" PDF reader. In practice that's most of the relevant cases — attackers exfiltrating documents typically look at them on a workstation with Acrobat or Preview, not in their browser.

**Real-world parallel:** Page-open URI actions are also the mechanism behind a class of PDF malware delivery, which is why some EDR products treat them as suspicious. We're using the same primitive defensively.

### 4. DOCX (footer with remote URI)

**File:** `backend/internal/token/generators/docx/generator.go`

**Mechanism:** A `.docx` file is a ZIP archive with a defined directory structure. The footer (typically `word/footer2.xml`) is an XML fragment that Word renders at the bottom of every page. We bake a placeholder URL into the footer and rewrite the ZIP archive entry with the real URL when the token is minted. When Word, LibreOffice, or Pages opens the document, it loads the footer, sees the URL, and fetches it.

**Why footer2.xml specifically:** Word's relationship files (`.rels`) decide which footer XML the document uses. Different templates use different paths (`footer1.xml`, `footer2.xml`, `footer3.xml`). Our `buildocxtemplate` build tool is responsible for picking the right one for the template we ship; the runtime generator just preserves whichever filename the template uses.

**Why ZIP-aware rewrite:** You cannot just `sed -i` a `.docx` file — the ZIP central directory records the size of each entry, and if you change the entry size without rewriting the central directory the file becomes corrupt. The generator opens the template as a `zip.Reader`, streams each entry to a `zip.Writer`, applies the URL substitution only to the footer entry, and lets the writer rebuild the central directory.

**Who you catch:** Anyone opening the stolen document in Word, LibreOffice, or Pages. Cloud-based viewers (Google Docs, Office Online) sometimes don't fire the request, which is a known limitation.

**Real-world parallel:** Office documents with remote-resource references have been a malware delivery vector for years (Follina / CVE-2022-30190 is the most famous recent example, though that one used MSDT not a footer URI). Same mechanism, pointed defensively.

### 5. Envfile (fake `.env` with embedded canary)

**Files:** `backend/internal/token/generators/envfile/generator.go` and `recipes/{aws,db,github,stripe}.go`

**Mechanism:** The artifact is a plain-text `.env` file containing a mix of fake credentials. The generator picks 2-4 recipes (each producing a realistic block of fake `AWS_ACCESS_KEY_ID=...`, database URL, GitHub token, or Stripe key), shuffles the sections in random order, and then appends a single canary line:

```
INTERNAL_METRICS_ENDPOINT=https://your-canary-host/c/{tokenID}
INTERNAL_METRICS_TOKEN=tok_live_{32-char-random}
```

The first time the attacker tries to use the `INTERNAL_METRICS_ENDPOINT` — typically by curling it as part of recon, or by running the application that consumed the `.env` and hit the endpoint as part of startup — the token fires.

**Why fake credentials matter:** Burn-in. An `.env` that's just `INTERNAL_METRICS_ENDPOINT=...` and nothing else screams honeypot. An `.env` with five sections of plausible AWS/DB/GitHub/Stripe credentials and *one* canary line buried in the middle looks like an unsanitised production config file the developer forgot to gitignore. The recipes are deliberately constructed to match real credential formats (AWS keys start with `AKIA`, Stripe live keys start with `sk_live_`, GitHub PATs start with `ghp_`, etc.).

**Real-world parallel:** Honey credentials in `.env` files are one of the highest-ROI deception placements in modern environments. The reason is that scraping `.env` files is one of the first things automated cloud-credential-stealer malware does (the [TeamTNT campaign](https://www.trendmicro.com/en_us/research/22/g/teamtnt-targeting-aws-alibaba.html) and various successors are well-documented examples). If you plant a single honey `.env` on a developer laptop or CI runner, you catch credential-stealer malware almost immediately on infection.

### 6. Kubeconfig (fake cluster credential)

**Files:** `backend/internal/token/generators/kubeconfig/generator.go`, `handler.go`, template at `template.yaml.tmpl`

**Mechanism:** The artifact is a Kubernetes `kubeconfig` YAML file pointing at our server's `/k/{tokenID}` path. The bearer token in the file is `{tokenID}` itself. When the attacker copies the file to their machine and runs `kubectl --kubeconfig=stolen.yaml get pods`, kubectl tries to authenticate against our server. Our wildcard `/k/{tokenID}/*` route catches the request — including the API path kubectl appends — and fires the trigger.

**Why a wildcard route:** kubectl doesn't just hit `/k/{tokenID}` — it hits `/k/{tokenID}/api/v1/namespaces/default/pods` or similar, depending on the command. The handler in `backend/internal/token/handler.go` registers `r.HandleFunc("/k/{tokenID}", ...)` and `r.HandleFunc("/k/{tokenID}/*", ...)` so kubectl's appended path doesn't bypass the trigger.

**Who you catch:** Anyone running `kubectl` against the stolen config. This is gold for catching post-exploitation lateral-movement attempts in cloud-native environments, where compromised CI runners and developer laptops typically have a `~/.kube/config` with cluster admin or near-admin permissions.

**Real-world parallel:** The [TeamTNT k8s-targeted campaigns](https://www.aquasec.com/blog/teamtnt-attacks-against-kubernetes-clusters/) actively scrape kubeconfig files from compromised hosts. A honey kubeconfig is one of the highest-precision detection signals available for cloud-native shops.

### 7. MySQL (real wire-protocol decoy)

**Files:** `backend/internal/token/generators/mysql/protocol.go`, `server.go`, `handler.go`, `generator.go`

**Mechanism:** This is the most ambitious token. The artifact is a connection string like `mysql://canary_abc123xyz789@db.your-host.com:3306/internal_db`. The username prefix `canary_` (defined in `backend/internal/token/generators/mysql/handler.go` as `mysqlUsernamePrefix`) is how the listener recognises one of our tokens — anything else gets silently dropped. When the attacker uses the `mysql` CLI or a programmatic MySQL client to connect, they hit a TCP listener on our server. Our listener speaks the **real** MySQL v10 wire protocol — sends a `HandshakeV10` packet with server version `5.7.40-canary`, reads the client's auth response, extracts the username, strips the prefix to recover the token ID, and replies with a properly-formatted `ERR_PACKET` carrying SQL state `28000` and the standard MySQL error message:

```
Access denied for user 'canary_abc123xyz789'@'attacker-ip' (using password: YES)
```

From the attacker's terminal, this looks exactly like a real MySQL server rejecting their password. They'll probably try a few more times with different passwords, then give up. Each attempt records an event.

**Why a real wire protocol:** Two reasons. First, it catches programmatic clients, not just CLI tools — a leaked connection string is more likely to be tried by an exfil tool's automated credential validator than by a human typing into a terminal, and those tools expect a real protocol. Second, the error message is the giveaway: a TCP listener that just closes the connection or returns garbage would tell the attacker immediately that something is off, and they might pivot to investigating. A real `Access denied` makes them assume the password is just wrong.

**The packet layout** (from `protocol.go`):

```
Packet:
  [3 bytes payload length LE] [1 byte sequence id] [payload]

HandshakeV10 payload:
  protocol version (0x0a) | server version "5.7.40-canary\0" |
  connection id (4 bytes LE) | auth-plugin-data part 1 (8 bytes) | filler 0x00 |
  capability flags lower (2 bytes LE = 0xf7ff) | charset (0x21 utf8mb4) |
  status flags (2 bytes LE = 0x0002) | capability flags upper (2 bytes LE = 0x81ff) |
  auth-plugin-data length (0x15) | reserved (10 bytes) |
  auth-plugin-data part 2 (12 bytes) | filler 0x00 |
  plugin name "mysql_native_password\0"

ERR packet payload:
  0xff | error code 1045 (LE) | '#' | sql state "28000" |
  "Access denied for user '<user>'@'<host>' (using password: YES)"
```

**Real-world parallel:** Connection strings in stolen `.env` files are the bread and butter of post-exploitation credential validation. An automated tool that finds `DATABASE_URL=mysql://...` and tries to connect to it is a routine part of modern attack pipelines. This token type catches that behaviour with high fidelity because it pretends to be exactly the system the attacker is testing for.

---

## Operational Considerations

### Burn-In (Making the Lure Believable)

A canary token only works if the attacker actually touches it. The technical mechanism is the easy part; the social engineering is the hard part. Every deployment decision should ask: "would a real attacker, mid-pivot, find this and decide it's worth investigating?"

A few rules from the Thinkst playbook and from real practitioners:

- **File names matter.** `password.docx` is a cliche and savvy attackers may skip it. `customer-q3-2026.docx` or `Vendor-Onboarding-2024.docx` blends in. Match your real document naming conventions.
- **Surrounding context matters.** A `.env` file alone in a directory looks staged. A `.env` next to `docker-compose.yml`, `app.py`, `requirements.txt`, and a `node_modules/` directory looks like a real repo somebody forgot to clean up.
- **Modification timestamps matter.** Use `touch -d "2 weeks ago"` on your honey files so they don't all share a fresh creation time.
- **Don't deploy too many.** If half the files on a share are canaries, the noise tells the attacker something. Plant a handful per host, in places the attacker has to look for.

### Dedup and Why It Matters

Every honeytoken deployment hits this problem within the first week: somebody scans the URL, or a backup process opens a file, or the attacker's tooling retries on failure, and your alert channel floods. The dedup gate in this project (`backend/internal/event/service.go` + Redis `dedup:trigger:{tokenID}:{sourceIP}`) silences the second-through-Nth event from the same source IP for 15 minutes after the first.

The events are still recorded in Postgres — you don't lose forensic data — but only the first one fires a notification. The manage page shows a "3 duplicate triggers silenced" counter so the operator knows there's noise to investigate.

15 minutes is a deliberate tradeoff. Long enough to cover most retry-loops and scan bursts. Short enough that a returning attacker after lunch produces a fresh alert.

### Enumeration Resistance

A naive trigger handler does this:

```
GET /c/abc                  → 404 Not Found
GET /c/abc123xyz789         → 200 OK + pixel + record event
```

An attacker who finds a leaked log entry mentioning a `/c/...` URL can now enumerate which token IDs are real by trying URLs and watching the status codes. That's bad — it lets them suppress the alert by not actually opening the file, or it tells them the system is a canary and they should pivot.

The trigger handler in this project does this instead:

```
GET /c/abc                  → 200 OK + pixel  (no event recorded)
GET /c/abc123xyz789         → 200 OK + pixel  + record event
```

Same response either way. The attacker cannot distinguish a real token from a fake one without seeing the alert side. For `slowredirect` specifically the response is more involved because the destination URL is required, but the same principle applies: the response for an invalid token serves a generic decoy destination of `/`.

### Operator Token Compromise

The admin API is gated by a single bearer token in `OPERATOR_TOKEN`. If that token leaks, an attacker can list every token you've deployed and which alert channels they fire on — i.e. they get a map of your entire deception infrastructure. The middleware compares with `subtle.ConstantTimeCompare` to prevent timing-based recovery of the token. The deployment guidance is: rotate `OPERATOR_TOKEN` periodically, log all `/api/admin/*` access at the reverse-proxy layer, and treat any unauthorized admin request the same way you'd treat unauthorized access to a SIEM.

---

## Real-World Incidents Where Honeytokens Mattered (Or Would Have)

A short selection from public post-mortems:

**The DNC breach (2016).** APT28 (Fancy Bear) had access to the DNC's network for months. The breach was eventually detected via CrowdStrike's response, not through DNC's own monitoring. Multiple public analyses noted that honey credentials in service accounts and file-share locations would have provided detection signal months earlier; service-account credentials in particular are textbook honeytoken candidates because no human ever logs in with them.

**SolarWinds / SUNBURST (2020).** The supply-chain compromise of the Orion update channel gave APT29 persistent access to thousands of customer networks for an average of ~9 months before public disclosure. The attack relied heavily on legitimate-looking outbound C2 traffic and credentialed lateral movement. Honey credentials in Active Directory service accounts and honey URLs in internal wikis would have given many of the victim networks a high-confidence detection. FireEye's own breach disclosure noted that one of the indicators that ultimately surfaced the campaign was unexpected access to a controlled account, which is functionally equivalent to a honeytoken trip.

**Twilio breach (2022).** A phishing campaign compromised employees' credentials and gave the attackers access to internal systems for several days. Honey credentials in internal tooling — and honey URLs in internal docs that the attackers would have browsed during reconnaissance — were among the post-mortem recommendations Twilio published.

**Uber breach (2022).** A social-engineering compromise of an Uber contractor's account let the attacker pivot to internal admin tools and dump credentials from a PowerShell script that contained a privileged Thycotic password. The attacker reportedly took several hours to escalate, during which honey credentials in the same PowerShell scripts they were combing through would have fired immediately.

The pattern: in every case, the attackers spent meaningful time inside the network looking for credentials, files, and infrastructure to pivot through. Every minute of that is a minute a planted honeytoken could fire.

---

## Mapping to MITRE ATT&CK (Defensive View)

Honeytokens don't map cleanly to ATT&CK because ATT&CK catalogues attacker behaviour, not defender behaviour. They map to MITRE Engage, which we covered above. But here is the inverse mapping — for each token type, the *attacker techniques* it detects:

| Token | Attacker Techniques Detected |
|-------|------------------------------|
| `webbug` | T1213 (Data from Information Repositories) — anyone reading planted internal docs; T1114 (Email Collection) if planted in email |
| `slowredirect` | T1566.002 (Spearphishing Link triage) — anyone clicking your honey-link; T1190 (Exploit Public-Facing Application) — scanners hitting fake admin URLs |
| `pdf`, `docx` | T1213 (Data from Information Repositories); T1005 (Data from Local System) — anyone exfiltrating planted files |
| `envfile` | T1552.001 (Credentials in Files); T1078 (Valid Accounts) — anyone using the fake creds |
| `kubeconfig` | T1552.001 (Credentials in Files); T1078.004 (Cloud Accounts); T1613 (Container and Resource Discovery) |
| `mysql` | T1552.001; T1078; T1110.001 (Brute Force: Password Guessing) — the password-spray after the first failure |

A defender mapping their detection coverage against ATT&CK can use this table to claim coverage on credential-access and discovery techniques that other detection sources (EDR, NIDS, SIEM) often miss because the attacker behaviour is too quiet to register on signature- or anomaly-based monitoring.

---

## Further Reading

- Thinkst Canary product documentation: [https://docs.canary.tools/](https://docs.canary.tools/) — the commercial reference for how this technology gets used in mature environments.
- Canarytokens (open-source predecessor): [https://canarytokens.org/generate](https://canarytokens.org/generate) — Thinkst's free hosted version, with a wider token catalogue than this project.
- MITRE Engage: [https://engage.mitre.org/matrix/](https://engage.mitre.org/matrix/) — the defensive deception matrix.
- Honeytokens chapter in *The Cuckoo's Egg* by Clifford Stoll (1989) — the original.
- "Practical Deception Engineering" by Haroon Meer (talks at BSidesLV and DEFCON over the past decade) — the modern doctrine, from the person who built Thinkst.
- Verizon 2024 DBIR: [https://www.verizon.com/business/resources/reports/dbir/](https://www.verizon.com/business/resources/reports/dbir/) — annual data on dwell time, breach causes, detection sources.
- IBM Cost of a Data Breach 2024: [https://www.ibm.com/reports/data-breach](https://www.ibm.com/reports/data-breach) — annual MTTI/MTTD numbers.

The architecture and code-walkthrough modules ([02 - Architecture](02-ARCHITECTURE.md), [03 - Implementation](03-IMPLEMENTATION.md)) take the theory above and show you exactly how each piece is implemented.
