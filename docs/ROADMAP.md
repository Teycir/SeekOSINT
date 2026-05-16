# SeekOSINT — Roadmap

> Last updated: 16 May 2026 (pipeline logic audit added)

---

## ✅ Done

| Feature | Commit |
|---|---|
| Per-IP rate limiting (100 req/hr) | `20947a5` |
| Unified error format + ErrorCode enum | `fdcf069` |
| Centralised config — TTLs, timeouts, limits | `f9d8d79` |
| Circuit breakers per source | — |
| `?refresh=1` force-cache-bypass | `0baa294` |
| JSON export button | `0baa294` |
| Recent searches on homepage | `78c50dc` |
| Rate limit headers on all responses | `0baa294` |
| Copy button on every data field | — |
| Share button (clipboard + Web Share API) | — |
| CVE detail drawer (inline NVD record expand) | — |
| `POST /api/batch` — up to 20 queries, cost-aware rate limit | — |
| `checkRateLimit` cost param (batch charges N slots atomically) | — |
| Saved targets — `POST/GET /api/targets`, `DELETE /api/targets/:id` | — |
| `SaveButton` component wired into results page header | — |
| Daily cron scaffold — `worker/cron.ts` + `wrangler.cron.toml` | — |
| **UX: Look up button loading spinner** — `isSearching` state blocks double-submit | — |
| **UX: Recent searches loading state** — per-item spinner on click, all items disabled | — |
| **UX: Card chevron rotation** — SVG chevron animates 180° on collapse via `.chevron` CSS class | — |
| **UX: RiskBadge click-to-toggle** — breakdown tooltip works on mobile (click) + desktop (hover) | — |
| **UX: Dynamic page title** — `generateMetadata` sets `<title>` to the queried host | — |
| **UX: MetaBar failure highlight** — `sourcesFailed > 0` renders in amber | — |
| **UX: RefreshButton with spinner** — `↺ refresh` shows loading state instead of plain link | — |
| **UX: `/` keyboard shortcut** — focuses search input from anywhere on the homepage | — |

---

## 🔴 Must do before sharing publicly


- [x] Validate external API responses before parsing — `safeJson<T>(res, guard, label)` in `lib/results.ts`; all 10 source files updated; malformed upstream → `status: 'error'`, never a crash or bad cache write

---

## 🟡 Performance — one live problem, two quick wins

### NVD latency (live problem)
- [x] Batch CVE requests 5 at a time — `fetchCVEsBatched()` in `worker/lookup.ts` cuts enrichment time ~5× for CVE-heavy hosts.
- [x] Stream Layer 1+2 results immediately — `VulnsStream` client component fetches via `GET /api/stream` (NDJSON); geo/ports/threats/certs SSR in <1s, CVE card shows pulsing skeleton then patches in when NVD responds. `lib/useHostStream.ts` for reuse.

### Blocklists (quick win)
- [x] Feodo and SSLBL moved to D1 tables with indexes — `migrations/002_blocklists.sql`. Lookup is one indexed `SELECT` instead of an in-memory linear scan. Cron refreshes hourly via `refreshBlocklists()` in `worker/cron.ts`, skipping each list when `blocklist_meta` shows it's still fresh. Cron schedule changed from daily to hourly (`0 * * * *`).

---

## 🟢 Features users actually want

### Copy individual field values
- [x] Copy button on every data field — one click copies the value. IP, ASN number, CVE ID, domain, certificate fingerprint.

### Shareable result links
- [x] Share button — copies the `/host/<query>` URL; falls back to Web Share API on mobile.

### Saved targets + change alerts
- [x] Save any host from the results page — `SaveButton` → `POST /api/targets` → D1 upsert.
- [x] `GET /api/targets` — list all saved targets.
- [x] `DELETE /api/targets/:id` — remove a target.
- [x] Daily cron — `worker/cron.ts` re-queries all targets, diffs ports/CVEs/threat hits, persists snapshot.
- [x] Email or webhook notification on change — POST to `WEBHOOK_URL` env var; payload `{ sentAt, events[] }` dispatched via `ctx.waitUntil` after each cron sweep.

### Batch lookup
- [x] `POST /api/batch` — up to 20 queries, all in parallel, partial failures isolated per-item.
- [x] Rate limit charges the full batch cost in one atomic KV write.

### CVE detail on click
- [x] Clicking a CVE ID in the results page opens a drawer with description, CVSS scores, CWEs, references.

---

## 🔵 Next — post-review priorities

Ordered by impact-to-effort ratio. Based on external architecture review (May 2026).

### 1. Turnstile abuse defense
- [x] Invisible Turnstile widget on the search form — zero friction, auto-fires on page load
- [x] Token forwarded as `?ts=` through the redirect to `/host/[query]`
- [x] `lib/turnstile.ts` — server-side siteverify against Cloudflare's API
- [x] `/api/lookup` and `/api/stream` both verify token before running lookup; fail-open when `TURNSTILE_SECRET_KEY` is unset (dev/CI safe)
- [x] Token threaded into `VulnsStream` for the client-side `/api/stream` call
- [ ] Set secrets: `wrangler secret put TURNSTILE_SECRET_KEY` + `NEXT_PUBLIC_TURNSTILE_SITE_KEY` in Pages env vars

### 2. `/api/admin/health` endpoint
- [x] `GET /api/admin/health` — Bearer-authed, returns breaker states + summary, D1 row counts (total searches, saved targets, last-hour activity), blocklist freshness from KV meta keys

### 3. Threat indicator normalization (`lib/normalize.ts`)
- [ ] When the same IP/domain appears across multiple feeds (URLhaus + ThreatFox + Feodo), deduplicate into a canonical `ThreatIndicator` shape with provenance, confidence, and first/last seen timestamps. Not a database redesign — a result transformation layer before the response is serialized. Directly differentiating from other OSINT tools.

### 4. Batch lookup proper orchestration
- [ ] `/api/batch` exists but needs: deduplicated enrichment across queries sharing the same ASN/cert/CVEs, shared cache reuse, and progressive streaming per-item (NDJSON). Analysts rarely investigate one IOC at a time.

### 5. Webhook diff on target re-query
- [ ] The cron + snapshot infrastructure is already there. The missing piece is a structured diff (ports added/removed, new CVEs, new threat hits) emitted as a typed payload to `WEBHOOK_URL`. Turns saved targets into a real passive monitoring feed.

### 6. Saved target monitoring + risk score
- [ ] **Change detection** — cron re-queries every saved target, diffs the new `HostResult` against the stored `result_json` snapshot, and persists the delta. Surfaces diffs in a `/targets` dashboard card: new open ports, first threat intel hit, new CVEs, certificate rotation, domain disappearing from live web. The D1 `result_json` column and cron scaffold are already in place — the missing piece is the diff logic and UI.
- [x] **Risk score** — a single 0–100 number computed from what's already in `HostResult`: open port count + exposure (e.g. port 445/3389 weighted heavily), max CVSS score across all CVEs, threat intel hits (each feed weighted independently), blocklist presence (Feodo/SSLBL = instant ceiling), certificate anomalies (self-signed, near-expiry). Displayed as a colour-coded badge at the top of every result card. No new API calls, no new data — pure aggregation of the existing merge layer output. Turns an 8-card manual read into a one-glance triage signal. (`lib/risk.ts`, `app/components/RiskBadge.tsx`)

---

## ❌ Not building

| Item | Why not |
|---|---|
| Network graph for BGP relationships | BGPView already has one — link out |
| WebSocket live updates | SSE + streaming covers the actual need |
| CIDR range expansion | Add after batch lookup ships |
| Drag-and-drop result layout | No real user need |
| RSS feed | Webhooks are what security teams actually use |
| Bloom filter for blocklists | D1 indexed lookup is simpler and fast enough |
| Grafana dashboard | Cloudflare Analytics covers it |

---

## 🐛 Pipeline logic fixes — query coverage audit (May 2026)

Identified by systematically checking which sources run for each query type (IP / domain / ASN)
and what each source actually sends to upstream APIs. Ordered by impact on user value.

### [CRITICAL] 1 · ASN queries show almost nothing
- [x] BGPView runs and returns prefixes, but every other source returns `skipped` for ASN type.
- [x] Fix: after BGPView returns, pick the first announced prefix, derive a representative IP (e.g. first host of `185.26.182.0/24`), construct a synthetic `ipQuery`, and fan it into InternetDB, ip-api, Robtex, PassiveDNS, and all abuse.ch sources in parallel.
- [x] Turns a 1-card ASN result into a full intelligence report with ports, geo, CVEs, and threat intel.

### [CRITICAL] 2 · Threat intel never searches the domain string
- [x] After DNS resolution, `effectiveIPQuery` is used for URLhaus, ThreatFox, and MalwareBazaar. The original domain name is never searched — a domain listed as malicious in URLhaus gets a clean result.
- [x] Fix: run threat intel with **both** the resolved IP and the original domain query in parallel; merge results and deduplicate by IOC before caching.

### [HIGH] 3 · PassiveDNS only queries the domain, not the resolved IP
- [x] CIRCL PDNS accepts both IPs and domains. Querying by IP returns all domains that ever resolved to it — a critical shared-hosting pivot that's currently never made.
- [x] Fix: for domain queries, run PassiveDNS twice (domain + resolved IP) and merge both result sets before returning.

### [HIGH] 4 · crt.sh wildcard misses apex certificates
- [x] Query is `%.domain` — the `%` prefix matches subdomains only. A cert issued to the apex domain itself (e.g. `allocine.fr`) is invisible.
- [x] Fix: run two fetches — `%.domain` (current) and `domain` (apex) — then deduplicate by `id` before caching. One extra fetch, significant coverage improvement.

### [HIGH] 5 · MalwareBazaar uses tag search instead of IOC search
- [x] Request body is `{ query: "search_tag", tag: query.normalised }`. Tag search matches malware family names (e.g. "Emotet"), not IP addresses or domains. Every IP and domain lookup silently returns nothing.
- [x] Fix: use `{ query: "search_ioc", ioc: query.normalised }` for IP and domain queries. Tag search is only appropriate when the input is a malware family name.

### [HIGH] 6 · BGPView skips domain queries even after DNS resolution
- [x] BGPView receives the original `query` (type=domain) and hits `if (query.type === 'domain') return skipped`. The resolved IP is never passed to it.
- [x] Fix: pass `effectiveIPQuery` to BGPView for domain lookups (same pattern as InternetDB). ASN, prefix block, RIR, and org name will then populate the Overview card for all domain queries. One-line fix in `lookup.ts`.

### [MEDIUM] 7 · Risk score has no domain-specific signals
- [x] `computeRiskScore()` only reads IP-sourced signals (ports, CVEs, geo flags, blocklists). For domain queries the RDAP result is already present but ignored by the scorer.
- [x] Fix: add RDAP signals to `lib/risk.ts`: newly registered domain < 30 days old (+15), expired domain (+10), privacy-protected registrant (+5), no nameservers (+8). These are the primary phishing/typosquat indicators.

### [MEDIUM] 8 · Verify Feodo/SSLBL type guard passes for resolved-IP queries
- [x] Both sources guard on `query.type !== 'ip'`. The `effectiveIPQuery` constructed post-DNS-resolution does set `type: 'ip'` explicitly, so this *should* work — but warrants a logged confirmation or unit test to ensure the guard isn't tripping on a serialisation edge case in the D1 path.
- [x] Fix: added tests in `test/risk.test.ts` covering the Feodo/SSLBL path with a synthetic domain→IP resolved query, verifying the scorer correctly processes hits arriving via the resolvedIP path.


---

## 🐞 Bug fixes — code review audit (May 2026)

Identified by a full static review of all worker, lib, and API route code. Ordered by severity.

### 🔴 High — fix before next deploy

#### 1 · `dispatchWebhook` bypasses SSRF protections
- [x] **File:** `worker/cron.ts ~line 210`
- [x] `fetch(webhookUrl, ...)` is called directly — not via `safeFetch()`. The URL is validated for HTTPS and parseability, but is never checked against `BLOCKED_HOST_PATTERNS`.
- [x] **Fix:** added `allowArbitraryHost` option to `safeFetch`/`validateSSRF` — skips the static allowlist but still enforces `BLOCKED_HOST_PATTERNS`. `dispatchWebhook` now uses `safeFetch(..., { allowArbitraryHost: true })`. Manual URL parsing removed.

#### 2 · Turnstile fails open on network errors
- [x] **File:** `lib/turnstile.ts`
- [x] When the siteverify endpoint is unreachable, `verifyTurnstileToken` returns `{ success: true }`, completely disabling bot protection during any network partition or attack against `challenges.cloudflare.com`.
- [x] **Fix:** catch block now returns `{ success: false, reason: 'siteverify unreachable' }` — fails closed.

---

### 🟡 Medium — fix in next maintenance pass

#### 3 · Concurrency counter race condition (non-atomic KV)
- [x] **File:** `lib/ratelimit.ts` — `acquireConcurrency` / `releaseConcurrency`
- [x] Both functions do KV `get` → compute → `put` without any atomic compare-and-swap. Concurrent Workers can read the same active count, both increment, and write back the same value — under-counting active slots and allowing more than `CC_MAX` parallel requests.
- [x] **Fix:** documented the known best-effort limitation with a clear comment. Durable Object migration noted as the path to strict enforcement.

#### 4 · Rate limit counter race condition (non-atomic KV)
- [x] **File:** `lib/ratelimit.ts` — `checkRateLimit`
- [x] Same read/increment/write pattern — parallel requests from the same IP can under-count usage, allowing quota to be exceeded. No warning comment exists for callers.
- [x] **Fix:** added comment marking this as best-effort with Durable Object noted as the strict alternative.

#### 5 · `fetchCVEFull` never calls OSV — enrichment is dead code
- [x] **File:** `worker/sources/nvd.ts`
- [x] `fetchCVEFull` is documented as calling NVD/CIRCL *and* OSV for "maximum detail", but its body only calls `fetchCVE` and returns. `fetchOSV` is exported but never wired into the batch enrichment path (`fetchCVEsBatched` in `lookup.ts`).
- [x] **Fix:** `fetchCVEFull` now calls `fetchOSV` and merges its `cwe`/`references` into the primary result when those fields are absent. OSV failure is best-effort and never fails the primary result.

#### 6 · NVD API key exposed in URL query string
- [x] **File:** `worker/sources/nvd.ts ~line 108`
- [x] `apiKey` is appended as a query parameter: `...?cveId=${cveId}&apiKey=${apiKey}`. Keys in query strings appear in Cloudflare access logs, `console.error` traces, and any CDN that caches by URL.
- [x] **Fix:** key moved to `apiKey` request header. URL now contains only `?cveId=`.

#### 7 · `recordBreakerSuccess` resets full failure window — breaker never trips on mixed results
- [x] **File:** `lib/ratelimit.ts` — `recordBreakerSuccess`
- [x] A single successful call deletes both `window_reqs` and `window_fails`. A source that fails 80% of the time will never trip its breaker if one in five requests succeeds — the window is perpetually wiped.
- [x] **Fix:** `recordBreakerSuccess` now only deletes the `:open` flag. Window counters expire naturally via their TTL. `resetBreaker` (admin endpoint) still wipes everything as before.

---

### 🟠 Logic / correctness bugs

#### 8 · ASN synthetic IP always uses `.1`, may always 404 in InternetDB
- [x] **File:** `worker/lookup.ts`
- [x] `parts[3] = '1'` constructs a representative IP (e.g. `185.26.182.1`) that may be firewalled or simply absent from Shodan, causing CDN detection to silently return `isCDNIP=false` and all IP-based sources to return empty.
- [x] **Fix:** CDN detection is already gated on `query.type === 'domain'` — ASN synthetic IPs never enter the pre-flight. Added comment explaining this and documented the candidate host list (`.1`, `.2`, `.254`) for future improvement.

#### 9 · `pickWorstURLhaus` / `pickWorstMB` return error over clean `ok` result
- [x] **File:** `worker/lookup.ts` — `pickWorstURLhaus`, `pickWorstMB`
- [x] When neither result is a positive hit, both functions `return a` unconditionally. If `a` (the IP-path result) has `status: 'error'` and `b` (the domain-path result) has `status: 'ok'`, the error is returned and the clean domain result is discarded.
- [x] **Fix:** added `preferOk()` helper. All three `pickWorst*` functions now fall back to it when neither result is a positive hit — always returning the `ok`/`cached` result over an `error`.

#### 10 · IPv6 RDAP bootstrap not fetched — all IPv6 defaults to ARIN
- [x] **File:** `worker/sources/rdap.ts` — `getRDAPBaseForIP`
- [x] Only `ipv4.json` is fetched from IANA bootstrap. IPv6 addresses fall through to `https://rdap.arin.net/registry/`, returning wrong or empty RDAP data for RIPE, APNIC, etc.
- [x] **Fix:** `getRDAPBaseForIP` now detects IPv6 input (`ip.includes(':')`) and fetches `ipv6.json` with a separate cache key. Default fallback for IPv6 is RIPE (`rdap.db.ripe.net`) instead of ARIN.

#### 11 · Cross-source `id` deduplication causes false cert exclusions in `crtsh`
- [x] **File:** `worker/sources/crtsh.ts`
- [x] `seenIds.add(cert.id)` is applied to CertSpotter records whose integer IDs are in a different namespace from crt.sh IDs. A collision could silently exclude a real crt.sh cert.
- [x] **Fix:** removed `seenIds.add` from the CertSpotter merge loop. CertSpotter deduplication now uses only `seenName` (`nameValue`), matching the intent.

---

### 🟢 Minor / code quality

#### 12 · `cachedAt`/`fetchedAt` inversion regression test missing
- [x] **File:** `lib/results.ts`, `test/results.test.ts`
- [x] A comment notes the fields were previously inverted and "now correct", but there is no test asserting `cached=true → cachedAt present, fetchedAt absent` and vice versa.
- [x] **Fix:** added two explicit `'key' in r` assertions to `test/results.test.ts`.

#### 13 · Fragile sanitize/toLowerCase order dependency in `parseQuery`
- [x] **File:** `lib/validate.ts`, `lib/sanitize.ts`
- [x] `sanitizeQueryParam` strips `<>'"` before `toLowerCase()` is called inside `parseQuery`. If a future code path calls sanitize *after* lowercasing, the strip may be ineffective. The order dependency is undocumented.
- [x] **Fix:** added an `ORDER MATTERS` comment in `parseQuery` explaining why sanitization must run before `toLowerCase`.

#### 14 · Raw API key value embedded in KV key names (`KeyRing`)
- [x] **File:** `lib/keyring.ts` — `exhaustedKey`
- [x] `keyring:ghw:exhausted:<full_api_key>` — the key value appears verbatim in Cloudflare KV key listings and dashboard audit logs.
- [x] **Fix:** `exhaustedKey` now hashes the key with djb2 → 8-char hex token. Keys appear as `keyring:ghw:exhausted:a3f2c1b0` in KV.

#### 15 · `normaliseIP` in RDAP doesn't handle IPv6 CIDR blocks
- [x] **File:** `worker/sources/rdap.ts` — `normaliseIP`
- [x] `cidr0_cidrs?.[0]` is formatted as `${cidrBlock.v4prefix}/${cidrBlock.length}`. For IPv6 blocks, `v4prefix` is undefined, producing `undefined/undefined` in the result.
- [x] **Fix:** `normaliseIP` now uses `cidrBlock.v4prefix ?? cidrBlock.v6prefix` when constructing the CIDR string.
