# SeekYou — Roadmap

> Last updated: 17 May 2026 (static analysis bug audit added)

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
- [x] `lib/normalize.ts` — full implementation: per-feed extractors (URLhaus, ThreatFox, Feodo, SSLBL, MalwareBazaar), IOC deduplication with provenance merging, confidence scoring with per-feed weights (Feodo C2 Online = 95, URLhaus online = 90, ThreatFox = native confidence_level, SSLBL = 80, MalwareBazaar = 85), unified firstSeen/lastSeen across sources, deduplicated tag union, sort by descending confidence.
- [x] Wired into `mergeResults()` — `normalizedThreats` field populated on every `HostResult`.

### 4. Batch lookup proper orchestration
- [x] `/api/batch` — up to 20 queries in parallel, atomic rate-limit charge, partial failure isolation per-item.
- [x] **Progressive NDJSON streaming per-item** — each lookup writes its frame to the `TransformStream` as soon as it settles; cached hits appear immediately without waiting for the slowest NVD fetch. Wire format: `{"type":"result","index":N,"query":"...","data":{...HostResult}}` / `{"type":"error",...}` / `{"type":"done",...}`. The `index` field lets clients re-sort out-of-order frames back to original input position. Accepts optional `refresh: true` in body.
- [ ] **Cross-query deduplicated enrichment** — queries sharing the same ASN/CVE IDs/cert chain could share a single upstream fetch; not yet implemented.

### 5. Webhook diff on target re-query
- [x] `worker/cron.ts` calls `diffHostResults` after each re-query, packages the full typed `TargetDiff` (ports, CVEs, threats, geo, certExpiry, risk delta) plus human-readable `summary` into a `ChangeEvent`, and POSTs `{ sentAt, events[] }` to `WEBHOOK_URL` via `ctx.waitUntil`.

### 6. Saved target monitoring + risk score
- [x] **Change detection** — cron re-queries all saved targets, diffs against stored `result_json` snapshot with `diffHostResults`, persists fresh snapshot synchronously via direct `await`. Structured log emitted per change.
- [x] **Risk score** — `computeRiskScore()` in `lib/risk.ts`; `RiskBadge` component in results and `/saved` page. `GET /api/targets` recomputes score from stored snapshot on every response.
- [x] **Saved targets dashboard** — `/saved` page (`SavedList.tsx`): risk badge, last-checked time, inline label editing, optimistic delete, purge-all with confirm step, cap/threshold banner and progress bar.

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

---

## 🐞 Bug fixes — static analysis audit (17 May 2026)

Identified by full static review of `worker/`, `lib/`, and `app/api/` after the pipeline logic audit. Ordered by severity.

### 🔴 High — fix before next deploy

#### 1 · `preferOk` discards domain-path threat hit when both paths succeed
- [x] **File:** `worker/lookup.ts` — `preferOk()`
- [x] When the IP-path and domain-path for URLhaus/ThreatFox/MalwareBazaar both return `ok`, `preferOk` always returns `a` (the IP path). A domain listed as malicious while its resolved IP is clean will silently get a clean result.
- [x] **Fix:** `preferOk` now falls through to `bUsable ? b : a` in the both-ok case, always preferring the domain path (`b`) rather than the IP path.

#### 2 · `pickWorstThreatFox` drops domain-path IOCs when counts are equal
- [x] **File:** `worker/lookup.ts` — `pickWorstThreatFox()`
- [x] When both paths return equal IOC counts (e.g. 2 each), `preferOk` returns `a` and the domain-path IOCs are never merged in. A target with different IOCs on each path loses half its results.
- [x] **Fix:** when both results are `ok` and have equal non-zero counts, `data.data` arrays are merged and deduplicated by `id`, returning a synthetic `SourceResult` containing the union.

#### 3 · crtsh breaker-open + cache-cold certspotter fallback never updates breaker counters
- [x] **File:** `worker/lookup.ts` — inline IIFE for `certs`
- [x] When crtsh breaker is open and KV cache is cold, `fetchCertSpotter` is called standalone and its result is re-labelled `source: 'crtsh'`. Neither `recordBreakerSuccess` nor `recordBreakerFailure` is called for `'crtsh'`, so the breaker can never recover via a certspotter success — it stays open until the 15-min KV TTL expires.
- [x] **Fix:** after calling `fetchCertSpotter` in this path, `recordBreakerSuccess('crtsh', env.KV)` on success or `recordBreakerFailure` on error, mirroring the closed/half-open path below.

#### 4 · Rate limiter quota can be exceeded under high parallelism
- [x] **File:** `lib/ratelimit.ts` — `checkRateLimit()`
- [x] The read → increment → write sequence is non-atomic. Concurrent Workers handling the same IP each read the same counter value and all write `count + 1`, allowing the effective limit to be multiplied by the parallelism factor (easily 5–10×).
- [x] **Fix:** prominent NOTE comment added to `checkRateLimit` and `acquireConcurrency` documenting the best-effort nature and the Durable Object migration path for strict enforcement.

---

### 🟡 Medium — fix in next maintenance pass

#### 5 · Cert expiry diff deduplication key is `commonName`, which is not unique
- [x] **File:** `lib/diff.ts` — cert expiry block
- [x] `prevCertExpiry` is a `Map` keyed by `cert.commonName`. Multiple certs with the same CN but different serial numbers / expiry dates (e.g. a renewed cert still in CT logs alongside the old one) collide — the Map keeps only the last entry. A renewed cert with a new `notAfter` may appear to have already been warned about, silently suppressing the alert.
- [x] **Fix:** Map is now keyed by `cert.serialNumber || \`${cert.commonName}::${cert.notAfter}\`` so each distinct certificate lifetime is tracked independently.

#### 6 · `sanitizeLabel` allows bare `'` and `"` characters — latent injection risk
- [x] **File:** `lib/sanitize.ts` — `sanitizeLabel()`
- [x] The character allowlist explicitly permitted `'` and `"`. All current D1 calls use prepared statements so there is no active injection path, but if a future query ever interpolates a label into SQL, these characters are an injection vector.
- [x] **Fix:** `'` and `"` removed from the allowlist. The regex `[^\w\s\-_.,:;!?()\[\]{}@#$%&+=]` now strips both. Comment documents the rationale.

#### 7 · cron snapshot persistence uses `waitUntil` incorrectly — fragile under early Worker termination
- [x] **File:** `worker/cron.ts` — target sweep loop
- [x] Wrapping `await updateTargetSnapshot` inside `ctx.waitUntil` could silently lose snapshot writes if the cron Worker terminated before the deferred task drained.
- [x] **Fix:** `updateTargetSnapshot` is now called with a direct `await` inside the loop's `try/catch`. `ctx.waitUntil` is reserved only for the fire-and-forget webhook dispatch that must survive past the end of the scheduled handler.

---

### 🟢 Minor / informational

#### 8 · `resolvedDomain` for IP queries comes from InternetDB, not PTR — misleading label
- [x] **File:** `lib/merge.ts` — `mergeResults()`
- [x] `HostResult.resolvedDomain` was documented as "PTR/rDNS hostname" but is actually `internetdb.hostnames[0]`, which may be an unrelated CDN hostname indexed by Shodan.
- [x] **Fix (doc):** TSDoc comment in `mergeResults` updated to accurately describe the Shodan/InternetDB source and note the future PTR improvement.

#### 9 · `KeyRing.exhaustedKey()` — djb2 hash collision could cross-exhaust two API keys
- [x] **File:** `lib/keyring.ts` — `exhaustedKey()`
- [x] djb2 on raw key strings: birthday-paradox collision probability ~1.4×10⁻⁶ for 18 keys, but non-zero.
- [x] **Fix:** `exhaustedKey` now hashes the key's *index* in the array (always a unique small integer) rather than the raw key string. Comment explains the rationale.

#### 10 · `isValidIPv6` rejects IPv4-mapped addresses (`::ffff:x.x.x.x`)
- [x] **File:** `lib/validate.ts` — `isValidIPv6()`
- [x] IPv4-mapped IPv6 addresses (RFC 4291 §2.5.5.2) failed validation because `8.8.8.8` is not a valid hex group.
- [x] **Fix:** `isValidIPv4MappedIPv6()` added; `parseQuery` calls it after `isValidIPv6`. Accepts `::ffff:a.b.c.d` and `::ffff:0:a.b.c.d` forms.

#### 11 · `backoff.ts` — `Retry-After` date-string format silently falls back to jitter with no log
- [x] **File:** `lib/backoff.ts` — `withBackoff()`
- [x] RFC 7231 allows `Retry-After` to be a delay-in-seconds or an HTTP-date string. `parseFloat` on an HTTP-date returns `NaN`, which was handled correctly but silently.
- [x] **Fix:** `console.warn` added when `retryAfterHeader` is truthy but `retryAfterMs` is `NaN`, making unexpected header formats visible in logs without breaking fallback behaviour.
