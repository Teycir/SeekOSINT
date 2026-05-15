# SeekOSINT — Roadmap

> Last updated: May 2026

This roadmap reflects honest engineering judgment — items are included only when the problem is real, the solution is clear, and the value justifies the cost. Items that are speculative, premature, or low-ROI have been removed.

---

## ✅ Completed

| Feature | Commit | Notes |
|---|---|---|
| Per-IP rate limiting (KV sliding window, 100 req/hr) | `20947a5` | Enforced in API route |
| Unified error format + `ErrorCode` enum | `fdcf069` | `lib/errors.ts` |
| Centralised config — all TTLs, timeouts, limits | `f9d8d79` | `lib/config.ts` |
| Circuit breakers per source (KV-backed) | — | `meta.circuitBreakers` in every response |
| `?refresh=1` force-cache-bypass | `0baa294` | Threads through all 11 fetchers |
| JSON export button | `0baa294` | Client-side, zero backend |
| Recent searches on homepage | `78c50dc` | D1-backed, fire-and-forget write |
| Rate limit headers on all responses | `0baa294` | `X-RateLimit-*` |

---

## 🔴 Phase 0 — Security debt (do before next public share)

These are not optional. They are pre-conditions for the project being safe to share or deploy publicly with real traffic.

### Secrets hygiene
- [ ] **Run BFG to scrub `.env` from git history** — `bfg --delete-files .env`, then force-push. Do this *after* rotating all keys, not before.
- [ ] **Rotate all 18 GrayHatWarfare keys** — assume they are compromised since they were committed.
- [ ] **Rotate NVD and abuse.ch keys** — same reason.
- [ ] **`wrangler secret put` for all remaining secrets** — NVD_KEY, ABUSECH_KEY, ADMIN_TOKEN, GRAYHATWARFARE_API_KEY_1..18.

### Input hardening
- [ ] **Validate all external API responses before parsing** — every source fetcher currently trusts the upstream response shape. Add narrow Zod schemas or manual field checks. A malformed upstream should produce `status: 'error'`, not a runtime crash or type confusion.
- [ ] **Wire up `/api/admin/reset-breaker`** — file exists, KV mutation not implemented. Without it, a stuck breaker requires a manual KV delete via dashboard.

---

## 🟡 Phase 1 — Performance (next sprint)

### Progressive streaming — NVD latency is a live problem
NVD allows 5 requests per 30 seconds without an API key, 50 with one. A host with 20 CVEs currently blocks the entire response for up to 120 seconds of NVD quota time. This is the single biggest UX problem in production today.

- [ ] **Stream Layer 1+2 results immediately, defer Layer 3+4** — convert the host page SSR fetch to a streaming response. Render core + threat data the moment Layer 1+2 settle (~300–800ms). CVEs and recon populate progressively. No queue needed — `ReadableStream` + client-side `EventSource` or chunked JSON.
- [ ] **Batch CVE requests — max 5 concurrent with backoff** — currently sequential with a fixed delay. True batching with `Promise.allSettled` in groups of 5 cuts enrichment time by 4× for hosts with many CVEs.
- [ ] **Pre-cache the 500 most common CVEs** — a one-time Wrangler script populating KV. CVE-2021-44228, CVE-2022-26134, and ~50 others appear on thousands of hosts. Caching them permanently eliminates most NVD calls.

### Blocklist optimization
Feodo and SSLBL are currently fetched as full bulk downloads on cache miss, parsed in-memory, and searched linearly. At current scale this is fine. At 10× scale it becomes a problem.

- [ ] **Move Feodo and SSLBL into D1 tables** — indexed on IP/SHA1. Replace linear scan with a single `SELECT` with `WHERE ip = ?`. Schema addition to `schema.sql`, one migration script.

---

## 🟡 Phase 2 — Intelligence quality (the most important architectural work)

This is where SeekOSINT evolves from "good aggregator" to "actual intelligence platform." The current schema is source-centric — each source returns its own struct and the UI renders them side by side. That's correct for v1. It becomes a ceiling the moment you want to do anything *across* sources.

### CVE → Service linkage
Right now: InternetDB returns `ports: [8080]`, `cpes: ["cpe:/a:apache:log4j:2.14.1"]`, `vulns: ["CVE-2021-44228"]` as three disconnected arrays. Layer 3 enriches the CVE but doesn't connect it back to the port or CPE that exposed it.

- [ ] **Link CVEs to the specific service/CPE that introduced them** — parse CPE strings, correlate with CVE data from NVD (the `configurations` field already has this). Produce `NormalizedService` entities with `vulns[]` attached. This is the most impactful single data quality change.

### Temporal normalization
PassiveDNS records have `time_first` and `time_last`. RDAP has `created` and `updated`. Wayback has timestamps. Right now they're all raw strings/numbers with no unified timeline.

- [ ] **Add a unified `timeline: TimelineEvent[]` to `HostResult`** — each event has `{ timestamp, type, source, detail }`. Populated from PassiveDNS, RDAP, crt.sh, Wayback. Enables "what changed when" without the UI having to reconstruct it from five different source structs.

### Cross-source deduplication
GrayHatWarfare and Wayback can surface the same S3 bucket URL. PassiveDNS and RDAP can disagree on current IP. Multiple certs can share SANs.

- [ ] **Deduplicate bucket results by URL** — trivial O(n) pass after Layer 4 settles. No new infrastructure.
- [ ] **Flag contradictions between sources explicitly** — when RDAP says IP A and PassiveDNS most-recent record says IP B, surface that as a `contradiction` in the response rather than leaving the user to notice it. Add `meta.contradictions: Contradiction[]`.

### Confidence scoring
Every `SourceResult` currently has `status: 'ok' | 'cached' | 'error' | 'skipped'`. That's not enough for downstream reasoning.

- [ ] **Add `confidence: number` (0–1) to `SourceResult`** — derived from: source reliability weight (NVD = 0.95, PassiveDNS = 0.7), data age (cached 23h ago = lower), corroboration (same fact from two sources = higher). Start with static source weights, add dynamic aging in a follow-up.

---

## 🟢 Phase 3 — Features that have clear value

These are only included because they have an obvious user need, a clear implementation path, and no architectural precondition that isn't already met.

### SSRF hardening (before adding any new fetch capability)
Current fetchers are safe — every URL is constructed from validated templates. The risk is latent, not live. Build this *before* adding screenshots, recursive DNS walking, or any user-URL-driven fetch — not before.

- [ ] **`lib/ssrf.ts` — RFC1918 + localhost + metadata IP blocklist** — called by any new fetcher that constructs a URL from external data. Blocks `10.x`, `172.16–31.x`, `192.168.x`, `127.x`, `169.254.x` (AWS metadata), `::1`, `fc00::/7`. Protocol allowlist: `https:` only for external calls.

### Saved targets + change detection
The `saved_targets` D1 table already exists. It has no application logic yet.

- [ ] **Save a target from the results page** — one button, one D1 insert. UI shows saved indicator.
- [ ] **Scheduled re-lookup via Cloudflare Cron** — daily re-query of all saved targets, store result in `searches`. No queue needed at this scale — a Cron Worker iterating `saved_targets` with a 500ms delay between queries is sufficient.
- [ ] **Change detection diff** — compare latest result against previous result for the same query. Surface added/removed ports, new CVEs, cert changes, new threat feed hits. Store diff in a new `diffs` D1 table. This is the feature that turns SeekOSINT from a lookup tool into a monitoring tool.

### Multi-query batch lookup
- [ ] **`POST /api/batch` — accepts `{ queries: string[] }`, returns `{ results: HostResult[] }`** — max 20 queries per request, rate-limit applies per-query. Useful for SOC workflows where you have a list of suspicious IPs from a log file. No new infrastructure beyond what exists.

---

## ❌ Removed from roadmap

Items removed because they are premature, low-value, or have a better alternative:

| Removed | Reason |
|---|---|
| Bloom filter for Feodo/SSLBL | D1 indexed lookup is simpler, fast enough, and debuggable |
| WebSocket live updates | SSE + streaming achieves the same UX without bidirectional complexity |
| Drag-and-drop card layout | No evidence users need this; adds React DnD dependency for cosmetic gain |
| Grafana dashboard | Cloudflare Analytics + structured logs cover 95% of the need |
| CIDR range expansion | Requires bulk lookup first; add after `POST /api/batch` ships |
| Network graph for BGP | BGPView already has this; linking out is more useful than reimplementing |
| RSS feed for monitored targets | Webhooks (Discord/Slack) are what security teams actually use |
| Request coalescing via KV locks | Premature — cache TTL of 24h already prevents duplicate upstream calls for all practical traffic patterns |
| Zod for runtime validation | Narrow manual checks are sufficient; Zod adds 13kb and complexity for marginal safety gain at this scale |

---

## Progress summary

| Phase | Status |
|---|---|
| 0 — Security debt | 🔴 Blocked on secret rotation + BFG |
| 1 — Performance | 🟡 NVD streaming is the priority |
| 2 — Intelligence quality | 🟡 CVE→service linkage first |
| 3 — Features | 🟢 Start after Phase 1 |
