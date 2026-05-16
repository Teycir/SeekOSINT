# SeekOSINT — Roadmap

> Last updated: May 2026

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

---

## 🔴 Must do before sharing publicly

- [ ] Run BFG to scrub `.env` from git history, then rotate all keys
- [ ] `wrangler secret put` for ADMIN_TOKEN, WEBHOOK_URL
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
