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
- [ ] `wrangler secret put` for NVD_KEY, ABUSECH_KEY, ADMIN_TOKEN, GRAYHATWARFARE_API_KEY_1..18
- [ ] Validate external API responses before parsing — malformed upstream should return `status: 'error'`, not crash
- [ ] Wire up `/api/admin/reset-breaker` — file exists, KV mutation not implemented

---

## 🟡 Performance — one live problem, two quick wins

### NVD latency (live problem)
A host with many CVEs blocks the entire response waiting for NVD's rate limit. Users see a spinner for 30–120 seconds.

- [ ] Stream Layer 1+2 results immediately — render ports, geo, threats within ~500ms. CVEs load in after. `ReadableStream` + chunked JSON on the client, no queue needed.
- [ ] Batch CVE requests 5 at a time instead of sequentially — cuts enrichment time by 4× for CVE-heavy hosts.

### Blocklists (quick win)
- [ ] Move Feodo and SSLBL into D1 tables with an index on IP/SHA1 — replace the current in-memory linear scan with a single indexed `SELECT`. One migration script.

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
- [ ] Email or webhook notification on change — `WEBHOOK_URL` env var wired, dispatch TODO behind flag.

### Batch lookup
- [x] `POST /api/batch` — up to 20 queries, all in parallel, partial failures isolated per-item.
- [x] Rate limit charges the full batch cost in one atomic KV write.

### CVE detail on click
- [x] Clicking a CVE ID in the results page opens a drawer with description, CVSS scores, CWEs, references.

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
