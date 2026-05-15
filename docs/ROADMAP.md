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
Right now you can export the whole result as JSON. You can't copy a single IP, ASN, or CVE ID without selecting text manually.

- [ ] Copy button on every data field — one click copies the value. IP, ASN number, CVE ID, domain, certificate fingerprint. Tiny component, used constantly.

### Shareable result links
- [ ] `/host/1.1.1.1` already works as a URL. Add an explicit share button that copies the link to clipboard. Users already share these — make it obvious.

### Saved targets + change alerts
The `saved_targets` D1 table exists and is empty. This is the feature it was built for.

- [ ] Save any host from the results page — one button, one D1 insert.
- [ ] Daily Cloudflare Cron re-queries all saved targets and diffs the result against the previous lookup — new open ports, new CVEs, new threat feed hits, cert changes.
- [ ] Email or webhook notification on change. Users monitoring infrastructure or tracking threat actors check back manually right now. This replaces that.

### Batch lookup
- [ ] Paste a list of IPs or domains, get results for all of them. `POST /api/batch`, max 20 queries, same rate limit applies per query. The most common SOC workflow — you have 15 suspicious IPs from a log and have to look them up one at a time right now.

### CVE detail on click
- [ ] Clicking a CVE ID opens a drawer with the full NVD record — description, CVSS score breakdown, affected versions, references. The data is already fetched in Layer 3. Right now it's buried in the JSON export.

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
