# Seek — Project Roadmap

> Last updated: May 2026

---

## 🚨 Phase 0 — Critical Security Fixes
**Timeline: Week 1 | Goal: Production-ready & secure**

### API Key Security
- [ ] Remove `.env` from git history (`git filter-branch` or BFG Repo-Cleaner)
- [x] Add `.env` to `.gitignore`
- [x] Create `.env.example` with placeholder values
- [ ] Rotate all 18 GrayHatWarfare keys
- [ ] Rotate NVD and abuse.ch keys
- [x] Migrate all secrets to Wrangler: `wrangler secret put KEY_NAME`
- [ ] Document secret management in README

### Rate Limiting
- [x] Implement KV-based rate limiter (100 requests/hour per IP) — `lib/ratelimit.ts`
- [ ] Add rate limit headers to API responses
- [ ] Create rate limit bypass for authenticated users (future-proofing)
- [ ] Add rate limit monitoring dashboard

### Input Validation
- [ ] Install Zod for runtime type validation
- [x] Add proper IPv6 validation — `lib/validate.ts`
- [ ] Validate all external API responses before parsing
- [ ] Add input sanitization for XSS prevention
- [x] Create validation error responses with helpful messages — `api/lookup/route.ts` returns 422

---

## 🔧 Phase 1 — Code Quality & Stability
**Timeline: Weeks 2–3 | Goal: Maintainability & reduced technical debt**

### Type Safety
- [ ] Replace all `any` types across codebase
- [x] Create strict TypeScript interfaces for all external API responses — `lib/types.ts`
- [ ] Add Zod schemas for runtime validation
- [ ] Enable `strict: true` and `noUncheckedIndexedAccess: true` in tsconfig
- [ ] Fix all resulting type errors

### Error Handling
- [ ] Create unified error response format
- [x] Standardize "no results" pattern (use `null` consistently) — `lib/results.ts`
- [ ] Add error codes for different failure types
- [ ] Document error handling patterns

### Configuration Management
- [ ] Create `lib/config.ts` with all timeouts, limits, and TTLs
- [ ] Add environment-based configuration (dev/staging/prod)
- [ ] Document all configuration options

### Testing Infrastructure
- [ ] Add integration tests for `runLookup()` orchestrator
- [ ] Add tests for all error scenarios (timeouts, 429s, malformed responses)
- [ ] Add tests for KeyRing exhaustion and recovery
- [ ] Add tests for cache hit/miss scenarios
- [ ] Target: 80% code coverage
- [ ] Set up Miniflare for local Worker testing

---

## 📊 Phase 2 — Observability & Monitoring
**Timeline: Week 4 | Goal: Visibility into production behavior**

### Structured Logging
- [ ] Implement structured logging with correlation IDs
- [ ] Add log levels (debug, info, warn, error)
- [ ] Log all external API calls with timing
- [ ] Create log aggregation dashboard

### Metrics Collection
- [ ] Track cache hit rates per source
- [ ] Track API response times per source
- [ ] Track error rates per source
- [ ] Track Cloudflare quota usage (KV reads/writes, D1 queries)
- [ ] Create Grafana / Cloudflare Analytics dashboard

### Error Tracking
- [ ] Integrate Sentry or Cloudflare Workers Logs
- [ ] Add error alerting for critical failures
- [ ] Create on-call runbook for common issues

### Circuit Breaker
- [x] Skip sources failing >50% of requests in a 5-minute window — `lib/ratelimit.ts`
- [x] Auto-recover after 15-minute cooldown — KV TTL-based
- [x] Add circuit breaker status to API response metadata — `meta.circuitBreakers`
- [ ] Create admin endpoint to manually reset circuit breakers

---

## ⚡ Phase 3 — Performance Optimization
**Timeline: Weeks 5–6 | Goal: Faster responses & better resource efficiency**

### Request Deduplication
- [ ] Implement request coalescing using KV locks
- [ ] Prevent duplicate external API calls for same query
- [ ] Add "request in progress" indicator to UI

### Cache Warming
- [ ] Create Cloudflare Cron trigger for popular queries
- [ ] Pre-cache top 100 most-queried IPs/domains daily
- [ ] Add cache warming admin endpoint

### Smart Cache Invalidation
- [ ] Add cache versioning for breaking changes
- [ ] Implement selective cache purge by source
- [ ] Add "force refresh" option in UI

### CVE Enrichment
- [x] Limit CVE enrichment to first 20 CVEs — `worker/lookup.ts` line 168
- [ ] Batch CVE requests (max 10 concurrent)
- [ ] Add "load more CVEs" button for remaining
- [ ] Pre-cache top 1,000 most common CVEs

### Blocklist Optimization
- [ ] Migrate Feodo/SSLBL from KV to D1 tables
- [ ] Add indexes for fast lookups
- [ ] Implement Bloom filter for negative lookups
- [ ] Reduce memory footprint in Workers

---

## 🎨 Phase 4 — UI/UX Enhancements
**Timeline: Weeks 7–8 | Goal: Better user experience & power-user features**

### Search Experience
- [ ] Display recent searches from D1
- [ ] Add "favorite" queries feature
- [ ] Export search history as CSV
- [ ] Add search suggestions based on history

### Advanced Search
- [ ] Multi-query batch lookup (paste list of IPs)
- [ ] CIDR range expansion (e.g. `1.2.3.0/24` → 256 lookups)
- [ ] Bulk export results as JSON/CSV
- [ ] Compare two hosts side-by-side

### Results Visualization
- [ ] Timeline visualization for DNS history
- [ ] Network graph for BGP relationships
- [ ] Geographic map for IP location
- [ ] CVE severity distribution chart

### Filtering & Sorting
- [ ] Filter results by severity/category
- [ ] Sort CVEs by CVSS score
- [ ] Hide/show specific sources
- [ ] Customize result layout (drag-and-drop cards)

### Real-time Updates
- [ ] WebSocket connection for live updates
- [ ] Auto-refresh stale cached results
- [ ] Notification when new threats detected
- [ ] RSS feed for monitored targets

---

## 🎯 High-ROI Quick Wins
**Easy tasks with outsized impact — do these next**

- [ ] **Rate limit enforcement in the API route** — `lib/ratelimit.ts` exists but `app/api/lookup/route.ts` never calls it. One import + one await away from working.
- [ ] **`lib/config.ts` — centralise all magic numbers** — timeouts, TTLs, window sizes are scattered. 30-min task, eliminates entire category of bugs.
- [ ] **`wrangler secret put` for remaining secrets** — keys are still in `.env`. One command per key, no code changes needed.
- [ ] **BFG / filter-branch to scrub `.env` from git history** — secrets are committed. Use `bfg --delete-files .env` before the keys are rotated.
- [ ] **Recent searches on homepage from D1** — `searches` table already exists and is being written to. One D1 query on the homepage, instant power-user feature with zero new infrastructure.
- [ ] **"Force refresh" query param** — add `?refresh=1` to bypass KV cache. Five lines in each source fetcher, huge debugging/freshness value.
- [ ] **Export results as JSON** — add a download button that does `JSON.stringify(result)` client-side. Zero backend work.

---

## Progress Summary

| Phase | Status | Target |
|-------|--------|--------|
| 0 — Security | 🟡 In progress | Week 1 |
| 1 — Code Quality | 🟡 In progress | Weeks 2–3 |
| 2 — Observability | 🟡 In progress | Week 4 |
| 3 — Performance | 🟡 In progress | Weeks 5–6 |
| 4 — UI/UX | 🔴 Not started | Weeks 7–8 |
