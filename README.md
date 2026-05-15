<!-- donation:eth:start -->
<div align="center">

## Support Development

If this project helps your work, support ongoing maintenance and new features.

**ETH Donation Wallet**  
`0x11282eE5726B3370c8B480e321b3B2aA13686582`

<a href="https://etherscan.io/address/0x11282eE5726B3370c8B480e321b3B2aA13686582">
  <img src="public/publiceth.svg" alt="Ethereum donation QR code" width="220" />
</a>

_Scan the QR code or copy the wallet address above._

</div>
<!-- donation:eth:end -->


# SeekOSINT

> **Unified threat intelligence and network reconnaissance** — Query any IP, domain, or ASN to get instant security posture, infrastructure details, and threat correlations from 17 sources.

**Live at:** https://seekosint.pages.dev

```
$ seek 1.1.1.1

✓ internetdb   80, 443, 8080 open · 1 CVE
✓ geo          Cloudflare · San Francisco · US · AS13335
✓ bgp          CLOUDFLARENET · ARIN · 4 upstreams
✓ rdap         1.1.1.0/24 · CLOUDFLARENET
✓ passivedns   one.one.one.one (A, last 2024-06-01)
✓ urlhaus      no results
✓ feodo        not listed
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  12 sources queried · 8 cache hits · 340 ms
```

---

## Table of Contents

- [SeekOSINT](#seekosint)
  - [Table of Contents](#table-of-contents)
  - [What SeekOSINT does](#what-seekosint-does)
  - [Use cases](#use-cases)
  - [Architecture overview](#architecture-overview)
  - [Execution model](#execution-model)
  - [Data sources](#data-sources)
  - [Project structure](#project-structure)
  - [Key design decisions](#key-design-decisions)
    - [1. Edge-first architecture](#1-edge-first-architecture)
    - [2. Layered execution](#2-layered-execution)
    - [3. Graceful degradation](#3-graceful-degradation)
    - [4. Aggressive caching](#4-aggressive-caching)
    - [5. Free-tier optimization](#5-free-tier-optimization)
  - [TypeScript types](#typescript-types)
  - [Caching strategy](#caching-strategy)
    - [KV cache structure](#kv-cache-structure)
    - [Cache invalidation](#cache-invalidation)
  - [Key rotation](#key-rotation)
    - [GrayHatWarfare (18 keys)](#grayhatwarfare-18-keys)
  - [D1 persistence](#d1-persistence)
    - [Schema](#schema)
    - [Usage](#usage)
  - [Development setup](#development-setup)
    - [Prerequisites](#prerequisites)
    - [Local development](#local-development)
    - [Environment setup](#environment-setup)
  - [Deployment](#deployment)
    - [Cloudflare Pages](#cloudflare-pages)
    - [Wrangler configuration](#wrangler-configuration)
  - [Running tests](#running-tests)
  - [Cloudflare free-tier limits](#cloudflare-free-tier-limits)
  - [Environment variables](#environment-variables)
    - [Required](#required)
    - [Optional](#optional)
  - [License](#license)
  - [Author](#author)
  - [Acknowledgments](#acknowledgments)

---

## What SeekOSINT does

SeekOSINT is a **host intelligence tool** — paste in an IP address, a domain name, or an ASN and get back a unified report covering:

| Category | What you get |
|---|---|
| Network | Open ports, CPEs, BGP prefixes, upstreams, peers, RIR |
| Identity | RDAP registration, WHOIS contacts, registrar, nameservers |
| Geo | Country, city, ISP, proxy/hosting/mobile flags |
| Certificates | crt.sh cert history, SANs, issuer chain |
| DNS | Passive DNS records, Robtex reverse/forward DNS |
| Threats | URLhaus, ThreatFox, MalwareBazaar, Feodo, SSLBL |
| CVEs | NVD + CIRCL enrichment for every CVE ID InternetDB reports |
| Recon | GrayHatWarfare exposed buckets, Wayback CDX snapshots |

Every source is queried in parallel. A failing or slow source degrades to a "source unavailable" badge — it never breaks the page.

---

## Use cases

**Security Operations**
- Incident response: Quickly profile suspicious IPs from logs
- Threat hunting: Correlate IOCs across multiple threat feeds
- Vulnerability assessment: Identify exposed services and CVEs
- Phishing investigation: Trace malicious domains and infrastructure

**Network Operations**
- BGP troubleshooting: Inspect routing, upstreams, and peers
- IP allocation research: RDAP/WHOIS lookups for network planning
- DNS debugging: Historical DNS records and reverse lookups
- Certificate monitoring: Track SSL/TLS cert changes over time

**Penetration Testing**
- Reconnaissance: Enumerate attack surface (ports, services, CPEs)
- OSINT gathering: Discover exposed buckets, archived pages, subdomains
- Infrastructure mapping: ASN enumeration and network relationships

**Research & Education**
- Malware analysis: Check C2 infrastructure against threat feeds
- Academic research: Study internet infrastructure and threat landscape
- Security training: Demonstrate OSINT techniques and data correlation

**Compliance & Risk**
- Third-party risk assessment: Profile vendor infrastructure
- Data leak detection: Find exposed cloud storage buckets
- Shadow IT discovery: Identify unauthorized external services

---

## Architecture overview

```
Browser / curl
     │
     ▼
┌─────────────────────────────────┐
│  Cloudflare Pages               │
│  Next.js App Router (SSR)       │
│                                 │
│  app/page.tsx  ──search form──► │
│  app/host/[query]/page.tsx      │
│    └─ fetches /api/lookup?q=…   │
└────────────┬────────────────────┘
             │ edge request
             ▼
┌─────────────────────────────────┐
│  app/api/lookup/route.ts        │
│  (Cloudflare Workers runtime)   │
│  runtime = 'edge'               │
└────────────┬────────────────────┘
             │ runLookup()
             ▼
┌─────────────────────────────────┐
│  worker/lookup.ts               │  ◄─── orchestrator
│  4-layer Promise.allSettled     │
└──┬──────┬──────┬────────────────┘
   │      │      │
   │      │      └─► Layer 4: GHW + Wayback
   │      └────────► Layer 3: CVE enrichment (conditional)
   └───────────────► Layers 1+2: 12 sources in parallel
             │
             ▼
┌─────────────────┐   ┌──────────────────┐
│ Cloudflare KV   │   │ Cloudflare D1    │
│ (response cache)│   │ (search history) │
└─────────────────┘   └──────────────────┘
```

---

## Execution model

Layers 1 and 2 run **simultaneously** in a single `Promise.allSettled` batch. Layers 3 and 4 fire after Layer 1 settles because they depend on its output (CVE IDs from InternetDB for Layer 3; query type for Layer 4).

---

## Data sources

| Layer | Source | What it provides | Free tier |
|---|---|---|---|
| 1 | InternetDB | Open ports, CPEs, CVE IDs | ✅ Unlimited |
| 1 | IPinfo | Geo, ISP, ASN, hosting/proxy flags | ✅ 50k/mo |
| 1 | BGPView | BGP prefixes, upstreams, peers, RIR | ✅ Unlimited |
| 1 | RDAP | Registration data, contacts, nameservers | ✅ Unlimited |
| 2 | crt.sh | Certificate history, SANs, issuer chain | ✅ Unlimited |
| 2 | PassiveDNS | Historical DNS records | ✅ Unlimited |
| 2 | Robtex | Reverse/forward DNS | ✅ Unlimited |
| 2 | URLhaus | Malware distribution URLs | ✅ Unlimited |
| 2 | ThreatFox | IOC database | ✅ Unlimited |
| 2 | MalwareBazaar | Malware samples | ✅ Unlimited |
| 2 | Feodo Tracker | Botnet C2 tracker | ✅ Unlimited |
| 2 | SSLBL | SSL blacklist | ✅ Unlimited |
| 3 | NVD | CVE details, CVSS scores | ✅ 5 req/30s |
| 3 | CIRCL | CVE enrichment | ✅ Unlimited |
| 4 | GrayHatWarfare | Exposed S3/Azure/GCS buckets | ✅ 100 req/day |
| 4 | Wayback | Historical snapshots | ✅ Rate-limited |

---

## Project structure

```
seek/
├── app/
│   ├── page.tsx                    # Landing page with search form
│   ├── host/[query]/page.tsx       # SSR host report page
│   ├── api/lookup/route.ts         # Edge API route
│   └── layout.tsx                  # Root layout
├── worker/
│   ├── lookup.ts                   # Main orchestrator
│   ├── sources/                    # Individual source fetchers
│   │   ├── internetdb.ts
│   │   ├── ipinfo.ts
│   │   ├── bgpview.ts
│   │   ├── rdap.ts
│   │   ├── crtsh.ts
│   │   ├── passivedns.ts
│   │   ├── robtex.ts
│   │   ├── urlhaus.ts
│   │   ├── threatfox.ts
│   │   ├── malwarebazaar.ts
│   │   ├── feodo.ts
│   │   ├── sslbl.ts
│   │   ├── nvd.ts
│   │   ├── circl.ts
│   │   ├── grayhatwarfare.ts
│   │   └── wayback.ts
│   ├── cache.ts                    # KV cache wrapper
│   ├── db.ts                       # D1 search history
│   └── types.ts                    # TypeScript types
├── components/
│   ├── SearchForm.tsx
│   ├── HostReport.tsx
│   └── SourceBadge.tsx
├── lib/
│   └── utils.ts
└── public/
    └── publiceth.svg               # Donation QR code
```

---

## Key design decisions

### 1. Edge-first architecture
- Next.js App Router with `runtime = 'edge'` for sub-50ms cold starts
- Cloudflare Workers runtime for global distribution
- No Node.js dependencies — pure Web APIs

### 2. Layered execution
- Layer 1: Critical sources (InternetDB, IPinfo, BGPView, RDAP)
- Layer 2: Enrichment sources (certs, DNS, threats)
- Layer 3: CVE enrichment (conditional on Layer 1 results)
- Layer 4: Recon sources (GHW, Wayback)

### 3. Graceful degradation
- Every source wrapped in try/catch
- Timeouts prevent slow sources from blocking
- Failed sources show "unavailable" badge
- Page always renders, even if all sources fail

### 4. Aggressive caching
- KV cache with 24h TTL for all sources
- Cache key includes source name + query
- Cache hits bypass external API calls entirely
- D1 stores search history for analytics

### 5. Free-tier optimization
- GrayHatWarfare: 18-key rotation (1,800 req/day)
- NVD: Request batching + 6s delay between calls
- Wayback: Exponential backoff on rate limits
- IPinfo: 50k/mo shared across all users

---

## TypeScript types

```typescript
export interface LookupResult {
  query: string;
  queryType: 'ip' | 'domain' | 'asn';
  timestamp: number;
  sources: SourceResult[];
  cacheHits: number;
  totalTime: number;
}

export interface SourceResult {
  name: string;
  status: 'success' | 'error' | 'unavailable';
  data?: any;
  error?: string;
  cached?: boolean;
  time?: number;
}

export interface Env {
  SEEK_CACHE: KVNamespace;
  SEEK_DB: D1Database;
  GRAYHATWARFARE_API_KEY_1: string;
  GRAYHATWARFARE_API_KEY_2: string;
  // ... 16 keys total
  NVD_API_KEY: string;
  ABUSECH_KEY: string;
}
```

---

## Caching strategy

### KV cache structure
```typescript
const cacheKey = `${sourceName}:${query}`;
const cachedData = await env.SEEK_CACHE.get(cacheKey, 'json');

if (cachedData) {
  return { ...cachedData, cached: true };
}

const freshData = await fetchSource(query);
await env.SEEK_CACHE.put(cacheKey, JSON.stringify(freshData), {
  expirationTtl: 86400 // 24 hours
});
```

### Cache invalidation
- Automatic expiration after 24h
- Manual purge via Cloudflare dashboard
- No cache for errors (always retry)

---

## Key rotation

### GrayHatWarfare (18 keys)
```typescript
const keyIndex = Math.floor(Math.random() * 18) + 1;
const apiKey = env[`GRAYHATWARFARE_API_KEY_${keyIndex}`];
const username = env[`GRAYHATWARFARE_USERNAME_${keyIndex}`];
```

**Daily capacity**: 18 keys × 100 req/day = 1,800 requests/day

---

## D1 persistence

### Schema
```sql
CREATE TABLE searches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  query TEXT NOT NULL,
  query_type TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  cache_hits INTEGER,
  total_time INTEGER
);

CREATE INDEX idx_timestamp ON searches(timestamp);
CREATE INDEX idx_query ON searches(query);
```

### Usage
```typescript
await env.SEEK_DB.prepare(
  'INSERT INTO searches (query, query_type, timestamp, cache_hits, total_time) VALUES (?, ?, ?, ?, ?)'
).bind(query, queryType, Date.now(), cacheHits, totalTime).run();
```

---

## Development setup

### Prerequisites
- Node.js 18+
- Cloudflare account (free tier)
- Wrangler CLI

### Local development
```bash
# Install dependencies
npm install

# Create .dev.vars for local secrets
cp .env .dev.vars

# Run dev server
npm run dev
```

### Environment setup
```bash
# Create KV namespace
wrangler kv:namespace create SEEK_CACHE

# Create D1 database
wrangler d1 create seek-db
wrangler d1 execute seek-db --file=schema.sql

# Add secrets
wrangler secret put GRAYHATWARFARE_API_KEY_1
wrangler secret put NVD_API_KEY
wrangler secret put ABUSECH_KEY
```

---

## Deployment

### Cloudflare Pages
```bash
# Build
npm run build

# Deploy
wrangler pages deploy .next
```

### Wrangler configuration
```toml
name = "seek"
compatibility_date = "2024-01-01"

[[kv_namespaces]]
binding = "SEEK_CACHE"
id = "your-kv-id"

[[d1_databases]]
binding = "SEEK_DB"
database_name = "seek-db"
database_id = "your-d1-id"
```

---

## Running tests

```bash
# Unit tests
npm test

# Integration tests (requires .dev.vars)
npm run test:integration

# Test specific source
npm test -- worker/sources/internetdb.test.ts
```

---

## Cloudflare free-tier limits

| Service | Free tier | Seek usage |
|---|---|---|
| Pages | 500 builds/mo | ~10 deploys/mo |
| Workers | 100k req/day | ~5k req/day |
| KV | 100k reads/day | ~3k reads/day |
| KV | 1k writes/day | ~500 writes/day |
| D1 | 5M rows read/day | ~5k rows/day |
| D1 | 100k rows write/day | ~500 rows/day |

**Estimated capacity**: 5,000 unique lookups/day on free tier

---

## Environment variables

### Required
```bash
# GrayHatWarfare (16 key pairs)
GRAYHATWARFARE_API_KEY_1=...
GRAYHATWARFARE_USERNAME_1=...
# ... repeat for keys 2-16

# NVD API
NVD_API_KEY=...

# abuse.ch (URLhaus, ThreatFox, MalwareBazaar)
ABUSECH_KEY=...
```

### Optional
```bash
# IPinfo (defaults to free tier)
IPINFO_TOKEN=...
```

---

## License

**Business Source License 1.1 (BSL)**

Copyright © 2025 Teycir Ben Soltane <teycir@pxdmail.net>

Permitted use:
- Personal use
- Research and education
- Non-commercial projects
- Internal business tools

Restricted use:
- Commercial SaaS offerings
- Reselling as a service
- Competitive products

After 4 years from release date, this software converts to Apache 2.0 license.

See [LICENSE](LICENSE) for full terms.

---

## Author

**Teycir Ben Soltane**  
Email: teycir@pxdmail.net  
GitHub: [@Teycir](https://github.com/Teycir)

---

## Acknowledgments

- InternetDB (Shodan)
- IPinfo
- BGPView
- RDAP
- crt.sh
- PassiveDNS
- Robtex
- abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo, SSLBL)
- NVD (NIST)
- CIRCL
- GrayHatWarfare
- Internet Archive (Wayback Machine)

---
