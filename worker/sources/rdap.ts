/**
 * RDAP — registration data for IPs and domains.
 *
 * Uses IANA bootstrap to route to the correct RDAP registry per IP block /
 * domain TLD. Bootstrap responses are themselves cached for 24 hours.
 *
 * IP:     ARIN → RIPE → APNIC → LACNIC → AFRINIC fallback chain
 * Domain: TLD-specific registry via IANA dns.json bootstrap
 * Auth:   none | Limits: unlimited | TTL: 24 hours
 */
import type { LookupQuery, RDAPContact, RDAPResult, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped } from '../../lib/results'

const SOURCE = 'rdap'

// ─── Bootstrap ───────────────────────────────────────────────────────────────

interface BootstrapEntry {
  services: [string[], string[]][]
}

async function getRDAPBaseForDomain(
  tld: string,
  kv: KVNamespace,
): Promise<string | null> {
  let boot = await cacheGet<BootstrapEntry>(kv, CacheKey.rdapBootDNS())
  if (!boot) {
    try {
      const res = await fetch('https://data.iana.org/rdap/dns.json', {
        signal: AbortSignal.timeout(8000),
      })
      if (!res.ok) return null
      boot = await res.json<BootstrapEntry>()
      await cachePut(kv, CacheKey.rdapBootDNS(), boot, TTL.RDAP)
    } catch {
      return null
    }
  }
  for (const [tlds, urls] of boot.services) {
    if (tlds.includes(tld) && urls[0]) return urls[0]
  }
  return null
}

async function getRDAPBaseForIP(
  ip: string,
  kv: KVNamespace,
): Promise<string> {
  // ARIN is the default — if it 404s we let callers fall back
  let boot = await cacheGet<BootstrapEntry>(kv, CacheKey.rdapBootIP())
  if (!boot) {
    try {
      const res = await fetch('https://data.iana.org/rdap/ipv4.json', {
        signal: AbortSignal.timeout(8000),
      })
      if (res.ok) {
        boot = await res.json<BootstrapEntry>()
        await cachePut(kv, CacheKey.rdapBootIP(), boot, TTL.RDAP)
      }
    } catch {
      // Fall through to ARIN default
    }
  }
  if (boot) {
    for (const [ranges, urls] of boot.services) {
      for (const cidr of ranges) {
        const base = parseInt(cidr.split('.')[0] ?? '0', 10)
        const bits = parseInt(cidr.split('/')[1] ?? '0', 10)
        const mask = ~((1 << (32 - bits)) - 1) >>> 0
        const ipInt = ip.split('.').reduce((acc, o) => (acc << 8) | parseInt(o, 10), 0) >>> 0
        const netInt = (base << 24) >>> 0
        if ((ipInt & mask) === (netInt & mask) && urls[0]) return urls[0]
      }
    }
  }
  return 'https://rdap.arin.net/registry/'
}

// ─── Normalisers ─────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseContacts(entities: any[]): RDAPContact[] {
  if (!Array.isArray(entities)) return []
  return entities.map(e => {
    const vcard = e.vcardArray?.[1] ?? []
    const email = vcard.find((v: string[]) => v[0] === 'email')?.[3] as string | undefined
    const org   = vcard.find((v: string[]) => v[0] === 'org')?.[3] as string | undefined
    return {
      role: (e.roles?.[0] ?? 'unknown') as string,
      ...(email !== undefined && { email }),
      ...(org !== undefined && { org }),
    }
  })
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normaliseIP(json: any): RDAPResult {
  const cidrBlock = json.cidr0_cidrs?.[0]
  return {
    ip:          json.startAddress,
    ...(cidrBlock && { cidr: `${cidrBlock.v4prefix}/${cidrBlock.length}` }),
    ...(json.name && { networkName: json.name }),
    ...(json.country && { country: json.country }),
    contacts:    parseContacts(json.entities ?? []),
    ...(json.status && { status: json.status }),
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normaliseDomain(json: any): RDAPResult {
  const events: { eventAction: string; eventDate: string }[] = json.events ?? []
  const getEvent = (action: string) =>
    events.find(e => e.eventAction === action)?.eventDate

  const registrar = json.entities?.find((e: { roles: string[] }) =>
    e.roles?.includes('registrar'))?.vcardArray?.[1]
    ?.find((v: string[]) => v[0] === 'fn')?.[3] as string | undefined

  const created = getEvent('registration')
  const expires = getEvent('expiration')
  const updated = getEvent('last changed')

  return {
    domain: json.ldhName ?? json.unicodeName,
    ...(registrar !== undefined && { registrar }),
    ...(created !== undefined && { created }),
    ...(expires !== undefined && { expires }),
    ...(updated !== undefined && { updated }),
    nameservers: (json.nameservers ?? []).map(
                   (ns: { ldhName: string }) => ns.ldhName),
    status:      json.status,
    contacts:    parseContacts(json.entities ?? []),
  }
}

// ─── Main fetch ──────────────────────────────────────────────────────────────

export async function fetchRDAP(
  query: LookupQuery,
  kv: KVNamespace,
): Promise<SourceResult<RDAPResult>> {
  if (query.type === 'asn') return skipped(SOURCE)

  const cacheKey = query.type === 'ip'
    ? CacheKey.rdapIP(query.normalised)
    : CacheKey.rdapDomain(query.normalised)

  const cached = await cacheGet<RDAPResult>(kv, cacheKey)
  if (cached) return ok(SOURCE, cached, true)

  try {
    let url: string

    if (query.type === 'ip') {
      const base = await getRDAPBaseForIP(query.normalised, kv)
      url = `${base}ip/${query.normalised}`
    } else {
      const tld = query.normalised.split('.').pop() ?? ''
      const base = await getRDAPBaseForDomain(tld, kv)
        ?? 'https://rdap.verisign.com/com/v1/'
      url = `${base}domain/${query.normalised}`
    }

    const res = await fetch(url, { signal: AbortSignal.timeout(8000) })

    if (!res.ok) {
      console.error(`[${SOURCE}] HTTP ${res.status} for ${query.normalised}`)
      return error(SOURCE, `HTTP ${res.status}`)
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const json = await res.json<any>()
    const data = query.type === 'ip' ? normaliseIP(json) : normaliseDomain(json)

    await cachePut(kv, cacheKey, data, TTL.RDAP)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
