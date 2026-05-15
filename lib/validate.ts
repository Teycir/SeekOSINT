import type { LookupQuery, QueryType } from './types'

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/
const IPV6_RE = /^[0-9a-fA-F:]{2,39}$/
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i
const ASN_RE = /^as\d+$/i

/**
 * Parse raw user input into a typed, normalised LookupQuery.
 * Returns null if the input cannot be identified as a valid IP, domain, or ASN.
 *
 * Strips protocol prefixes and trailing paths before matching, so inputs like
 * "https://example.com/path" are handled gracefully.
 */
export function parseQuery(raw: string): LookupQuery | null {
  const s = raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')

  if (IPV4_RE.test(s) && isValidIPv4(s)) return make(raw, 'ip', s)
  if (IPV6_RE.test(s))                   return make(raw, 'ip', s)
  if (ASN_RE.test(s))                    return make(raw, 'asn', s)
  if (DOMAIN_RE.test(s))                 return make(raw, 'domain', s)

  return null
}

function make(raw: string, type: QueryType, normalised: string): LookupQuery {
  return { raw, type, normalised }
}

function isValidIPv4(ip: string): boolean {
  return ip.split('.').every(octet => parseInt(octet, 10) <= 255)
}

/**
 * Collect numbered wrangler secrets into an array.
 * e.g. collectSecrets(env, 'GHW_KEY', 18) → [env.GHW_KEY_1, ..., env.GHW_KEY_18]
 * Filters out undefined/empty values so callers get only bound keys.
 */
export function collectSecrets(
  env: Record<string, unknown>,
  prefix: string,
  count: number,
): string[] {
  const keys: string[] = []
  for (let i = 1; i <= count; i++) {
    const val = env[`${prefix}_${i}`]
    if (typeof val === 'string' && val.length > 0) keys.push(val)
  }
  return keys
}
