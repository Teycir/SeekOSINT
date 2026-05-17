import type { LookupQuery, QueryType } from './types'
import { sanitizeString, validateQueryInput } from './sanitize'

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i
const ASN_RE = /^as\d+$/i

/**
 * Parse raw user input into a typed, normalised LookupQuery.
 * Returns null if the input cannot be identified as a valid IP, domain, or ASN.
 *
 * Strips protocol prefixes and trailing paths before matching, so inputs like
 * "https://example.com/path" are handled gracefully.
 *
 * Includes injection detection as defense-in-depth.
 */
export function parseQuery(raw: string): LookupQuery | null {
  // Sanitize and validate input first.
  // ORDER MATTERS: sanitizeString strips injection chars (including < > ' ")
  // before we call .toLowerCase() below. Do not reorder these steps — moving
  // sanitization after lowercasing would not break anything today, but would
  // silently remove that guarantee for future callers.
  const sanitized = sanitizeString(raw, 500)
  
  // Check for injection patterns
  const validation = validateQueryInput(sanitized)
  if (!validation.valid) {
    console.warn('[validate] rejected input:', validation.reason, sanitized.slice(0, 50))
    return null
  }
  
  const s = sanitized
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')

  if (IPV4_RE.test(s) && isValidIPv4(s)) return make(raw, 'ip', s)
  if (isValidIPv6(s))                     return make(raw, 'ip', s)
  if (isValidIPv4MappedIPv6(s))           return make(raw, 'ip', s)
  if (ASN_RE.test(s))                     return make(raw, 'asn', s)
  if (DOMAIN_RE.test(s))                  return make(raw, 'domain', s)

  return null
}

function make(raw: string, type: QueryType, normalised: string): LookupQuery {
  return { raw, type, normalised }
}

/**
 * Validate an IPv4 address:
 *   - Each octet must be purely numeric (no leading zeros — they are
 *     ambiguous per RFC 6943 and rejected by most OSINT APIs).
 *   - Each octet must be in the range 0–255.
 */
function isValidIPv4(ip: string): boolean {
  return ip.split('.').every(octet => {
    if (!/^\d+$/.test(octet)) return false
    if (octet.length > 1 && octet[0] === '0') return false   // no leading zeros
    return parseInt(octet, 10) <= 255
  })
}

/**
 * Validate an IPv6 address using a structural approach rather than a
 * single monolithic regex.
 *
 * The previous regex-only approach had a critical bug: the prefix pattern
 * (?:[hex]:)* consumed the first colon of a "::" double-colon, leaving
 * only a single colon which then failed to match the "::" literal.
 * This caused addresses like "fe80::1", "2001:db8::1", and
 * "2001:4860:4860::8888" to be incorrectly rejected.
 *
 * This implementation follows RFC 4291 §2.2 strictly:
 *   - Exactly one "::" is allowed (represents one or more all-zero groups).
 *   - Without "::", exactly 8 hex groups separated by ":" are required.
 *   - With "::", left + right group counts must not exceed 7 (the "::"
 *     expands to fill the remaining groups up to 8 total).
 *   - Each group is 1–4 hex digits.
 *   - Zone IDs (e.g. "fe80::1%eth0") and embedded IPv4 suffixes are
 *     intentionally not supported here — OSINT APIs don't accept them.
 */
function isValidIPv6(s: string): boolean {
  if (s === '::') return true

  const halves = s.split('::')
  if (halves.length > 2) return false // more than one '::'

  const hexGroup = /^[0-9a-fA-F]{1,4}$/

  if (halves.length === 2) {
    // Compressed form: left::right  (either side may be empty)
    const left  = halves[0] ? halves[0].split(':') : []
    const right = halves[1] ? halves[1].split(':') : []
    if (left.length + right.length > 7) return false
    return [...left, ...right].every(g => hexGroup.test(g))
  }

  // No '::' — must be exactly 8 colon-separated hex groups
  const groups = s.split(':')
  return groups.length === 8 && groups.every(g => hexGroup.test(g))
}

/**
 * Validate an IPv4-mapped IPv6 address (RFC 4291 §2.5.5.2).
 * These have the form ::ffff:x.x.x.x or ::ffff:0:x.x.x.x.
 *
 * isValidIPv6() correctly rejects these because the IPv4 suffix is not a
 * valid hex group.  We handle them separately so users can look up
 * addresses like ::ffff:8.8.8.8 without receiving a 422.
 *
 * The SSRF guard (validateSSRFResolved) will still block any private-range
 * IPv4 suffix (e.g. ::ffff:192.168.1.1) before it reaches any upstream API.
 */
function isValidIPv4MappedIPv6(s: string): boolean {
  // Canonical forms accepted: ::ffff:a.b.c.d  and  ::ffff:0:a.b.c.d
  const mapped    = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i
  const mappedAlt = /^::ffff:0:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i
  const m = mapped.exec(s) ?? mappedAlt.exec(s)
  if (!m || !m[1]) return false
  return isValidIPv4(m[1])
}

/**
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
