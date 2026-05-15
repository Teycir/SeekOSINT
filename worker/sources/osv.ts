/**
 * OSV.dev — open source vulnerability database cross-reference.
 *
 * Standalone module for direct OSV queries. The NVD+CIRCL race in nvd.ts
 * handles per-CVE enrichment; this module is the OSV-specific wrapper
 * re-exported for the orchestrator.
 *
 * Endpoint: https://api.osv.dev/v1/vulns/{id}
 * Auth:     none | Limits: unlimited | TTL: 30 days
 */
export { fetchOSV } from './nvd'
