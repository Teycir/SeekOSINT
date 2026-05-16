import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

/**
 * Middleware — runs at the edge before every response.
 *
 * Primary job: set a permissive Content-Security-Policy that allows
 * Cloudflare Turnstile to function correctly.
 *
 * WHY THIS EXISTS:
 * Cloudflare Pages rewrites the CSP header set in public/_headers,
 * replacing it with a nonce-based policy (`nonce-<random>` per request)
 * that strips 'unsafe-inline'. Turnstile's challenge iframe injects
 * inline scripts that need 'unsafe-inline', and its Web Worker needs
 * 'unsafe-eval'. Without both, Turnstile fails with:
 *   - "TrustedHTML/TrustedScript assignment blocked"
 *   - "Form submission canceled because the form is not connected"
 *
 * Setting the header from middleware runs INSIDE the Worker, after
 * Cloudflare Pages' header rewrite layer, so it takes precedence.
 *
 * SECURITY NOTE:
 * 'unsafe-inline' is required specifically for Turnstile's srcdoc iframe.
 * 'unsafe-eval' is required for Turnstile's Web Worker.
 * These are Cloudflare's own requirements — see:
 * https://developers.cloudflare.com/turnstile/reference/content-security-policy/
 */

const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://challenges.cloudflare.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "frame-src https://challenges.cloudflare.com",
  "connect-src 'self' https://challenges.cloudflare.com",
  "worker-src blob:",
  "child-src blob: https://challenges.cloudflare.com",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self' https://challenges.cloudflare.com",
].join('; ')

export function middleware(request: NextRequest) {
  const response = NextResponse.next()

  // Override whatever CSP Cloudflare Pages set — ours wins because
  // middleware runs after the Pages header injection layer.
  response.headers.set('Content-Security-Policy', CSP)

  // Keep the Permissions-Policy clean (suppress Turnstile's FLoC warnings)
  response.headers.set(
    'Permissions-Policy',
    'browsing-topics=(), interest-cohort=()',
  )

  return response
}

export const config = {
  // Run on all routes except static assets and _next internals
  matcher: [
    '/((?!_next/static|_next/image|favicon|apple-icon|icon|robots|sitemap).*)',
  ],
}
