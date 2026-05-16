/**
 * lib/turnstile.ts — Cloudflare Turnstile server-side token verification.
 *
 * Uses the siteverify endpoint to validate tokens issued by the Turnstile
 * widget on the client. When TURNSTILE_SECRET_KEY is not configured (local
 * dev or CI), verification is skipped and the request is allowed through.
 *
 * Docs: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
 */

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'

export interface TurnstileVerifyResult {
  success: boolean
  /** Populated when success is false */
  reason?: string
}

/**
 * Verify a Turnstile token returned by the client widget.
 *
 * @param token   - the cf-turnstile-response value from the client
 * @param secret  - TURNSTILE_SECRET_KEY from env (undefined = skip in dev)
 * @param ip      - optional client IP for additional validation
 */
export async function verifyTurnstileToken(
  token: string | null,
  secret: string | undefined,
  ip?: string,
): Promise<TurnstileVerifyResult> {
  // Skip verification when secret is not configured (local dev / CI)
  if (!secret) {
    return { success: true }
  }

  if (!token) {
    return { success: false, reason: 'missing turnstile token' }
  }

  try {
    const body = new URLSearchParams({
      secret,
      response: token,
      ...(ip ? { remoteip: ip } : {}),
    })

    const res = await fetch(SITEVERIFY_URL, {
      method: 'POST',
      body,
    })

    if (!res.ok) {
      return { success: false, reason: `siteverify HTTP ${res.status}` }
    }

    let data: { success: boolean; 'error-codes'?: string[] }
    try {
      data = await res.json() as { success: boolean; 'error-codes'?: string[] }
    } catch (parseErr) {
      console.error('[turnstile] siteverify response is not valid JSON', parseErr)
      return { success: false, reason: 'siteverify returned non-JSON response' }
    }

    if (!data.success) {
      return {
        success: false,
        reason: data['error-codes']?.join(',') ?? 'turnstile rejected',
      }
    }

    return { success: true }
  } catch (err) {
    // Network failure verifying — fail CLOSED to prevent bot protection bypass.
    // A siteverify outage should not silently allow all requests through.
    console.error('[turnstile] siteverify error — failing closed', err)
    return { success: false, reason: 'siteverify unreachable' }
  }
}
