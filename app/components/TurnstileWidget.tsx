'use client'

/**
 * TurnstileWidget.tsx
 *
 * Renders the Cloudflare Turnstile challenge widget explicitly.
 * Uses appearance="interaction-only" so the widget is invisible to human
 * visitors on clean traffic, and only shows a challenge when Cloudflare
 * decides it's needed — matching the "Managed" mode in the dashboard.
 *
 * The widget fires onSuccess(token) once a token is issued. Tokens expire
 * after 300 seconds; the parent should call reset() if the user takes too
 * long before submitting.
 *
 * Usage:
 *   <TurnstileWidget siteKey={SITE_KEY} onSuccess={setToken} ref={widgetRef} />
 *   widgetRef.current?.reset()
 */

import { useEffect, useRef, useImperativeHandle, forwardRef } from 'react'

declare global {
  interface Window {
    turnstile: {
      render: (container: string | HTMLElement, options: TurnstileOptions) => string
      reset: (widgetId: string) => void
      remove: (widgetId: string) => void
      getResponse: (widgetId: string) => string | undefined
    }
    onTurnstileLoad?: () => void
  }
}

interface TurnstileOptions {
  sitekey: string
  callback: (token: string) => void
  'error-callback'?: () => void
  'expired-callback'?: () => void
  theme?: 'light' | 'dark' | 'auto'
  language?: string
}

export interface TurnstileWidgetRef {
  reset: () => void
}

interface TurnstileWidgetProps {
  siteKey: string
  onSuccess: (token: string) => void
  onError?: () => void
  onExpire?: () => void
}

const TURNSTILE_SCRIPT_SRC =
  'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'

export const TurnstileWidget = forwardRef<TurnstileWidgetRef, TurnstileWidgetProps>(
  function TurnstileWidget({ siteKey, onSuccess, onError, onExpire }, ref) {
    const containerRef = useRef<HTMLDivElement>(null)
    const widgetIdRef  = useRef<string | null>(null)

    useImperativeHandle(ref, () => ({
      reset() {
        if (widgetIdRef.current != null && window.turnstile) {
          window.turnstile.reset(widgetIdRef.current)
        }
      },
    }))

    useEffect(() => {
      function renderWidget() {
        if (!containerRef.current || !window.turnstile) return
        // Avoid double-rendering if effect runs twice (StrictMode)
        if (widgetIdRef.current != null) return
        const options: TurnstileOptions = {
          sitekey:  siteKey,
          theme:    'dark',
          callback: onSuccess,
        }
        if (onError) options['error-callback'] = onError
        if (onExpire) options['expired-callback'] = onExpire
        widgetIdRef.current = window.turnstile.render(containerRef.current, options)
      }

      if (window.turnstile) {
        // Script already loaded (e.g. navigating back to this page)
        renderWidget()
      } else if (!document.querySelector(`script[src="${TURNSTILE_SCRIPT_SRC}"]`)) {
        // First load — inject script and render on callback
        window.onTurnstileLoad = renderWidget
        const script = document.createElement('script')
        script.src   = `${TURNSTILE_SCRIPT_SRC}&onload=onTurnstileLoad`
        script.async = true
        script.defer = true
        document.head.appendChild(script)
      } else {
        // Script tag exists but not yet executed — poll briefly
        const timer = setInterval(() => {
          if (window.turnstile) {
            clearInterval(timer)
            renderWidget()
          }
        }, 50)
        return () => clearInterval(timer)
      }

      return () => {
        if (widgetIdRef.current != null && window.turnstile) {
          window.turnstile.remove(widgetIdRef.current)
          widgetIdRef.current = null
        }
      }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [siteKey])

    return <div ref={containerRef} />
  },
)
