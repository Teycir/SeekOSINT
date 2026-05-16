/**
 * lib/useHostStream.ts
 *
 * React hook that consumes GET /api/stream?q=<query> and returns
 * progressively-populated state that the results page can render.
 *
 * States:
 *   loading  — waiting for the first frame
 *   partial  — Layer 1+2 arrived; CVEs still pending
 *   complete — all frames received
 *   error    — stream errored or connection lost
 *
 * Usage:
 *   const { state, partial, vulns, error } = useHostStream('1.1.1.1')
 */
'use client'

import { useState, useEffect } from 'react'
import type { CVEDetail, HostResult } from './types'

// HostResult without vulns (what Frame 1 carries)
export type PartialResult = Omit<HostResult, 'vulns'>

export type StreamState = 'loading' | 'partial' | 'complete' | 'error'

export interface HostStreamResult {
  state:   StreamState
  partial: PartialResult | null
  vulns:   CVEDetail[]
  error:   string | null
}

export function useHostStream(query: string, refresh = false): HostStreamResult {
  const [state,   setState]   = useState<StreamState>('loading')
  const [partial, setPartial] = useState<PartialResult | null>(null)
  const [vulns,   setVulns]   = useState<CVEDetail[]>([])
  const [errMsg,  setErrMsg]  = useState<string | null>(null)

  useEffect(() => {
    if (!query) return

    // Reset on new query
    setState('loading')
    setPartial(null)
    setVulns([])
    setErrMsg(null)

    const url = `/api/stream?q=${encodeURIComponent(query)}${refresh ? '&refresh=1' : ''}`
    const controller = new AbortController()

    ;(async () => {
      try {
        const res = await fetch(url, { signal: controller.signal })
        if (!res.ok || !res.body) {
          setErrMsg(`HTTP ${res.status}`)
          setState('error')
          return
        }

        const reader  = res.body.getReader()
        const decoder = new TextDecoder()
        let   buffer  = ''

        while (true) {
          const { done, value } = await reader.read()
          if (done) break

          buffer += decoder.decode(value, { stream: true })
          const lines = buffer.split('\n')
          buffer = lines.pop() ?? ''   // keep incomplete last line

          for (const line of lines) {
            if (!line.trim()) continue
            try {
              const frame = JSON.parse(line) as {
                type: 'partial' | 'vulns' | 'done' | 'error'
                data: unknown
              }

              if (frame.type === 'partial') {
                setPartial(frame.data as PartialResult)
                setState('partial')
              } else if (frame.type === 'vulns') {
                setVulns(frame.data as CVEDetail[])
              } else if (frame.type === 'done') {
                setState('complete')
              } else if (frame.type === 'error') {
                const d = frame.data as { message?: string }
                setErrMsg(d.message ?? 'unknown error')
                setState('error')
              }
            } catch {
              // malformed JSON line — skip
            }
          }
        }

        // If stream closed without a 'done' frame, still mark complete
        setState(s => s === 'partial' ? 'complete' : s)
      } catch (err: unknown) {
        if ((err as { name?: string }).name === 'AbortError') return
        setErrMsg(String(err))
        setState('error')
      }
    })()

    return () => controller.abort()
  }, [query, refresh])

  return { state, partial, vulns, error: errMsg }
}
