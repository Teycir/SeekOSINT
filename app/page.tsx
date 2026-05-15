/**
 * Search landing page — single input, client-side validation, redirect on submit.
 */
'use client'

import { useState, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { parseQuery } from '../lib/validate'

export default function HomePage() {
  const router = useRouter()
  const [input, setInput] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const q = input.trim()
    if (!q) return

    const parsed = parseQuery(q)
    if (!parsed) {
      setValidationError('Enter a valid IPv4, IPv6, domain name, or ASN (e.g. AS15169)')
      return
    }

    setValidationError(null)
    router.push(`/host/${encodeURIComponent(parsed.normalised)}`)
  }

  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-neutral-950 px-4">
      <div className="w-full max-w-xl space-y-6">
        <div className="space-y-1 text-center">
          <h1 className="text-3xl font-semibold tracking-tight text-white">Seek</h1>
          <p className="text-sm text-neutral-400">
            Host intelligence across 12 sources — IP, domain, or ASN
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          <input
            type="text"
            value={input}
            onChange={e => {
              setInput((e.target as HTMLInputElement).value)
              setValidationError(null)
            }}
            placeholder="8.8.8.8  ·  example.com  ·  AS15169"
            className="w-full rounded-lg border border-neutral-700 bg-neutral-900 px-4 py-3 
                       text-white placeholder-neutral-500 outline-none
                       focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            autoFocus
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
          />

          {validationError && (
            <p className="text-sm text-red-400">{validationError}</p>
          )}

          <button
            type="submit"
            className="w-full rounded-lg bg-blue-600 px-4 py-3 font-medium text-white
                       transition hover:bg-blue-500 active:bg-blue-700"
          >
            Look up
          </button>
        </form>
      </div>
    </main>
  )
}
