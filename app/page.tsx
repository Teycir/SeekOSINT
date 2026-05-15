/**
 * Search landing page — single input, client-side validation, redirect on submit.
 */
'use client'

import { useState, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { parseQuery } from '../lib/validate'
import DecryptedText from './components/DecryptedText'
import { AnimatedTagline } from './components/AnimatedTagline'
import { RecentSearches } from './components/RecentSearches'

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
    <main className="flex min-h-[85vh] flex-col items-center justify-center px-4">
      {/* Background glow */}
      <div className="pointer-events-none fixed inset-0 flex items-center justify-center">
        <div className="h-[600px] w-[600px] rounded-full bg-neon-red/5 blur-[120px]" />
      </div>

      <div className="relative w-full max-w-xl space-y-8">
        {/* Header */}
        <div className="space-y-2 text-center">
          <h1 className="text-4xl font-bold tracking-tight text-neon-red glow-text pulse-glow font-mono">
            <DecryptedText 
              text="seekosint" 
              speed={30}
              maxIterations={8}
              animateOn="view"
              className="text-neon-red"
              encryptedClassName="text-neon-red/50"
            />
          </h1>
          <AnimatedTagline text="Host intelligence across 12 sources — IP, domain, or ASN" />
        </div>

        {/* Form */}
        <div className="space-y-3">
          <input
            type="text"
            value={input}
            onChange={e => {
              setInput((e.target as HTMLInputElement).value)
              setValidationError(null)
            }}
            onKeyDown={e => e.key === 'Enter' && handleSubmit(e as unknown as FormEvent)}
            placeholder="8.8.8.8  ·  example.com  ·  AS15169"
            className={`w-full rounded-lg border-2 bg-black/50 px-4 py-3 font-mono text-neon-red
                        placeholder-neon-red/20 outline-none transition-all
                        focus:border-neon-red focus:shadow-[0_0_15px_rgba(255,26,26,0.3)]
                        ${validationError
                          ? 'border-red-500/70 input-error'
                          : 'border-neon-red/30 hover:border-neon-red/50'
                        }`}
            autoFocus
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
          />

          {validationError && (
            <p className="text-sm text-red-400 font-mono">{validationError}</p>
          )}

          <button
            onClick={handleSubmit}
            className="w-full rounded-lg border-2 border-neon-red/50 bg-transparent px-4 py-3
                       font-mono font-bold uppercase tracking-wider text-neon-red/70
                       transition-all duration-300
                       hover:border-neon-red hover:bg-neon-red/5 hover:text-neon-red
                       hover:shadow-[0_0_20px_rgba(255,26,26,0.2)]
                       active:scale-[0.98]"
          >
            Look up
          </button>
        </div>

        {/* Sources hint */}
        <p className="text-center text-xs text-neon-red/30 font-mono">
          InternetDB · IPinfo · BGPView · RDAP · crt.sh · PassiveDNS · and 11 more
        </p>

        {/* Recent searches — client-fetched from D1, hidden when empty */}
        <RecentSearches />
      </div>
    </main>
  )
}
