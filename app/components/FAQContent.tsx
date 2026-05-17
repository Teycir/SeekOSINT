'use client'

import { motion } from 'framer-motion'
import { BackgroundBeams } from './ui/background-beams'
import { Card } from './Card'
import DecryptedText from './DecryptedText'

export function FAQContent() {
  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative w-full overflow-hidden pb-20">
      <BackgroundBeams className="absolute top-0 left-0 w-full h-full z-0" />
      <div className="max-w-4xl w-full space-y-8 relative z-10">

        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-12"
        >
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-bold mb-4 px-2"
            style={{ textShadow: '0 0 10px rgba(255,26,26,0.5), 0 0 20px rgba(255,26,26,0.3)' }}>
            <DecryptedText text="FAQ" animateOn="view" className="text-neon-red" speed={75} maxIterations={20} />
          </h1>
          <p className="text-neon-red/70 text-sm sm:text-base px-4">Frequently Asked Questions</p>
        </motion.div>

        <Card className="p-4 sm:p-6 md:p-8 space-y-6">

          <div>
            <h2 className="text-base sm:text-lg font-bold text-neon-red mb-2">What input formats does SeekYou accept?</h2>
            <p className="text-neon-red/60 text-sm mb-2">SeekYou automatically detects and normalises:</p>
            <ul className="list-disc list-inside ml-4 space-y-1 text-xs text-neon-red/60">
              <li><strong className="text-neon-red">IPv4:</strong> plain dotted-decimal, e.g. <code>1.1.1.1</code></li>
              <li><strong className="text-neon-red">IPv6:</strong> full or compressed notation, e.g. <code>2606:4700:4700::1111</code></li>
              <li><strong className="text-neon-red">Domain:</strong> with or without <code>http://</code>, trailing slashes stripped</li>
              <li><strong className="text-neon-red">ASN:</strong> <code>AS15169</code> or plain <code>15169</code></li>
            </ul>
          </div>

          <div>
            <h2 className="text-base sm:text-lg font-bold text-neon-red mb-2">How many sources does SeekYou query?</h2>
            <p className="text-neon-red/60 text-sm">Up to 15, depending on query type. All sources are queried in parallel — the page renders results as each source responds rather than waiting for all to finish.</p>
          </div>

          <div>
            <h2 className="text-base sm:text-lg font-bold text-neon-red mb-2">Does SeekYou actively scan targets?</h2>
            <p className="text-neon-red/60 text-sm">No. SeekYou is entirely <strong className="text-neon-red">passive</strong>. It only queries existing public databases and APIs. No packets are sent to the target host.</p>
          </div>

          <div>
            <h2 className="text-base sm:text-lg font-bold text-neon-red mb-2">Are my queries logged?</h2>
            <p className="text-neon-red/60 text-sm">SeekYou stores only anonymous recent-search query strings (not IPs) for the homepage recent-searches widget. No user identity is tracked. Upstream APIs may log queries on their end per their own privacy policies.</p>
          </div>

          <div>
            <h2 className="text-base sm:text-lg font-bold text-neon-red mb-2">Why do some sources show &quot;unavailable&quot;?</h2>
            <p className="text-neon-red/60 text-sm mb-2">A source may be unavailable for several reasons:</p>
            <ul className="list-disc list-inside ml-4 space-y-1 text-xs text-neon-red/60">
              <li>The source timed out (20 second limit)</li>
              <li>The source&apos;s circuit breaker tripped after repeated failures — it auto-recovers in 15 minutes</li>
              <li>The source does not support the queried type (e.g. some sources are IP-only)</li>
            </ul>
          </div>

          <div>
            <h2 className="text-base sm:text-lg font-bold text-neon-red mb-2">What are the rate limits?</h2>
            <p className="text-neon-red/60 text-sm"><strong className="text-neon-red">500 requests per hour</strong> per IP on a rolling window. If you hit the limit you&apos;ll receive a 429 response. Self-hosting with your own API keys removes this constraint.</p>
          </div>

          <div>
            <h2 className="text-base sm:text-lg font-bold text-neon-red mb-2">Can I look up private / RFC-1918 addresses?</h2>
            <p className="text-neon-red/60 text-sm">Private ranges (10.x, 172.16–31.x, 192.168.x) are rejected at validation. They have no meaningful public intelligence data.</p>
          </div>

          <div>
            <h2 className="text-base sm:text-lg font-bold text-neon-red mb-2">Is SeekYou open source?</h2>
            <p className="text-neon-red/60 text-sm">Yes. The source is available on <a href="https://github.com/teycir/SeekYou" target="_blank" rel="noopener noreferrer" className="underline hover:text-neon-red">GitHub</a> under the project license. Contributions, bug reports, and source suggestions are welcome.</p>
          </div>

          <div>
            <h2 className="text-base sm:text-lg font-bold text-neon-red mb-2">Is it legal to use SeekYou?</h2>
            <p className="text-neon-red/60 text-sm">SeekYou only queries public data sources — there is no active probing. However, you are responsible for complying with the terms of service of each underlying source and the laws of your jurisdiction. Only investigate hosts you own or have explicit authorisation to investigate.</p>
          </div>

          <div>
            <h2 className="text-base sm:text-lg font-bold text-neon-red mb-2">How current is the data?</h2>
            <p className="text-neon-red/60 text-sm">Each source has its own data freshness — from live DNS resolution to 12-hour certificate caches to 24-hour BGP snapshots. Results are KV-cached at the edge for performance; hit the refresh button to bypass the cache and fetch live data.</p>
          </div>

          <div>
            <h2 className="text-base sm:text-lg font-bold text-neon-red mb-2">Can I use SeekYou programmatically?</h2>
            <p className="text-neon-red/60 text-sm">The worker exposes a JSON API at <code className="text-neon-red/80">/api/lookup?q=&lt;target&gt;</code>. Self-host your own instance for higher throughput and direct API access without rate limits.</p>
          </div>

          <div>
            <h2 className="text-base sm:text-lg font-bold text-neon-red mb-2">How do I self-host SeekYou?</h2>
            <ul className="list-disc list-inside ml-4 space-y-1 text-xs text-neon-red/60">
              <li>Clone the repo from GitHub</li>
              <li>Copy <code className="text-neon-red/80">.env.example</code> → <code className="text-neon-red/80">.env</code> and fill in your API keys</li>
              <li>Run <code className="text-neon-red/80">npm install</code> then <code className="text-neon-red/80">npm run dev</code> for local dev</li>
              <li>Deploy with <code className="text-neon-red/80">npm run deploy</code> (Cloudflare Pages via OpenNext)</li>
            </ul>
          </div>

        </Card>

        <div className="text-center pt-4">
          <a href="/"
            className="inline-block px-6 py-3 border-2 border-neon-red/50 text-neon-red/70 font-bold font-mono
                       uppercase tracking-wider rounded-lg transition-all duration-300
                       hover:border-neon-red hover:bg-neon-red/5 hover:text-neon-red
                       hover:shadow-[0_0_20px_rgba(255,26,26,0.2)]">
            LOOK UP A HOST
          </a>
        </div>

      </div>
    </div>
  )
}
