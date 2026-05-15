'use client';

import { motion } from 'framer-motion';
import { BackgroundBeams } from '../components/ui/background-beams';
import { Card } from '../components/Card';
import DecryptedText from '../components/DecryptedText';

export default function FAQPage() {
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
            <h3 className="text-base sm:text-lg font-bold text-neon-red mb-2">What input formats does Seek accept?</h3>
            <p className="text-neon-red/60 text-sm mb-2">Seek automatically detects and normalises:</p>
            <ul className="list-disc list-inside ml-4 space-y-1 text-xs text-neon-red/60">
              <li><strong className="text-neon-red">IPv4:</strong> plain dotted-decimal, e.g. <code>1.1.1.1</code></li>
              <li><strong className="text-neon-red">IPv6:</strong> full or compressed notation, e.g. <code>2606:4700:4700::1111</code></li>
              <li><strong className="text-neon-red">Domain:</strong> with or without <code>http://</code>, trailing slashes stripped</li>
              <li><strong className="text-neon-red">ASN:</strong> <code>AS15169</code> or plain <code>15169</code></li>
            </ul>
          </div>

          <div>
            <h3 className="text-base sm:text-lg font-bold text-neon-red mb-2">How many sources does Seek query?</h3>
            <p className="text-neon-red/60 text-sm">Up to 12, depending on query type and which API keys are configured. All sources are queried in parallel — the page renders results as each source responds rather than waiting for all to finish.</p>
          </div>

          <div>
            <h3 className="text-base sm:text-lg font-bold text-neon-red mb-2">Does Seek actively scan targets?</h3>
            <p className="text-neon-red/60 text-sm">No. Seek is entirely <strong className="text-neon-red">passive</strong>. It only queries existing public databases and APIs. No packets are sent to the target host.</p>
          </div>

          <div>
            <h3 className="text-base sm:text-lg font-bold text-neon-red mb-2">Are my queries logged?</h3>
            <p className="text-neon-red/60 text-sm">Seek does not store query history or associate queries with users. Upstream APIs (Shodan, VirusTotal, etc.) may log queries on their end per their own privacy policies.</p>
          </div>

          <div>
            <h3 className="text-base sm:text-lg font-bold text-neon-red mb-2">Why do some sources show &quot;unavailable&quot;?</h3>
            <p className="text-neon-red/60 text-sm mb-2">A source may be unavailable for several reasons:</p>
            <ul className="list-disc list-inside ml-4 space-y-1 text-xs text-neon-red/60">
              <li>API key not configured for that source</li>
              <li>The source timed out (&gt; 8 seconds)</li>
              <li>Rate limit exceeded for that source</li>
              <li>The source does not support the queried type (e.g. some sources are IP-only)</li>
            </ul>
          </div>

          <div>
            <h3 className="text-base sm:text-lg font-bold text-neon-red mb-2">What are the rate limits?</h3>
            <p className="text-neon-red/60 text-sm mb-2"><strong className="text-neon-red">Per IP:</strong> 10 requests per minute, burst of 3.</p>
            <p className="text-neon-red/60 text-sm">If you hit the limit you&apos;ll receive a 429 response. Limits reset on a rolling window. Self-hosting with your own API keys removes this constraint.</p>
          </div>

          <div>
            <h3 className="text-base sm:text-lg font-bold text-neon-red mb-2">Can I look up private / RFC-1918 addresses?</h3>
            <p className="text-neon-red/60 text-sm">Private ranges (10.x, 172.16–31.x, 192.168.x) are rejected at validation. They have no meaningful public intelligence data and would return empty results from every source.</p>
          </div>

          <div>
            <h3 className="text-base sm:text-lg font-bold text-neon-red mb-2">How do I get a Shodan / VirusTotal API key?</h3>
            <p className="text-neon-red/60 text-sm mb-2">Each source has its own free tier:</p>
            <ul className="list-disc list-inside ml-4 space-y-1 text-xs text-neon-red/60">
              <li><strong className="text-neon-red">Shodan:</strong> <a href="https://account.shodan.io/register" target="_blank" rel="noopener noreferrer" className="underline hover:text-neon-red">account.shodan.io/register</a> — free dev key</li>
              <li><strong className="text-neon-red">VirusTotal:</strong> <a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noopener noreferrer" className="underline hover:text-neon-red">virustotal.com/gui/join-us</a> — free API tier</li>
              <li><strong className="text-neon-red">AbuseIPDB:</strong> <a href="https://www.abuseipdb.com/register" target="_blank" rel="noopener noreferrer" className="underline hover:text-neon-red">abuseipdb.com/register</a> — free tier</li>
              <li><strong className="text-neon-red">ipinfo:</strong> <a href="https://ipinfo.io/signup" target="_blank" rel="noopener noreferrer" className="underline hover:text-neon-red">ipinfo.io/signup</a> — 50k req/month free</li>
            </ul>
          </div>

          <div>
            <h3 className="text-base sm:text-lg font-bold text-neon-red mb-2">How do I self-host Seek?</h3>
            <ul className="list-disc list-inside ml-4 space-y-1 text-xs text-neon-red/60">
              <li>Clone the repo from GitHub</li>
              <li>Copy <code className="text-neon-red/80">.env.example</code> → <code className="text-neon-red/80">.env</code> and fill in your API keys</li>
              <li>Run <code className="text-neon-red/80">npm install</code> then <code className="text-neon-red/80">npm run dev</code> for local dev</li>
              <li>Deploy with <code className="text-neon-red/80">npm run deploy</code> (Cloudflare Pages via OpenNext)</li>
            </ul>
          </div>

          <div>
            <h3 className="text-base sm:text-lg font-bold text-neon-red mb-2">Is Seek open source?</h3>
            <p className="text-neon-red/60 text-sm">Yes. The source is available on GitHub under the project license. Contributions, bug reports, and source suggestions are welcome.</p>
          </div>

          <div>
            <h3 className="text-base sm:text-lg font-bold text-neon-red mb-2">Is it legal to use Seek?</h3>
            <p className="text-neon-red/60 text-sm">Seek only queries public data sources — there is no active probing of any kind. However, you are responsible for complying with the terms of service of each underlying source and the laws of your jurisdiction. Only investigate hosts you own or have explicit authorisation to investigate.</p>
          </div>

          <div>
            <h3 className="text-base sm:text-lg font-bold text-neon-red mb-2">How current is the data?</h3>
            <p className="text-neon-red/60 text-sm">Each source has its own data freshness. Shodan scans can be days to weeks old. DNS records are live. VirusTotal reputation data is updated continuously. Seek surfaces the timestamp where available so you know how fresh each result is.</p>
          </div>

          <div>
            <h3 className="text-base sm:text-lg font-bold text-neon-red mb-2">Can I use Seek programmatically?</h3>
            <p className="text-neon-red/60 text-sm">The worker exposes a JSON API at <code className="text-neon-red/80">/api/lookup?q=&lt;target&gt;</code>. Self-host your own instance for higher throughput and direct API access without rate limits.</p>
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
  );
}
