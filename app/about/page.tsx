'use client';

import { motion } from 'framer-motion';
import { BackgroundBeams } from '../components/ui/background-beams';
import { Card } from '../components/Card';
import DecryptedText from '../components/DecryptedText';
import { Search, Globe, Shield, Zap, Server, Eye, GitBranch } from 'lucide-react';

export default function AboutPage() {
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
            <DecryptedText text="HOW TO USE" animateOn="view" className="text-neon-red" speed={60} maxIterations={20} />
          </h1>
          <p className="text-neon-red/70 text-sm sm:text-base px-4">
            Host intelligence across 12 sources — in seconds
          </p>
        </motion.div>

        <Card className="p-4 sm:p-6 md:p-8 space-y-6">
          <h2 className="text-xl sm:text-2xl font-bold text-neon-red mb-4 flex items-center gap-2">
            <Search className="w-6 h-6" /> What is Seek?
          </h2>
          <p className="text-neon-red/60 text-sm leading-relaxed">
            Seek is an OSINT (Open Source Intelligence) tool that aggregates host data from 12
            different intelligence sources into a single, unified view. Enter any IP address,
            domain name, or ASN and get a comprehensive threat and infrastructure profile instantly.
          </p>
        </Card>

        <Card className="p-4 sm:p-6 md:p-8 space-y-6">
          <h2 className="text-xl sm:text-2xl font-bold text-neon-red mb-4 flex items-center gap-2">
            <Zap className="w-6 h-6" /> Quick Start
          </h2>
          <div className="space-y-4 text-sm text-neon-red/60">
            <div>
              <p className="text-neon-red font-bold mb-2">1. Enter a target</p>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li><strong className="text-neon-red">IPv4:</strong> e.g. <code className="text-neon-red/80">8.8.8.8</code></li>
                <li><strong className="text-neon-red">IPv6:</strong> e.g. <code className="text-neon-red/80">2001:4860:4860::8888</code></li>
                <li><strong className="text-neon-red">Domain:</strong> e.g. <code className="text-neon-red/80">example.com</code></li>
                <li><strong className="text-neon-red">ASN:</strong> e.g. <code className="text-neon-red/80">AS15169</code></li>
              </ul>
            </div>
            <div>
              <p className="text-neon-red font-bold mb-2">2. Hit Look up</p>
              <p>Seek validates your input and routes you to a results page. Queries are normalised automatically — no need to strip <code className="text-neon-red/80">http://</code> or trailing slashes.</p>
            </div>
            <div>
              <p className="text-neon-red font-bold mb-2">3. Read the report</p>
              <p>Results are fetched in parallel from all available sources and displayed as soon as each one responds. Slow or unavailable sources time out gracefully without blocking the rest.</p>
            </div>
          </div>
        </Card>

        <Card className="p-4 sm:p-6 md:p-8 space-y-6">
          <h2 className="text-xl sm:text-2xl font-bold text-neon-red mb-4 flex items-center gap-2">
            <Globe className="w-6 h-6" /> Intelligence Sources
          </h2>
          <p className="text-neon-red/60 text-sm leading-relaxed mb-4">
            Seek queries up to 12 sources depending on the query type. Not all sources support all query types.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm text-neon-red/60">
            <div>
              <p className="text-neon-red font-bold mb-2">Threat Intelligence</p>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Shodan — banners, ports, CVEs</li>
                <li>VirusTotal — malware / URL reputation</li>
                <li>AbuseIPDB — abuse reports &amp; confidence</li>
                <li>AlienVault OTX — threat indicators</li>
              </ul>
            </div>
            <div>
              <p className="text-neon-red font-bold mb-2">Network &amp; DNS</p>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>ipinfo.io — geolocation, ASN, carrier</li>
                <li>Cloudflare DNS — authoritative records</li>
                <li>BGP.tools — routing, prefix, peers</li>
                <li>RDAP / WHOIS — registration data</li>
              </ul>
            </div>
            <div>
              <p className="text-neon-red font-bold mb-2">Certificates &amp; Web</p>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>crt.sh — certificate transparency logs</li>
                <li>SecurityTrails — DNS history</li>
              </ul>
            </div>
            <div>
              <p className="text-neon-red font-bold mb-2">Passive Recon</p>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Censys — internet-wide scanning</li>
                <li>GreyNoise — noise vs. targeted traffic</li>
              </ul>
            </div>
          </div>
        </Card>

        <Card className="p-4 sm:p-6 md:p-8 space-y-6">
          <h2 className="text-xl sm:text-2xl font-bold text-neon-red mb-4 flex items-center gap-2">
            <Server className="w-6 h-6" /> Query Types
          </h2>
          <div className="space-y-3 text-sm text-neon-red/60">
            <div className="border-l-2 border-neon-red/20 pl-3">
              <p className="text-neon-red font-bold">IP Address (IPv4 / IPv6)</p>
              <p>Geolocation, ASN, open ports, banners, abuse history, threat score, BGP routing, reverse DNS.</p>
            </div>
            <div className="border-l-2 border-neon-red/20 pl-3">
              <p className="text-neon-red font-bold">Domain</p>
              <p>DNS records (A, AAAA, MX, TXT, NS), WHOIS registration, certificate history, subdomains, reputation.</p>
            </div>
            <div className="border-l-2 border-neon-red/20 pl-3">
              <p className="text-neon-red font-bold">ASN</p>
              <p>Organisation name, announced prefixes, peer ASNs, BGP community tags, country of origin.</p>
            </div>
          </div>
        </Card>

        <Card className="p-4 sm:p-6 md:p-8 space-y-6">
          <h2 className="text-xl sm:text-2xl font-bold text-neon-red mb-4 flex items-center gap-2">
            <Shield className="w-6 h-6" /> Privacy &amp; Ethics
          </h2>
          <ul className="text-neon-red/60 text-sm space-y-2 list-disc list-inside">
            <li>All data is sourced from <strong className="text-neon-red">public, passive</strong> intelligence — no active scanning</li>
            <li>No queries are logged or stored by Seek itself</li>
            <li>Results are fetched on demand and not cached beyond the request</li>
            <li>Use responsibly — only investigate hosts you own or have permission to investigate</li>
          </ul>
        </Card>

        <Card className="p-4 sm:p-6 md:p-8 space-y-4">
          <h2 className="text-xl sm:text-2xl font-bold text-neon-red mb-4 flex items-center gap-2">
            <Eye className="w-6 h-6" /> Rate Limits
          </h2>
          <p className="text-neon-red/60 text-sm leading-relaxed mb-2">
            Seek enforces per-IP rate limiting to protect upstream API quotas. Limits are generous for normal use:
          </p>
          <ul className="text-neon-red/60 text-sm space-y-2 list-disc list-inside">
            <li><strong className="text-neon-red">10 requests / minute</strong> per IP</li>
            <li>Burst of 3 allowed before throttling kicks in</li>
            <li>Limits reset on a rolling window — no hard daily cap</li>
          </ul>
        </Card>

        <Card className="p-4 sm:p-6 md:p-8 space-y-4">
          <h2 className="text-xl sm:text-2xl font-bold text-neon-red mb-4 flex items-center gap-2">
            <GitBranch className="w-6 h-6" /> Self-Hosting
          </h2>
          <p className="text-neon-red/60 text-sm leading-relaxed mb-3">
            Seek is open source. Deploy your own instance on Cloudflare Pages with your own API keys for higher quotas:
          </p>
          <ul className="text-neon-red/60 text-sm space-y-2 list-disc list-inside">
            <li>Clone the repo and copy <code className="text-neon-red/80">.env.example</code> to <code className="text-neon-red/80">.env</code></li>
            <li>Add your API keys for each source you want enabled</li>
            <li>Run <code className="text-neon-red/80">npm run deploy</code> to publish to Cloudflare Pages</li>
            <li>Sources without keys are automatically skipped</li>
          </ul>
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
