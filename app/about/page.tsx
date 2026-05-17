/**
 * app/about/page.tsx — server component for metadata + SEO.
 * Animations live in AboutContent (client component).
 */
import type { Metadata } from 'next'
import { AboutContent } from '../components/AboutContent'

export const metadata: Metadata = {
  title: 'How to Use',
  description:
    'Learn how to use SeekYou — look up any IP address, domain, or ASN and get ' +
    'a comprehensive intelligence report from 15 sources including geolocation, ' +
    'open ports, CVEs, threat feeds, certificate transparency, and passive DNS.',
  alternates: { canonical: 'https://seekyou.workers.dev/about' },
  openGraph: {
    title: 'How to Use SeekYou',
    description:
      'Look up any IP, domain, or ASN. Get threat intel, geolocation, open ports, ' +
      'CVEs, certs, DNS history, and BGP routing — all in one place.',
    url: 'https://seekyou.workers.dev/about',
  },
}

export default function AboutPage() {
  return <AboutContent />
}
