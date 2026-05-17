/**
 * app/faq/page.tsx — server component for metadata + SEO.
 * Animations live in FAQContent (client component).
 */
import type { Metadata } from 'next'
import { FAQContent } from '../components/FAQContent'

export const metadata: Metadata = {
  title: 'FAQ',
  description:
    'Frequently asked questions about SeekOSINT — IP lookup, domain intelligence, ' +
    'ASN lookup, rate limits, privacy, self-hosting, and data sources.',
  alternates: { canonical: 'https://seekyou.workers.dev/faq' },
  openGraph: {
    title: 'SeekOSINT FAQ',
    description:
      'Everything you need to know about SeekOSINT — how it works, what sources ' +
      'it queries, rate limits, privacy, and self-hosting.',
    url: 'https://seekyou.workers.dev/faq',
  },
}

export default function FAQPage() {
  return <FAQContent />
}
