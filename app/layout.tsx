import type { Metadata } from 'next'
import { JetBrains_Mono } from 'next/font/google'
import './globals.css'
import { Footer } from './components/Footer'
import { ScrollProgress } from './components/ScrollProgress'
import { TopNav } from './components/TopNav'
import { TrustedTypesPolicy } from './components/TrustedTypesPolicy'

const jetbrainsMono = JetBrains_Mono({ subsets: ['latin'] })

const SITE_URL = 'https://seekyou.workers.dev'
const SITE_NAME = 'SeekYou'
const DESCRIPTION =
  'Free OSINT tool — look up any IP address, domain, or ASN and get a ' +
  'comprehensive intelligence report across 15 sources: geolocation, open ports, ' +
  'CVEs, threat feeds, certificates, DNS history, BGP routing, and more.'

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: `${SITE_NAME} — Host Intelligence`,
    template: `%s — ${SITE_NAME}`,
  },
  description: DESCRIPTION,
  keywords: [
    'OSINT', 'IP lookup', 'domain lookup', 'ASN lookup', 'threat intelligence',
    'geolocation', 'open ports', 'CVE', 'certificate transparency', 'passive DNS',
    'BGP routing', 'IP reputation', 'network intelligence', 'cybersecurity',
    'internet scanner', 'host intelligence', 'malware', 'threat feed',
  ],
  authors: [{ name: 'Teycir Ben Soltane', url: 'https://teycirbensoltane.tn' }],
  creator: 'Teycir Ben Soltane',
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: SITE_URL,
    siteName: SITE_NAME,
    title: `${SITE_NAME} — Host Intelligence`,
    description: DESCRIPTION,
    images: [{ url: '/og.png', width: 1200, height: 630, alt: `${SITE_NAME} — Host Intelligence` }],
  },
  twitter: {
    card: 'summary_large_image',
    title: `${SITE_NAME} — Host Intelligence`,
    description: DESCRIPTION,
    images: ['/og.png'],
    creator: '@teycirbensoltane',
  },
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true, 'max-snippet': -1, 'max-image-preview': 'large' },
  },
  alternates: { canonical: SITE_URL },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'WebApplication',
    name: 'SeekYou',
    url: 'https://seekyou.workers.dev',
    description: DESCRIPTION,
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Any',
    offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
    author: { '@type': 'Person', name: 'Teycir Ben Soltane', url: 'https://teycirbensoltane.tn' },
  }

  return (
    <html lang="en">
      <head>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body
        className={`${jetbrainsMono.className} min-h-screen bg-dark-bg text-dark-text overflow-x-hidden antialiased selection:bg-neon-red/30 selection:text-neon-red`}
      >
        <ScrollProgress />
        <TrustedTypesPolicy />
        <TopNav />
        {children}
        <Footer />
      </body>
    </html>
  )
}
