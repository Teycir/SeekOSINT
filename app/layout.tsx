import type { Metadata } from 'next'
import { JetBrains_Mono } from 'next/font/google'
import './globals.css'
import { Footer } from './components/Footer'
import { ScrollProgress } from './components/ScrollProgress'

const jetbrainsMono = JetBrains_Mono({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Seek — Host Intelligence',
  description: 'OSINT tool — IP, domain, and ASN intelligence across 12 sources',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body
        className={`${jetbrainsMono.className} min-h-screen bg-dark-bg text-dark-text overflow-x-hidden antialiased selection:bg-neon-red/30 selection:text-neon-red`}
      >
        <ScrollProgress />
        {children}
        <Footer />
      </body>
    </html>
  )
}
