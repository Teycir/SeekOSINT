import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Seek — Host Intelligence',
  description: 'OSINT tool — IP, domain, and ASN intelligence across 17 sources',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="bg-neutral-950">
      <body className="antialiased">{children}</body>
    </html>
  )
}
