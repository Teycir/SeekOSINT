import type { MetadataRoute } from 'next'

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: '*',
        allow: ['/', '/about', '/faq'],
        // Block result pages — live data, no value to index
        disallow: ['/host/', '/api/', '/saved'],
      },
    ],
    sitemap: 'https://seekyou.workers.dev/sitemap.xml',
  }
}
