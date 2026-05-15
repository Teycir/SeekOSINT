import type { NextConfig } from 'next'
import { initOpenNextCloudflareForDev } from '@opennextjs/cloudflare'

// Required for getCloudflareContext() to work during `next dev`
// and for the adapter to correctly wire up the Workers context at build time.
// See: https://opennext.js.org/cloudflare/howtos/dev-deploy
initOpenNextCloudflareForDev()

const nextConfig: NextConfig = {}

export default nextConfig
