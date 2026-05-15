#!/bin/bash
set -e

echo "▶ Building for Cloudflare..."
npx opennextjs-cloudflare build

echo "▶ Deploying with wrangler..."
wrangler deploy

echo "✓ Deploy complete"
