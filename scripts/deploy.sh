#!/bin/bash
set -e

echo "Building..."
npm run pages:build

echo "Copying worker and static assets..."
cp .open-next/worker.js .open-next/_worker.js
cd .open-next && cp -r assets/_next . 2>/dev/null || true && cd ..

echo "Creating _routes.json..."
cat > .open-next/_routes.json << 'EOF'
{
  "version": 1,
  "include": ["/*"],
  "exclude": [
    "/_next/static/*",
    "/favicon.ico",
    "/publiceth.svg"
  ]
}
EOF

echo "Deploying..."
wrangler pages deploy .open-next --project-name=seekosint --branch=master --commit-dirty=true
