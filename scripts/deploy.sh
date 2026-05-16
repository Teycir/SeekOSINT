#!/bin/bash
set -e

echo "▶ Building..."
npm run pages:build

echo "▶ Preparing Pages output..."
# Pages needs _worker.js at the root of the deploy directory
# and static assets alongside it
cp .open-next/worker.js .open-next/_worker.js

# Copy static assets up from assets/ into root so Pages serves them
cp -r .open-next/assets/. .open-next/

# Generate _routes.json so Pages knows to route everything through the worker
cat > .open-next/_routes.json << 'EOF'
{
  "version": 1,
  "include": ["/*"],
  "exclude": ["/_next/static/*", "/publiceth.svg", "/schema.sql", "/BUILD_ID", "/_headers"]
}
EOF

echo "▶ Deploying to Pages..."
npx wrangler pages deploy .open-next \
  --project-name=seekosint \
  --branch=master \
  --commit-dirty=true

echo "✓ Done"
