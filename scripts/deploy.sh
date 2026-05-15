#!/bin/bash
set -e

npm run pages:build
cp .open-next/worker.js .open-next/_worker.js
cp -r .open-next/assets/* .open-next/
cat > .open-next/_routes.json << 'ROUTES'
{
  "version": 1,
  "include": ["/*"],
  "exclude": ["/_next/static/*", "/publiceth.svg", "/schema.sql"]
}
ROUTES
wrangler pages deploy .open-next
