#!/bin/bash
# Symlink config files back to root for tools that expect them there
ln -sf config/wrangler.toml wrangler.toml
ln -sf config/open-next.config.ts open-next.config.ts
ln -sf config/postcss.config.js postcss.config.js
ln -sf config/tailwind.config.ts tailwind.config.ts
ln -sf config/tsconfig.json tsconfig.json
ln -sf config/tsconfig.worker.json tsconfig.worker.json
ln -sf config/vitest.config.ts vitest.config.ts
ln -sf docs/README.md README.md
ln -sf public/schema.sql schema.sql
