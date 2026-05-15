#!/bin/bash
set -e

npm run pages:build
cp .open-next/worker.js .open-next/_worker.js
wrangler pages deploy .open-next
