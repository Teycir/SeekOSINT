#!/bin/bash
set -e

npm run pages:build
wrangler pages deploy --project-name=seekosint --branch=master --commit-dirty=true
