#!/bin/bash
set -e
npm run pages:build
wrangler deploy
