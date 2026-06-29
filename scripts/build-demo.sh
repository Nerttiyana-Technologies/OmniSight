#!/usr/bin/env bash
#
# Build the static, read-only OmniSight demo (no backend, no database, no keys).
# Output: apps/web/dist  — deployable to GitHub Pages or any static host.
#
# Usage:
#   scripts/build-demo.sh                 # builds for root path "/"
#   VITE_BASE=/OmniSight/ scripts/build-demo.sh   # for a GitHub Pages project path
#
# Then preview locally with:  pnpm --filter @omnisight/web preview
#
set -euo pipefail
cd "$(dirname "$0")/.."

export VITE_DEMO=true
export VITE_BASE="${VITE_BASE:-/}"

echo "▶ Installing dependencies…"
pnpm install

echo "▶ Building static demo (VITE_DEMO=true, VITE_BASE=$VITE_BASE)…"
pnpm --filter @omnisight/web build

# GitHub Pages serves the files as-is (no Jekyll).
touch apps/web/dist/.nojekyll

echo "✓ Static demo built at: apps/web/dist"
echo "  Preview:  pnpm --filter @omnisight/web preview"
echo "  Deploy:   push to main (GitHub Pages workflow) or upload apps/web/dist to any static host."
