#!/usr/bin/env bash
set -euo pipefail

echo "============================================="
echo "DCMP Local Development Setup (POSIX)"
echo "============================================="

# 1. Check prerequisites
command -v node >/dev/null 2>&1 || { echo >&2 "Node.js (>=20) is required. Aborting."; exit 1; }
command -v pnpm >/dev/null 2>&1 || { echo >&2 "pnpm (>=9) is required. Installing via corepack..."; corepack enable && corepack prepare pnpm@9.15.9 --activate; }

# 2. Environment file
if [ ! -f .env ]; then
  echo "Creating .env from .env.example..."
  cp .env.example .env
fi

# 3. Install dependencies
echo "Installing pnpm monorepo dependencies..."
pnpm install

# 4. Flutter dependencies
if command -v flutter >/dev/null 2>&1; then
  echo "Installing Flutter dependencies..."
  (cd apps/mobile-app && flutter pub get)
else
  echo "WARNING: flutter command not found. Flutter dependencies skipped."
fi

# 5. Start Docker infrastructure
if command -v docker >/dev/null 2>&1; then
  echo "Starting local PostgreSQL and Redis containers..."
  docker compose up -d
else
  echo "WARNING: docker command not found. Please start PostgreSQL and Redis manually."
fi

echo "============================================="
echo "DCMP environment initialization complete!"
echo "Run 'pnpm build' to compile all packages and apps."
echo "============================================="
