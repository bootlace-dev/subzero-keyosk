#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

echo "[+] Compiling TUI..."
node build_tui.cjs

echo "[+] Launching TUI in ephemeral Alpine Node container..."
docker run -it --rm \
    --name subzero-tui-sandbox \
    --read-only \
    --tmpfs /tmp \
    -v "$(pwd)/dist:/app/dist:ro" \
    -w /app \
    node:20-alpine \
    node dist/tui.cjs
