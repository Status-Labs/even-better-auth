#!/usr/bin/env bash
# Builds the axum example server and drives it with the official better-auth JS client.
set -euo pipefail
cd "$(dirname "$0")"
[ -d node_modules ] || npm install --silent
cargo build -q -p axum-server-example
BIN=../../target/debug/axum-server-example
export GITHUB_CLIENT_ID=e2e-client-id GITHUB_CLIENT_SECRET=e2e-secret BETTER_AUTH_SECRET=e2e-secret-e2e-secret-e2e-secret-1234 RUST_LOG=warn E2E=1
PORT=3123

run_server() {
  PORT=$PORT "$@" "$BIN" & SERVER=$!
  trap 'kill $SERVER 2>/dev/null || true' EXIT
  for _ in $(seq 50); do curl -sf "http://localhost:$PORT/api/auth/ok" >/dev/null && return; sleep 0.1; done
  echo "server did not start" >&2; exit 1
}
stop_server() { kill $SERVER 2>/dev/null; wait $SERVER 2>/dev/null || true; }

run_server env
BASE_URL=http://localhost:$PORT node client-test.mjs
BASE_URL=http://localhost:$PORT node plugins-test.mjs
stop_server

for strategy in compact jwt jwe; do
  run_server env COOKIE_CACHE=$strategy
  BASE_URL=http://localhost:$PORT STRATEGY=$strategy node cookie-cache-test.mjs
  stop_server
done
