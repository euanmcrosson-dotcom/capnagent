#!/usr/bin/env bash
# Build the capnagent-wasm artifact for bundler consumers.
#
# This is a thin wrapper around `wasm-pack build` so contributors can
# invoke the build from any shell without remembering the flag set:
#
#   ./scripts/build-wasm.sh
#
# The npm script `npm run build:wasm` invokes wasm-pack directly with
# the same arguments; this script exists for users who want to run the
# build outside an npm context (e.g. inside an editor task, a Makefile,
# or a manual repro of the CI step).
#
# Output: crates/capnagent-wasm/pkg/ — committed to .gitignore.

set -euo pipefail

# Resolve the repo root from this script's location so the command works
# from any CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "error: wasm-pack not found on PATH." >&2
  echo "       install with: cargo install wasm-pack" >&2
  exit 127
fi

exec wasm-pack build crates/capnagent-wasm --target bundler --out-dir pkg "$@"
