#!/usr/bin/env bash
# Backwards-compat shim — the build script now lives at the repo root.
exec "$(dirname "$0")/../../build.sh" "${1:-all}"
