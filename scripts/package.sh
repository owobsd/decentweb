#!/usr/bin/env bash
# Builds a release bundle for this platform: dist/dweb-<os>-<arch>/ with the
# programs, network.toml and the browser profile + installer.
#
# A fork ships its own network.toml: pass it as the first argument.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${1:-$ROOT/network.toml}"
cargo build --release --manifest-path "$ROOT/Cargo.toml"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
EXT=""
case "$OS" in mingw*|msys*|cygwin*) OS=windows; EXT=".exe" ;; esac
OUT="$ROOT/dist/dweb-$OS-$ARCH"
rm -rf "$OUT" && mkdir -p "$OUT/bin" "$OUT/browser"
for b in dweb-node dweb-resolver dweb-site dweb-wallet; do
  cp "$ROOT/target/release/$b$EXT" "$OUT/bin/"
done
cp "$CONFIG" "$OUT/network.toml"
cp "$ROOT/browser/"* "$OUT/browser/"
cp "$ROOT/README.md" "$ROOT/LICENSE-MIT" "$ROOT/LICENSE-APACHE" "$OUT/"
cp -r "$ROOT/docs" "$OUT/docs"
echo "bundle in $OUT"
