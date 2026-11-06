#!/usr/bin/env bash
#
# test-bump-formula.sh — the bump-formula.sh cases a release depends on (SSO-4268).
#
# Usage: scripts/release/test-bump-formula.sh
#
# Runs bump-formula.sh in a throwaway copy of the repository layout, so the
# real Formula/thoryn.rb is never touched. `ci` runs this on every pull request.
#
#   * every brew platform present        → a formula with on_macos AND on_linux, exit 0
#   * only the Intel-macOS binary absent → still written (one macOS URL is enough)
#   * the darwin binary absent           → exit 1, formula unchanged (cli-v0.58.0)
#   * both linux binaries absent         → exit 1, formula unchanged
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
pass() { echo "ok:   $*"; }

# A fresh fake repo: the script resolves Formula/ relative to its own location.
setup() {
  rm -rf "$work/repo" "$work/assets"
  mkdir -p "$work/repo/scripts/release" "$work/repo/Formula" "$work/assets"
  cp "$repo_root/scripts/release/bump-formula.sh" "$work/repo/scripts/release/"
  echo "# previous formula" > "$work/repo/Formula/thoryn.rb"
  local asset
  for asset in "$@"; do
    echo "$asset" > "$work/assets/$asset"
  done
}

run_bump() {
  bash "$work/repo/scripts/release/bump-formula.sh" 9.9.9 "$work/assets" > "$work/out.txt" 2>&1
}

formula="$work/repo/Formula/thoryn.rb"

# 1. Every platform the matrix builds today.
setup thoryn-darwin-arm64 thoryn-linux-arm64 thoryn-linux-amd64
if run_bump && grep -q 'on_macos do' "$formula" && grep -q 'on_linux do' "$formula" \
  && grep -q 'releases/download/cli-v#{version}/thoryn-darwin-arm64"' "$formula" \
  && grep -q 'version "9.9.9"' "$formula"; then
  pass "all platforms present → formula with on_macos and on_linux"
else
  fail "all platforms present"; cat "$work/out.txt" "$formula" >&2
fi

# 2. Intel macOS is not in the matrix; its absence alone must not block a release.
if grep -q 'thoryn-darwin-amd64' "$formula"; then
  fail "absent thoryn-darwin-amd64 still got a URL"
else
  pass "absent thoryn-darwin-amd64 is omitted, not refused"
fi

# 3. cli-v0.58.0: the darwin leg failed.
setup thoryn-linux-arm64 thoryn-linux-amd64
if run_bump; then
  fail "no darwin binary was accepted"; cat "$formula" >&2
elif [ "$(cat "$formula")" != "# previous formula" ]; then
  fail "no darwin binary: the formula was rewritten anyway"
elif ! grep -q '::error::no macOS' "$work/out.txt"; then
  fail "no darwin binary: no ::error:: naming macOS"; cat "$work/out.txt" >&2
else
  pass "no darwin binary → exit 1, formula unchanged"
fi

# 4. Both linux legs failed.
setup thoryn-darwin-arm64
if run_bump; then
  fail "no linux binary was accepted"
elif [ "$(cat "$formula")" != "# previous formula" ]; then
  fail "no linux binary: the formula was rewritten anyway"
else
  pass "no linux binary → exit 1, formula unchanged"
fi

if [ "$failures" -gt 0 ]; then
  echo "$failures case(s) failed" >&2
  exit 1
fi
echo "bump-formula.sh: all cases pass"
