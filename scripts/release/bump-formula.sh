#!/usr/bin/env bash
#
# bump-formula.sh — rewrite Formula/thoryn.rb for a tagged release (SSO-2936).
#
# Usage: scripts/release/bump-formula.sh <version> <assets-dir>
#
#   <version>     the release version WITHOUT the `cli-v` prefix, e.g. 0.1.0
#   <assets-dir>  a directory containing the released native binaries, named
#                 exactly as they are attached to the GitHub Release:
#                   thoryn-darwin-arm64  thoryn-darwin-amd64
#                   thoryn-linux-arm64   thoryn-linux-amd64
#
# It regenerates the whole formula from a template so the four sha256 values and
# the version stay in lockstep — no fragile in-place sed. The release workflow
# (.github/workflows/release.yml) runs this and commits the result back to the
# default branch. Homebrew only consumes the four macOS/Linux binaries; the
# Windows binary and the fat jar are release assets but not brew-installed.
set -euo pipefail

version="${1:?usage: bump-formula.sh <version> <assets-dir>}"
assets="${2:?usage: bump-formula.sh <version> <assets-dir>}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
formula="${repo_root}/Formula/thoryn.rb"

sha256_of() {
  local f="$1"
  [ -f "$f" ] || { echo "::error::missing release asset: $f" >&2; exit 1; }
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  else
    shasum -a 256 "$f" | awk '{print $1}'
  fi
}

darwin_arm="$(sha256_of "${assets}/thoryn-darwin-arm64")"
darwin_amd="$(sha256_of "${assets}/thoryn-darwin-amd64")"
linux_arm="$(sha256_of "${assets}/thoryn-linux-arm64")"
linux_amd="$(sha256_of "${assets}/thoryn-linux-amd64")"

cat > "$formula" <<EOF
# typed: false
# frozen_string_literal: true

# Homebrew formula for the \`thoryn\` customer-plane CLI (SSO-2936, epic SSO-2934).
#
# This formula lives IN the thoryn-cli repo so the repo doubles as its own tap:
#
#     brew tap thoryn-io/thoryn-cli
#     brew install thoryn
#
# It installs the prebuilt GraalVM native-image binary from the matching GitHub
# Release (tag \`cli-v#{version}\`, published by .github/workflows/release.yml).
#
# The \`version\` line and the four \`sha256\` lines below are rewritten on every
# tagged release by scripts/release/bump-formula.sh, which the release workflow
# runs and commits back to the default branch. Do NOT hand-edit them — bump by
# cutting a \`cli-v*\` tag.
class Thoryn < Formula
  desc "Thoryn customer-plane CLI (OAuth 2.0 / OIDC identity broker)"
  homepage "https://github.com/thoryn-io/thoryn-cli"
  version "${version}"

  on_macos do
    on_arm do
      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/thoryn-darwin-arm64"
      sha256 "${darwin_arm}"
    end
    on_intel do
      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/thoryn-darwin-amd64"
      sha256 "${darwin_amd}"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/thoryn-linux-arm64"
      sha256 "${linux_arm}"
    end
    on_intel do
      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/thoryn-linux-amd64"
      sha256 "${linux_amd}"
    end
  end

  def install
    # The release asset is downloaded under its per-OS/arch name (thoryn-<os>-<arch>);
    # install it as the plain \`thoryn\` executable on PATH.
    bin.install Dir["thoryn-*"].first => "thoryn"
  end

  test do
    assert_match "thoryn", shell_output("#{bin}/thoryn --version")
  end
end
EOF

echo "Rewrote ${formula} for version ${version}"
echo "  darwin-arm64 ${darwin_arm}"
echo "  darwin-amd64 ${darwin_amd}"
echo "  linux-arm64  ${linux_arm}"
echo "  linux-amd64  ${linux_amd}"
