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
# It regenerates the whole formula from a template so the sha256 values and the
# version stay in lockstep — no fragile in-place sed. The release workflow
# (.github/workflows/release.yml) runs this and commits the result back to the
# default branch. Homebrew only consumes the four macOS/Linux binaries; the
# Windows binary and the fat jar are release assets but not brew-installed.
#
# BEST-EFFORT tolerance (SSO-2936): native binaries are built best-effort per
# runner availability, so any one of the four may be ABSENT (e.g. the retiring
# Intel-macOS runner leaves `thoryn-darwin-amd64` unbuilt). This script emits an
# `on_arm` / `on_intel` branch ONLY for the assets that are actually present, so
# the formula never points `brew` at a download that does not exist. `brew`
# still works for the platforms that shipped; the missing platform simply has no
# bottle in the formula.
set -euo pipefail

version="${1:?usage: bump-formula.sh <version> <assets-dir>}"
assets="${2:?usage: bump-formula.sh <version> <assets-dir>}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
formula="${repo_root}/Formula/thoryn.rb"

# sha256 of a file, or empty string when the asset was not produced.
sha256_of() {
  local f="$1"
  [ -f "$f" ] || { echo ""; return 0; }
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  else
    shasum -a 256 "$f" | awk '{print $1}'
  fi
}

# Emit one `on_arm`/`on_intel` block for a present asset; nothing when absent.
# Prints DIRECTLY to stdout (do not capture via $(...) — that strips the
# trailing newline and runs the next block onto the same line, breaking Ruby).
#   $1 = on_arm | on_intel   $2 = asset filename   $3 = sha256 (may be empty)
arch_block() {
  local kind="$1" asset="$2" sha="$3"
  [ -n "$sha" ] || return 0
  printf '    %s do\n' "$kind"
  printf '      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/%s"\n' "$asset"
  printf '      sha256 "%s"\n' "$sha"
  printf '    end\n'
}

# Emit an `on_macos`/`on_linux` wrapper only if at least one of its two archs
# produced a binary. Prints DIRECTLY to stdout.
#   $1 = on_macos|on_linux  $2/$3 = arm asset,sha  $4/$5 = intel asset,sha
os_block() {
  local kind="$1" arm_asset="$2" arm_sha="$3" intel_asset="$4" intel_sha="$5"
  [ -n "$arm_sha" ] || [ -n "$intel_sha" ] || return 0
  printf '  %s do\n' "$kind"
  arch_block on_arm   "$arm_asset"   "$arm_sha"
  arch_block on_intel "$intel_asset" "$intel_sha"
  printf '  end\n'
}

darwin_arm="$(sha256_of "${assets}/thoryn-darwin-arm64")"
darwin_amd="$(sha256_of "${assets}/thoryn-darwin-amd64")"
linux_arm="$(sha256_of "${assets}/thoryn-linux-arm64")"
linux_amd="$(sha256_of "${assets}/thoryn-linux-amd64")"

have_macos=0; { [ -n "$darwin_arm" ] || [ -n "$darwin_amd" ]; } && have_macos=1
have_linux=0; { [ -n "$linux_arm" ] || [ -n "$linux_amd" ]; } && have_linux=1

if [ "$have_macos" -eq 0 ] && [ "$have_linux" -eq 0 ]; then
  echo "::warning::no brew-installable native binaries were produced for ${version} — the formula will carry no download URLs." >&2
fi

# Assemble the formula. Bash expands ${...}; Ruby's #{version} is left literal.
{
  cat <<EOF
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
# The \`version\` line and the \`sha256\` lines below are rewritten on every
# tagged release by scripts/release/bump-formula.sh, which the release workflow
# runs and commits back to the default branch. Native binaries are best-effort
# per runner availability, so a platform whose binary was not produced is omitted
# here rather than pointed at a missing download. Do NOT hand-edit — bump by
# cutting a \`cli-v*\` tag.
class Thoryn < Formula
  desc "Thoryn customer-plane CLI (OAuth 2.0 / OIDC identity broker)"
  homepage "https://github.com/thoryn-io/thoryn-cli"
  version "${version}"

EOF
  os_block on_macos thoryn-darwin-arm64 "$darwin_arm" thoryn-darwin-amd64 "$darwin_amd"
  [ "$have_macos" -eq 1 ] && [ "$have_linux" -eq 1 ] && printf '\n'
  os_block on_linux thoryn-linux-arm64 "$linux_arm" thoryn-linux-amd64 "$linux_amd"
  cat <<'EOF'

  def install
    # The release asset is downloaded under its per-OS/arch name (thoryn-<os>-<arch>);
    # install it as the plain `thoryn` executable on PATH.
    bin.install Dir["thoryn-*"].first => "thoryn"
  end

  test do
    assert_match "thoryn", shell_output("#{bin}/thoryn --version")
  end
end
EOF
} > "$formula"

echo "Rewrote ${formula} for version ${version}"
printf '  darwin-arm64 %s\n' "${darwin_arm:-<absent — omitted>}"
printf '  darwin-amd64 %s\n' "${darwin_amd:-<absent — omitted>}"
printf '  linux-arm64  %s\n' "${linux_arm:-<absent — omitted>}"
printf '  linux-amd64  %s\n' "${linux_amd:-<absent — omitted>}"
