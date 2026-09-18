# typed: false
# frozen_string_literal: true

# Homebrew formula for the `thoryn` customer-plane CLI (SSO-2936, epic SSO-2934).
#
# This formula lives IN the thoryn-cli repo so the repo doubles as its own tap:
#
#     brew tap thoryn-io/thoryn-cli
#     brew install thoryn
#
# It installs the prebuilt GraalVM native-image binary from the matching GitHub
# Release (tag `cli-v#{version}`, published by .github/workflows/release.yml).
#
# The `version` line and the `sha256` lines below are rewritten on every
# tagged release by scripts/release/bump-formula.sh, which the release workflow
# runs and commits back to the default branch. Native binaries are best-effort
# per runner availability, so a platform whose binary was not produced is omitted
# here rather than pointed at a missing download. Do NOT hand-edit — bump by
# cutting a `cli-v*` tag.
class Thoryn < Formula
  desc "Thoryn customer-plane CLI (OAuth 2.0 / OIDC identity broker)"
  homepage "https://github.com/thoryn-io/thoryn-cli"
  version "0.19.0"

  on_macos do
    on_arm do
      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/thoryn-darwin-arm64"
      sha256 "38bca18317770d3e15d30457d1d86e5484da39c97f7b65f1a2e7c08bc4c213c1"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/thoryn-linux-arm64"
      sha256 "e714de2e388b017d278b27fbe51559b770d90d279a9a67f611cc89abd19c6531"
    end
    on_intel do
      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/thoryn-linux-amd64"
      sha256 "3430bb8e30ad80714e8d3ef8b7aee7548a8d5860088fd41e217cf4bd7c6201cd"
    end
  end

  def install
    # The release asset is downloaded under its per-OS/arch name (thoryn-<os>-<arch>);
    # install it as the plain `thoryn` executable on PATH.
    bin.install Dir["thoryn-*"].first => "thoryn"
  end

  test do
    assert_match "thoryn", shell_output("#{bin}/thoryn --version")
  end
end
