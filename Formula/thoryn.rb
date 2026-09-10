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
  version "0.3.7"

  on_macos do
    on_arm do
      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/thoryn-darwin-arm64"
      sha256 "71f7d5db2519917c397286c0b40b17fdfba28820322fc36c11449a919e313610"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/thoryn-linux-arm64"
      sha256 "624a5d080d915fd14fec2319b2b8e2e0c2035c26fc9b5f4598d717e933780f03"
    end
    on_intel do
      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/thoryn-linux-amd64"
      sha256 "460f7874b1cbd55d466c0dc899261ede79e6b8afb6f8c4295462b53232891a01"
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
