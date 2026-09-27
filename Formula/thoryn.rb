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
  version "0.30.1"

  on_macos do
    on_arm do
      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/thoryn-darwin-arm64"
      sha256 "a21d8694203ecc05f5a4ba0ba472da794bda2c79e4de85a5a97450bf5bde813f"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/thoryn-linux-arm64"
      sha256 "6120318245dab0f7490ca7ab0929b0c26adccfe56743734228bf0217f4a87837"
    end
    on_intel do
      url "https://github.com/thoryn-io/thoryn-cli/releases/download/cli-v#{version}/thoryn-linux-amd64"
      sha256 "3bd265067ac82fd285038a6436400b2eb560b6615b93e8b9c2a10150365666a7"
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
