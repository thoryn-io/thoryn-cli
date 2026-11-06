#!/usr/bin/env bash
#
# check-macos-minos.sh — the darwin binary must still run on macOS 14 (SSO-4268).
#
# Usage: scripts/release/check-macos-minos.sh <binary> [<expected-minos>]
#
#   <binary>          the native-image binary, e.g. cli/target/thoryn
#   <expected-minos>  the minimum macOS it must declare; default 14.0
#
# The build host's OS sets a Mach-O binary's minimum macOS (LC_BUILD_VERSION
# minos) unless the linker is told otherwise. GitHub retired the macos-14 image
# on 2026-11-02, so the darwin leg builds on macos-15, and cli/pom.xml's
# native-macos-min-version profile passes -mmacosx-version-min=14.0 to the
# linker. cli-v0.58.0 came out at minos 15.0 (MACOSX_DEPLOYMENT_TARGET did not
# reach native-image's link), which this check refused.
#
# release.yml runs this after the darwin build, and native-macos.yml runs it on
# every pull request that changes the native build, so a broken darwin build
# shows up before a tag rather than as a release without thoryn-darwin-arm64.
set -euo pipefail

binary="${1:?usage: check-macos-minos.sh <binary> [<expected-minos>]}"
expected="${2:-14.0}"

minos="$(otool -l "$binary" | awk '/LC_BUILD_VERSION/{f=1} f&&$1=="minos"{print $2; exit}')"
echo "minos=${minos:-<none>}"
if [ "$minos" != "$expected" ]; then
  echo "::error::the darwin binary needs macOS ${minos:-unknown}, not ${expected} — the -mmacosx-version-min linker option (cli/pom.xml native-macos-min-version) did not take, so macOS ${expected%%.*} users could not run it."
  exit 1
fi
