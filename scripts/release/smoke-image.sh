#!/usr/bin/env bash
#
# smoke-image.sh — run the thoryn-cli container image the way the Thoryn init container does (SSO-3687).
#
# Usage: scripts/release/smoke-image.sh <image> <expected-version> [<platform>]
#
#   <image>             a local image, e.g. thoryn-cli:ci-amd64
#   <expected-version>  the version the binary must report, e.g. 0.33.0
#   <platform>          optional, e.g. linux/arm64 (runs under QEMU when it is not the host's)
#
# Used by ci.yml (every PR, nothing pushed) and release.yml (before the push). Offline: no hub, no
# gateway, no registry. It fails when:
#   * the image does not run as the distroless nonroot user 65532:65532;
#   * `thoryn --version` does not start (a shared library the base lacks — the libz.so.1 trap — or a
#     newer glibc than Debian 12's) or reports another version;
#   * the commands the init container runs cannot even be instantiated. `--version` alone proves
#     nothing here: when the native image's picocli reflection config is missing, the root command
#     still answers `--version` while EVERY subcommand fails with "Cannot instantiate …: the class has
#     no constructor" — which is what the cli-v0.32.0 Linux binaries did. Signed out, a working
#     `login --status` / `clients rotate-secret` answers "Not signed in"; that answer is the proof.
#     They run read-only, with the same file-store opt-in and the same RAM-volume layout the
#     documented manifest uses.
set -euo pipefail

image="${1:?usage: smoke-image.sh <image> <expected-version> [<platform>]}"
version="${2:?usage: smoke-image.sh <image> <expected-version> [<platform>]}"
platform="${3:-}"

run=(docker run --rm)
if [ -n "$platform" ]; then run+=(--platform "$platform"); fi
# The commas are --tmpfs mount options inside one argument, not array separators.
# shellcheck disable=SC2054
init=("${run[@]}" --read-only
  --tmpfs /thoryn-session:uid=65532,gid=65532,mode=0700
  --tmpfs /shared:uid=65532,gid=65532,mode=0700
  -e THORYN_CI_PLAINTEXT_TOKENS=1
  -e THORYN_TOKEN_FILE=/thoryn-session/tokens.json)

user="$(docker image inspect --format '{{.Config.User}}' "$image")"
if [ "$user" != "65532:65532" ]; then
  echo "::error::$image runs as '$user', expected the distroless nonroot user 65532:65532."
  exit 1
fi

out="$("${run[@]}" "$image" --version)"
echo "--version: $out"
case "$out" in
  *"$version"*) ;;
  *) echo "::error::$image reported '$out', expected version $version."; exit 1 ;;
esac

expect_signed_out() {
  local label="$1"; shift
  local output
  output="$("${init[@]}" "$image" "$@" 2>&1 || true)"
  if grep -q 'Cannot instantiate\|class has no constructor\|InitializationException' <<< "$output"; then
    echo "::error::$image cannot instantiate \`thoryn $label\` — the native image is missing its picocli reflection config (see NativeReflectionConfigWithoutKeychainTest):"
    grep -v '^[[:space:]]*at ' <<< "$output" | head -5
    exit 1
  fi
  if ! grep -q 'Not signed in' <<< "$output"; then
    echo "::error::\`thoryn $label\` in $image did not answer 'Not signed in' as a signed-out CLI must:"
    grep -v '^[[:space:]]*at ' <<< "$output" | head -10
    exit 1
  fi
  echo "$label: answers 'Not signed in' (instantiated, file store on the session volume)"
}
expect_signed_out "login --status" login --status
expect_signed_out "clients rotate-secret" clients rotate-secret smoke-client --secret-file /shared/client-secret

echo "OK — $image (${platform:-host platform}) runs as 65532, reports $version, and its init-container commands work."
