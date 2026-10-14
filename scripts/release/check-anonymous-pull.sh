#!/usr/bin/env bash
#
# check-anonymous-pull.sh — prove that an ANONYMOUS client can pull an image from GHCR (SSO-3687).
#
# Usage: scripts/release/check-anonymous-pull.sh <ghcr.io/owner/name:tag> [<expected-digest>]
#
#   <ghcr.io/owner/name:tag>  the reference to check, e.g. ghcr.io/thoryn-io/thoryn-cli:0.25.0
#   <expected-digest>         optional sha256:… — the tag must resolve to exactly this digest
#                             (the one the release just pushed), not merely exist
#
# The release workflow runs this right after pushing the thoryn-cli image. A package GitHub creates on
# its first push is PRIVATE, and everything before this check (build, push, sign) succeeds regardless —
# so without it a release could publish an image no customer cluster can pull and still report green.
#
# It speaks the registry protocol with curl and NO credential at all: it asks ghcr.io's token service
# for an anonymous pull token, then requests the manifest with it. Nothing it does can pick up a
# docker login, a credential helper, or the job's GITHUB_TOKEN. Exit 0 = anonymously pullable (and at
# the expected digest); exit 1 = not, with the operator fix printed.
set -euo pipefail

ref="${1:?usage: check-anonymous-pull.sh <ghcr.io/owner/name:tag> [<expected-digest>]}"
expected="${2:-}"

case "$ref" in
  ghcr.io/*:*) ;;
  *) echo "check-anonymous-pull: '$ref' is not a ghcr.io/<owner>/<name>:<tag> reference" >&2; exit 64 ;;
esac
path="${ref#ghcr.io/}"
repo="${path%:*}"
tag="${path##*:}"
package="${repo##*/}"
owner="${repo%%/*}"

attempts="${CHECK_ANONYMOUS_PULL_ATTEMPTS:-5}"
delay="${CHECK_ANONYMOUS_PULL_DELAY:-6}"
accept="application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"

fail() {
  cat >&2 <<EOF
::error::$ref is NOT anonymously pullable: $1
An init container in a customer cluster pulls this image with no registry credential, so a private (or
missing) package is a broken release even though the push succeeded.

Operator fix (an owner of the ${owner} organization, once per package):
  1. Organization settings -> Packages -> "Package creation": allow PUBLIC packages
     (https://github.com/organizations/${owner}/settings/packages).
  2. Package settings -> "Danger Zone" -> "Change visibility" -> Public
     (https://github.com/orgs/${owner}/packages/container/${package}/settings).
  3. Re-run this job (or: gh workflow run release.yml -f tag=<the cli-v tag>). Re-running only
     re-checks; the image is already pushed and signed.
EOF
  exit 1
}

last=""
for i in $(seq 1 "$attempts"); do
  # 1. An anonymous pull token. ghcr.io hands one out for any repository name; whether it is GOOD for a
  #    pull is what step 2 finds out.
  token_json="$(curl -sS --max-time 20 "https://ghcr.io/token?service=ghcr.io&scope=repository:${repo}:pull" || true)"
  token="$(printf '%s' "$token_json" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  if [ -z "$token" ]; then
    last="the token service gave no anonymous pull token (response: ${token_json:0:200})"
  else
    # 2. The manifest, with that token only.
    headers="$(mktemp)"
    code="$(curl -sS --max-time 20 -o /dev/null -D "$headers" -w '%{http_code}' \
      -H "Authorization: Bearer ${token}" -H "Accept: ${accept}" \
      "https://ghcr.io/v2/${repo}/manifests/${tag}" || echo 000)"
    digest="$(tr -d '\r' < "$headers" | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest:[[:space:]]*//p' | head -1)"
    rm -f "$headers"
    if [ "$code" = "200" ]; then
      if [ -n "$expected" ] && [ "$digest" != "$expected" ]; then
        # Pullable, but not what was just pushed — a stale tag, or a race with another publish.
        echo "::error::$ref is pullable but resolves to ${digest:-<no digest>}, not the digest just pushed ($expected)." >&2
        exit 1
      fi
      echo "OK — $ref is anonymously pullable (${digest:-digest not reported})."
      exit 0
    fi
    last="the anonymous manifest request answered HTTP $code"
  fi
  if [ "$i" -lt "$attempts" ]; then
    echo "attempt $i/$attempts: $last — retrying in ${delay}s" >&2
    sleep "$delay"
  fi
done
fail "$last"
