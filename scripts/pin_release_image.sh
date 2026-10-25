#!/usr/bin/env bash
# Point action.yml, pipe.yml and the bitbucket-pipelines.yml sample at the
# released image by tag and digest instead of :latest. Touches nothing else.
# Run from the repo root by .github/workflows/release.yml.
#
# Usage: scripts/pin_release_image.sh VERSION sha256:DIGEST
set -euo pipefail

version=$1
digest=$2

pin() { # file image: swap its one "<image>:latest" for "<image>:VERSION@DIGEST"
  if [ "$(grep -cF -- "$2:latest" "$1")" != 1 ]; then
    echo "::error::$1 must contain $2:latest exactly once"
    exit 1
  fi
  sed -i.bak "s|$2:latest|$2:${version}@${digest}|" "$1"
  rm "$1.bak"
}

pin action.yml docker://ghcr.io/sbomify/sbomify-action
pin pipe.yml sbomifyhub/sbomify-action
pin bitbucket-pipelines.yml docker://sbomifyhub/sbomify-action
