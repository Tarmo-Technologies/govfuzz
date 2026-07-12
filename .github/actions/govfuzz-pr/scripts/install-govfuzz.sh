#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install the govfuzz CLI onto a GitHub Actions runner.
#
# Fast path: download the cargo-dist release installer for the requested tag
# (default: latest). Fallback: `cargo install --git` from source. Either way
# the resulting binary directory is appended to $GITHUB_PATH.
set -euo pipefail

REPO="Tarmo-Technologies/govfuzz"
version="${INPUT_VERSION:-latest}"
build_from_source="${INPUT_BUILD_FROM_SOURCE:-false}"

install_from_source() {
  echo "govfuzz: installing from source (cargo install --git https://github.com/${REPO})"
  cargo install --git "https://github.com/${REPO}" govfuzz --locked
  echo "${CARGO_HOME:-$HOME/.cargo}/bin" >> "$GITHUB_PATH"
}

if [[ "$build_from_source" == "true" ]]; then
  install_from_source
  exit 0
fi

# Resolve the release tag.
tag=""
if [[ "$version" == "latest" || -z "$version" ]]; then
  tag="$(gh api "repos/${REPO}/releases/latest" --jq .tag_name 2>/dev/null || true)"
else
  tag="$version"
fi

if [[ -z "$tag" ]]; then
  echo "govfuzz: no published release found; falling back to a source build"
  install_from_source
  exit 0
fi

installer="https://github.com/${REPO}/releases/download/${tag}/govfuzz-installer.sh"
echo "govfuzz: installing ${tag} via ${installer}"
if curl --proto '=https' --tlsv1.2 -LsSf "$installer" | sh; then
  echo "${CARGO_HOME:-$HOME/.cargo}/bin" >> "$GITHUB_PATH"
  echo "govfuzz: installed ${tag}"
else
  echo "govfuzz: release installer failed; falling back to a source build"
  install_from_source
fi
