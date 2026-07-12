#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Resolve the git ref to diff against for PR-native fuzzing.
#
# Precedence:
#   1. an explicit `base-ref` input,
#   2. the PR base commit (pull_request events),
#   3. the repo default branch (push events),
#   4. HEAD~1 (last resort).
set -euo pipefail

ref="${INPUT_BASE_REF:-}"
if [[ -z "$ref" ]]; then
  if [[ -n "${GH_BASE_SHA:-}" ]]; then
    ref="$GH_BASE_SHA"
  elif [[ -n "${GH_DEFAULT_BRANCH:-}" ]]; then
    ref="origin/${GH_DEFAULT_BRANCH}"
  else
    ref="HEAD~1"
  fi
fi

echo "ref=$ref" >> "$GITHUB_OUTPUT"
echo "govfuzz: diffing against $ref"
