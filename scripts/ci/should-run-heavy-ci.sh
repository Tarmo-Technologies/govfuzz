#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Be conservative when the caller cannot determine the changed paths.
if (( $# == 0 )); then
  echo true
  exit 0
fi

for path in "$@"; do
  case "$path" in
    *.md | docs/* | scripts/docs/* | LICENSE | NOTICE | .github/ISSUE_TEMPLATE/* | .github/PULL_REQUEST_TEMPLATE*)
      ;;
    *)
      echo true
      exit 0
      ;;
  esac
done

echo false
