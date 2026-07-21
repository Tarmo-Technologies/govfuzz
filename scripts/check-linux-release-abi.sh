#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/check-linux-release-abi.sh [RELEASE_DIR]

Verify that the shipped Linux ELF artifacts run on the RHEL 7 glibc baseline
and that the preload shim retains its required public interception symbols.

Environment:
  MAX_GLIBC_VERSION  Highest permitted GLIBC symbol version (default: 2.17)
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi
[[ $# -le 1 ]] || {
  usage >&2
  exit 2
}

release_dir=${1:-target/release}
max_glibc=${MAX_GLIBC_VERSION:-2.17}
artifacts=(govfuzz govfuzz-daemon libgovfuzz_runtrace_shim.so)

command -v objdump >/dev/null 2>&1 || {
  echo "error: objdump is required" >&2
  exit 1
}
command -v nm >/dev/null 2>&1 || {
  echo "error: nm is required" >&2
  exit 1
}

for artifact in "${artifacts[@]}"; do
  path="$release_dir/$artifact"
  [[ -f $path ]] || {
    echo "error: missing release artifact: $path" >&2
    exit 1
  }

  required=$(
    objdump -T "$path" \
      | sed -n 's/.*GLIBC_\([0-9][0-9.]*\).*/\1/p' \
      | sort -Vu \
      | tail -n 1
  )
  [[ -n $required ]] || {
    echo "error: no GLIBC requirements found in $path" >&2
    exit 1
  }

  newest=$(printf '%s\n%s\n' "$max_glibc" "$required" | sort -V | tail -n 1)
  if [[ $newest != "$max_glibc" ]]; then
    echo "error: $path requires GLIBC_$required, newer than GLIBC_$max_glibc" >&2
    exit 1
  fi
  printf '%s: maximum required symbol GLIBC_%s\n' "$artifact" "$required"
done

shim="$release_dir/libgovfuzz_runtrace_shim.so"
required_exports=(
  printf
  fprintf
  dprintf
  sprintf
  snprintf
  __assert_fail
  __assert_perror_fail
)
for symbol in "${required_exports[@]}"; do
  if ! nm -D --defined-only "$shim" | awk -v wanted="$symbol" \
    '$3 == wanted { found = 1 } END { exit !found }'; then
    echo "error: $shim does not export required symbol $symbol" >&2
    exit 1
  fi
done
printf '%s: required preload exports present\n' "$shim"
