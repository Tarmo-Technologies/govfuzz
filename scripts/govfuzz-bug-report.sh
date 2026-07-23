#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

usage() {
  printf '%s\n' \
    'Usage: govfuzz-bug-report WORK_DIR [OUTPUT_FILE]' \
    '' \
    'Create one compact scrubbed report from a running or completed govfuzz auto work directory.' \
    'No source, harness code, corpus data, paths, file names, targets, variables, types, units,' \
    'symbols, or macros are included. Default output: ./govfuzz-support-report.txt'
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
  '')
    usage >&2
    exit 2
    ;;
esac

work_dir=$1
output_file=${2:-govfuzz-support-report.txt}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

govfuzz_bin=
for candidate in "$script_dir/govfuzz" "$script_dir/../govfuzz"; do
  if [ -x "$candidate" ]; then
    govfuzz_bin=$candidate
    break
  fi
done
if [ -z "$govfuzz_bin" ]; then
  govfuzz_bin=$(command -v govfuzz 2>/dev/null || true)
fi
if [ -z "$govfuzz_bin" ]; then
  printf '%s\n' 'govfuzz-bug-report: could not find the govfuzz executable' >&2
  exit 2
fi

exec "$govfuzz_bin" bug-report "$work_dir" --output "$output_file" --stdout \
  --examples 6 --max-bytes 4000
