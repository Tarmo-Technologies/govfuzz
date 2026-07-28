#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly FIXTURE_PIPELINES="swallowed_constraint_error access_param private_state missing_dependency fake_corba_servant"

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    printf 'required environment variable %s is not set\n' "$name" >&2
    exit 2
  fi
}

validate_value() {
  local name="$1"
  local value="$2"
  shift 2
  for allowed in "$@"; do
    if [ "$value" = "$allowed" ]; then
      return 0
    fi
  done

  printf 'unsupported %s value: %s\n' "$name" "$value" >&2
  exit 2
}

write_gprbuild_wrapper() {
  local wrapper_dir="$1"
  local config_path="$2"

  mkdir -p "$wrapper_dir"
  cat >"$wrapper_dir/gprbuild" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -gt 0 ]; then
  case "$1" in
    --help|--version)
      exec /usr/bin/gprbuild "$@"
      ;;
  esac
fi

exec /usr/bin/gprbuild --config="${GOVFUZZ_M19_GPR_CONFIG:?}" "$@"
EOF
  chmod +x "$wrapper_dir/gprbuild"

  export GOVFUZZ_M19_GPR_CONFIG="$config_path"
  export PATH="$wrapper_dir:$PATH"
}

link_versioned_gnat_tools() {
  local wrapper_dir="$1"
  local version="$2"

  mkdir -p "$wrapper_dir"
  for tool in gcc gnat gnatbind gnatclean gnatkr gnatlink gnatls gnatmake gnatname gnatprep; do
    if command -v "${tool}-${version}" >/dev/null 2>&1; then
      ln -sf "$(command -v "${tool}-${version}")" "$wrapper_dir/$tool"
    fi
  done
}

gnatmake_supports_ada2022() {
  local gnatmake="$1"
  local probe_dir
  probe_dir="$(mktemp -d)"
  (
    cd "$probe_dir"
    printf '%s\n' 'procedure Canary is begin null; end Canary;' > canary.adb
    "$gnatmake" -c -gnat2022 canary.adb >/dev/null 2>&1
  )
}

install_ada2022_compat_wrapper() {
  local wrapper_dir="$1"
  local config_path="$2"
  local version="$3"
  local real_gcc="/usr/bin/gcc-${version}"
  local wrapper="$wrapper_dir/gcc-${version}-ada2022-compat"

  cat >"$wrapper" <<EOF
#!/usr/bin/env bash
set -euo pipefail

args=()
for arg in "\$@"; do
  if [ "\$arg" = "-gnat2022" ]; then
    args+=("-gnat2020")
  else
    args+=("\$arg")
  fi
done

exec "$real_gcc" "\${args[@]}"
EOF
  chmod +x "$wrapper"

  sed -i "s#\"$real_gcc\"#\"$wrapper\"#g" "$config_path"
  printf 'GNAT %s does not support -gnat2022; using -gnat2020 compiler compatibility wrapper\n' \
    "$version"
}

main() {
  require_env GOVFUZZ_GNAT_VERSION
  require_env GOVFUZZ_ADA_DIALECT
  require_env GOVFUZZ_PROFILE

  validate_value GOVFUZZ_GNAT_VERSION "$GOVFUZZ_GNAT_VERSION" 11 12 13 14
  validate_value GOVFUZZ_ADA_DIALECT "$GOVFUZZ_ADA_DIALECT" ada95 ada2005 ada2012 ada2022
  validate_value GOVFUZZ_PROFILE "$GOVFUZZ_PROFILE" strict-permissive external-tools

  local gnatmake="gnatmake-${GOVFUZZ_GNAT_VERSION}"
  if ! command -v "$gnatmake" >/dev/null 2>&1; then
    printf 'missing %s on PATH\n' "$gnatmake" >&2
    exit 2
  fi
  if ! command -v gprconfig >/dev/null 2>&1; then
    printf 'missing gprconfig on PATH\n' >&2
    exit 2
  fi

  local temp_root="${RUNNER_TEMP:-/tmp}"
  local config_path="${temp_root}/govfuzz-gnat-${GOVFUZZ_GNAT_VERSION}.cgpr"
  local wrapper_dir="${temp_root}/govfuzz-gnat-${GOVFUZZ_GNAT_VERSION}-bin"

  # BOTH languages, or none of them. The generated config is force-fed to every
  # gprbuild in this cell by the wrapper below, and the Ada runtime project
  # declares `for Languages use ("Ada", "C")` — it compiles `adafuzz_cov.c`, the
  # uninstrumented trace-pc callback. An Ada-only config carries C naming
  # conventions but no C DRIVER, so every cell died on
  # `adafuzz_runtime.gpr:2:09: no compiler for language "C"` and this matrix had
  # been red on every nightly run. The C compiler is version-matched to the Ada
  # one so the pair is what gprconfig would have chosen itself.
  gprconfig --batch \
    "--config=Ada,,,,$gnatmake" \
    "--config=C,,,,gcc-${GOVFUZZ_GNAT_VERSION}" \
    -o "$config_path"
  link_versioned_gnat_tools "$wrapper_dir" "$GOVFUZZ_GNAT_VERSION"
  if [ "$GOVFUZZ_ADA_DIALECT" = "ada2022" ] && ! gnatmake_supports_ada2022 "$gnatmake"; then
    install_ada2022_compat_wrapper "$wrapper_dir" "$config_path" "$GOVFUZZ_GNAT_VERSION"
  fi
  write_gprbuild_wrapper "$wrapper_dir" "$config_path"

  printf 'GNAT matrix cell: GNAT %s / %s / %s\n' \
    "$GOVFUZZ_GNAT_VERSION" "$GOVFUZZ_ADA_DIALECT" "$GOVFUZZ_PROFILE"
  "$gnatmake" --version | sed -n '1p'
  printf 'fixture pipelines: %s\n' "$FIXTURE_PIPELINES"

  GOVFUZZ_M19_FULL_CI=1 \
    cargo test -p govfuzz --test m19_full_ci_matrix \
      full_ci_fixture_pipelines_cover_active_matrix_cell -- --nocapture
}

main "$@"
