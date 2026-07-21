#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

PREFIX="/opt/govfuzz"
BIN_DIR="/usr/local/bin"
NON_INTERACTIVE=0
DRY_RUN=0
NO_SYSTEM_PACKAGES=0
PACKAGE_MANAGER="auto"
NO_RUSTUP=0
NO_CONTENT=0
NO_SYMLINK=0
NO_SMOKE=0
INSTALL_SEEDS=0
SMOKE_WORK_DIR=""
LANGUAGES=""
TARGETS=""
FUZZERS=""
EXTRAS=""

DEFAULT_LANGUAGES="c,cpp,rust,java,python,perl,go,ada"
DEFAULT_TARGETS="native"
DEFAULT_FUZZERS="builtin"
DEFAULT_EXTRAS="build-recovery,archives"

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Install or update a binary-only GovFuzz distribution.

On a TTY the interactive installer shows a whiptail (or dialog) boxed "popup"
checklist — Up/Down move, Space toggles, Enter accepts, Esc/Cancel aborts. If
neither whiptail nor dialog is installed (or GOVFUZZ_INSTALL_NO_GUI is set) it
uses a built-in arrow-key checklist; minimal terminals use a numbered
multi-select. Pass --non-interactive to skip all prompts and use
--languages/--targets/--fuzzers.

Options:
  --prefix DIR            Install prefix (default: /opt/govfuzz)
  --bin-dir DIR           Directory for govfuzz symlinks (default: /usr/local/bin)
  --non-interactive       Do not prompt; use selected or default profiles
  --languages LIST        Comma list: c,cpp,rust,java,python,perl,go,ada,cobol,
                          fortran,csharp,javascript,typescript,ruby,lua,php,all,none
  --targets LIST          Comma list: native,windows,aarch64,all,none
  --fuzzers LIST          Comma list: builtin,afl,all,none
  --extras LIST           Comma list: build-recovery,sandbox,archives,all,none
  --install-seeds         Extract bundled seed corpus into <prefix>/corpora/seeds
  --package-manager NAME  System package manager: auto, apt-get, dnf, yum, none
                          (default: auto)
  --no-system-packages    Skip system package installation
  --no-apt                Compatibility alias for --no-system-packages
  --no-rustup             Skip rustup installation and nightly toolchain setup
  --no-content            Skip signed content pack verify/install
  --no-symlink            Do not create govfuzz symlinks in --bin-dir
  --no-smoke              Skip the post-install govfuzz auto smoke test
  --smoke-work-dir DIR    Work directory for the post-install smoke test
  --dry-run               Print commands without executing them
  -h, --help              Show this help
EOF
}

die() {
  printf 'install.sh: %s\n' "$*" >&2
  exit 1
}
warn() {
  printf 'install.sh: warning: %s\n' "$*" >&2
}

normalize_list() {
  local value="${1:-}"
  value="${value// /}"
  printf '%s' "$value" | tr '[:upper:]' '[:lower:]'
}

contains_item() {
  local list
  local item
  list=",$(normalize_list "$1"),"
  item="$(normalize_list "$2")"
  [[ "$list" == *",$item,"* ]]
}

quote_cmd() {
  local first=1
  local arg
  for arg in "$@"; do
    if [[ "$first" -eq 0 ]]; then
      printf ' '
    fi
    printf '%q' "$arg"
    first=0
  done
  printf '\n'
}

run() {
  printf '+ '
  quote_cmd "$@"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    "$@"
  fi
}

run_with_optional_prefix() {
  local prefix=$1
  shift
  if [[ -n "$prefix" ]]; then
    run "$prefix" "$@"
  else
    run "$@"
  fi
}

path_writable_for_create() {
  local path="$1"
  local parent
  if [[ -e "$path" ]]; then
    [[ -w "$path" && -x "$path" ]]
    return
  fi
  parent="$(dirname "$path")"
  while [[ ! -e "$parent" && "$parent" != "/" ]]; do
    parent="$(dirname "$parent")"
  done
  [[ -d "$parent" && -w "$parent" && -x "$parent" ]]
}

sudo_prefix_for_path() {
  local path="$1"
  if [[ "${EUID:-$(id -u)}" -eq 0 ]] || path_writable_for_create "$path"; then
    return 0
  fi
  printf 'sudo'
}

add_unique() {
  local array_name=$1
  shift
  local item existing
  for item in "$@"; do
    [[ -n "$item" ]] || continue
    case "$array_name" in
      APT_PACKAGES)
        for existing in "${APT_PACKAGES[@]:-}"; do
          [[ "$existing" == "$item" ]] && continue 2
        done
        APT_PACKAGES+=("$item")
        ;;
      RPM_PACKAGES)
        for existing in "${RPM_PACKAGES[@]:-}"; do
          [[ "$existing" == "$item" ]] && continue 2
        done
        RPM_PACKAGES+=("$item")
        ;;
      AVAILABLE_RPM_PACKAGES)
        for existing in "${AVAILABLE_RPM_PACKAGES[@]:-}"; do
          [[ "$existing" == "$item" ]] && continue 2
        done
        AVAILABLE_RPM_PACKAGES+=("$item")
        ;;
      *)
        die "internal error: unsupported package array '$array_name'"
        ;;
    esac
  done
}

expand_selection() {
  local selection
  selection="$(normalize_list "$1")"
  shift
  local all_items=("$@")
  local out=()
  local raw item allowed

  if [[ -z "$selection" || "$selection" == "none" ]]; then
    printf '%s' ""
    return 0
  fi
  if [[ "$selection" == "all" ]]; then
    (IFS=,; printf '%s' "${all_items[*]}")
    return 0
  fi

  IFS=',' read -r -a raw <<<"$selection"
  for item in "${raw[@]}"; do
    [[ -n "$item" ]] || continue
    for allowed in "${all_items[@]}"; do
      if [[ "$item" == "$allowed" ]]; then
        out+=("$item")
        continue 2
      fi
    done
    die "unknown selection '$item' (expected one of: ${all_items[*]}, all, none)"
  done
  (IFS=,; printf '%s' "${out[*]}")
}

terminal_checklist_render() {
  local title="$1"
  local cursor="$2"
  # Bash uses dynamic scoping for local variables, so these arrays resolve to
  # terminal_checklist's locals. Avoid namerefs (`local -n`), which require
  # Bash 4.3 and are unavailable on RHEL 7's Bash 4.2.
  local count="${#tags[@]}"
  local i marker checked

  printf '\033[H\033[J' >&2
  printf '%s\n' "$title" >&2
  printf 'Use Up/Down to move, Space to toggle options, Enter to accept OK or Cancel.\n\n' >&2

  for ((i = 0; i < count; i++)); do
    marker=" "
    if [[ "$cursor" -eq "$i" ]]; then
      marker=">"
    fi
    checked=" "
    if [[ "${states[$i]}" == "on" ]]; then
      checked="x"
    fi
    printf '%s [%s] %-14s %s\n' "$marker" "$checked" "${tags[$i]}" "${descs[$i]}" >&2
  done

  printf '\n' >&2
  marker=" "
  if [[ "$cursor" -eq "$count" ]]; then
    marker=">"
  fi
  printf '%s [ OK ]       Continue with the selected items\n' "$marker" >&2
  marker=" "
  if [[ "$cursor" -eq $((count + 1)) ]]; then
    marker=">"
  fi
  printf '%s [ Cancel ]   Abort installation\n' "$marker" >&2
}

terminal_checklist_emit() {
  local selected=()
  local i
  for ((i = 0; i < ${#tags[@]}; i++)); do
    if [[ "${states[$i]}" == "on" ]]; then
      selected+=("${tags[$i]}")
    fi
  done
  (IFS=,; printf '%s' "${selected[*]}")
}

terminal_checklist() {
  local title="$1"
  local defaults="$2"
  shift 2
  local choices=("$@")
  local tags=()
  local descs=()
  local states=()
  local row tag desc state
  local cursor=0
  local key rest
  local choice_count max_cursor

  for row in "${choices[@]}"; do
    IFS='|' read -r tag desc state <<<"$row"
    if contains_item "$defaults" "$tag"; then
      state="on"
    fi
    tags+=("$tag")
    descs+=("$desc")
    states+=("$state")
  done

  choice_count="${#tags[@]}"
  max_cursor=$((choice_count + 1))

  while true; do
    terminal_checklist_render "$title" "$cursor"
    IFS= read -rsn1 key || key=""
    case "$key" in
      $'\033')
        rest=""
        IFS= read -rsn2 -t 0.1 rest || true
        case "$rest" in
          "[A")
            if (( cursor == 0 )); then
              cursor="$max_cursor"
            else
              cursor=$((cursor - 1))
            fi
            ;;
          "[B")
            if (( cursor == max_cursor )); then
              cursor=0
            else
              cursor=$((cursor + 1))
            fi
            ;;
        esac
        ;;
      $'\t')
        if (( cursor < choice_count )); then
          cursor="$choice_count"
        elif (( cursor == choice_count )); then
          cursor=$((choice_count + 1))
        else
          cursor="$choice_count"
        fi
        ;;
      " ")
        if (( cursor < choice_count )); then
          if [[ "${states[cursor]}" == "on" ]]; then
            states[cursor]="off"
          else
            states[cursor]="on"
          fi
        elif (( cursor == choice_count )); then
          printf '\033[H\033[J' >&2
          terminal_checklist_emit
          return 0
        else
          printf '\033[H\033[J' >&2
          printf 'Install cancelled.\n' >&2
          return 130
        fi
        ;;
      "")
        printf '\033[H\033[J' >&2
        if (( cursor == choice_count + 1 )); then
          printf 'Install cancelled.\n' >&2
          return 130
        fi
        terminal_checklist_emit
        return 0
        ;;
    esac
  done
}

fallback_checklist() {
  local title="$1"
  local defaults="$2"
  shift 2
  local choices=("$@")
  local row tag desc answer
  local -a tags=()

  printf '\n%s\n' "$title" >&2
  local index=1
  for row in "${choices[@]}"; do
    IFS='|' read -r tag desc _ <<<"$row"
    tags+=("$tag")
    if contains_item "$defaults" "$tag"; then
      printf '  %d. [%s] %s\n' "$index" "x" "$desc" >&2
    else
      printf '  %d. [%s] %s\n' "$index" " " "$desc" >&2
    fi
    index=$((index + 1))
  done
  printf 'Select numbers/tags separated by commas, or all/none. Enter keeps defaults: ' >&2
  read -r answer || true
  answer="$(normalize_list "$answer")"
  if [[ -z "$answer" ]]; then
    printf '%s' "$defaults"
    return 0
  fi
  if [[ "$answer" == "all" ]]; then
    (IFS=,; printf '%s' "${tags[*]}")
    return 0
  fi
  if [[ "$answer" == "none" ]]; then
    printf '%s' ""
    return 0
  fi

  local -a picked=()
  local part selected
  IFS=',' read -r -a selected <<<"$answer"
  for part in "${selected[@]}"; do
    [[ -n "$part" ]] || continue
    if [[ "$part" =~ ^[0-9]+$ ]]; then
      if (( part < 1 || part > ${#tags[@]} )); then
        die "selection '$part' is out of range"
      fi
      picked+=("${tags[$((part - 1))]}")
    else
      picked+=("$part")
    fi
  done
  (IFS=,; printf '%s' "${picked[*]}")
}

# Boxed "popup" checklist via whiptail (or dialog) — the classic Linux-installer
# GUI feel, and far more robust across terminals (SSH, tmux, serial/disconnected
# consoles) than the hand-rolled escape-sequence checklist below. Same interface
# as ask_checklist: prints the selected tags as a comma list on stdout. Returns
# 130 if the user cancels, or 2 (no output) when neither tool is installed so the
# caller can fall back.
gui_checklist() {
  local title="$1"
  local defaults="$2"
  shift 2
  # Escape hatch: force the built-in arrow-key checklist (skip whiptail/dialog).
  # Useful on a minimal/CI terminal where the boxed popup misbehaves, and lets the
  # test suite drive the deterministic fallback.
  if [[ -n "${GOVFUZZ_INSTALL_NO_GUI:-}" ]]; then
    return 2
  fi
  local tool
  if command -v whiptail >/dev/null 2>&1; then
    tool="whiptail"
  elif command -v dialog >/dev/null 2>&1; then
    tool="dialog"
  else
    return 2
  fi

  local -a items=()
  local row tag desc state onoff count=0
  for row in "$@"; do
    IFS='|' read -r tag desc state <<<"$row"
    onoff="off"
    if [[ "$state" == "on" ]] || contains_item "$defaults" "$tag"; then
      onoff="on"
    fi
    items+=("$tag" "$desc" "$onoff")
    count=$((count + 1))
  done

  local listh="$count"
  (( listh > 12 )) && listh=12
  local height=$((listh + 8))
  local width=78

  # whiptail/dialog draw the UI on the terminal and write the result to fd 2;
  # the 3>&1 1>&2 2>&3 dance captures that result into `out` while the box still
  # renders. --separate-output yields one selected tag per line.
  local out rc=0
  out="$(
    "$tool" --title "$title" --separate-output \
      --checklist "Up/Down move · Space toggles · Enter accepts · Esc/Cancel aborts" \
      "$height" "$width" "$listh" "${items[@]}" \
      3>&1 1>&2 2>&3
  )" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    printf 'Install cancelled.\n' >&2
    return 130
  fi

  local -a picked=()
  local line
  while IFS= read -r line; do
    [[ -n "$line" ]] && picked+=("$line")
  done <<<"$out"
  (IFS=,; printf '%s' "${picked[*]}")
}

ask_checklist() {
  local title="$1"
  local defaults="$2"
  shift 2
  if [[ -t 0 && -t 2 ]]; then
    # Preferred: the whiptail/dialog boxed popup (reliable across terminals).
    local gui rc=0
    gui="$(gui_checklist "$title" "$defaults" "$@")" || rc=$?
    if [[ "$rc" -eq 0 ]]; then
      printf '%s' "$gui"
      return 0
    elif [[ "$rc" -eq 130 ]]; then
      exit 130
    fi
    # rc == 2: neither whiptail nor dialog present. Fall back to the built-in
    # arrow-key checklist (needs a capable TERM), else numbered prompts.
    if [[ "${TERM:-dumb}" != "dumb" ]]; then
      terminal_checklist "$title" "$defaults" "$@"
    else
      fallback_checklist "$title" "$defaults" "$@"
    fi
  else
    fallback_checklist "$title" "$defaults" "$@"
  fi
}

resolve_bundle_root() {
  local script_dir="$1"
  if [[ -f "$script_dir/tool/govfuzz" ]]; then
    printf '%s' "$script_dir"
    return 0
  fi
  if [[ -f "$PWD/tool/govfuzz" ]]; then
    printf '%s' "$PWD"
    return 0
  fi
  die "could not find distribution root; expected tool/govfuzz beside install.sh or in the current directory"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      [[ $# -ge 2 ]] || die "--prefix requires a directory"
      PREFIX="$2"
      shift 2
      ;;
    --bin-dir)
      [[ $# -ge 2 ]] || die "--bin-dir requires a directory"
      BIN_DIR="$2"
      shift 2
      ;;
    --non-interactive)
      NON_INTERACTIVE=1
      shift
      ;;
    --languages)
      [[ $# -ge 2 ]] || die "--languages requires a list"
      LANGUAGES="$2"
      shift 2
      ;;
    --targets)
      [[ $# -ge 2 ]] || die "--targets requires a list"
      TARGETS="$2"
      shift 2
      ;;
    --fuzzers)
      [[ $# -ge 2 ]] || die "--fuzzers requires a list"
      FUZZERS="$2"
      shift 2
      ;;
    --extras)
      [[ $# -ge 2 ]] || die "--extras requires a list"
      EXTRAS="$2"
      shift 2
      ;;
    --install-seeds)
      INSTALL_SEEDS=1
      shift
      ;;
    --package-manager)
      [[ $# -ge 2 ]] || die "--package-manager requires a name"
      PACKAGE_MANAGER="$(normalize_list "$2")"
      shift 2
      ;;
    --no-system-packages|--no-apt)
      NO_SYSTEM_PACKAGES=1
      shift
      ;;
    --no-rustup)
      NO_RUSTUP=1
      shift
      ;;
    --no-content)
      NO_CONTENT=1
      shift
      ;;
    --no-symlink)
      NO_SYMLINK=1
      shift
      ;;
    --no-smoke)
      NO_SMOKE=1
      shift
      ;;
    --smoke-work-dir)
      [[ $# -ge 2 ]] || die "--smoke-work-dir requires a directory"
      SMOKE_WORK_DIR="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option '$1'"
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
BUNDLE_ROOT="$(resolve_bundle_root "$SCRIPT_DIR")"
TOOL_DIR="$BUNDLE_ROOT/tool"
CONTENT_ROOT="$BUNDLE_ROOT/content"
PACK_ROOT="$CONTENT_ROOT/packs/current"
PACK_MANIFEST="$PACK_ROOT/update-pack.json"
POLICY_FILE="$CONTENT_ROOT/govfuzz-policy.json"
SMOKE_ROOT="$BUNDLE_ROOT/smoke/c"

if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
  LANGUAGES="${LANGUAGES:-$DEFAULT_LANGUAGES}"
  TARGETS="${TARGETS:-$DEFAULT_TARGETS}"
  FUZZERS="${FUZZERS:-$DEFAULT_FUZZERS}"
  EXTRAS="${EXTRAS:-$DEFAULT_EXTRAS}"
  LANGUAGES="$(ask_checklist "Languages to support" "$LANGUAGES" \
    "c|C harnesses with clang + built-in engine|on" \
    "cpp|C++ harnesses with clang++ + built-in engine|on" \
    "rust|Rust harnesses with nightly sanitizers|on" \
    "java|Java harnesses and coverage agent|on" \
    "python|Python harnesses and coverage driver|on" \
    "perl|Perl harnesses and coverage driver|on" \
    "go|Go harnesses with atomic coverage|on" \
    "ada|Ada harnesses with GNAT/GPRbuild|on" \
    "cobol|COBOL harnesses with GnuCOBOL|off" \
    "fortran|Fortran harnesses with gfortran|off" \
    "csharp|C# harnesses with .NET + SharpFuzz|off" \
    "javascript|JavaScript harnesses with Node.js|off" \
    "typescript|TypeScript with Node.js + esbuild|off" \
    "ruby|Ruby harnesses and coverage driver|off" \
    "lua|Lua harnesses and coverage driver|off" \
    "php|PHP harnesses and coverage driver|off")"
  TARGETS="$(ask_checklist "Compile targets to support" "$TARGETS" \
    "native|Native Linux target|on" \
    "windows|Windows cross target and Wine smoke execution|off" \
    "aarch64|AArch64 cross target and qemu-user execution|off")"
  FUZZERS="$(ask_checklist "Fuzzers to install" "$FUZZERS" \
    "builtin|GovFuzz built-in coverage-guided fork-server engine|on" \
    "afl|AFL++ for native C/C++ targets|off")"
  EXTRAS="$(ask_checklist "Additional tooling" "$EXTRAS" \
    "build-recovery|Build recovery tools: cmake, ninja, autotools, meson|on" \
    "sandbox|Sandbox helpers: bubblewrap and firejail|off" \
    "archives|Archive utilities: zip, unzip, xz, zstd|on")"
else
  LANGUAGES="${LANGUAGES:-$DEFAULT_LANGUAGES}"
  TARGETS="${TARGETS:-$DEFAULT_TARGETS}"
  FUZZERS="${FUZZERS:-$DEFAULT_FUZZERS}"
  EXTRAS="${EXTRAS:-$DEFAULT_EXTRAS}"
fi

LANGUAGES="$(expand_selection "$LANGUAGES" c cpp rust java python perl go ada cobol fortran csharp javascript typescript ruby lua php)"
TARGETS="$(expand_selection "$TARGETS" native windows aarch64)"
FUZZERS="$(expand_selection "$FUZZERS" builtin afl)"
EXTRAS="$(expand_selection "$EXTRAS" build-recovery sandbox archives)"

printf 'GovFuzz distribution install\n'
printf '  bundle:    %s\n' "$BUNDLE_ROOT"
printf '  prefix:    %s\n' "$PREFIX"
printf '  languages: %s\n' "${LANGUAGES:-none}"
printf '  targets:   %s\n' "${TARGETS:-none}"
printf '  fuzzers:   %s\n' "${FUZZERS:-none}"
printf '  extras:    %s\n' "${EXTRAS:-none}"

detect_package_manager() {
  local requested="$1"
  local os_id=""
  local os_like=""

  case "$requested" in
    apt|apt-get) printf 'apt-get'; return 0 ;;
    dnf|yum|none) printf '%s' "$requested"; return 0 ;;
    auto) ;;
    *) die "unknown package manager '$requested' (expected: auto, apt-get, dnf, yum, none)" ;;
  esac

  if [[ -r /etc/os-release ]]; then
    # os-release is a shell-compatible file supplied by the operating system.
    # shellcheck disable=SC1091
    os_id="$(. /etc/os-release; printf '%s' "${ID:-}")"
    # shellcheck disable=SC1091
    os_like="$(. /etc/os-release; printf '%s' "${ID_LIKE:-}")"
  fi
  case " $os_id $os_like " in
    *rhel*|*fedora*|*centos*|*rocky*|*almalinux*)
      if command -v dnf >/dev/null 2>&1; then
        printf 'dnf'
      elif command -v yum >/dev/null 2>&1; then
        printf 'yum'
      else
        printf 'none'
      fi
      return 0
      ;;
    *debian*|*ubuntu*)
      command -v apt-get >/dev/null 2>&1 && printf 'apt-get' || printf 'none'
      return 0
      ;;
  esac

  if command -v dnf >/dev/null 2>&1; then
    printf 'dnf'
  elif command -v yum >/dev/null 2>&1; then
    printf 'yum'
  elif command -v apt-get >/dev/null 2>&1; then
    printf 'apt-get'
  else
    printf 'none'
  fi
}

APT_PACKAGES=()
RPM_PACKAGES=()
add_unique APT_PACKAGES ca-certificates curl
add_unique RPM_PACKAGES ca-certificates curl

if [[ "$NO_SMOKE" -eq 0 ]]; then
  add_unique APT_PACKAGES make clang llvm
  add_unique RPM_PACKAGES make clang llvm
fi
if contains_item "$LANGUAGES" c || contains_item "$LANGUAGES" cpp || contains_item "$LANGUAGES" rust; then
  add_unique APT_PACKAGES make clang llvm lld
  add_unique RPM_PACKAGES make clang llvm lld
  # RHEL 7's base clang is 3.4 and predates SanitizerCoverage. When the
  # supported RHSCL/SCLo repository is enabled, install LLVM Toolset 7 as the
  # coverage-capable compiler; the govfuzz binary activates its nonstandard
  # PATH/LD_LIBRARY_PATH automatically.
  RPM_PLATFORM_VERSION="$(awk -F= '$1 == "VERSION_ID" { gsub(/\"/, "", $2); print $2; exit }' /etc/os-release 2>/dev/null)"
  if [[ "$RPM_PLATFORM_VERSION" == 7 || "$RPM_PLATFORM_VERSION" == 7.* ]]; then
    add_unique RPM_PACKAGES llvm-toolset-7.0-clang llvm-toolset-7.0-compiler-rt
  fi
fi
if contains_item "$LANGUAGES" cpp; then
  add_unique APT_PACKAGES g++
  add_unique RPM_PACKAGES gcc-c++
fi
if contains_item "$LANGUAGES" ada; then
  add_unique APT_PACKAGES gnat gprbuild
  add_unique RPM_PACKAGES gcc-gnat gprbuild
fi
if contains_item "$LANGUAGES" java; then
  add_unique APT_PACKAGES default-jdk maven gradle
  add_unique RPM_PACKAGES java-17-openjdk-devel maven gradle
fi
if contains_item "$LANGUAGES" python; then
  add_unique APT_PACKAGES python3
  add_unique RPM_PACKAGES python3
fi
if contains_item "$LANGUAGES" perl; then
  add_unique APT_PACKAGES perl
  add_unique RPM_PACKAGES perl
fi
if contains_item "$LANGUAGES" go; then
  add_unique APT_PACKAGES golang-go
  add_unique RPM_PACKAGES golang
fi
if contains_item "$LANGUAGES" cobol; then
  add_unique APT_PACKAGES gnucobol make clang llvm
  add_unique RPM_PACKAGES gnucobol make clang llvm
fi
if contains_item "$LANGUAGES" fortran; then
  add_unique APT_PACKAGES gfortran make clang llvm
  add_unique RPM_PACKAGES gcc-gfortran make clang llvm
fi
if contains_item "$LANGUAGES" javascript || contains_item "$LANGUAGES" typescript; then
  add_unique APT_PACKAGES nodejs npm
  add_unique RPM_PACKAGES nodejs npm
fi
if contains_item "$LANGUAGES" ruby; then
  add_unique APT_PACKAGES ruby
  add_unique RPM_PACKAGES ruby
fi
if contains_item "$LANGUAGES" lua; then
  add_unique APT_PACKAGES lua5.4
  add_unique RPM_PACKAGES lua
fi
if contains_item "$LANGUAGES" php; then
  add_unique APT_PACKAGES php-cli
  add_unique RPM_PACKAGES php-cli
fi
if contains_item "$TARGETS" windows; then
  add_unique APT_PACKAGES gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 wine64
  add_unique RPM_PACKAGES mingw64-gcc mingw64-gcc-c++ wine
fi
if contains_item "$TARGETS" aarch64; then
  add_unique APT_PACKAGES gcc-aarch64-linux-gnu g++-aarch64-linux-gnu qemu-user
  # RHEL does not provide stable package names for these cross tools in its
  # base repositories. Keep qemu-user in the plan when an enabled supplemental
  # repository provides it; stage the cross compiler separately otherwise.
  add_unique RPM_PACKAGES qemu-user
fi
if contains_item "$FUZZERS" afl; then
  add_unique APT_PACKAGES afl++
  add_unique RPM_PACKAGES aflplusplus
fi
if contains_item "$EXTRAS" build-recovery; then
  add_unique APT_PACKAGES build-essential pkg-config cmake ninja-build meson autoconf automake libtool
  add_unique RPM_PACKAGES gcc gcc-c++ pkgconf-pkg-config cmake ninja-build meson autoconf automake libtool
fi
if contains_item "$EXTRAS" sandbox; then
  add_unique APT_PACKAGES bubblewrap firejail
  add_unique RPM_PACKAGES bubblewrap firejail
fi
if contains_item "$EXTRAS" archives; then
  add_unique APT_PACKAGES zip unzip tar gzip xz-utils zstd
  add_unique RPM_PACKAGES zip unzip tar gzip xz zstd
fi

SUDO_PACKAGES_WORD=""
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  SUDO_PACKAGES_WORD="sudo"
fi

PACKAGE_MANAGER="$(detect_package_manager "$PACKAGE_MANAGER")"
if [[ "$NO_SYSTEM_PACKAGES" -eq 1 ]]; then
  PACKAGE_MANAGER="none"
fi

case "$PACKAGE_MANAGER" in
  apt-get)
    # Best-effort: an offline update may already have every required package.
    # Warn and continue when the mirror cannot be reached; the bundled GovFuzz
    # binaries and runtimes can still be installed.
    if ! run_with_optional_prefix "$SUDO_PACKAGES_WORD" apt-get update; then
      warn "apt-get update failed (no network?); skipping dependency installation. Stage missing toolchains through your offline mirror and rerun, or use --no-system-packages. Continuing."
    elif ! run_with_optional_prefix "$SUDO_PACKAGES_WORD" apt-get install -y "${APT_PACKAGES[@]}"; then
      warn "apt-get install failed; some optional system toolchains may be missing. Continuing."
    fi
    ;;
  dnf|yum)
    if ! run_with_optional_prefix "$SUDO_PACKAGES_WORD" "$PACKAGE_MANAGER" -y makecache; then
      warn "$PACKAGE_MANAGER makecache failed (no network?); skipping dependency installation. Stage missing toolchains through your RHEL repository mirror and rerun, or use --no-system-packages. Continuing."
    elif [[ "$DRY_RUN" -eq 1 ]]; then
      run_with_optional_prefix "$SUDO_PACKAGES_WORD" "$PACKAGE_MANAGER" install -y "${RPM_PACKAGES[@]}"
    else
      # RHEL base/AppStream and optional supplemental repositories expose
      # different subsets. Install every requested package that is available so
      # one absent optional lane (for example GNAT or Wine) cannot block C/C++.
      AVAILABLE_RPM_PACKAGES=()
      for package in "${RPM_PACKAGES[@]}"; do
        if rpm -q "$package" >/dev/null 2>&1 \
          || "$PACKAGE_MANAGER" -q list --available "$package" >/dev/null 2>&1; then
          add_unique AVAILABLE_RPM_PACKAGES "$package"
        else
          warn "$package is unavailable in the enabled $PACKAGE_MANAGER repositories; its language/target lane may remain unavailable"
        fi
      done
      if [[ "${#AVAILABLE_RPM_PACKAGES[@]}" -gt 0 ]] \
        && ! run_with_optional_prefix "$SUDO_PACKAGES_WORD" "$PACKAGE_MANAGER" install -y "${AVAILABLE_RPM_PACKAGES[@]}"; then
        warn "$PACKAGE_MANAGER install failed; some optional system toolchains may be missing. Continuing."
      fi
    fi
    ;;
  none)
    printf 'Skipping system package dependency installation.\n'
    ;;
esac

clang_supports_govfuzz_coverage() {
  local compiler="$1"
  local runtime_lib="${2:-}"
  if [[ -n "$runtime_lib" ]]; then
    LD_LIBRARY_PATH="$runtime_lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
      "$compiler" -x c -c /dev/null -o /dev/null \
        -fsanitize-coverage=trace-pc-guard,trace-cmp >/dev/null 2>&1
  else
    "$compiler" -x c -c /dev/null -o /dev/null \
      -fsanitize-coverage=trace-pc-guard,trace-cmp >/dev/null 2>&1
  fi
}

if [[ "$DRY_RUN" -eq 0 ]] \
  && { [[ "$NO_SMOKE" -eq 0 ]] \
    || contains_item "$LANGUAGES" c \
    || contains_item "$LANGUAGES" cpp \
    || contains_item "$LANGUAGES" rust; }; then
  COVERAGE_CLANG_OK=0
  if command -v clang >/dev/null 2>&1 \
    && clang_supports_govfuzz_coverage "$(command -v clang)"; then
    COVERAGE_CLANG_OK=1
  else
    for SCL_ROOT in /opt/rh/llvm-toolset-7.0/root/usr /opt/rh/llvm-toolset-7/root/usr; do
      if [[ -x "$SCL_ROOT/bin/clang" ]] \
        && clang_supports_govfuzz_coverage "$SCL_ROOT/bin/clang" "$SCL_ROOT/lib64"; then
        COVERAGE_CLANG_OK=1
        break
      fi
    done
  fi
  if [[ "$COVERAGE_CLANG_OK" -ne 1 ]]; then
    die "C/C++ fuzzing requires Clang with -fsanitize-coverage=trace-pc-guard,trace-cmp. On RHEL 7, enable the Red Hat Software Collections repository (rhel-server-rhscl-7-rpms), install llvm-toolset-7.0-clang and llvm-toolset-7.0-compiler-rt, then rerun this installer"
  fi
fi

if contains_item "$LANGUAGES" rust && [[ "$NO_RUSTUP" -eq 0 ]]; then
  # A dry run is a PLAN, not a probe of this host: show the full fresh-install
  # command sequence deterministically (rustup + nightly) regardless of what the
  # current machine happens to have, so `--dry-run` output is host-independent.
  if [[ "$DRY_RUN" -eq 1 ]]; then
    run sh -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    run rustup toolchain install nightly
  else
    # rustup itself: install ONLY when absent. On an update the host already has
    # it, so it is never re-fetched. If it is absent on an offline host, fetching
    # it needs the network — warn and continue rather than aborting (pass
    # --no-rustup to skip this block entirely).
    if ! command -v rustup >/dev/null 2>&1; then
      if run sh -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"; then
        export PATH="$HOME/.cargo/bin:$PATH"
      else
        warn "rustup is not installed and could not be fetched (no network?). The Rust fuzzing lane needs a nightly toolchain; install it later on a connected host with 'rustup toolchain install nightly'. Continuing without it."
      fi
    fi
    # nightly toolchain: SKIP the (network-touching) install when it is already
    # present — the normal case for an UPDATE where Rust was set up while connected.
    # This is the fix for an offline update erroring on static.rust-lang.org. Only
    # fetch when genuinely missing, and never abort the install if that fetch fails
    # offline.
    if command -v rustup >/dev/null 2>&1; then
      if rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
        printf 'Rust nightly toolchain already installed; skipping download.\n'
      elif ! run rustup toolchain install nightly; then
        warn "could not install the Rust nightly toolchain (no network?). The Rust lane stays unavailable until you run 'rustup toolchain install nightly' on a connected host. Continuing."
      fi
    fi
  fi
else
  printf 'Skipping rustup nightly setup.\n'
fi

# Linux distributions do not expose one stable, distribution-independent
# package name for the current .NET SDK, SharpFuzz.CommandLine is a dotnet
# global tool, and esbuild may be project-local. Keep those choices explicit
# instead of silently adding a third-party feed or fetching npm/NuGet content.
if contains_item "$LANGUAGES" csharp; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'C# prerequisite: install a .NET 8 SDK and: dotnet tool install --global SharpFuzz.CommandLine\n'
  else
    command -v dotnet >/dev/null 2>&1 || warn "C# selected but no dotnet SDK is on PATH; install a .NET 8 SDK before fuzzing C#"
    if ! command -v sharpfuzz >/dev/null 2>&1 && [[ ! -x "${HOME}/.dotnet/tools/sharpfuzz" ]]; then
      warn "C# selected but SharpFuzz.CommandLine is missing; install it on a connected staging host with 'dotnet tool install --global SharpFuzz.CommandLine'"
    fi
  fi
fi
if contains_item "$LANGUAGES" typescript; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'TypeScript prerequisite: put esbuild on PATH or in the target project for npx --no-install esbuild.\n'
  elif ! command -v esbuild >/dev/null 2>&1; then
    warn "TypeScript selected but esbuild is not on PATH; a project-local esbuild reachable by 'npx --no-install esbuild' also works"
  fi
fi

[[ -d "$TOOL_DIR" ]] || die "missing tool directory: $TOOL_DIR"
[[ -f "$TOOL_DIR/govfuzz" ]] || die "missing GovFuzz binary: $TOOL_DIR/govfuzz"

SUDO_INSTALL_WORD="$(sudo_prefix_for_path "$PREFIX")"

TIMESTAMP="$(date +%Y%m%d%H%M%S)"
NEW_PREFIX="${PREFIX}.new.$$"
BACKUP_PREFIX="${PREFIX}.backup.${TIMESTAMP}"

run_with_optional_prefix "$SUDO_INSTALL_WORD" rm -rf "$NEW_PREFIX"
run_with_optional_prefix "$SUDO_INSTALL_WORD" mkdir -p "$NEW_PREFIX"
run_with_optional_prefix "$SUDO_INSTALL_WORD" cp -a "$TOOL_DIR/." "$NEW_PREFIX/"

if [[ -d "$PREFIX/packs" ]]; then
  run_with_optional_prefix "$SUDO_INSTALL_WORD" rm -rf "$NEW_PREFIX/packs"
  run_with_optional_prefix "$SUDO_INSTALL_WORD" cp -a "$PREFIX/packs" "$NEW_PREFIX/packs"
fi
if [[ -d "$PREFIX/corpora" ]]; then
  run_with_optional_prefix "$SUDO_INSTALL_WORD" rm -rf "$NEW_PREFIX/corpora"
  run_with_optional_prefix "$SUDO_INSTALL_WORD" cp -a "$PREFIX/corpora" "$NEW_PREFIX/corpora"
fi

if [[ -e "$PREFIX" ]]; then
  run_with_optional_prefix "$SUDO_INSTALL_WORD" rm -rf "$BACKUP_PREFIX"
  run_with_optional_prefix "$SUDO_INSTALL_WORD" mv "$PREFIX" "$BACKUP_PREFIX"
  printf 'Previous install moved to %s\n' "$BACKUP_PREFIX"
fi
run_with_optional_prefix "$SUDO_INSTALL_WORD" mv "$NEW_PREFIX" "$PREFIX"

if [[ "$NO_SYMLINK" -eq 0 ]]; then
  SUDO_BIN_WORD="$(sudo_prefix_for_path "$BIN_DIR")"
  run_with_optional_prefix "$SUDO_BIN_WORD" mkdir -p "$BIN_DIR"
  run_with_optional_prefix "$SUDO_BIN_WORD" ln -sfn "$PREFIX/govfuzz" "$BIN_DIR/govfuzz"
  if [[ -f "$PREFIX/govfuzz-daemon" ]]; then
    run_with_optional_prefix "$SUDO_BIN_WORD" ln -sfn "$PREFIX/govfuzz-daemon" "$BIN_DIR/govfuzz-daemon"
  fi
fi

if [[ "$NO_CONTENT" -eq 0 && -f "$PACK_MANIFEST" ]]; then
  PACK_VERIFY=("$PREFIX/govfuzz" pack verify "$PACK_MANIFEST" --root "$PACK_ROOT")
  PACK_INSTALL=("$PREFIX/govfuzz" pack install "$PACK_MANIFEST" --root "$PACK_ROOT" --install-dir "$PREFIX/packs")
  if [[ -f "$POLICY_FILE" ]]; then
    PACK_VERIFY+=(--policy "$POLICY_FILE")
    PACK_INSTALL+=(--policy "$POLICY_FILE")
  fi
  run "${PACK_VERIFY[@]}"
  run_with_optional_prefix "$SUDO_INSTALL_WORD" mkdir -p "$PREFIX/packs"
  run_with_optional_prefix "$SUDO_INSTALL_WORD" "${PACK_INSTALL[@]}"
else
  printf 'Skipping signed content pack installation.\n'
fi

SEED_TAR="$PACK_ROOT/corpus/seeds.tar.gz"
if [[ "$INSTALL_SEEDS" -eq 1 && -f "$SEED_TAR" ]]; then
  run_with_optional_prefix "$SUDO_INSTALL_WORD" mkdir -p "$PREFIX/corpora/seeds"
  run_with_optional_prefix "$SUDO_INSTALL_WORD" tar -C "$PREFIX/corpora/seeds" -xzf "$SEED_TAR"
fi

printf '+ '
quote_cmd "$PREFIX/govfuzz" --help
if [[ "$DRY_RUN" -eq 0 ]]; then
  "$PREFIX/govfuzz" --help >/dev/null
fi

if [[ "$NO_SMOKE" -eq 0 ]]; then
  [[ -d "$SMOKE_ROOT" ]] || die "missing post-install smoke fixture: $SMOKE_ROOT"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    command -v clang >/dev/null 2>&1 || die "post-install smoke requires clang; install clang or rerun with --no-smoke"
    command -v make >/dev/null 2>&1 || die "post-install smoke requires make; install make or rerun with --no-smoke"
  fi
  if [[ -z "$SMOKE_WORK_DIR" ]]; then
    SMOKE_WORK_DIR="${TMPDIR:-/tmp}/govfuzz-smoke.$$"
  fi
  run rm -rf "$SMOKE_WORK_DIR"
  run "$PREFIX/govfuzz" auto "$SMOKE_ROOT" \
    --work-dir "$SMOKE_WORK_DIR" \
    --languages c \
    --max-targets 1 \
    --per-target-time 1 \
    --iterations 8 \
    --single-pass \
    --no-discovery-cache
  printf 'Post-install smoke report: %s\n' "$SMOKE_WORK_DIR/auto/run.md"
else
  printf 'Skipping post-install govfuzz auto smoke test.\n'
fi

printf 'GovFuzz installed at %s\n' "$PREFIX"
