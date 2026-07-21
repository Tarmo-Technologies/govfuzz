#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Add GovFuzz's EL7 prerequisite guidance to dist's generated CLI installer."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile


CALL_MARKER = 'download_binary_and_run_installer "$@" || exit 1'
BEGIN_MARKER = "# GOVFUZZ_RHEL7_GUIDANCE_BEGIN"

GUIDANCE = r'''# GOVFUZZ_RHEL7_GUIDANCE_BEGIN
# The lightweight release installer deliberately does not elevate privileges or
# modify system repositories. Make that boundary and the EL7 prerequisites
# visible before installing the CLI, including for `--help` invocations.
govfuzz_release_installer_os_value() {
    _govfuzz_key="$1"
    awk -F= -v key="$_govfuzz_key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' \
        "$_govfuzz_os_release" | sed 's/^"//; s/"$//'
}

govfuzz_release_installer_rhel7_guidance() {
    _govfuzz_os_release="${GOVFUZZ_OS_RELEASE_FILE:-/etc/os-release}"
    [ -r "$_govfuzz_os_release" ] || return 0

    _govfuzz_os_id="$(govfuzz_release_installer_os_value ID)"
    _govfuzz_os_like="$(govfuzz_release_installer_os_value ID_LIKE)"
    _govfuzz_os_version="$(govfuzz_release_installer_os_value VERSION_ID)"
    case " $_govfuzz_os_id $_govfuzz_os_like " in
        *" rhel "*|*" centos "*|*" redhat "*) ;;
        *) return 0 ;;
    esac
    case "$_govfuzz_os_version" in
        7|7.*) ;;
        *) return 0 ;;
    esac

    say ""
    say "RHEL 7 prerequisite notice:"
    say "  This govfuzz-installer.sh asset installs the CLI only. It does not enable"
    say "  repositories, install compiler packages, or install Linux preload shims."
    if [ "$_govfuzz_os_id" = "rhel" ]; then
        say "  Before C/C++ fuzzing, enable RHSCL and install LLVM Toolset 7:"
        say "    sudo subscription-manager repos --enable rhel-server-rhscl-7-rpms"
    else
        say "  CentOS 7 requires an organization-approved vault/archive source for SCL packages."
    fi
    say "    sudo yum install -y gcc gcc-c++ make llvm-toolset-7.0-clang llvm-toolset-7.0-compiler-rt"

    if [ -x /opt/rh/llvm-toolset-7.0/root/usr/bin/clang ] \
        || [ -x /opt/rh/llvm-toolset-7/root/usr/bin/clang ]; then
        say "  LLVM Toolset 7 detected; GovFuzz activates it automatically."
    else
        warn "LLVM Toolset 7 was not detected; the CLI can install, but RHEL 7 C/C++ fuzzing will not work until the packages above are available"
    fi

    for _govfuzz_base_url in $ARTIFACT_DOWNLOAD_URLS; do
        break
    done
    say "  Full govfuzz auto runtime coverage also needs the separate runtrace shim:"
    say "    curl --proto '=https' --tlsv1.2 -LsSf \"$_govfuzz_base_url/govfuzz_runtrace_shim-installer.sh\" | sh"
    say "  Recommended for C/C++ build-command recovery:"
    say "    curl --proto '=https' --tlsv1.2 -LsSf \"$_govfuzz_base_url/govfuzz_cc_intercept-installer.sh\" | sh"
    say ""
}

govfuzz_release_installer_rhel7_guidance
# GOVFUZZ_RHEL7_GUIDANCE_END
'''


def augment(installer: Path) -> None:
    text = installer.read_text(encoding="utf-8")
    if BEGIN_MARKER in text:
        return
    if text.count(CALL_MARKER) != 1:
        raise SystemExit(
            f"expected one final installer call in {installer}, found "
            f"{text.count(CALL_MARKER)}"
        )

    updated = text.replace(CALL_MARKER, f"{GUIDANCE}\n{CALL_MARKER}")
    mode = installer.stat().st_mode
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=installer.parent, delete=False
    ) as handle:
        handle.write(updated)
        temporary = Path(handle.name)
    os.chmod(temporary, mode)
    os.replace(temporary, installer)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} INSTALLER")
    installer = Path(sys.argv[1])
    if not installer.is_file():
        raise SystemExit(f"installer not found: {installer}")
    augment(installer)


if __name__ == "__main__":
    main()
