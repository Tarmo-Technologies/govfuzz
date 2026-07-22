#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Make cargo-dist PowerShell installers safe in non-interactive sessions."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile


MARKER = '$InformationPreference = "Continue"\n'
FIX = (
    MARKER
    + "# Expand-Archive otherwise reads the console progress buffer, which fails "
    "in Windows OpenSSH sessions.\n"
    + '$ProgressPreference = "SilentlyContinue"\n'
)
ARCHIVE_MARKER = '      Expand-Archive -Path $dir_path -DestinationPath "$tmp";\n'
ARCHIVE_FIX = (
    "      # Avoid console progress-buffer access in Windows OpenSSH sessions.\n"
    + '      $ProgressPreference = "SilentlyContinue"\n'
    + ARCHIVE_MARKER
)


def fix(installer: Path) -> None:
    text = installer.read_text(encoding="utf-8")
    updated = text
    if FIX not in updated:
        if updated.count(MARKER) != 1:
            raise SystemExit(
                f"expected one information-preference marker in {installer}, found "
                f"{updated.count(MARKER)}"
            )
        updated = updated.replace(MARKER, FIX)
    if ARCHIVE_FIX not in updated:
        if updated.count(ARCHIVE_MARKER) != 1:
            raise SystemExit(
                f"expected one Expand-Archive marker in {installer}, found "
                f"{updated.count(ARCHIVE_MARKER)}"
            )
        updated = updated.replace(ARCHIVE_MARKER, ARCHIVE_FIX)
    if updated == text:
        return
    mode = installer.stat().st_mode
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=installer.parent, delete=False
    ) as handle:
        handle.write(updated)
        temporary = Path(handle.name)
    os.chmod(temporary, mode)
    os.replace(temporary, installer)


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} INSTALLER [INSTALLER ...]")
    for argument in sys.argv[1:]:
        installer = Path(argument)
        if not installer.is_file():
            raise SystemExit(f"installer not found: {installer}")
        fix(installer)


if __name__ == "__main__":
    main()
