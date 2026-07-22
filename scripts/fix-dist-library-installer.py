#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Correct cargo-dist's Unix installer chmod path for packaged libraries."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile


BROKEN = 'chmod +x "$_lib_install_dir/$_lib_name"'
FIXED = 'chmod +x "$_lib_install_temp/$_lib_name"'


def fix(installer: Path) -> None:
    text = installer.read_text(encoding="utf-8")
    if BROKEN not in text:
        if FIXED in text:
            return
        raise SystemExit(f"library chmod marker not found in {installer}")

    updated = text.replace(BROKEN, FIXED)
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
