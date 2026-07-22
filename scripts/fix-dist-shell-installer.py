#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Make cargo-dist shell installers check for the xz archive helper."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile


MARKER = "    need_cmd tar\n"
FIX = (
    MARKER
    + "    # Release archives are tar.xz; some minimal RHEL images omit xz.\n"
    + "    need_cmd xz\n"
)


def fix(installer: Path) -> None:
    text = installer.read_text(encoding="utf-8")
    if FIX in text:
        return
    if text.count(MARKER) != 1:
        raise SystemExit(
            f"expected one tar dependency marker in {installer}, found "
            f"{text.count(MARKER)}"
        )

    updated = text.replace(MARKER, FIX)
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
