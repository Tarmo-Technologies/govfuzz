# SPDX-License-Identifier: Apache-2.0

import atheris
import sys

with atheris.instrument_imports():
    from validate.links import find_links_in_text


def test_one_input(data: bytes) -> None:
    find_links_in_text(data.decode("utf-8", "replace"))


atheris.Setup(sys.argv, test_one_input)
atheris.Fuzz()
