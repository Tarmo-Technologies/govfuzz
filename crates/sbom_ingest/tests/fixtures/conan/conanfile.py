# SPDX-License-Identifier: Apache-2.0
# Fixture: conanfile.py for Conan cataloger tests (static extraction only — never exec).

from conan import ConanFile

class MyProject(ConanFile):
    name = "myproject"
    version = "1.0.0"

    requires = (
        "fmt/10.1.1",
        "poco/1.12.4",
        "spdlog/1.13.0",
    )
    tool_requires = "ninja/1.11.1"
    python_requires = "pyreq/0.1.0"

    def requirements(self):
        self.requires("libpng/1.6.40")
