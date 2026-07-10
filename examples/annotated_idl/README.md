<!-- SPDX-License-Identifier: Apache-2.0 -->

# Annotated IDL Validation Fixture

This fixture is a reduced reproducer for DDS/OpenDDS-style IDL annotations found
during real-codebase validation.

The current expected outcome is a parser failure on `@topic` or `@key`. Issue
#213 tracks accepting these annotations, likely by ignoring unsupported
annotation metadata while preserving the decorated declarations.
