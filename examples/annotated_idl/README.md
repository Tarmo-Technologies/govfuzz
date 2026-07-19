<!-- SPDX-License-Identifier: Apache-2.0 -->

# Annotated IDL Validation Fixture

This fixture is a reduced reproducer for DDS/OpenDDS-style IDL annotations found
during real-codebase validation.

The IDL parser accepts these annotations: `@topic` and `@key` are ignored
(each records an "ignored IDL annotation" warning) while the decorated
declarations are preserved, so the fixture parses and generates its Ada
mapping. This resolves the gap formerly tracked by issue #213.
