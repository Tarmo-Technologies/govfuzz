<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fake CORBA Servant Fixture

This fixture exercises fake CORBA servant fuzzing. `Bar_Impl.Compute` raises
and swallows `Foo.BadInput`; M10 generates the missing `Foo` package and base
fake CORBA packages so the servant can build without a real ORB.

M12 generates a servant-direct harness, feeds the `"neg"` testcase through the
fake-CORBA build, and emits a finding for the handled `Foo.BadInput` path.
