<!-- SPDX-License-Identifier: Apache-2.0 -->

# Legacy IDL Acceptance Fixture

This fixture exercises the M11 real-world legacy IDL acceptance path. The IDL
uses an include guard, object-like macros, conditional declarations, nested
modules, vendor pragmas, repository pragmas, exceptions, attributes, inline
sequences, `any`, `Object`, and interface inheritance.

The Ada client references the generated Helper, Skel, Stub, sequence, Any,
TypeCode, and Object surfaces so `govfuzz fake-corba --idl` and `govfuzz build`
prove the generated mapping builds without manual edits or a real ORB.
