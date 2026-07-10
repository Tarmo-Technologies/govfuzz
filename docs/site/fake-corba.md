<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fake-CORBA

GovFuzz fake-CORBA support lets legacy Ada code with CORBA-style generated
bindings be fuzzed without a full broker runtime.

## Capabilities

- Parse a CORBA IDL 3.0 subset (modules, interfaces, sequences, unions,
  exceptions, valuetype, `fixed<>`).
- Apply the lightweight C++-style preprocessor needed by legacy IDL headers.
- Generate Ada package stubs for helper, skeleton, object reference, Any, and
  TypeCode surfaces.
- Adopt vendor pragmas that appear in imported interface definitions.
- Discover servant entry points for direct-call harness generation.
- Translate ROS `.msg` / `.srv` / `.action` interface files through the same
  Ada mapping pipeline.

## Workflow

`govfuzz auto` runs fake-CORBA generation automatically from the source tree;
invoke `fake-corba` manually only to regenerate the scaffolding on its own or
against an IDL file outside the `auto` pipeline.

```sh
govfuzz fake-corba govfuzz_work --idl idl/legacy.idl
govfuzz generate-harness src/legacy/servant.adb --target Legacy.Servant.Process --output govfuzz_work/generated_harnesses
govfuzz build govfuzz_work --harness H-1A2B
```

Use the actual harness id printed by `generate-harness` (its ids follow
`H-<4-hex>`, hashed from the source path + target id); the value above is
illustrative. The `H-A<line>-<hash>` form is what the `govfuzz auto` pipeline
prints, not `generate-harness`.

`fake-corba` writes the generated Ada packages under
`<work-dir>/fake_corba/`. Pass `--idl-include-dir` for `#include` resolution
and `--idl-define NAME[=VALUE]` for preprocessor symbols when an enclave IDL
relies on conditionals. `--ros-interface` translates ROS `.msg` / `.srv` /
`.action` files through the same mapping pipeline.

The generated fake-CORBA packages are test scaffolding, not a production ORB.
They are designed to compile enough of a target project to expose servant logic
to fuzzing.
