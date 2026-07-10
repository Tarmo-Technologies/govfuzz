<!-- SPDX-License-Identifier: Apache-2.0 -->

# Golden Ada Corpus

This directory contains synthetic Ada fixtures for the M1 scanner acceptance gate. Do not vendor third-party Ada source here.

## Layout

Each fixture lives at:

```text
<dialect>/<scenario>/{src.adb|src.ads,manifest.toml}
```

Use `src.adb` for bodies and subunits, `src.ads` for specs. If both exist, the harness scans `src.adb`.

## Manifest

`manifest.toml` is the ground truth from human inspection of the Ada source:

```toml
description = "Short fixture purpose"
dialect_hint = "ada_2012"

[expected]
ada_standard = "ada_2012"
unit_kind = "body"
subprograms = 1
handlers = 0
raises = 0
types = 0
use_clauses = 0
with_clauses = []
pragmas = ["ada_2012"]

[expected.names]
subprograms = ["run"]
handler_choices = []
type_kinds = []
```

`dialect_hint` is optional. Omit it when the fixture is meant to exercise pragma or heuristic dialect detection.

The optional name lists are allow-lists for extracted names. If a list is present, every extracted item in that category must appear in the manifest.

## Adding A Fixture

1. Create a new scenario directory under the lowest applicable dialect.
2. Add a small synthetic Ada source file with an Apache-2.0 SPDX header.
3. Add `manifest.toml` with an Apache-2.0 SPDX header.
4. Set expected counts from the source, not from extractor output.
5. Run:

```bash
cargo test -p ada_parser --test golden -- --nocapture
cargo run -p spdx_check -- check
```

If a fixture exposes an extractor bug, write a failing focused test in the extractor or reconcile module first, then fix the extractor. Do not lower manifest counts to match current behavior unless a follow-up issue documents an out-of-scope known bug.

## Acceptance

The golden harness requires at least 50 fixtures and enforces aggregate M1 thresholds:

- subprograms: extracted / expected >= 0.95
- handlers + raises: extracted / expected >= 0.99

It also rejects false-positive names through manifest allow-lists.
