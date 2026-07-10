<!-- SPDX-License-Identifier: Apache-2.0 -->
# GF-545 GraphQL-Injection Sweep - 2026-07-08

This memo records the validation for `GF-545` (CWE-943 GraphQL injection), a
Python static rule that flags a GraphQL operation document parsed via `gql()`
from a dynamically-built string.

## Rule shape

`GF-545` fires only when all three hold on a line:

- a `gql(` parser call (word-boundary matched, not inside a string literal),
- dynamic-string evidence (`+` concatenation, an f-string, or `.format(`), and
- GraphQL operation syntax (`query`/`mutation`/`subscription`).

A literal operation document with request data bound through `variable_values`
is the safe form and does not fire. This mirrors the SQL rule (`GF-419`): the
sink requires concat/format evidence, so a parameterized/variable-bound query is
clean.

## Sweep

- Branch: `sast-graphql-hardening-2026-07-08`
- Scanner: `target/debug/govfuzz static-scan <repo>`
- Corpus: three real GraphQL Python projects.

| Repo | Total findings | GF-545 total | GF-545 outside tests |
|---|--:|--:|--:|
| `graphql-python/gql` | ~2.9k | 71 | 0 |
| `strawberry-graphql/strawberry` | 8 | 0 | 0 |
| `graphql-python/graphene` | 5 | 0 | 0 |

The two server frameworks (strawberry, graphene) build schemas rather than
client-side operation strings, so they produce zero `GF-545` noise — the rule is
scoped to the `gql()` client pattern.

All 71 `gql` reports are in that library's own test suite, in the shape
`gql(subscription_str.format(count=count))` — a genuine dynamic operation
document. Whether the interpolated value is attacker-controlled is a taint
question the syntactic rule does not resolve, exactly as with `GF-419`; the
library source itself produced no reports.

## Unit coverage

`python_rule_pack_flags_dynamic_graphql_documents` asserts three positive shapes
(concat, f-string, `.format`) and a negative block covering: a literal document
bound with `variable_values`, `gql(CONST)`, a dynamic SQL `execute` on the same
tree (fires `GF-419`, not `GF-545`), and a `gql(` needle that appears only inside
a string literal.

## Commands

```sh
cargo fmt --check
cargo test -p finding_rules -p static_analysis --quiet
cargo test -p static_analysis --test precision_benchmark
cargo build -p govfuzz --quiet
cargo run -p spdx_check -- check
```
