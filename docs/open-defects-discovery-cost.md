<!-- SPDX-License-Identifier: Apache-2.0 -->
# Discovery cost: what a huge C++ file cost, and what fixed it

Handoff document. Everything here was measured on the 2026-07-27 re-run of the
500-project sweep (`benchmarks/campaign-2026-07-25`, `results-0727/`). Both
defects in this class are now FIXED; the measurements that isolated them are
kept because the METHOD is what transfers.

---

## Context: how the class was found

The sweep's `--problems` list showed 22 projects ending `exit=-9` with
`timed_out=False` — SIGKILL, no timeout, 44 to 250 seconds in — and 14 more
ending at the 510-second campaign ceiling. All but three were C++.

`exit=-9` in the sweep harness means two different things, and they must be told
apart: `timed_out=True` is the harness's own kill, `timed_out=False` is the
kernel. `/sys/fs/cgroup/user.slice/memory.events` confirmed the second
(`oom_kill 46`) — the kernel log was not readable, so the cgroup counter is the
evidence to reach for on a box without `dmesg`.

It would have been easy to write these off as the sweep oversubscribing a 13 GB
box with six concurrent projects. They are not:

```
govfuzz auto simdjson            (39 MB tree, alone, idle box)  12.4 GiB  OOM-killed
govfuzz list targets simdjson                                    225 MiB  ok
govfuzz static-scan simdjson                                      70 MiB  ok
```

**Measure one run alone before blaming the runner.**

---

## 1. A cyclic construction recipe recursed forever — FIXED

### Root cause

`crates/harness_gen/src/cpp_decoders.rs`, the class-construction recipe block,
carried this invariant in a comment:

> The recipe is only registered for the target's DIRECT opaque-class parameters,
> so a constructor's argument types are always directly decodable — the recursive
> arg decode below terminates immediately.

The producer graph (`resolve_cpp_parameter_constructions` in
`crates/cli/src/generate_harness.rs`) made that false. It exists precisely to
resolve what a chosen constructor's own arguments need, to a fixed point, and its
own comment says the graph is cyclic — `A(B)`, `B(A)` — and that its termination
comes from `MAX_PRODUCER_DEPTH`. The CONSUMER had no such bound, so following one
recipe into the next never returned, allocating a decode statement per frame.

### Fix

The decoder threads the chain of class keys it is currently expanding. A key
already on the chain means the recipe needs a value it is in the middle of
producing; the parameter falls through to the ordinary opaque skip. Depth is not
what is cut — a three-deep acyclic chain still resolves, and a type reached twice
by different paths is not a cycle. Both are pinned by
`a_cyclic_construction_recipe_terminates_instead_of_recursing`.

### How it was isolated

Worth reusing, because the bisect alone was misleading:

1. Stage bisect (`list targets` vs `auto --list-targets` vs `static-scan`) put it
   inside `auto`'s discovery.
2. A directory bisect said `include/` + `src/` together blew up while each alone
   was 20 MiB — a cross-file signature — and a file bisect named
   `src/generic/stage2/tape_builder.h`. **Both were the last straw, not the
   cause**: the file was fine on its own, and re-testing the "culprit" pair in
   isolation did not reproduce.
3. What actually settled it was RSS probes printed BEFORE each stage, then before
   each file, then inside the per-function loop. The probe that mattered printed
   *before* the work, not after: the offending call never returns, so an
   after-probe prints nothing at all.

The exact trigger was `simdjson/src/rvv-vls.cpp`'s
`stage2(dom::document &_doc)` — the first function in that tree whose parameter
resolved a non-empty recipe set.

---

## 2. The preflight re-derived per FILE what it had already computed — FIXED

### Symptom

With the memory fixed, simdjson still could not be swept: discovery did not
finish. The cost was concentrated in one directory.

```
list targets   simdjson/singleheader/  (7.7 MB simdjson.h + 2.7 MB simdjson.cpp)   145 s
auto           simdjson/singleheader/                                            > 1500 s (killed)
auto           simdjson minus singleheader/                                         59 s
```

`list targets` and `auto` parse the same files, so the whole difference was work
`auto` adds.

### Root cause

Two loop-invariant computations were redone inside per-function loops. **Profiling
named them; the first guess was wrong** — `find_cpp_factory_for_class` scanning
every function looked like the obvious quadratic and was not the cost.

- **97% was `recipe_mining::for_source`.** The recipes are cached by project root,
  but a cache HIT handed back a CLONE of the whole map — one entry per
  constructible class in the project. Called once per function, that was **133 of
  the preflight's 137 seconds** on the 2,863-function `simdjson.cpp`. It is shared
  by `Arc` now, and hoisted out of the loop besides.
- **The rest was `cpp_class_is_default_constructible` re-parsing the closure.** It
  took the include-closure TEXTS and ran `collect_cpp_class_info_for_harness` on
  them per call, from inside a per-parameter loop whose caller had computed
  exactly that once — 7.7 MB of C++ re-parsed per opaque parameter. It takes the
  already-collected class info now, which is the same answer by construction.

### Measured

| | before | after |
|---|---:|---:|
| preflight, `simdjson.cpp` (2,863 fns) | 137 s | 3.9 s |
| preflight, `simdjson.h` (10,894 fns) | never finished | 9.5 s |
| `auto --list-targets`, whole `singleheader/` | >1500 s (killed) | **218 s**, 250 MB |

What remains is dominated by the tree-sitter parse of the 7.7 MB header itself,
which is honest work.

### What was NOT done, and why

The preflight is advisory — its only effect is
`KNOWN_UNBUILDABLE_SIGNATURE_DEMOTION`, a RANK demotion for signatures generation
would refuse anyway — so bounding it by function count with a logged skip was the
cheap alternative. It was not needed once the real cost was measured, and a cap
would have read as "checked" when it was not.

Do not "fix" a future instance of this by excluding amalgamated headers from
discovery. sqlite's `sqlite3.c` and simdjson's `simdjson.h` are what many projects
actually ship, and `dedup_amalgamated_single_header` exists to keep their targets
from double-counting rather than to drop them.

---

## Re-measuring

```
# One run, alone, with the peak RSS of its whole process tree.
python3 - <<'EOF'   # or reuse the sweep scratch script
# poll /proc/<pid>/statm over the process tree; print peak by program
EOF

# Which stage: these three over the same tree should be within an order of
# magnitude of each other. When `auto` is not, the extra is auto-only work.
govfuzz list targets <tree> --format json --top 5
govfuzz static-scan  <tree> --out /tmp/s
govfuzz auto         <tree> --work-dir /tmp/w --list-targets
```

`--list-targets` returns immediately after discovery + ranking, so it isolates
discovery from build and fuzz without a budget confound.
