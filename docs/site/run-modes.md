<!-- SPDX-License-Identifier: Apache-2.0 -->

# Run Modes (Reporting vs Attacking)

`govfuzz auto` and `govfuzz fuzz` both accept `--mode reporting|attacking`. The
default is `reporting`.

```sh
govfuzz auto path/to/src --mode attacking
```

The mode does **not** change how a finding's verdict is computed — verdicts are
always derived from the collected evidence (see below). What the mode changes is
which targets get fuzzed first and which findings the report foregrounds. The
chosen mode is also stamped into every finding's actionability record so
downstream tooling can profile a run by it.

## Verdicts Are the Same in Both Modes

Regardless of mode, each finding is classified from evidence into one verdict:

- `real_reachable` — reproduced, with a source fix location, on an
  attacker-reachable entry. A candidate vulnerability.
- `likely_reachable` — a real failure on a plausible entry, but reachability is
  not fully proven.
- `lab_only` — the path depends on generated stubs, fake resources,
  missing-environment injections, or mocks. Reproducible in the lab; public-API
  reachability is unproven. Also assigned when the fuzzed entry is positively
  *not* an attacker-controlled channel (an internal helper or output serializer
  the harness drove directly).
- `blocked` — a real resource was missing with no substitution, so the target
  could not be exercised.
- `unknown` — reachability was not assessed (e.g. Ada targets, which are ranked
  structurally, or legacy findings).

Switching modes never moves a finding between these buckets.

LLM output never moves a finding between them either. Optional agent/model
assistance may explain or prioritize the evidence, but only deterministic run,
reachability, replay, stub/fake, and oracle fields compute the verdict.

## Reporting Mode (default)

Developer-workflow quality first. Findings are surfaced with replay commands,
minimized artifacts when available, source fix locations, patch guidance, and
clear labels for lab-only paths. This is the mode for triaging your own code and
fixing what comes back.

## Attacking Mode

Foregrounds the externally reachable, security-relevant findings — the
attacker's view. Two concrete differences:

- **Target scheduling (auto only).** The candidate queue is re-sorted so
  attacker-reachable and dangerous-sink targets are fuzzed first. The attacking
  score adds to each candidate's base rank: `+50` when the target name contains a
  reachable-surface keyword (`parse`, `decode`, `read`, `open`, `connect`,
  `spawn`, `query`, `sql`, `load`), and `+100` for each dangerous-API oracle the
  source text matches. This is **decisive under a target cap or time budget**
  (`--max-targets`, `--campaign-time`, `--total-time`) — you fuzz the scary
  surface before the clock runs out. On an unbounded full sweep it only changes
  order, not which targets run. `govfuzz fuzz` drives a single harness, so
  scheduling does not apply there; only the actionability profile changes.
- **Report emphasis.** Externally reachable, security-relevant findings are
  promoted. Findings that depend on stubs, fakes, missing-environment shims, or
  mocks are still recorded, but stay classified `lab_only` and are excluded from
  the real-reachable counts.

## Gating CI on Actionability

The verdict ladder is what `govfuzz ci` gates on, independent of the run mode:

```sh
govfuzz ci . --fail-on-actionability likely --min-actionability-confidence medium
```

- `real` — strict attacker-reachable gate.
- `likely` — security gate that accepts strong static entry/sink evidence.
- `lab` — fail the build on lab-only findings too.
- `any` — fail on every recorded finding.

## When To Use Which

- **Reporting** for routine development and self-triage — you want the fix
  workflow front and center.
- **Attacking** when prioritizing an audit under a budget: it schedules the
  reachable, dangerous surface first and foregrounds the findings an external
  attacker could actually reach. Most impactful combined with `--max-targets` or
  `--campaign-time` on a large tree.

## See Also

- [Auto](../auto/) — `--mode` in the full flag table and the actionability
  section.
- [CLI](../cli/) — actionability modes and the `govfuzz ci` gates.
