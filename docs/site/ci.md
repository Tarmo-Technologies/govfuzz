<!-- SPDX-License-Identifier: Apache-2.0 -->
# Run govfuzz on every pull request

`govfuzz ci` fuzzes only the code a pull request changes and reports the results
where reviewers already are: inline annotations on the changed lines and a single
summary comment. The GitHub Action wraps it so the whole thing is one `uses:` line
with no config file.

## Quick start

Copy this to `.github/workflows/govfuzz-pr.yml`:

```yaml
name: govfuzz PR
on: pull_request
permissions:
  contents: read
  pull-requests: write   # sticky summary comment
  security-events: write # SARIF upload → code-scanning annotations
jobs:
  govfuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # required so merge-base against the PR base resolves
      - uses: Tarmo-Technologies/govfuzz/.github/actions/govfuzz-pr@main
        with:
          path: .
          campaign-time: "180"
```

On the next PR you get: the run scoped to the diff, SARIF uploaded to the
code-scanning tab (inline annotations in the **Files changed** tab), a sticky
summary comment, and a check that fails only when the PR introduces a
fuzz-confirmed finding.

## What the action does

1. **Resolves the base ref** — the PR base commit (via `merge-base`, so a branch
   behind its base does not re-fuzz the base's own changes), or the repo default
   branch on `push`. Override with `base-ref`.
2. **Installs govfuzz** — downloads the release binary for the runner, falling
   back to a source build.
3. **Runs `govfuzz ci --changed-since <base>`** — discovery still walks the tree,
   but only the changed files' targets are built and fuzzed, and the discovery
   cache is reused across runs so repeat PR runs are fast.
4. **Uploads SARIF** to code-scanning for inline annotations.
5. **Posts a sticky summary comment** (one comment, updated in place).
6. **Enforces the gate** — see below.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Source root to scan. |
| `base-ref` | *(auto)* | Git ref to diff against. Default: PR base / default branch. |
| `languages` | *(all)* | Comma list to restrict any of the sixteen lanes (`ada,c,cpp,rust,java,python,perl,go,cobol,fortran,csharp,javascript,typescript,ruby,lua,php`). |
| `campaign-time` | `180` | Whole-run wall-clock budget (seconds). |
| `per-target-time` | `30` | Per-target fuzz budget (seconds). |
| `pr-gate` | `confirmed` | `confirmed` \| `all` \| `never` — when to fail the check. |
| `comment` | `true` | Post/update the sticky PR summary comment. |
| `upload-sarif` | `true` | Upload SARIF to the code-scanning tab. |
| `version` | `latest` | govfuzz release tag to install. |
| `build-from-source` | `false` | Install from source (`cargo install --git`) instead. |

## Gate policy

`pr-gate` decides when the check fails:

| Value | Fails the PR when… |
|---|---|
| `confirmed` (default) | a **fuzz-confirmed** finding (actionability verdict `real` or `likely`) is present in the changed code. |
| `all` | any finding is present (including static-only / low-confidence). |
| `never` | never — annotate-only mode. |

The default is deliberately quiet: a static-only or lab-only signal annotates the
PR but does not block it, so the gate flags introduced defects rather than
pre-existing noise.

## Requirements

- **`fetch-depth: 0`** on `actions/checkout` — a shallow clone has no merge-base
  and the action will error rather than silently fuzzing the whole tree.
- **Code-scanning** for inline annotations: free on public repositories; private
  repositories need GitHub Advanced Security. Without it, set `upload-sarif:
  false` and rely on the summary comment (the SARIF file is still produced).
- **Permissions**: `pull-requests: write` (comment) and `security-events: write`
  (SARIF). `contents: read` is enough for the checkout.
- **Toolchains**: the runner needs the compiler for each language you fuzz (e.g.
  `clang`/`make` for C/C++). Missing toolchains skip that lane rather than failing.

## Make it a required check

In **Settings → Branches → Branch protection**, add the `govfuzz` job as a
required status check so a PR cannot merge while it introduces a confirmed finding.

## Using the CLI directly (non-GitHub CI)

The Action is a thin wrapper; the CLI works in any CI:

```sh
govfuzz ci . \
  --changed-since origin/main \
  --campaign-time 180 \
  --sarif govfuzz.sarif \
  --ci-json govfuzz-ci.json \
  --pr-gate confirmed \
  --work-dir "$RUNNER_TEMP/govfuzz_work"
```

- `--changed-since <ref>` scopes to the diff (`<merge-base>..HEAD`).
- `--changed-paths-from <file>` uses a precomputed newline-separated file list
  instead of asking git.
- `--sarif <path>` writes a SARIF 2.1.0 report; `--ci-json <path>` writes a compact
  machine-readable result (counts by severity/verdict, confirmed count, scoped
  file count) for your own reporting.
- Exit code is `0` unless the gate fails.

## LLM and agent use in CI

GovFuzz does not require or call an LLM in CI. Keep PR gates deterministic:
gate on GovFuzz exit status, actionability, replay, and SARIF/JSON fields—not on
a model's wording or severity guess. `govfuzz llm prompt` can render a bounded,
provider-free triage prompt as a separate artifact; `llm assist` makes a remote
or local provider request and should remain a non-gating, explicitly configured
step.

If a CI agent summarizes findings, give it the normalized finding and bounded
run metadata rather than the checkout or full logs. Review artifacts for target
credentials and private source before sending them to a cloud or authenticated
CLI provider, inject provider keys through the CI secret store, and do not write
key values into arguments, workflow YAML, caches, or uploaded prompts. See
[LLM Assistance](./llm.md) for the exact provider and MCP boundaries.

## Honesty

A diff-scoped run fuzzes only the changed files' targets under a bounded time
budget. A green check means "no confirmed finding was introduced in the changed
code within the budget" — **not** that the code is safe. Raise `campaign-time` for
deeper runs, and run a full `govfuzz auto` sweep periodically (e.g. nightly)
alongside the per-PR gate.

## Future work

Baseline delta (fuzz the base ref and the head ref, then report only *newly
introduced* findings) is planned. Today, diff-scoping already restricts findings
to changed code, which covers the common case.
