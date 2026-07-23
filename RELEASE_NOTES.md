<!-- SPDX-License-Identifier: Apache-2.0 -->

# GovFuzz v0.2.19 release notes

Released 2026-07-23.

GovFuzz v0.2.19 focuses on making real legacy Ada, C, and C++ targets reach the
fuzzer. It addresses the failure patterns observed when a large old codebase
discovered thousands of targets but did not successfully fuzz an endpoint.

## Highlights

- Ada overloads are selected by exact declaration identity and receive their
  own source dependency closures. Missing-symbol repairs no longer fabricate
  declarations that do not exist in the referenced unit. Governing projects
  with obsolete AdaFuzz runtime imports are safely overlaid instead of extended,
  and generic-local result types are named through the generated package
  instance just like parameters and constructors.
- Reopened modules from multiple IDL files are merged without overwriting Ada
  bindings. Checked-in CORBA servant implementations use their concrete receiver
  types and build as direct harnesses.
- C++ lifecycle discovery handles accessible constructors, setup methods,
  deleted/inaccessible decoys, default-constructible configuration objects,
  namespaced types, forward declarations, and neutral
  `CORBA::Environment &` call contexts.
- Header targets and repair-added translation units retain the applicable
  compiler family, standard, forced includes, safe flags, and per-file defines
  instead of compiling every source under one guessed command. Sources included
  directly by a generated C++ harness are not linked a second time, and bare
  `make` reliably selects the complete harness build. Standalone-header
  preflights use the same standard-library path recovery and defensive prelude
  as the real harness build.
- Ranking uses conservative harness viability so opaque, undeclared, or blocked
  parameter shapes do not crowd straightforward byte-driven endpoints out of a
  bounded top-N campaign.
- Successful reports now prove that fuzz inputs entered the selected project
  endpoint. Fallback chains and terminal failure stages remain visible instead
  of appearing as unexplained null repair/error fields.

The remediation ledger documents 47 investigated issues. Forty-five are closed;
the two remaining statuses are intentional, tested capability boundaries: K&R
C declarations are reported honestly rather than rewritten unsafely, and Ada
task/protected targets require an explicit scheduling wrapper.

## Interrupted campaign recovery

Repeat the original command with the same source tree and work directory, adding
`--resume`:

```sh
govfuzz auto /path/to/project \
  --work-dir /results/govfuzz-real \
  --max-targets 500 \
  --resume
```

Completed targets are loaded from atomic checkpoints and skipped. An active
target that did not finish is retried before the campaign continues. Resume is
target-granular; it does not restore the exact in-memory mutation state from the
interrupted fuzz pass.

## Privacy-safe support report

The full distribution installs a compact collector:

```sh
govfuzz-bug-report /results/govfuzz-real
```

It writes and prints `govfuzz-support-report.txt`, capped at 4,000 bytes by
default. The report excludes source, generated harnesses, corpus bytes, paths,
filenames, target names, variables, types, Ada units, symbols, and macros.

## Complete Linux distribution

The recommended Linux installation is the full distribution archive:

```sh
VERSION=v0.2.19
BASE="https://github.com/Tarmo-Technologies/govfuzz/releases/download/${VERSION}"
ARCHIVE="govfuzz-dist-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"

curl --proto '=https' --tlsv1.2 -fLO "$BASE/$ARCHIVE"
curl --proto '=https' --tlsv1.2 -fLO "$BASE/$ARCHIVE.sha256"
sha256sum -c "$ARCHIVE.sha256"
tar xzf "$ARCHIVE"
cd "${ARCHIVE%.tar.gz}"
./install.sh
```

The full archive includes the CLI, daemon, both Linux preload shims, harness
runtimes, signed content, support-report collector, smoke fixture, and these
standard documents:

- `INSTALL.md`
- `LICENSE`
- `README.md`
- `RELEASE_NOTES.md`

## Validation

- Six fresh zero-fuzz end-to-end campaigns passed across Ada and C++.
- The legacy K&R boundary tests passed 2/2.
- The fake-CORBA/GNAT suite passed 17/17.
- Offline distribution and installer tests passed 14/14, including the
  required-document and release-workflow gates.
- Workspace library tests passed, including 1,295 GovFuzz CLI tests and 555
  harness-generator tests.
- Formatting, workspace compilation, and diff checks passed on the remediation
  tree.

See `CHANGELOG.md` for the cumulative project history and
`docs/validation/2026-07-23-zero-fuzz-remediation.md` for the complete issue and
proof matrix.
