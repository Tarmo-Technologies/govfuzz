<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release checklist

The full distribution archive (`govfuzz-dist-<version>-x86_64-unknown-linux-gnu.tar.gz`)
is the standard release shape. Every release must ship it, and it must contain
`install.sh`, `INSTALL.md`, `LICENSE`, `README.md`, and `RELEASE_NOTES.md` at its
root alongside the CLI, daemon, both Linux preload shims, and the harness
runtimes. This checklist is mandatory for every version.

## Automated gates (enforced by `.github/workflows/release.yml`)

- [ ] The `build-local-artifacts` job builds the full distribution archive with
      `scripts/package-offline-dist.sh` and its `.sha256` sidecar.
- [ ] The archive-content gate fails the release if any mandatory root file is
      missing: `install.sh` (executable), `INSTALL.md`, `LICENSE`, `README.md`,
      `RELEASE_NOTES.md`.
- [ ] The gate extracts the archive and runs `install.sh --non-interactive` in a
      clean directory, then verifies the installed `govfuzz`, `govfuzz-bug-report`,
      and both shims — proving an offline install from the archive works.
- [ ] `cargo test -p govfuzz --test release_bundle_manifest` passes (the packaging
      manifest and the workflow gate both list every mandatory root file).

## Manual verification

- [ ] `RELEASE_NOTES.md` documents the major changes and the resume guarantees,
      including the build-context invalidation rules.
- [ ] The `README.md` resume section shows the stop → reboot → resume commands
      against the same `--work-dir`, and they work locally with `--resume`.
- [ ] Build-context invalidation is documented (GPR, `compile_commands.json`,
      IDL, `--project`, and the harness-affecting options).
- [ ] No secrets or absolute host paths appear in the archive.

## Post-release

- [ ] The GitHub Release contains the full distribution archive and its `.sha256`
      sidecar as assets.
- [ ] The release announcement names the full distribution archive as the primary
      offline / air-gapped installation method.
