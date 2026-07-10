<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release Packaging

GovFuzz uses `dist` 0.31.0, formerly `cargo-dist`, to plan and publish binary
release artifacts from GitHub Actions.

The releasable applications are:

- `govfuzz`: the command-line interface from `crates/cli`
- `govfuzz-daemon`: the JSON-RPC daemon from `crates/daemon`
- `govfuzz_runtrace_shim`: the `cdylib` loaded by `govfuzz auto` for runtime
  virtualisation on Linux

The workspace defaults every package to `dist = false`; the two app packages
and the runtrace shim opt back in. The app packages also override their
distributed binary lists so test and legacy compatibility binaries such as
`cli`, `daemon`, and fixture harnesses are not included in release archives.

The runtrace shim package opts in with `package-libraries = ["cdylib"]` and
`install-libraries = ["cdylib"]` so dist publishes a shim archive and installer
containing `libgovfuzz_runtrace_shim`. The runtime preload libraries are
Linux-only, and the generated release workflow currently publishes the
smoke-tested `x86_64-unknown-linux-gnu` binary target. For archive installs,
extract the `govfuzz_runtrace_shim-*` archive next to the `govfuzz-*` archive
directory, or set `GOVFUZZ_RUNTRACE_SHIM` to the library path. For installer
installs, install both `govfuzz` and `govfuzz_runtrace_shim` so the library
lands beside the CLI. The CLI also accepts the renamed
`libgovfuzz_runtrace.so` produced by source builds.

## Binary-Only Distribution Package

Use `scripts/package-offline-dist.sh` when a connected build machine has the
source checkout but the destination machine should receive an installable
tarball instead of the GovFuzz application source tree:

```sh
scripts/package-offline-dist.sh
```

When CVE DBs or seeds are not provided, the script creates and packages:

```text
dist/content-inputs/sbom-cves.json
dist/content-inputs/binary-cves.json
dist/content-inputs/seeds/
```

Those generated CVE DBs are valid empty defaults. Replace them with real feed
data and rerun the same command when you need SBOM or binary-CVE matching.

The script runs `cargo build --release --workspace`, stages the release binaries,
the runtrace shim, harness runtime support files, a tiny `govfuzz auto` smoke
fixture, and a signed content pack, then produces
`dist/govfuzz-dist-<version>-<triple>.tar.gz` plus a `.sha256` sidecar. The
tarball includes `install.sh`, `README-DIST.md`, and `RUN-GOVFUZZ.md`.
`install.sh` can install or update interactively with an arrow-key terminal
checklist or non-interactively:

```sh
./install.sh --non-interactive \
  --languages all \
  --targets native,windows,aarch64 \
  --fuzzers builtin,afl \
  --extras build-recovery,sandbox,archives
```

The installer runs the smoke fixture by default after install; use `--no-smoke`
only when the C toolchain is intentionally absent.

## Targets

The generated release workflow builds this target triple:

- `x86_64-unknown-linux-gnu`

Each archive has a SHA-256 checksum sidecar. macOS, Windows, and Linux/aarch64
artifacts are intentionally not published until the Linux-only preload packages
are split from the portable CLI and daemon archives or gain native support on
those targets.

GitHub Artifact Attestations are disabled in the generated workflow because
GitHub currently rejects attestation persistence for this private
Tarmo-Technologies organization/repository plan. Until org/repo support is
available, release integrity is verified with SHA-256 sidecars, and the
offline distribution verifies its signed content pack during package creation
and install.

When GitHub attestation support is available for the repository, re-enable it by
setting `github-attestations = true` and adding
`github-attestations-phase = "host"` in `[workspace.metadata.dist]`, regenerate
the release workflow with `dist generate --mode ci`, and restore the attestation
verification command to these docs.

## Verifying Releases

Download the release asset and its checksum sidecar from the GitHub Release,
then verify the checksum first:

```sh
sha256sum -c <asset>.sha256
```

For binary-only distribution tarballs, also verify the signed content pack after
extracting or installing the archive. The installer runs this by default; a
manual verification looks like:

```sh
./tool/govfuzz pack verify \
  ./content/packs/current/update-pack.json \
  --root ./content/packs/current \
  --policy ./content/govfuzz-policy.json
```

References:

- [dist GitHub Attestations](https://axodotdev.github.io/cargo-dist/book/supplychain-security/attestations/github.html)

## Release Flow

Pull requests run the generated `Release / plan` check. Tag pushes matching a
semantic version, such as `v0.1.0`, run the full release workflow:

0. bump `[workspace.package].version` in `Cargo.toml` to the exact release
   version and refresh `Cargo.lock`
1. plan artifacts with `dist plan`
2. build platform archives and checksums
3. generate shell installers
4. upload artifacts to a GitHub Release

Run this before opening release-packaging changes or cutting a tag:

```sh
dist host --steps=create --tag=vX.Y.Z
```
