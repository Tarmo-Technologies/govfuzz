<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release Packaging

GovFuzz uses `dist` 0.31.0, formerly `cargo-dist`, to plan and publish binary
release artifacts from GitHub Actions.

> This page focuses on the offline binary-distribution tarball
> (`scripts/package-offline-dist.sh`). For the published-site reference — the
> full artifact table and archive-install layout — see
> [`docs/site/release-packaging.md`](./site/release-packaging.md).

The releasable applications are:

- `govfuzz`: the command-line interface from `crates/cli`
- `govfuzz-daemon`: the JSON-RPC and read-only MCP daemon from `crates/daemon`
- `govfuzz_runtrace_shim`: the `cdylib` loaded by `govfuzz auto` for runtime
  virtualisation on Linux
- `govfuzz_cc_intercept`: the build-time compiler-interception `cdylib` used by
  C/C++ `--probe-build` / `--build-command` recovery

## Asset Selection for Release Consumers

The release provides both an all-in-one Linux bundle and separate components;
users should choose one delivery style rather than install every file:

| Consumer scenario | Assets to use |
|---|---|
| Complete Linux install | `govfuzz-dist-<version>-x86_64-unknown-linux-gnu.tar.gz` and its checksum; extract and run `./install.sh` |
| Windows CLI | `govfuzz-installer.ps1`, or the Windows CLI ZIP and its checksum—not both |
| Basic Linux CLI | `govfuzz-installer.sh`, or the Linux CLI archive and its checksum—not both |
| Full Linux `govfuzz auto` | The CLI, runtrace shim, and compiler-interception shim; choose the three installers or the three archives/checksums |
| IDE/JSON-RPC/MCP | Add the platform's `govfuzz-daemon` installer/archive; it is not required by the CLI |
| Manual/offline install | Download only the matching platform archives and their `.sha256` sidecars; do not also download installers |
| Source audit/rebuild | `source.tar.gz` and its checksum |
| Release automation | `dist-manifest.json`, individual sidecars, and/or the aggregate `sha256.sum` |

The runtrace and compiler-interception shims are Linux-only. The runtrace shim
adds runtime audit, behavioral/taint oracles, and fake resources. The compiler-
interception shim matters only for complex C/C++ build recovery. The detailed
consumer-facing decision guide and exact commands live in
[`docs/site/install.md`](./site/install.md#choose-release-assets-by-task).

The workspace defaults every package to `dist = false`; the two app packages
and both Linux preload-shim packages opt back in. The app packages also override their
distributed binary lists so test and legacy compatibility binaries such as
`cli`, `daemon`, and fixture harnesses are not included in release archives.
The CLI package explicitly includes all eleven harness-runtime trees. The CLI
also embeds those tracked runtime sources and securely stages them on first use,
which keeps shell/PowerShell installer deployments functional even though dist
installers place only the executable in `CARGO_HOME/bin`.

The runtrace shim package opts in with `package-libraries = ["cdylib"]` and
`install-libraries = ["cdylib"]` so dist publishes a shim archive and installer
containing `libgovfuzz_runtrace_shim`. The runtime preload libraries are
Linux-only. The generated workflow publishes the CLI and daemon for
`x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc`, while publishing the
two preload libraries only for Linux. The Linux target is built in a pinned
manylinux2014 / CentOS 7 container and checked for a maximum glibc 2.17 ABI,
covering Ubuntu 22.04/24.04/26.04 LTS and RHEL 7 through RHEL 10. The same gate
verifies the runtrace shim's required interposition exports. For manual
component installs, copy `libgovfuzz_runtrace_shim.so` and
`libgovfuzz_cc_intercept.so` into the extracted `govfuzz-*` CLI directory, or
set `GOVFUZZ_RUNTRACE_SHIM` and `GOVFUZZ_CC_INTERCEPT` to absolute paths. The
runtrace shim can also be found in a sibling dist directory; the compiler-
interception shim cannot, so directly co-locating both is the least surprising
layout. Every component archive includes `INSTALL.md`. For component-installer
installs, run the CLI and each required shim installer so all files land beside
one another. The CLI also accepts the renamed `libgovfuzz_runtrace.so` produced
by source builds.

After `dist` generates the main Unix installer, the release workflow runs
`scripts/augment-release-installer.py`. On an EL7-family host the resulting
installer explains, before downloading the CLI, that it does not enable system
repositories or install toolchains/shims; it prints the exact RHSCL LLVM 7
packages and the separate runtrace/compiler-interception installer commands.
The augmentation is idempotent and the release workflow rejects an installer
that does not contain the guidance marker.

`scripts/fix-dist-shell-installer.py` adds an explicit `xz` dependency check to
all four Unix installers. Cargo-dist already checks for `tar`, but its `.tar.xz`
archives also require the external `xz` helper on minimal RHEL installations.
The release gate rejects any Unix installer without this check.

The workflow also runs `scripts/fix-dist-library-installer.py` over both Linux
preload-library installers. This corrects cargo-dist 0.31's temporary-directory
`chmod` path before publication; a release gate rejects either installer if the
fixed path is absent.

`scripts/fix-dist-powershell-installer.py` makes both Windows installers usable
from local PowerShell and non-interactive Windows OpenSSH sessions by disabling
`Expand-Archive` console progress in the extraction scope. This avoids the
Server 2019 `ReadConsoleOutput` access-denied failure while leaving installation
output and errors visible.

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
both Linux shims, harness runtime support files, a tiny `govfuzz auto` smoke
fixture, and a signed content pack, then produces
`dist/govfuzz-dist-<version>-<triple>.tar.gz` plus a `.sha256` sidecar. The
tarball includes `install.sh`, `README-DIST.md`, and `RUN-GOVFUZZ.md`.
It also includes `INSTALL.md`, which documents both the bundled installer and
the manual component-archive co-location layout.
`install.sh` can install or update interactively with an arrow-key terminal
checklist or non-interactively:

The runtime trees cover C/C++, Ada, Rust, Java, Python, Perl, C#,
JavaScript/TypeScript, Ruby, Lua, and PHP. COBOL, Fortran, and Go use their
system toolchains plus the shared C runtime. `--languages all` selects installer
dependencies for all sixteen lanes; the default checklist keeps the original
eight core lanes selected and offers the newer lanes as opt-ins.

```sh
./install.sh --non-interactive \
  --languages all \
  --targets native,windows,aarch64 \
  --fuzzers builtin,afl \
  --extras build-recovery,sandbox,archives
```

The installer runs the smoke fixture by default after install; use `--no-smoke`
only when the C toolchain is intentionally absent.

The generated release workflow also produces this all-in-one package from the
same EL7-baseline binaries used by the component archives, installs it into a
temporary prefix, runs its smoke fixture, and publishes the tarball and checksum
as first-class release assets.

## Targets

The generated release workflow builds these target triples:

- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc` (`govfuzz` and `govfuzz-daemon` only)

Each archive has a SHA-256 checksum sidecar. The Linux binaries are built in the
pinned manylinux2014 container for Ubuntu 22.04/24.04/26.04 LTS and RHEL 7
through 10. Windows binaries are built and smoke-tested on Windows Server 2022,
then the same binaries are exercised on Server 2025; Server 2019, Windows 11
Enterprise 25H2, and Windows 11 Enterprise LTSC 2024 are covered by the platform
VM validation. PowerShell installers are published alongside the Unix shell
installers. The runtime and
compiler-interception preload shims remain Linux-only assets. macOS,
Linux/aarch64, and Windows-on-Arm artifacts are not currently published.

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
2. build platform archives and checksums against the RHEL 7 ABI / native Windows
3. inspect both CLI archives for every required harness runtime
4. generate Unix shell and Windows PowerShell installers
5. upload artifacts to a GitHub Release

Run this before opening release-packaging changes or cutting a tag:

```sh
dist host --steps=create --tag=vX.Y.Z
```
