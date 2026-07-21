<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release Packaging

GovFuzz uses `dist` to publish binary archives for the `govfuzz` CLI, the
`govfuzz-daemon` JSON-RPC/read-only-MCP service, the `govfuzz_runtrace_shim` cdylib that
`govfuzz auto` loads for runtime virtualisation on Linux, and the
`govfuzz_cc_intercept` cdylib that C/C++ build recovery uses to observe
absolute-path and `posix_spawn` compiler invocations.

## Artifacts

Release archives are currently built for the smoke-tested
`x86_64-unknown-linux-gnu` target. The runtime preload libraries are Linux-only,
so macOS, Windows, and Linux/aarch64 artifacts are intentionally not published
until those packages are split from the portable CLI and daemon archives or gain
native support on those targets. The preload shims are shipped as cdylibs
through dist's library packaging settings.

The GitHub Release contains one archive and one shell installer per component:

| Asset | Purpose | Required for |
|---|---|---|
| `govfuzz-*` | Main CLI | All CLI workflows |
| `govfuzz_runtrace_shim-*` | Runtime virtualisation `LD_PRELOAD` shim | Full `govfuzz auto` runtime audit/fake-resource support |
| `govfuzz_cc_intercept-*` | Build-time compiler interception `LD_PRELOAD` shim | C/C++ `--probe-build` / `--build-command` recovery when builds invoke compilers by absolute path or via `posix_spawn` |
| `govfuzz-daemon-*` | JSON-RPC and read-only MCP daemon | IDE/editor or MCP/agent integrations |
| `source.tar.gz` | Release source snapshot | Source audit or rebuilds |
| `dist-manifest.json`, `sha256.sum`, `*.sha256` | dist metadata and checksums | Automation and integrity verification |

For archive installs, extract the `govfuzz_runtrace_shim-*` and
`govfuzz_cc_intercept-*` archives next to the `govfuzz-*` archive directory, or
set `GOVFUZZ_RUNTRACE_SHIM` / `GOVFUZZ_CC_INTERCEPT` to the extracted library
paths. For installer installs, run each component installer you need; installing
`govfuzz` alone installs only the CLI. Each archive has a SHA-256 checksum
sidecar, and binary-only distribution packages carry a signed content pack that
is verified during package creation and install.

## Binary-Only Distribution Package

For customer or enclave installs where the build host has source but the
destination host should receive only an installable package, use:

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

The script builds `cargo build --release --workspace`, stages the CLI, daemon,
runtrace shim, harness runtime support files, a tiny `govfuzz auto` smoke
fixture, a signed content pack, and `install.sh`, then writes
`dist/govfuzz-dist-<version>-<triple>.tar.gz` plus a SHA-256 sidecar. The
package does not include the GovFuzz application source tree; it does include
runtime support files needed to compile generated harnesses on the destination.
It also includes `README-DIST.md` for install options and `RUN-GOVFUZZ.md` for
post-install operation.

The staged runtime trees cover C/C++, Ada, Rust, Java, Python, Perl, C#,
JavaScript/TypeScript, Ruby, Lua, and PHP. COBOL, Fortran, and Go use their
system toolchains plus the shared C runtime and do not have separate runtime
trees. `--languages all` selects all sixteen installer dependency profiles;
the interactive/default profile remains the original eight core lanes so new
toolchains are opt-in.

The bundled `install.sh` prompts with an arrow-key terminal checklist for
languages, compile targets, fuzzers, and extras. Up/Down moves through options
and the OK/Cancel rows, Space toggles options, and Enter accepts the highlighted
action. Non-interactive all-features install:

```sh
./install.sh --non-interactive \
  --languages all \
  --targets native,windows,aarch64 \
  --fuzzers builtin,afl \
  --extras build-recovery,sandbox,archives
```

The installer runs the bundled smoke fixture by default after install; pass
`--no-smoke` only for constrained installs where the C toolchain is intentionally
absent.

## Verification

```sh
sha256sum -c <asset>.sha256
```

GitHub Artifact Attestations are disabled in the generated workflow because
GitHub currently rejects attestation persistence for this private
Tarmo-Technologies organization/repository plan. When repository support is
available, re-enable `github-attestations = true`, regenerate the workflow, and
restore the connected `gh attestation verify` step.

## Release Flow

Before cutting a release tag, bump `[workspace.package].version` in `Cargo.toml`
to the exact tag version, refresh `Cargo.lock`, and validate dist's local
release plan:

```sh
dist host --steps=create --tag=vX.Y.Z
```

Tag pushes matching semantic versions, such as `v0.2.10`, run the generated
release workflow. The workflow plans artifacts, builds the Linux archive and
checksums, generates shell installers, and uploads artifacts to the GitHub
Release.

## Air-Gapped Packs

Update packs are local JSON manifests for rules, CVE databases, corpora, and
other offline content. Create one with deterministic hashes and an optional
offline signature digest:

```sh
govfuzz pack create --root packs/current \
  --pack-id rules-2026-06 \
  --version 2026.06 \
  --item rules:rules/static.json \
  --item cve:cve/sbom-cves.json \
  --item cve:cve/binary-cves.json \
  --item corpus:corpus/seeds.tar.gz \
  --sign-key offline-root \
  --out packs/current/update-pack.json

govfuzz pack verify packs/current/update-pack.json \
  --root packs/current \
  --policy govfuzz-policy.json
```
