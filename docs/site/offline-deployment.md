<!-- SPDX-License-Identifier: Apache-2.0 -->

# Offline / Air-Gapped Deployment & Updates

GovFuzz is designed to run with no network access. This page is the operational
guide for **installing and updating GovFuzz on a disconnected (air-gapped)
machine** — including the question of whether to build on a connected machine
and transfer the binary, or transfer the source and build on the offline host.

GovFuzz fuzzes sixteen languages (Ada, C, C++, Rust, Java, Python, Perl, Go,
COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua, and PHP); toolchain
requirements differ by language — see
[Toolchains on the offline host](#toolchains-on-the-offline-host).

There is no GovFuzz auto-updater and the tool never phones home. Updating is a
deliberate transfer step that you control. If you are building from a private
source checkout but do not want to hand the checkout to the destination user,
use the binary-only distribution flow below.

---

## Decision: build-and-transfer, or transfer-and-build?

| | **Model A — transfer binaries** | **Model B — transfer source, build offline** |
|---|---|---|
| You move | The built `govfuzz`, `govfuzz-daemon`, and runtrace shim | The repo + a vendored crate cache |
| Offline host needs Rust? | **No** | **Yes** (pinned `stable` toolchain) |
| Binary/host match | You must match OS + CPU arch + glibc | Exact, built on the host itself |
| Best when | The offline host's OS/arch is known and matches a build host or release target | The offline host's libc/arch is unusual, hardened, or unknown |

Both models still require the **build/fuzz toolchains** (`clang`, `make`,
optionally GNAT) to be present on the offline host — see
[Toolchains on the offline host](#toolchains-on-the-offline-host). Those build
the *generated harnesses*; they are separate from building GovFuzz itself.

## Optional LLM assistance in an enclave

The complete deterministic GovFuzz workflow needs no model and makes no network
request. Do not configure OpenAI/Anthropic or authenticated Codex/Claude CLI
providers on a host that must remain air-gapped. If local policy permits model
assistance, transfer approved model weights separately and point
`--provider local --model <id> --base-url <local-openai-compatible-url>` at an
endpoint inside the enclave. GovFuzz's distribution does not bundle weights or
a model server.

`govfuzz-daemon --mcp` can also serve its five read-only tools locally, but the
MCP host must itself use an enclave-approved local model; MCP transport alone
does not make a cloud-backed host offline. Review prompts, code, logs, findings,
and MCP transcripts as controlled data. See [LLM Assistance](./llm.md) for the
current provider, agentic, memory, and privacy boundaries.

---

## Model A — build on a connected host, transfer binaries

This is the simplest path and the recommended default.

### A0. Build a binary-only distribution package from source

Use this when you have the source on a build machine but the destination machine
should receive only an installable package. The package does **not** include the
GovFuzz application source tree. It does include the harness runtime support
files that generated harnesses and interpreter drivers need at build/run time.

The package contains:

- `tool/govfuzz`, `tool/govfuzz-daemon`, and the runtrace shim
- `tool/c_runtime`, `tool/ada_runtime`, `tool/java_runtime`,
  `tool/python_runtime`, `tool/perl_runtime`, `tool/crates/rust_runtime`,
  `tool/csharp_runtime`, `tool/js_runtime`, `tool/ruby_runtime`,
  `tool/lua_runtime`, and `tool/php_runtime`
- `content/packs/current/update-pack.json`, a signed content pack
- `content/govfuzz-policy.json`, requiring the configured content-pack key
- `smoke/c/govfuzz_smoke.c`, a tiny post-install `govfuzz auto` fixture
- `install.sh`, the interactive/update-safe installer
- `README-DIST.md` and `RUN-GOVFUZZ.md`, the install and post-install run guides

The signed content pack currently carries these pack kinds:

| Pack kind | Files | Purpose |
|---|---|---|
| `rules` | `rules/static.json` | Built-in finding/static-analysis rule catalog exported by `govfuzz rules list --json` |
| `cve` | `cve/sbom-cves.json` | Offline CVE/SCA database used by `govfuzz sbom --vuln-db` |
| `cve` | `cve/binary-cves.json` | Offline binary component/CVE database used by binary scanning workflows |
| `corpus` | `corpus/seeds.tar.gz` | Optional shared seed corpus |

CWE IDs/mappings used in rule metadata and vulnerability output are built into
GovFuzz and the bundled rule catalog; there is no separate CWE pack to generate.

On the **build machine**:

```sh
# Toolchain/bootstrap from the README install section, if not already present:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt-get update
sudo apt-get install -y make clang llvm

# Optional but useful if this build machine also runs the smoke tests:
sudo apt-get install -y gnat gprbuild default-jdk maven gradle python3 perl golang-go afl++ \
  gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 wine64 \
  qemu-user gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
rustup toolchain install nightly

# From the GovFuzz source checkout. Omitted CVE DB and seed inputs are generated
# under dist/content-inputs/ and then packaged.
scripts/package-offline-dist.sh

# Transfer both files:
sha256sum -c dist/govfuzz-dist-*.tar.gz.sha256
```

The generated input files are:

```text
dist/content-inputs/sbom-cves.json
dist/content-inputs/binary-cves.json
dist/content-inputs/seeds/
```

The generated CVE DBs are valid empty defaults, so SBOM and binary-CVE workflows
still execute but produce no CVE matches. Replace those files with your real
feed data and rerun `scripts/package-offline-dist.sh` when you need CVE matching
in the packaged content.

On the **destination machine**:

```sh
sha256sum -c govfuzz-dist-*.tar.gz.sha256
tar xzf govfuzz-dist-*.tar.gz
cd govfuzz-dist-*

# Interactive arrow-key install:
./install.sh

# Or install/update everything non-interactively:
./install.sh --non-interactive \
  --languages all \
  --targets native,windows,aarch64 \
  --fuzzers builtin,afl \
  --extras build-recovery,sandbox,archives
```

The installer defaults to `/opt/govfuzz` and symlinks `govfuzz` into
`/usr/local/bin`. It backs up an existing install to
`/opt/govfuzz.backup.<timestamp>`, preserves existing `packs/` and `corpora/`,
verifies the signed content pack, and installs it under
`/opt/govfuzz/packs/<pack_id>`. It then runs a tiny C `govfuzz auto` smoke test
from the bundled `smoke/c` fixture to prove discovery, harness generation,
build, fuzz execution, and reporting work after install. Use `./install.sh
--help` for `--prefix`, `--bin-dir`, `--package-manager`,
`--no-system-packages`, `--no-rustup`,
`--no-content`, `--install-seeds`, `--no-smoke`, and other automation controls.

If the destination host is truly air-gapped, stage the apt/dnf and rustup
toolchains through your normal offline mirror first, then run the installer with
`--no-system-packages` and/or `--no-rustup`. The old `--no-apt` spelling remains
as a compatibility alias.

### A1. Use the published release archives (preferred)

Releases are produced by `dist` and attached to the GitHub Release for each tag.
Each app is a separate archive with a `.sha256` sidecar:

- `govfuzz-*` — the CLI
- `govfuzz-daemon-*` — the JSON-RPC/read-only-MCP daemon (only for IDE or MCP use)
- `govfuzz_runtrace_shim-*` — the `LD_PRELOAD` shim `govfuzz auto` uses for
  runtime virtualisation on Linux (native C/C++/Ada/Rust/Go/COBOL/Fortran plus
  Python/Perl/Ruby/Lua/PHP interpreters; deliberately off for Java, C#,
  JavaScript/TypeScript, and cross/emulated targets)
- `govfuzz_cc_intercept-*` — the `LD_PRELOAD` shim C/C++ build recovery uses to
  capture compiler invocations made by absolute path or via `posix_spawn`

On the **connected** host:

```sh
# Download the archives + checksums for the published Linux target.
gh release download vX.Y.Z --repo Tarmo-Technologies/govfuzz \
  --pattern 'govfuzz-*x86_64-unknown-linux-gnu*' \
  --pattern 'govfuzz_runtrace_shim-*x86_64-unknown-linux-gnu*' \
  --pattern 'govfuzz_cc_intercept-*x86_64-unknown-linux-gnu*'

# Verify integrity (also re-runnable offline — the sidecar travels with the file)
sha256sum -c govfuzz-*.tar.xz.sha256
sha256sum -c govfuzz_runtrace_shim-*.tar.xz.sha256
sha256sum -c govfuzz_cc_intercept-*.tar.xz.sha256

# GitHub Artifact Attestations are not published for current private releases;
# verify checksums here and rely on signed content-pack verification during
# install.
```

The `sha256sum -c` check works fully offline and is your archive-integrity gate
on the air-gapped side — copy the `.sha256` sidecars across with the archives.
The installer also verifies the signed content pack before installing it.

Transfer the archives (e.g. via approved removable media), then on the
**offline** host:

```sh
sha256sum -c govfuzz-*.tar.xz.sha256          # re-verify after transfer
tar xf govfuzz-*.tar.xz
tar xf govfuzz_runtrace_shim-*.tar.xz         # extract the shim *beside* the CLI dir
tar xf govfuzz_cc_intercept-*.tar.xz          # optional, for C/C++ build recovery
./govfuzz/govfuzz --help
```

The CLI locates the runtime shim automatically when it sits next to the binary;
otherwise point at the preload libraries explicitly:

```sh
export GOVFUZZ_RUNTRACE_SHIM=/opt/govfuzz/libgovfuzz_runtrace_shim.so
export GOVFUZZ_CC_INTERCEPT=/opt/govfuzz/libgovfuzz_cc_intercept.so
```

### A2. Build from source on a connected host, transfer the three artifacts

Use this when you need a tag/commit that has no published archive, or a target
triple the release job does not build.

On the **connected** host, build against a glibc no newer than the offline host.
For RHEL 7 through 9, use the pinned manylinux2014 image and ABI check shown in
`.github/workflows/release.yml`; a normal build on a current Ubuntu host is not
portable back to EL7:

```sh
cargo build --release --workspace
```

Transfer these three files and keep the shim next to the CLI:

```
target/release/govfuzz
target/release/govfuzz-daemon              # only if you use IDE JSON-RPC or MCP
target/release/libgovfuzz_runtrace_shim.so
```

> **Match the runtime, not just the CPU.** The runtrace shim is `LD_PRELOAD`-ed
> into the harness processes GovFuzz compiles on the offline host, so it must be
> built against the **same libc** the offline host's `clang` links against. Build
> on a host whose glibc is the same as, or older than, the offline host's. A
> mismatched/newer glibc shows up as `version 'GLIBC_2.xx' not found` when a
> harness runs. When in doubt, use Model B.

The published Linux release is checked against a GLIBC 2.17 ceiling and is the
preferred Model A artifact for RHEL 7, 8, and 9. The stock EL7 linker cannot
link the current preload shim from source, so an EL7 source rebuild should use
the pinned manylinux2014 build image rather than stock binutils.

---

## Model B — transfer the source and build on the offline host

This guarantees a binary that matches the offline host exactly. It requires a
Rust toolchain on the offline host and a one-time crate vendor on the connected
host (GovFuzz pins all dependency versions in `Cargo.lock`).

On the **connected** host, from a clean checkout of the desired tag:

```sh
# Pull every crate the lockfile references into a local directory and print
# the cargo config that redirects builds to it.
cargo vendor vendor-offline > offline-cargo-config.toml
```

`cargo vendor` writes the full dependency set (~470 MB) into `vendor-offline/`
and prints a `[source.*]` block. Bundle the whole repository **plus**
`vendor-offline/`, `Cargo.lock`, and the printed config for transfer.

On the **offline** host:

```sh
# Wire builds to the vendored crates (paths are relative to the repo root)
mkdir -p .cargo
cp offline-cargo-config.toml .cargo/config.toml      # edit `directory =` to "vendor-offline"

# Install the pinned toolchain offline if rustup is not already provisioned.
# (rust-toolchain.toml pins `stable` with rustfmt + clippy.)

cargo build --release --workspace --offline
```

`--offline` forces cargo to use only the vendored crates and never touch the
network; the build fails loudly if anything is missing rather than reaching out.
The resulting `target/release/` binaries are identical in shape to Model A.

---

## Toolchains on the offline host

GovFuzz discovers, ranks, and recovers source with no external tools, but to
**build and fuzz** the generated harnesses it shells out to compilers that must
already be installed on the offline host:

| Lane | Required | Provides |
|---|---|---|
| C / C++ | `clang`, `clang++` (ASan/UBSan + sancov coverage), `make` | harness build + fuzz |
| Ada | FSF `gnat`, `gprbuild` (and `alr` for dependency resolution, only under `--run-untrusted`) | harness build + fuzz |
| Rust | `cargo`, `rustc` (nightly for sancov + ASan), `clang` to link the fork-server driver | harness build + fuzz |
| Java | `javac`, `java` (JDK 8+), optionally `maven`/`gradle` (coverage via the bundled ASM bytecode agent) | harness build + fuzz |
| Python | `python3` (3.12+ for `sys.monitoring` edge coverage; `sys.settrace` fallback) | harness build (`py_compile` + import smoke-test) + fuzz |
| Perl | `perl` (per-statement edge coverage via the bundled `-d:GovfuzzCov` debugger) | harness build (`perl -c` + `require` smoke-test) + fuzz |
| Go | `go` (`-cover -covermode=atomic` block feedback; safe black-box fallback) | harness build + fuzz |
| COBOL | `cobc`, `clang`, `make` | GnuCOBOL-to-C harness build + coverage-guided fuzz |
| Fortran | `gfortran`, `clang`, `make` | ASan + trace-pc/trace-cmp harness build + fuzz |
| C# | .NET SDK plus `SharpFuzz.CommandLine` | IL instrumentation, warm-CLR harness + fuzz |
| JavaScript | `node` | syntax check, V8 block coverage + warm-process fuzz |
| TypeScript | `node`, `esbuild` | transpile/bundle, V8 block coverage + warm-process fuzz |
| Ruby | Ruby 2.0+ | `TracePoint` coverage + interpreter fuzz |
| Lua | Lua 5.3+ (`lua`/`luac`) | line-hook coverage + interpreter fuzz |
| PHP | PHP 8.0+; `pcov` recommended | syntax check + interpreter fuzz (`pcov` coverage or black-box fallback) |
| AFL++ engine (optional, C/C++ only) | `afl-fuzz`, `afl-clang-fast` | alternate fuzz engine for native C/C++ targets only |

Stage these from your distribution's offline package mirror or a pre-downloaded
`.deb`/`.rpm` bundle (e.g. `apt-get install --download-only` on a connected
mirror, transfer, `dpkg -i`). Without them, `govfuzz auto` still runs discovery
and build-recovery; Ada, C, and C++ targets then report as un-buildable, while
targets in every lane whose compiler/interpreter is absent skip cleanly (no
error and no finding), for example Rust without nightly or Go without `go`.

The binary installer maps both Debian/Ubuntu (`apt-get`) and RHEL-family
(`dnf`/`yum`) package names. On RHEL it filters the selected set through the
enabled repositories before installing, so an unavailable supplemental package
does not prevent available core tools from being installed. The C# lane still
requires an explicitly staged .NET 8 SDK and global `SharpFuzz.CommandLine`
tool. TypeScript requires `esbuild` either on `PATH` or already present in the
target project so `npx --no-install esbuild` succeeds. A C# harness also restores
its SharpFuzz NuGet package; pre-populate the NuGet cache or configure an
approved offline package source before moving into the enclave.

On RHEL 7, point `yum` at an active subscription or organization mirror before
running the installer. CentOS 7 compatibility labs must use an archive mirror;
the retired default mirrorlist can no longer supply dependencies.

> **License profile reminder.** GNAT and GPRbuild are GPL. GovFuzz only ever
> invokes them as subprocesses under `--profile external-tools`; the default
> `strict-permissive` profile links nothing GPL. This matters when you stage
> toolchains for an air-gapped Ada deployment — see
> [licensing.md](./licensing.md).

---

## Staging harness dependencies across the air gap

Toolchains build the harnesses; the harnesses themselves still need the
*project's own* dependency headers, libraries, and Ada units. A legacy tree that
`#include`s a vendored SDK or `with`s an external Ada library will not build
offline until those are staged. GovFuzz turns this into a single scan-then-stage
trip instead of a build-hit-copy loop.

| Flag | Network | What it does |
|---|---|---|
| `--deps-only` | offline | Discover and build each target as far as possible (stubbing what's missing), emit the missing-dependency manifest, then **skip fuzzing**. The fast "what does this tree need?" pass. |
| `--install-deps` | **online** | After the sweep, fetch the still-blocking deps via the package managers present (`apt-get` for headers/libs, `alr get` for Ada units). The **only** part of `auto` that touches the network — run it on the connected host. |
| `--ada-deps <DIR>` | offline | Add local directories of Ada dependency source to the build path. Point at vendored/air-gapped units a project `with`s. Repeatable. |
| `--extra-include <DIR>` | offline | Add C/C++ include dirs for dependency headers that live outside the swept tree (a vendored SDK's `include/`). Read from disk only. Repeatable. |
| `--probe-build` | offline | Recover the project's real compile wiring (`-I`/`-D`/`-std`, generated headers) by running its own build once. **Executes the project's untrusted build scripts** (sandboxed under bwrap/firejail when available). |
| `--run-untrusted` | offline | Consent umbrella for materializing generated dependencies: implies `--probe-build` plus an Ada `alr build` / `gprbuild` probe. Off by default; same untrusted-execution caveat. |

The recommended air-gapped flow:

```sh
# On the OFFLINE host — find everything the tree needs, no fuzzing:
govfuzz auto path/to/src --work-dir govfuzz_work --deps-only
#   → writes govfuzz_work/auto/missing-deps.txt (human list)
#           govfuzz_work/auto/missing-deps.json (machine-readable)

# Carry missing-deps.txt to the CONNECTED host and fetch there. Either run
# `auto --install-deps` (the only network-touching path) or stage the
# headers/libs/Ada units by hand, then transfer them back across the gap.

# Back on the OFFLINE host — point auto at the staged deps and fuzz for real:
govfuzz auto path/to/src --work-dir govfuzz_work \
  --extra-include /opt/staged/sdk/include \
  --ada-deps /opt/staged/ada-units
```

Those files exist before the first target build and are atomically checkpointed
after every completed target. Start with the first `Required toolchains,
runtimes, generated and vendor source` section. Each row identifies its evidence
as declared, observed, or inferred; `missing-deps.json` also records whether the
checkpoint is final. A parent-process OOM preserves everything learned before
the target that was running when the kill occurred.

`--run-untrusted` / `--probe-build` are needed only when a dependency is
*generated* by the project's own build (CMake/configure codegen, Alire config),
and they run that build offline — use them only when you accept executing the
project's scripts. Without them, GovFuzz stubs the generated deps and records
them in the manifest instead of running anything.

---

## Updating the govfuzz tool in place (data-safe)

Re-running `install.sh` from a newer package **updates** an existing install; you
do not uninstall first. It is idempotent — safe to run repeatedly, and safe to
re-run over the same version — and it never destroys your data.

On the offline host, unpack the new package and run the installer exactly as for
a first install:

```sh
sha256sum -c govfuzz-dist-*.tar.gz.sha256
tar xzf govfuzz-dist-*.tar.gz
cd govfuzz-dist-*
./install.sh                       # same prefix as before (default /opt/govfuzz)
# or, non-interactive, reusing your prior selections:
./install.sh --non-interactive --languages all --targets native --fuzzers builtin
```

What the update does, atomically (stages `<prefix>.new.$$`, then swaps it in):

| Action | Items |
|---|---|
| **Replaced** (updated to the new version) | `govfuzz`, `govfuzz-daemon`, the `libgovfuzz_runtrace*.so` and `libgovfuzz_cc_intercept.so` shims, and every `*_runtime/` codegen tree. Re-installed even if unchanged — a re-run is a clean overwrite. |
| **Preserved** (copied forward from the old install) | `<prefix>/packs/` (rules + CVE DB content) and `<prefix>/corpora/` (seed corpus). |
| **Backed up** (full rollback) | The previous install is moved to `<prefix>.backup.<timestamp>` before the swap. Roll back with `mv <prefix>.backup.<ts> <prefix>`. |
| **Never touched** | Your run outputs — findings, reports, harnesses, and corpora under any `--work-dir` you pass at runtime — live outside the prefix and are not seen by the installer. |

So on the same offline machine you can drop in a newer package, run `./install.sh`,
and it replaces the binaries/runtimes while keeping your content packs, seed
corpora, and all prior run data. `govfuzz --version` (or `cat <prefix>/VERSION`)
confirms the new build. If the old and new selections differ, pass the same
`--languages/--targets/--fuzzers` flags you used before (or use interactive mode,
which pre-fills them).

---

## When govfuzz itself errors: `--debug` and `bug-report.json`

If govfuzz *itself* fails on your tree — an internal panic, or a harness it
generated that its own codegen left broken — it now records that as a **bug
report** instead of only crashing. This is distinct from findings (bugs in your
target) and from `missing-deps.txt` (dependencies your environment lacks): the
bug report is govfuzz's *own* defects, boiled down to what a maintainer needs to
fix them offline.

- A govfuzz-internal panic while parsing or fuzzing **one** file is caught at that
  file/target boundary — the sweep records it and keeps going instead of aborting
  the whole run.
- Whenever a run hits any internal defect, govfuzz writes
  `<work-dir>/auto/bug-report.json` and `bug-report.md` and prints a one-line
  pointer. A clean run writes neither.

Add `--debug` to capture a **backtrace** per panic (it sets `RUST_BACKTRACE` for
you), which pins the exact source line:

```sh
govfuzz auto --debug <source-tree> --work-dir govfuzz_work
# → govfuzz_work/auto/bug-report.md   (paste an entry to the maintainer)
```

`bug-report.md` lists each issue with its category (`PANIC` / `codegen`), the
source file and target it happened on, the language, the govfuzz version +
commit, and (under `--debug`) the backtrace. Send that file — or a single entry
from it — to get the defect fixed; it carries everything needed to reproduce.

---

## Updating offline content: rules, CVE DB, corpora

Updating the *tool* (above) is separate from updating the *content* it consults
(static-analysis rules, the CVE/SCA database, seed corpora). Content ships as
signed **update packs** — local JSON manifests with deterministic hashes — so it
can move across the air gap independently of a GovFuzz release.

The full binary-only package flow in [A0](#a0-build-a-binary-only-distribution-package-from-source)
creates and installs this pack for you. Run `govfuzz pack create` directly only
when you are publishing a content-only update.

On the **connected** host:

```sh
govfuzz pack create --root packs/current \
  --pack-id rules-2026-06 --version 2026.06 \
  --item rules:rules/static.json \
  --item cve:cve/sbom-cves.json \
  --item cve:cve/binary-cves.json \
  --item corpus:corpus/seeds.tar.gz \
  --sign-key offline-root \
  --out packs/current/update-pack.json
```

Transfer `packs/current/`, then on the **offline** host verify before use:

```sh
govfuzz pack verify packs/current/update-pack.json \
  --root packs/current --policy govfuzz-policy.json
```

See [release-packaging.md](./release-packaging.md#air-gapped-packs) for the full
pack format.

---

## Post-update smoke test

After any update, confirm the install on the offline host before relying on it:

```sh
govfuzz --help                                  # CLI resolves
govfuzz auto <a small bundled source tree> \    # full pipeline end-to-end
  --work-dir /tmp/gf-smoke --per-target-time 5 --verbose
```

`--per-target-time` is the per-target TOTAL fuzz wall-clock budget (default
60s), split evenly across the empty/rng/fuzz-driven passes under one shared
deadline — so the per-target wall is roughly this value regardless of pass
count (the libFuzzer `-max_total_time` / AFL `-V` per-target parity knob). To
bound the WHOLE run across all targets use `--campaign-time <secs>`; to stop a
target once it has produced N distinct crash signatures use
`--per-target-finding-count N` (`1` ≈ libFuzzer stop-on-first-crash). The old
`--total-time` flag still parses but is a deprecated, hidden alias — don't reach
for it.

A healthy run prints per-target fuzz lines with non-zero `execs=` and lists at
least one `built+fuzzed` target (given a C target and `clang`). If the summary
shows `(N STUB-ONLY)` or a `⚠ STUB-ONLY` warning, the harness fuzzed blind
stubs, not real library code — a clean result there is a **false clean**, so
pick a bundled C target with `clang` present for a meaningful smoke test. If you
see `libgovfuzz_runtrace_shim.so not found` or every target reports build
failure, re-check the shim location (`GOVFUZZ_RUNTRACE_SHIM`) and the
[toolchains](#toolchains-on-the-offline-host) respectively.
