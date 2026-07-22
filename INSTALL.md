<!-- SPDX-License-Identifier: Apache-2.0 -->

# Installing a GovFuzz Release

Linux releases provide two complete installation choices. Use the all-in-one
bundle when you want `install.sh` to install the CLI, daemon, both Linux shims,
harness runtimes, and the signed content pack together. Use the component
archives when you want to choose and place the files yourself.

Do not mix versions or target triples. The commands below use the published
64-bit GNU/Linux artifacts.

## Choice 1: all-in-one `install.sh` bundle

Download `govfuzz-dist-<version>-x86_64-unknown-linux-gnu.tar.gz` and its
`.sha256` sidecar from the same release, then:

```sh
sha256sum -c govfuzz-dist-*.tar.gz.sha256
tar xzf govfuzz-dist-*.tar.gz
cd govfuzz-dist-*-x86_64-unknown-linux-gnu
./install.sh
```

The interactive installer selects language toolchains, targets, fuzzers, and
optional extras. Its default install prefix is `/opt/govfuzz`, with `govfuzz`
and `govfuzz-daemon` symlinks in `/usr/local/bin`.

For automation or an offline host whose system dependencies were staged
separately:

```sh
./install.sh --non-interactive \
  --languages c,cpp,rust \
  --targets native \
  --fuzzers builtin \
  --extras build-recovery,archives

# Add these when the offline host must not contact package or Rust servers:
#   --no-system-packages --no-rustup
```

Run `./install.sh --help` for custom prefixes, dependency controls, seed
installation, smoke-test controls, and every available language profile.

## Choice 2: manually co-locate component archives

Download the CLI plus the two Linux shims and their checksum sidecars:

```text
govfuzz-x86_64-unknown-linux-gnu.tar.xz
govfuzz_runtrace_shim-x86_64-unknown-linux-gnu.tar.xz
govfuzz_cc_intercept-x86_64-unknown-linux-gnu.tar.xz
```

The daemon archive is optional and is needed only for IDE, JSON-RPC, or MCP
use. Verify and extract the selected archives from their download directory:

```sh
sha256sum -c govfuzz-x86_64-unknown-linux-gnu.tar.xz.sha256
sha256sum -c govfuzz_runtrace_shim-x86_64-unknown-linux-gnu.tar.xz.sha256
sha256sum -c govfuzz_cc_intercept-x86_64-unknown-linux-gnu.tar.xz.sha256

tar xf govfuzz-x86_64-unknown-linux-gnu.tar.xz
tar xf govfuzz_runtrace_shim-x86_64-unknown-linux-gnu.tar.xz
tar xf govfuzz_cc_intercept-x86_64-unknown-linux-gnu.tar.xz
```

Copy the two libraries into the CLI directory. This gives both components one
reliable automatic-discovery layout:

```sh
CLI_DIR=govfuzz-x86_64-unknown-linux-gnu

install -m 0755 \
  govfuzz_runtrace_shim-x86_64-unknown-linux-gnu/libgovfuzz_runtrace_shim.so \
  "$CLI_DIR/"
install -m 0755 \
  govfuzz_cc_intercept-x86_64-unknown-linux-gnu/libgovfuzz_cc_intercept.so \
  "$CLI_DIR/"

"./$CLI_DIR/govfuzz" --version
```

You can run in place or copy the co-located directory to a permanent prefix:

```sh
PREFIX="${GOVFUZZ_PREFIX:-$HOME/.local/share/govfuzz}"
BIN_DIR="${GOVFUZZ_BIN_DIR:-$HOME/.local/bin}"

mkdir -p "$PREFIX" "$BIN_DIR"
cp -a "$CLI_DIR/." "$PREFIX/"
ln -sfn "$PREFIX/govfuzz" "$BIN_DIR/govfuzz"
```

To add the optional daemon, extract its archive, copy `govfuzz-daemon` into the
same prefix, and create a matching symlink:

```sh
tar xf govfuzz-daemon-x86_64-unknown-linux-gnu.tar.xz
install -m 0755 \
  govfuzz-daemon-x86_64-unknown-linux-gnu/govfuzz-daemon "$PREFIX/"
ln -sfn "$PREFIX/govfuzz-daemon" "$BIN_DIR/govfuzz-daemon"
```

If policy requires the libraries to remain elsewhere, set absolute paths
instead of copying them:

```sh
export GOVFUZZ_RUNTRACE_SHIM=/absolute/path/libgovfuzz_runtrace_shim.so
export GOVFUZZ_CC_INTERCEPT=/absolute/path/libgovfuzz_cc_intercept.so
```

The runtrace shim provides runtime auditing, behavioral/taint oracles, and fake
resources. The compiler-interception shim enables complex C/C++ build recovery
for compiler processes launched by absolute path or `posix_spawn`.

The runtrace shim can also be found in its sibling extracted archive directory.
The compiler-interception shim cannot: keep it directly beside `govfuzz` or set
`GOVFUZZ_CC_INTERCEPT` to its absolute path.

See `README.md` in the same archive and the
[online installation guide](https://github.com/Tarmo-Technologies/govfuzz/blob/main/docs/site/install.md)
for supported operating systems and per-language toolchain prerequisites.
