// SPDX-License-Identifier: Apache-2.0

//! Native Go fuzzing lane (M3.3): generate a harness `main` package that imports
//! the target package via a module `replace`, `go build -cover -covermode=atomic`
//! it to `harnesses/<id>/main`, and let the builtin engine drive it over the
//! `GOVFUZZ_FRAMED` fork-server protocol — the SAME execution path as the C/Rust
//! lanes, no third-party fuzzer.
//!
//! Coverage is REAL edge coverage (not black-box): per input the harness clears
//! Go's `-cover` atomic counters, runs the target, then folds the SET of executed
//! blocks (via `runtime/coverage.WriteCounters`, ignoring the count VALUE so a
//! loop's trip count is never false novelty) into govfuzz's shared `GOVFUZZ_COV_SHM`
//! edge map — the same coverage-guided feedback the other lanes get. Parsing Go's
//! internal covcounters format is version-guarded: a mismatch folds nothing
//! (graceful black-box fallback), never a wrong signal.
//!
//! Go is compiled + statically typed, so the harness decodes by the parameter's
//! declared type. A Go panic (nil deref, index OOB, divide-by-zero, ...) is
//! `recover`ed and reported as a finding; an unrecoverable `fatal error` crashes
//! the process and the engine catches the death. A missing `go` toolchain, a
//! target outside a module, a method (needs a receiver), or an unsupported
//! parameter type skips cleanly (the GNAT-less rule).

use crate::auto::candidate::Candidate;
use go_parser::{parse_go_functions, GoFunc};
use std::path::{Path, PathBuf};
use std::process::Command;

pub enum GoBuildResult {
    Built,
    Failed { reason: String, skip: bool },
}

fn probe_go() -> Option<PathBuf> {
    which::which("go").ok()
}

pub fn build_go_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    _source_root: &Path,
) -> GoBuildResult {
    let Some(go) = probe_go() else {
        return GoBuildResult::Failed {
            reason: "no `go` toolchain found; install Go to fuzz Go (the lane skips \
                     cleanly, like a GNAT-less Ada skip)"
                .to_owned(),
            skip: true,
        };
    };

    let func = match resolve_target(candidate) {
        Ok(f) => f,
        Err(reason) => return GoBuildResult::Failed { reason, skip: true },
    };
    if func.is_method {
        return GoBuildResult::Failed {
            reason: format!(
                "Go method `{}` needs a receiver value; receiver synthesis is not yet \
                 supported (skipped cleanly)",
                func.name
            ),
            skip: true,
        };
    }

    // Locate the enclosing Go module (go.mod) so the harness can import the target
    // package by its module import path.
    let target_abs = candidate
        .source_path
        .canonicalize()
        .unwrap_or_else(|_| candidate.source_path.clone());
    let Some((mod_root, module_path)) = find_go_module(&target_abs) else {
        return GoBuildResult::Failed {
            reason: "target is not inside a Go module (no go.mod found); only \
                     module-based Go targets are supported (skipped cleanly)"
                .to_owned(),
            skip: true,
        };
    };
    let import_path = compute_import_path(&module_path, &mod_root, &target_abs);

    // Build the decode/call body; an unsupported required param type skips cleanly.
    let body = match generate_call(&func) {
        Ok(b) => b,
        Err(reason) => return GoBuildResult::Failed { reason, skip: true },
    };

    let auto_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(e) = std::fs::create_dir_all(&auto_dir) {
        return GoBuildResult::Failed {
            reason: format!("create {}: {e}", auto_dir.display()),
            skip: false,
        };
    }

    let main_go = generate_main_go(&import_path, &body);
    if let Err(e) = std::fs::write(auto_dir.join("govfuzz_harness.go"), &main_go) {
        return GoBuildResult::Failed {
            reason: format!("write harness: {e}"),
            skip: false,
        };
    }
    let go_mod = format!(
        "module govfuzzharness\n\ngo 1.21\n\nrequire {module_path} v0.0.0-incompatible\n\nreplace {module_path} => {root}\n",
        module_path = module_path,
        root = mod_root.display(),
    );
    if let Err(e) = std::fs::write(auto_dir.join("go.mod"), &go_mod) {
        return GoBuildResult::Failed {
            reason: format!("write go.mod: {e}"),
            skip: false,
        };
    }

    // Resolve the dependency graph (offline-tolerant) then build the binary.
    // GOTOOLCHAIN=local: use the INSTALLED Go, never auto-download a newer toolchain
    // a target's `go 1.x` directive asks for (that needs network + is an env limit,
    // not a govfuzz failure). The version-compatible majority then still builds.
    let bin = auto_dir.join("main");
    let _ = Command::new(&go)
        .args(["mod", "tidy"])
        .current_dir(&auto_dir)
        .env("GOFLAGS", "-mod=mod")
        .env("GOTOOLCHAIN", "local")
        .output();
    // Real edge coverage (was black-box): build with `-cover -covermode=atomic` so
    // the harness can read per-input executed-block sets via `runtime/coverage` and
    // fold them into govfuzz's shared edge map — the same coverage-guided feedback
    // the C/Rust/Python/Perl lanes get. `atomic` is required by `WriteCounters`.
    let run_build = |overlay: Option<&Path>, cover: bool| {
        let mut cmd = Command::new(&go);
        cmd.args(["build", "-o"]).arg(&bin);
        // Flags MUST precede the `.` package argument — `go build` stops parsing
        // flags at the first non-flag, so an `-overlay` placed after `.` is
        // silently treated as a package pattern and ignored.
        if cover {
            cmd.args(["-cover", "-covermode=atomic"]);
        }
        if let Some(overlay) = overlay {
            cmd.arg(format!("-overlay={}", overlay.display()));
        }
        cmd.arg(".")
            .current_dir(&auto_dir)
            .env("GOFLAGS", "-mod=mod")
            .env("GOTOOLCHAIN", "local");
        cmd.output()
    };
    let mut use_cover = true;
    let mut build = run_build(None, use_cover);
    // Never lose a target over the coverage instrumentation: if the `-cover` build
    // fails where a plain one might not, retry black-box (the harness then folds no
    // edges — graceful degradation to the old behavior).
    if use_cover
        && build
            .as_ref()
            .is_ok_and(|out| !out.status.success() || !bin.is_file())
    {
        use_cover = false;
        build = run_build(None, false);
    }
    // Many modern modules DECLARE a newer `go` directive than the installed
    // toolchain but never use its features. Under GOTOOLCHAIN=local that
    // directive HARD-fails the build ("module … requires go >= 1.2x"), which
    // previously blocked every such module wholesale. Retry once with a
    // `-overlay` that lowers the TARGET module's go.mod directive to the local
    // toolchain — non-mutating (the scanned tree is never edited). A module
    // whose code is actually version-compatible now builds; one that genuinely
    // uses newer features still fails on the real symbol and skips cleanly below.
    let version_gated = build.as_ref().is_ok_and(|out| {
        !out.status.success() && String::from_utf8_lossy(&out.stderr).contains("requires go >=")
    });
    if version_gated {
        if let Some(overlay) = write_lowered_go_overlay(&auto_dir, &mod_root, &go) {
            build = run_build(Some(&overlay), use_cover);
        }
    }
    match build {
        Ok(out) if out.status.success() && bin.is_file() => GoBuildResult::Built,
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // A target needing external modules we can't fetch offline, or a newer Go
            // toolchain than installed, is an ENVIRONMENT limit, not a govfuzz failure
            // — skip cleanly.
            let skip = stderr.contains("cannot find module")
                || stderr.contains("missing go.sum")
                || stderr.contains("dial tcp")
                || stderr.contains("no required module")
                || stderr.contains("toolchain not available")
                || stderr.contains("download go1")
                || stderr.contains("requires go >=");
            GoBuildResult::Failed {
                reason: format!("go build failed: {}", stderr.lines().last().unwrap_or("")),
                skip,
            }
        }
        Err(e) => GoBuildResult::Failed {
            reason: format!("could not run go build: {e}"),
            skip: false,
        },
    }
}

fn resolve_target(candidate: &Candidate) -> Result<GoFunc, String> {
    let source = std::fs::read_to_string(&candidate.source_path)
        .map_err(|e| format!("read {}: {e}", candidate.source_path.display()))?;
    parse_go_functions(&source)
        .map_err(|_| "failed to parse Go source".to_owned())?
        .into_iter()
        .find(|f| f.name == candidate.name && f.line == candidate.line)
        .or_else(|| {
            parse_go_functions(&source)
                .ok()
                .and_then(|fs| fs.into_iter().find(|f| f.name == candidate.name))
        })
        .ok_or_else(|| format!("target `{}` no longer present in source", candidate.name))
}

/// Local Go toolchain language version as `MAJOR.MINOR` ("1.22"), from
/// `go env GOVERSION` ("go1.22.2"). None if it can't be parsed.
fn local_go_minor(go: &Path) -> Option<String> {
    let out = Command::new(go)
        .args(["env", "GOVERSION"])
        .env("GOTOOLCHAIN", "local")
        .output()
        .ok()?;
    parse_go_minor(&String::from_utf8_lossy(&out.stdout))
}

/// Parse `go1.22.2` / `go1.24` into `1.22` / `1.24`. None if not a `goX.Y…`
/// string (a `devel …` toolchain, empty output, ...).
fn parse_go_minor(goversion: &str) -> Option<String> {
    let version = goversion.trim().strip_prefix("go")?;
    let mut parts = version.split('.');
    let major = parts.next()?;
    let minor: String = parts
        .next()?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    if !major.is_empty() && major.chars().all(|c| c.is_ascii_digit()) && !minor.is_empty() {
        Some(format!("{major}.{minor}"))
    } else {
        None
    }
}

/// Write a `go build -overlay` JSON that maps the target module's go.mod to a
/// copy whose `go` directive is lowered to the local toolchain (and any pinned
/// `toolchain` line dropped), so a build gated only by a declared-too-new
/// directive can proceed WITHOUT mutating the scanned tree. Returns the overlay
/// file path, or None if the local version is unknown or any file op fails.
fn write_lowered_go_overlay(auto_dir: &Path, mod_root: &Path, go: &Path) -> Option<PathBuf> {
    let local = local_go_minor(go)?;
    let gomod = mod_root.join("go.mod");
    let src = std::fs::read_to_string(&gomod).ok()?;
    let lowered = lower_go_mod_directive(&src, &local);
    let lowered_path = auto_dir.join("govfuzz_lowered_go.mod");
    std::fs::write(&lowered_path, lowered).ok()?;
    let mut replace = serde_json::Map::new();
    replace.insert(
        gomod.to_string_lossy().into_owned(),
        serde_json::Value::String(lowered_path.to_string_lossy().into_owned()),
    );
    let overlay = serde_json::json!({ "Replace": serde_json::Value::Object(replace) });
    let overlay_path = auto_dir.join("govfuzz_overlay.json");
    std::fs::write(&overlay_path, serde_json::to_vec(&overlay).ok()?).ok()?;
    Some(overlay_path)
}

/// Lower a go.mod's language requirement so it won't gate the local toolchain:
/// rewrite the `go MAJOR.MINOR…` directive to `go <local>` and drop any pinned
/// `toolchain …` line. Every other line is preserved verbatim.
fn lower_go_mod_directive(src: &str, local_minor: &str) -> String {
    let mut out = String::with_capacity(src.len() + 8);
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("toolchain ") {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("go ") {
            if rest.trim_start().starts_with(|c: char| c.is_ascii_digit()) {
                out.push_str("go ");
                out.push_str(local_minor);
                out.push('\n');
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Walk up from the target file to the nearest `go.mod`; return (module root dir,
/// module path).
fn find_go_module(target_abs: &Path) -> Option<(PathBuf, String)> {
    let mut dir = target_abs.parent()?;
    loop {
        let gomod = dir.join("go.mod");
        if gomod.is_file() {
            let text = std::fs::read_to_string(&gomod).ok()?;
            let module = text.lines().find_map(|l| {
                l.trim()
                    .strip_prefix("module ")
                    .map(|m| m.trim().to_owned())
            })?;
            return Some((dir.to_path_buf(), module));
        }
        dir = dir.parent()?;
    }
}

/// Import path of the target package = module path + the target dir relative to the
/// module root.
fn compute_import_path(module_path: &str, mod_root: &Path, target_abs: &Path) -> String {
    let Some(parent) = target_abs.parent() else {
        return module_path.to_owned();
    };
    match parent.strip_prefix(mod_root) {
        Ok(rel) if rel.as_os_str().is_empty() => module_path.to_owned(),
        Ok(rel) => format!(
            "{}/{}",
            module_path,
            rel.to_string_lossy().replace('\\', "/")
        ),
        Err(_) => module_path.to_owned(),
    }
}

/// Build the decode lines + the call statement for the target's params. Returns an
/// error (clean skip) if a required parameter type can't be synthesized.
fn generate_call(func: &GoFunc) -> Result<String, String> {
    let n = func.params.len();
    let mut lines = String::new();
    let mut args = Vec::new();
    for (i, p) in func.params.iter().enumerate() {
        let last = i + 1 == n;
        let expr = decode_for_type(&p.ty, last)
            .ok_or_else(|| format!("unsupported Go parameter type `{}` (skipped)", p.ty))?;
        lines.push_str(&format!("\ta{i} := {expr}\n"));
        args.push(format!("a{i}"));
    }
    lines.push_str(&format!("\ttgt.{}({})\n", func.name, args.join(", ")));
    Ok(lines)
}

/// Map a Go parameter type to a decode expression over the cursor `c`. `None` for
/// an unsupported type (struct/map/pointer/interface/slice-of-other).
fn decode_for_type(ty: &str, last: bool) -> Option<String> {
    let t = ty.trim();
    Some(match t {
        "[]byte" => {
            if last {
                "c.rest()".to_owned()
            } else {
                "c.bytesField()".to_owned()
            }
        }
        "string" => {
            if last {
                "string(c.rest())".to_owned()
            } else {
                "string(c.bytesField())".to_owned()
            }
        }
        "[]rune" => "[]rune(string(c.rest()))".to_owned(),
        "io.Reader" | "io.ReadCloser" => "bytes.NewReader(c.rest())".to_owned(),
        "bool" => "(c.u8()&1 == 1)".to_owned(),
        "byte" | "uint8" => "c.u8()".to_owned(),
        "rune" | "int32" => "int32(c.i64())".to_owned(),
        "int" => "int(c.i64())".to_owned(),
        "int8" => "int8(c.i64())".to_owned(),
        "int16" => "int16(c.i64())".to_owned(),
        "int64" => "c.i64()".to_owned(),
        "uint" => "uint(c.i64())".to_owned(),
        "uint16" => "uint16(c.i64())".to_owned(),
        "uint32" => "uint32(c.i64())".to_owned(),
        "uint64" => "uint64(c.i64())".to_owned(),
        "uintptr" => "uintptr(c.i64())".to_owned(),
        "float32" => "float32(c.f64())".to_owned(),
        "float64" => "c.f64()".to_owned(),
        _ => return None,
    })
}

/// The full harness `main.go`. All imports are referenced inside cursor methods so
/// none is "unused" regardless of which decode paths a given target uses.
fn generate_main_go(import_path: &str, body: &str) -> String {
    format!(
        r#"// SPDX-License-Identifier: Apache-2.0
// Generated by govfuzz (native Go lane). Decodes fuzz bytes into typed args and
// calls the target; a recovered panic is a finding. Do not edit. GOVFUZZ_FRAMED
package main

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"runtime/coverage"
	"runtime/debug"
	"syscall"

	tgt "{import_path}"
)

// --- govfuzz real edge coverage (Go -cover atomic counters -> shared edge map) ---
// The builtin engine reads GOVFUZZ_COV_SHM as a cumulative 64KB AFL edge bitmap.
// Per input we clear Go's coverage counters, run the target, then fold the SET of
// executed blocks (counter != 0 — the count VALUE is ignored, so a loop's trip
// count is never false novelty) into the map. Parsing Go's internal covcounters
// format is version-guarded: any mismatch folds nothing (black-box fallback), so a
// future format change degrades gracefully rather than emitting a wrong signal.
const govfuzzCovBits = 1 << 16

var govfuzzCovMap []byte
var govfuzzCovBuf bytes.Buffer

func govfuzzCovInit() {{
	path := os.Getenv("GOVFUZZ_COV_SHM")
	if path == "" {{
		return
	}}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o600)
	if err != nil {{
		return
	}}
	_ = syscall.Ftruncate(fd, govfuzzCovBits)
	m, err := syscall.Mmap(fd, 0, govfuzzCovBits, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	_ = syscall.Close(fd)
	if err == nil {{
		govfuzzCovMap = m
	}}
	_ = coverage.ClearCounters()
}}

func govfuzzCovClear() {{
	if govfuzzCovMap != nil {{
		_ = coverage.ClearCounters()
	}}
}}

func govfuzzCovRecord() {{
	if govfuzzCovMap == nil {{
		return
	}}
	govfuzzCovBuf.Reset()
	if coverage.WriteCounters(&govfuzzCovBuf) != nil {{
		_ = coverage.ClearCounters()
		return
	}}
	b := govfuzzCovBuf.Bytes()
	_ = coverage.ClearCounters()
	if len(b) < 32 || b[1] != 'c' || b[2] != 'w' || b[3] != 'm' {{
		return
	}}
	flavor := b[24]
	p := 32 // magic[4] version[4] metaHash[16] flavor[1] bigEndian[1] pad[6]
	le := func(n int) uint64 {{
		var v uint64
		for i := 0; i < n; i++ {{
			v |= uint64(b[p+i]) << (8 * uint(i))
		}}
		p += n
		return v
	}}
	uleb := func() (uint64, bool) {{
		var v uint64
		var s uint
		for {{
			if p >= len(b) {{
				return 0, false
			}}
			c := b[p]
			p++
			v |= uint64(c&0x7f) << s
			if c&0x80 == 0 {{
				break
			}}
			s += 7
		}}
		return v, true
	}}
	rd := func() (uint64, bool) {{
		if flavor == 1 {{ // CtrRaw: fixed uint32
			if p+4 > len(b) {{
				return 0, false
			}}
			return le(4), true
		}}
		return uleb() // CtrULeb128
	}}
	if p+16 > len(b) {{
		return
	}}
	fcn := le(8)
	strtab := le(4)
	args := le(4)
	p += int(strtab) + int(args)
	if p > len(b) {{
		return
	}}
	for f := uint64(0); f < fcn; f++ {{
		nc, ok := rd()
		if !ok {{
			return
		}}
		pkg, ok2 := rd()
		if !ok2 {{
			return
		}}
		fnc, ok3 := rd()
		if !ok3 {{
			return
		}}
		for c := uint64(0); c < nc; c++ {{
			v, ok4 := rd()
			if !ok4 {{
				return
			}}
			if v != 0 {{
				idx := ((uint32(pkg) * 2654435761) ^ (uint32(fnc) * 40503) ^ uint32(c)) & (govfuzzCovBits - 1)
				if govfuzzCovMap[idx] != 0xff {{
					govfuzzCovMap[idx]++
				}}
			}}
		}}
	}}
}}

type cur struct {{
	d []byte
	p int
}}

func (c *cur) rest() []byte {{ r := c.d[c.p:]; c.p = len(c.d); return r }}
func (c *cur) u8() byte {{
	if c.p < len(c.d) {{
		v := c.d[c.p]
		c.p++
		return v
	}}
	return 0
}}
func (c *cur) i64() int64 {{
	var v uint64
	for i := 0; i < 8 && c.p < len(c.d); i++ {{
		v |= uint64(c.d[c.p]) << (8 * uint(i))
		c.p++
	}}
	return int64(v)
}}

// bytesField reads a 1-byte length then that many bytes (bounded by what remains),
// so multiple []byte/string params each get a chunk.
func (c *cur) bytesField() []byte {{
	n := int(c.u8())
	if rem := len(c.d) - c.p; n > rem {{
		n = rem
	}}
	r := c.d[c.p : c.p+n]
	c.p += n
	return r
}}

// f64 decodes a float (and keeps the math import referenced even when no float
// param is decoded by a given target).
func (c *cur) f64() float64 {{ return math.Float64frombits(uint64(c.i64())) }}

// reader keeps the io import referenced even when no io.Reader param is decoded.
var _ = io.EOF

func runOne(data []byte) {{
	defer func() {{
		if r := recover(); r != nil {{
			os.Stderr.WriteString("== govfuzz go finding: " + fmt.Sprint(r) + "\n")
			os.Stderr.Write(debug.Stack()) // stack frames so findings cluster by site
			_ = os.Stderr.Sync()
			os.Exit(86)
		}}
	}}()
	c := &cur{{d: data}}
	_ = bytes.MinRead
{body}}}

func readU32(f *os.File) (int, bool) {{
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(f, hdr); err != nil {{
		return 0, false
	}}
	return int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16 | int(hdr[3])<<24, true
}}

func main() {{
	// Save the control pipe (fd 1), then redirect fd 1 + os.Stdout to /dev/null so
	// the target's prints can't corrupt the sync stream (#427).
	ctlFd, _ := syscall.Dup(1)
	control := os.NewFile(uintptr(ctlFd), "ctl")
	if dn, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {{
		_ = syscall.Dup2(int(dn.Fd()), 1)
		os.Stdout = dn
	}}
	in := os.NewFile(0, "in")
	if os.Getenv("GOVFUZZ_FRAMED") != "" {{
		govfuzzCovInit()
		_, _ = control.Write([]byte{{1}}) // ready
		for {{
			n, ok := readU32(in)
			if !ok {{
				break
			}}
			buf := make([]byte, n)
			if _, err := io.ReadFull(in, buf); err != nil && n > 0 {{
				break
			}}
			govfuzzCovClear()
			runOne(buf)
			govfuzzCovRecord()
			_, _ = control.Write([]byte{{1}}) // sync
		}}
		return
	}}
	// Per-spawn replay: argv[1] file else stdin.
	var data []byte
	if len(os.Args) > 1 {{
		if b, err := os.ReadFile(os.Args[1]); err == nil {{
			data = b
		}}
	}} else {{
		data, _ = io.ReadAll(in)
	}}
	runOne(data)
}}
"#,
        import_path = import_path,
        body = body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn func(name: &str, params: &[(&str, &str)], method: bool) -> GoFunc {
        GoFunc {
            name: name.to_owned(),
            line: 1,
            package: "p".to_owned(),
            is_exported: true,
            is_method: method,
            receiver_type: None,
            params: params
                .iter()
                .map(|(n, t)| go_parser::GoParam {
                    name: (*n).to_owned(),
                    ty: (*t).to_owned(),
                })
                .collect(),
        }
    }

    #[test]
    fn generates_typed_call_for_bytes() {
        let body = generate_call(&func("ParseRecord", &[("data", "[]byte")], false)).unwrap();
        assert!(body.contains("a0 := c.rest()"));
        assert!(body.contains("tgt.ParseRecord(a0)"));
    }

    #[test]
    fn typed_params_decode_by_type() {
        let body = generate_call(&func("Decode", &[("s", "string"), ("n", "int")], false)).unwrap();
        assert!(body.contains("a0 := string(c.bytesField())"));
        assert!(body.contains("a1 := int(c.i64())"));
        assert!(body.contains("tgt.Decode(a0, a1)"));
    }

    #[test]
    fn unsupported_param_type_is_skip() {
        let e = generate_call(&func("F", &[("m", "map[string]int")], false));
        assert!(e.is_err(), "map param -> clean skip");
    }

    #[test]
    fn import_path_computation() {
        let root = Path::new("/proj");
        let f = Path::new("/proj/internal/parser/p.go");
        assert_eq!(
            compute_import_path("github.com/x/proj", root, f),
            "github.com/x/proj/internal/parser"
        );
        let rootf = Path::new("/proj/p.go");
        assert_eq!(
            compute_import_path("github.com/x/proj", root, rootf),
            "github.com/x/proj"
        );
    }

    #[test]
    fn parse_go_minor_extracts_major_minor() {
        assert_eq!(parse_go_minor("go1.22.2").as_deref(), Some("1.22"));
        assert_eq!(parse_go_minor("go1.24\n").as_deref(), Some("1.24"));
        assert_eq!(parse_go_minor("  go1.21  ").as_deref(), Some("1.21"));
        // Toolchains with a pre-release minor keep the numeric prefix.
        assert_eq!(parse_go_minor("go1.25rc1").as_deref(), Some("1.25"));
        assert_eq!(parse_go_minor("devel go1.99"), None);
        assert_eq!(parse_go_minor(""), None);
    }

    #[test]
    fn lower_go_mod_directive_lowers_go_and_drops_toolchain() {
        // A module declaring a too-new directive (+ a toolchain pin) is rewritten
        // to the local version so the build isn't gated; everything else is kept.
        let src = "module github.com/x/y\n\ngo 1.24\n\ntoolchain go1.24.0\n\nrequire github.com/z/w v1.2.3\n";
        let out = lower_go_mod_directive(src, "1.22");
        assert!(out.contains("go 1.22\n"), "go directive lowered: {out}");
        assert!(
            !out.contains("1.24"),
            "no 1.24 directive/toolchain remains: {out}"
        );
        assert!(!out.contains("toolchain "), "toolchain pin dropped: {out}");
        assert!(out.contains("module github.com/x/y"), "module line kept");
        assert!(
            out.contains("require github.com/z/w v1.2.3"),
            "require kept"
        );
    }

    #[test]
    fn lower_go_mod_directive_leaves_non_version_go_lines() {
        // `go` appearing as a require path segment or comment must not be touched;
        // only a `go <digit>` directive is rewritten.
        let src = "module m\ngo 1.23\nrequire golang.org/x/text v0.3.0\n";
        let out = lower_go_mod_directive(src, "1.22");
        assert!(out.contains("go 1.22\n"));
        assert!(out.contains("require golang.org/x/text v0.3.0"));
    }

    #[test]
    fn main_go_carries_framed_marker() {
        let m = generate_main_go("x/y", "\ttgt.F()\n");
        assert!(m.contains("GOVFUZZ_FRAMED"));
        assert!(m.contains("tgt \"x/y\""));
    }

    #[test]
    fn main_go_carries_real_edge_coverage() {
        // The Go lane is no longer black-box: the harness reads Go's -cover atomic
        // counters and folds executed blocks into the shared GOVFUZZ_COV_SHM map,
        // clearing+recording around each framed input.
        let m = generate_main_go("x/y", "\ttgt.F()\n");
        assert!(m.contains("runtime/coverage"), "imports runtime/coverage");
        assert!(m.contains("GOVFUZZ_COV_SHM"), "maps the shared edge map");
        assert!(m.contains("WriteCounters"), "reads per-input counters");
        // The framed loop hooks coverage around runOne: clear before, record after.
        // Match the call SEQUENCE directly (whitespace-normalized) so the function
        // DEFINITIONS earlier in the file can't satisfy an index-ordering check.
        let calls: String = m.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            calls.contains("govfuzzCovClear() runOne(buf) govfuzzCovRecord()"),
            "framed loop must clear -> runOne -> record in order"
        );
    }
}
