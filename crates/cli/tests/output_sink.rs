// SPDX-License-Identifier: Apache-2.0

//! Bounded output sinks for Ada output parameters the direct decoder would
//! otherwise pass as a null pointer. An access-to-array out parameter (the
//! canonical `decode (Dst : out p_Buffer; ...)` idiom) gets a real heap-backed
//! bounded buffer, and an access-to-`Root_Stream_Type'Class` out parameter gets
//! a generated discard stream. So: the callee's write path actually executes
//! (no null-deref artifact); a planted out-of-bounds write surfaces at its
//! original source line; and the deliberate fixed allocation is freed at exit
//! so LeakSanitizer does not report it as a leak (which would drown findings).
//! Also covers value-parameter fuzzing where a bare decoder would emit a neutral
//! (an Unbounded_String input must decode fuzz bytes, not the empty value).
//! Gnat-gated; skips cleanly without a compiler.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-cli-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// `(exception_name, "<file>:<line>")` for every finding under `work_dir`.
fn findings(work_dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(work_dir.join("findings")) else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(bytes) = fs::read(entry.path().join("finding.json")) else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let name = v["exception"]["name"].as_str().unwrap_or("").to_owned();
        let file = v["exception"]["source_file"]
            .as_str()
            .unwrap_or("")
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_owned();
        let line = v["exception"]["source_line"].to_string();
        out.push((name, format!("{file}:{line}")));
    }
    out.sort();
    out.dedup();
    out
}

/// Recursively find the generated harness `main.adb` under `work`.
fn find_main_adb(work: &Path) -> Option<String> {
    let mut stack = vec![work.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == "main.adb") {
                return fs::read_to_string(&path).ok();
            }
        }
    }
    None
}

#[test]
fn access_to_array_out_param_gets_real_sink_and_surfaces_overflow() {
    if which::which("gprbuild").is_err() && which::which("gnatmake").is_err() {
        eprintln!("skipping: no Ada compiler on PATH");
        return;
    }

    let root = temp_dir("output-sink");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("decoder.ads"),
        "--  SPDX-License-Identifier: Apache-2.0\n\
         with Ada.Streams; use Ada.Streams;\n\
         package Decoder is\n\
         \x20  type Output_Buffer is access Stream_Element_Array;\n\
         \x20  --  Write Count bytes into the caller-supplied buffer. A malicious\n\
         \x20  --  Count drives a write past the buffer end (planted OOB write).\n\
         \x20  procedure Decode (Dst : out Output_Buffer; Count : Natural);\n\
         end Decoder;\n",
    )
    .unwrap();
    fs::write(
        src.join("decoder.adb"),
        "--  SPDX-License-Identifier: Apache-2.0\n\
         package body Decoder is\n\
         \x20  procedure Decode (Dst : out Output_Buffer; Count : Natural) is\n\
         \x20  begin\n\
         \x20     for I in 0 .. Count - 1 loop\n\
         \x20        Dst (Stream_Element_Offset (I)) := Stream_Element (I mod 256);\n\
         \x20     end loop;\n\
         \x20  end Decode;\n\
         end Decoder;\n",
    )
    .unwrap();

    let work = root.join("govfuzz_work");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "auto",
            "--per-target-time",
            "4",
            "--target",
            "decode",
            src.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
        ]),
        0
    );

    // The generated harness allocates a REAL bounded backing buffer for the
    // access-to-array out parameter, not a null pointer.
    let main_adb = find_main_adb(&work).expect("a harness main.adb was generated");
    assert!(
        main_adb.contains("new Ada.Streams.Stream_Element_Array"),
        "expected a real heap sink for the access-to-array out param, got:\n{main_adb}"
    );
    assert!(
        !main_adb.contains("Dst : Decoder.Output_Buffer := null"),
        "the out buffer must not be a bare null pointer"
    );
    // ...and frees it after the loop so LeakSanitizer stays quiet.
    assert!(main_adb.contains("Gf_Free_Dst (Dst);"));

    let found = findings(&work);
    // The planted out-of-bounds write is surfaced (Ada index check or ASAN
    // heap-buffer-overflow, depending on the build's sanitizer config).
    assert!(
        found
            .iter()
            .any(|(name, _)| name.contains("CONSTRAINT_ERROR")
                || name.contains("HEAP_BUFFER_OVERFLOW")),
        "expected the planted OOB write to be found, got: {found:?}"
    );
    // The deliberate sink allocation must NOT show up as a leak.
    assert!(
        !found
            .iter()
            .any(|(name, _)| name.contains("LSAN") || name.contains("MEMORY_LEAK")),
        "the freed sink must not produce LeakSanitizer findings, got: {found:?}"
    );
}

#[test]
fn access_to_stream_out_param_gets_discard_stream_sink_and_builds() {
    if which::which("gprbuild").is_err() && which::which("gnatmake").is_err() {
        eprintln!("skipping: no Ada compiler on PATH");
        return;
    }

    let root = temp_dir("output-sink-stream");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // A serialize-to-stream API: the canonical access-to-Root_Stream_Type'Class
    // output. Without a sink the harness null-dereferences `Target.all`.
    fs::write(
        src.join("serializer.ads"),
        "--  SPDX-License-Identifier: Apache-2.0\n\
         with Ada.Streams; use Ada.Streams;\n\
         package Serializer is\n\
         \x20  type Stream_Ptr is access all Ada.Streams.Root_Stream_Type'Class;\n\
         \x20  procedure Emit (Target : Stream_Ptr; N : Natural);\n\
         end Serializer;\n",
    )
    .unwrap();
    fs::write(
        src.join("serializer.adb"),
        "--  SPDX-License-Identifier: Apache-2.0\n\
         package body Serializer is\n\
         \x20  procedure Emit (Target : Stream_Ptr; N : Natural) is\n\
         \x20     Chunk : Stream_Element_Array (1 .. 8) := (others => 0);\n\
         \x20  begin\n\
         \x20     for I in 1 .. N mod 64 loop\n\
         \x20        Ada.Streams.Write (Target.all, Chunk);\n\
         \x20     end loop;\n\
         \x20  end Emit;\n\
         end Serializer;\n",
    )
    .unwrap();

    let work = root.join("govfuzz_work");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "auto",
            "--per-target-time",
            "3",
            "--target",
            "emit",
            src.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
        ]),
        0
    );

    let main_adb = find_main_adb(&work).expect("a harness main.adb was generated");
    // Backed by the generated discard stream, not a null pointer.
    assert!(
        main_adb.contains("new Gf_Sink_Streams.Null_Stream"),
        "expected a discard-stream sink for the access-to-stream out param, got:\n{main_adb}"
    );
    assert!(!main_adb.contains("Target : Serializer.Stream_Ptr := null"));
    // The write-to-stream path executes against a real sink, so there is no
    // null-deref CONSTRAINT_ERROR artifact.
    let found = findings(&work);
    assert!(
        !found
            .iter()
            .any(|(name, loc)| name.contains("CONSTRAINT_ERROR") && loc.contains("serializer.adb")),
        "the discard stream must prevent a null-deref artifact, got: {found:?}"
    );
}

#[test]
fn unbounded_string_param_fuzzes_its_content() {
    if which::which("gprbuild").is_err() && which::which("gnatmake").is_err() {
        eprintln!("skipping: no Ada compiler on PATH");
        return;
    }

    let root = temp_dir("unbounded-param");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // An Unbounded_String input parameter must decode fuzz bytes (not the empty
    // Null_Unbounded_String), so a content-dependent fault is reachable. The
    // source uses a `use` clause, so the harness must also fully-qualify the decl.
    fs::write(
        src.join("cfg.ads"),
        "--  SPDX-License-Identifier: Apache-2.0\n\
         with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;\n\
         package Cfg is\n\
         \x20  procedure Parse (S : Unbounded_String);\n\
         end Cfg;\n",
    )
    .unwrap();
    fs::write(
        src.join("cfg.adb"),
        "--  SPDX-License-Identifier: Apache-2.0\n\
         with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;\n\
         package body Cfg is\n\
         \x20  procedure Parse (S : Unbounded_String) is\n\
         \x20     Tab : array (0 .. 3) of Integer := (others => 0);\n\
         \x20  begin\n\
         \x20     if Length (S) > 0 then\n\
         \x20        Tab (Character'Pos (Element (S, 1)) mod 16) := 1;\n\
         \x20     end if;\n\
         \x20  end Parse;\n\
         end Cfg;\n",
    )
    .unwrap();

    let work = root.join("govfuzz_work");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "auto",
            "--per-target-time",
            "4",
            "--target",
            "parse",
            src.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
        ]),
        0
    );

    let main_adb = find_main_adb(&work).expect("a harness main.adb was generated");
    // The parameter decodes fuzz bytes, fully qualified (no `use` in the harness).
    assert!(
        main_adb.contains("Ada.Strings.Unbounded.To_Unbounded_String"),
        "Unbounded_String param must decode fuzz bytes, got:\n{main_adb}"
    );
    assert!(!main_adb.contains("Null_Unbounded_String"));
    // The content-dependent fault is reachable only because the param fuzzes.
    let found = findings(&work);
    assert!(
        found
            .iter()
            .any(|(name, loc)| name.contains("CONSTRAINT_ERROR") && loc.contains("cfg.adb")),
        "the content-dependent fault must be found, proving the param fuzzes: {found:?}"
    );
}
