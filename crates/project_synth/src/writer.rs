// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::AdaStandard;
use std::path::Path;

use crate::{ProjectSpec, ProjectSynthError};

pub fn render_project(spec: &ProjectSpec) -> Result<String, ProjectSynthError> {
    spec.validate()?;

    let mut out = String::new();
    out.push_str("--  SPDX-License-Identifier: Apache-2.0\n");
    for with_clause in &spec.with_clauses {
        out.push_str(&format!("with \"{}\";\n", with_clause.to_string_lossy()));
    }
    out.push('\n');
    out.push_str(&format!("project {} is\n\n", spec.project_name));

    // Distinct source-dir paths: a dir may appear under more than one language
    // (an Ada dependency tree that also ships C glue), but GPR wants each dir once.
    let mut seen_dirs = std::collections::BTreeSet::new();
    let dirs = spec
        .source_roots
        .iter()
        .map(|root| root.path.to_string_lossy().into_owned())
        .filter(|dir| seen_dirs.insert(dir.clone()))
        .map(|dir| format!("\"{dir}\""))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!("   for Source_Dirs use ({dirs});\n"));
    // Languages: Ada always; add C when the source dirs carry C glue a real Ada
    // library binds to (else the Ada link fails on the bound C symbols). Omitted
    // for pure-Ada trees so the project stays byte-for-byte the historical one.
    if spec.compile_c {
        out.push_str("   for Languages use (\"Ada\", \"C\");\n");
    }
    // Drop C sources that would collide on object-file name with a same-stem Ada
    // unit (`sxxx.adb` + `sxxx.c` -> `sxxx.o`), which gprbuild rejects outright.
    // Base names only, which is what `Excluded_Source_Files` wants.
    if !spec.excluded_source_files.is_empty() {
        let files = spec
            .excluded_source_files
            .iter()
            .map(|f| format!("\"{f}\""))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("   for Excluded_Source_Files use ({files});\n"));
    }
    out.push_str(&format!(
        "   for Object_Dir use \"{}\";\n",
        spec.object_dir.to_string_lossy()
    ));
    if let Some(main_adb) = &spec.main_adb {
        out.push_str(&format!("   for Main use (\"{main_adb}\");\n"));
    }
    if let Some(target) = &spec.target {
        out.push_str(&format!("   for Target use \"{target}\";\n"));
    }
    if let Some(runtime) = &spec.runtime {
        out.push_str(&format!("   for Runtime (\"Ada\") use \"{runtime}\";\n"));
    }
    if let Some(toolchain) = &spec.toolchain {
        out.push_str(&format!(
            "   for Toolchain_Name (\"Ada\") use \"{toolchain}\";\n"
        ));
    }

    out.push('\n');
    out.push_str("   package Compiler is\n");
    let switches = spec
        .switches
        .default
        .iter()
        .map(|switch| format!("\"{switch}\""))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!(
        "      for Default_Switches (\"Ada\") use ({switches}, \"{}\");\n",
        dialect_switch(spec.ada_standard)
    ));
    if spec.compile_c {
        // Glue C is third-party binding code — compile it for debug only, never
        // instrument it (coverage is for the Ada target, not the libc shims).
        out.push_str("      for Default_Switches (\"C\") use (\"-g\");\n");
    }
    out.push_str("   end Compiler;\n\n");
    if let (Some(main_adb), Some(exe)) = (&spec.main_adb, &spec.executable_name) {
        out.push_str("   package Builder is\n");
        out.push_str(&format!(
            "      for Executable (\"{main_adb}\") use \"{exe}\";\n"
        ));
        out.push_str("   end Builder;\n\n");
    }
    out.push_str(&format!("end {};\n", spec.project_name));

    Ok(out)
}

pub fn write_project(spec: &ProjectSpec, dest_path: &Path) -> Result<(), ProjectSynthError> {
    let rendered = render_project(spec)?;
    std::fs::write(dest_path, rendered)?;
    Ok(())
}

fn dialect_switch(standard: AdaStandard) -> &'static str {
    match standard {
        AdaStandard::Ada83 => "-gnat83",
        AdaStandard::Ada95 => "-gnat95",
        AdaStandard::Ada2005 => "-gnat05",
        AdaStandard::Ada2012 => "-gnat12",
        AdaStandard::Ada2022 => "-gnat2022",
    }
}
