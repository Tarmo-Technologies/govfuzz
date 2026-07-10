// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExcludeCategory {
    Tests,
    Tools,
    Examples,
}

pub(crate) fn path_matches_exclusion(
    path: &Path,
    root: &Path,
    exclude_paths: &[String],
    exclude: &[ExcludeCategory],
) -> bool {
    let normalized = normalized_relative_path(path, root);
    if normalized.split('/').any(|component| {
        matches!(
            component,
            "generated_harnesses" | "harnesses" | "govfuzz_work" | "target" | ".git"
        )
    }) {
        return true;
    }
    exclude_paths
        .iter()
        .any(|pattern| !pattern.is_empty() && normalized.contains(&normalize_path_text(pattern)))
        || exclude
            .iter()
            .any(|category| category_matches_path(*category, &normalized))
}

fn normalized_relative_path(path: &Path, root: &Path) -> String {
    let base = if root.is_dir() {
        root
    } else {
        root.parent().unwrap_or_else(|| Path::new(""))
    };
    let relative = path.strip_prefix(base).unwrap_or(path);
    normalize_path_text(&relative.display().to_string())
}

fn normalize_path_text(value: &str) -> String {
    value.replace('\\', "/")
}

fn category_matches_path(category: ExcludeCategory, normalized_path: &str) -> bool {
    normalized_path.split('/').any(|component| match category {
        ExcludeCategory::Tests => matches!(component, "test" | "tests" | "regtests"),
        ExcludeCategory::Tools => component == "tools",
        ExcludeCategory::Examples => matches!(component, "example" | "examples"),
    })
}
