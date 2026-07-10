// SPDX-License-Identifier: Apache-2.0

//! Print the bug-oracle plugin inventory in a fixed-width table.

use finding_rules::oracle_manifest::ORACLE_MANIFEST;
use finding_rules::oracle_sdk::OracleManifestEntry;

pub fn render() -> String {
    render_entries(ORACLE_MANIFEST)
}

fn render_entries(entries: &[OracleManifestEntry]) -> String {
    let mut out = String::new();
    out.push_str("NAME                       RULE     CATEGORY      DANGEROUS_APIS\n");
    for entry in entries {
        out.push_str(&format!(
            "{:<27}{:<9}{:<14}{}\n",
            entry.name,
            entry.rule_id,
            entry.category.as_str(),
            entry.dangerous_apis.join(" "),
        ));
    }
    out
}

#[derive(Debug, clap::Args)]
pub struct ListOraclesArgs {}

pub fn run(_args: ListOraclesArgs) -> i32 {
    print!("{}", render());
    0
}

#[cfg(test)]
mod tests {
    use super::render;

    #[test]
    fn render_lists_path_traversal_ada() {
        let out = render();
        assert!(out.contains("path-traversal-ada"));
        assert!(out.contains("GF-101"));
        assert!(out.contains("logic-bug"));
        assert!(out.contains("Ada.Directories.Open"));
    }
}
