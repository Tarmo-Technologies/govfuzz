// SPDX-License-Identifier: Apache-2.0

//! `govfuzz rules` subcommand - inspect the rule catalog.
//!
//! The rule catalog drives finding identifiers (GF-NNNN), CWE / CERT-C /
//! CERT-C++ / MISRA / ISO TR 24772-2 mappings, default severity, and the
//! security-severity score SARIF carries through to GitHub Code Scanning.
//! Surfacing it via the CLI lets integrators discover which rule ids
//! govfuzz emits without grepping source.

use clap::{Args, Subcommand};
use finding_rules::{Rule, RULES};
use std::collections::BTreeSet;

#[derive(Debug, Args)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub command: RulesCommand,
}

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// Print every rule as a one-line table.
    List(ListArgs),
    /// Print the full rule definition (CWE, CERT, MISRA, references, ...).
    Show(ShowArgs),
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Emit one JSON document with every rule instead of human-readable
    /// columns. Useful for piping into jq / building dashboards.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// Rule identifier - either the numeric id (`GF-201`) or the slug
    /// (`govfuzz.c/heap-buffer-overflow`).
    pub rule: String,

    /// Emit the rule definition as JSON instead of formatted text.
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: RulesArgs) -> i32 {
    match args.command {
        RulesCommand::List(list_args) => list(list_args),
        RulesCommand::Show(show_args) => show(show_args),
    }
}

fn list(args: ListArgs) -> i32 {
    if args.json {
        match serde_json::to_string_pretty(RULES) {
            Ok(json) => {
                println!("{json}");
                0
            }
            Err(error) => {
                eprintln!("serialize rule catalog: {error}");
                1
            }
        }
    } else {
        println!(
            "{:<8}  {:<10}  {:<8}  {:<8}  SLUG",
            "ID", "CWE", "SEVERITY", "TOP25"
        );
        for rule in RULES {
            let top25 = rule
                .cwe_top_25
                .map(|n| format!("#{n}"))
                .unwrap_or_else(|| "-".to_owned());
            println!(
                "{:<8}  {:<10}  {:<8}  {:<8}  {}",
                rule.id,
                rule.cwe,
                rule.default_severity.as_str(),
                top25,
                rule.slug
            );
        }
        0
    }
}

fn show(args: ShowArgs) -> i32 {
    let rule = match finding_rules::by_id(&args.rule).or_else(|| finding_rules::by_slug(&args.rule))
    {
        Some(rule) => rule,
        None => {
            eprintln!(
                "rule '{}' not found. Try `govfuzz rules list` for known ids.",
                args.rule
            );
            return 2;
        }
    };

    if args.json {
        match serde_json::to_string_pretty(rule) {
            Ok(json) => {
                println!("{json}");
                0
            }
            Err(error) => {
                eprintln!("serialize rule: {error}");
                1
            }
        }
    } else {
        render_text(rule);
        0
    }
}

fn render_text(rule: &Rule) {
    println!("{} - {}", rule.id, rule.name);
    println!("  slug:              {}", rule.slug);
    println!("  cwe:               {}", rule.cwe);
    if let Some(rank) = rule.cwe_top_25 {
        println!("  cwe-top-25:        #{rank}");
    }
    println!(
        "  severity:          {} (security_severity {:.1})",
        rule.default_severity.as_str(),
        rule.security_severity
    );
    println!("  default-confidence: {}", rule.default_confidence.as_str());
    if let Some(owasp) = rule.owasp_top_10 {
        println!("  owasp-top-10:      {owasp}");
    }
    let mut tags: BTreeSet<&str> = BTreeSet::new();
    if let Some(c) = rule.cert_c {
        tags.insert(c);
    }
    if let Some(c) = rule.cert_cpp {
        tags.insert(c);
    }
    if let Some(c) = rule.misra_c {
        tags.insert(c);
    }
    if let Some(c) = rule.misra_cpp {
        tags.insert(c);
    }
    if !tags.is_empty() {
        let joined: Vec<&str> = tags.iter().copied().collect();
        println!("  standards:         {}", joined.join(", "));
    }
    if !rule.iso_tr_24772_ada.is_empty() {
        println!("  iso-tr-24772-ada:  {}", rule.iso_tr_24772_ada.join(", "));
    }
    println!();
    println!("  {}", rule.description);
    if !rule.references.is_empty() {
        println!();
        println!("  References:");
        for r in rule.references {
            println!("    - {r}");
        }
    }
}
