// SPDX-License-Identifier: Apache-2.0

//! Ada state-machine inference.
//!
//! Walks Ada source via tree-sitter and extracts a `StateMachine`
//! per `protected type` and `task type` declaration. Entries
//! become transition keys; barrier expressions become per-entry
//! guards. Used by stateful fuzzing (#302) to feed an AFLNet-style
//! state vector to the engine.
//!
//! Strategic note: Ada protected types and task types declare
//! state machines syntactically. No other mainstream fuzzer can
//! extract this without writing its own Ada front end. Govfuzz
//! already ships one — this is structural differentiation.

use serde::Serialize;
use tree_sitter::Node;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StateMachine {
    pub kind: MachineKind,
    pub name: String,
    pub states: Vec<State>,
    pub transitions: Vec<Transition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineKind {
    /// `protected type X is ... entry E ... end X;` — state
    /// transitions are entry calls gated by barriers.
    Protected,
    /// `task type X is entry E ... end X;` — state transitions are
    /// accept statements.
    Task,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct State {
    pub name: String,
    /// Which entries are currently open in this state. Empty means
    /// none are callable (likely a dead state).
    pub open_entries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Transition {
    pub from: String,
    pub entry: String,
    pub to: String,
    pub barrier: Option<EntryBarrier>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntryBarrier {
    /// Source text of the barrier expression (e.g. `Count > 0`).
    pub source: String,
}

#[derive(Debug, thiserror::Error)]
pub enum InferError {
    #[error("tree-sitter parser failed to set Ada language")]
    ParserSetup,
    #[error("tree-sitter parse returned no tree")]
    ParseFailed,
}

/// Parse the supplied Ada source and extract one `StateMachine`
/// per `protected type` / `task type` declaration. Returns an
/// empty vec when the source contains no such declarations.
pub fn infer_from_source(source: &str) -> Result<Vec<StateMachine>, InferError> {
    let tree = ada_parser::parse_with_tree_sitter(source).ok_or(InferError::ParseFailed)?;
    let root = tree.root_node();
    let mut machines = Vec::new();
    walk(root, source.as_bytes(), &mut machines);
    Ok(machines)
}

fn walk(node: Node<'_>, source: &[u8], out: &mut Vec<StateMachine>) {
    let kind = node.kind();
    let machine_kind = match kind {
        "protected_type_declaration" | "single_protected_declaration" => {
            Some(MachineKind::Protected)
        }
        "task_type_declaration" | "single_task_declaration" => Some(MachineKind::Task),
        _ => None,
    };
    if let Some(machine_kind) = machine_kind {
        if let Some(machine) = extract_machine(node, source, machine_kind) {
            out.push(machine);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, out);
    }
}

fn extract_machine(node: Node<'_>, source: &[u8], kind: MachineKind) -> Option<StateMachine> {
    let name = find_type_name(node, source)?;
    let mut entries: Vec<(String, Option<String>)> = Vec::new();
    collect_entries(node, source, &mut entries);
    if entries.is_empty() {
        return None;
    }
    let entry_names: Vec<String> = entries.iter().map(|(n, _)| n.clone()).collect();

    // v0.1 state model: a single state per entry (call it "ready"
    // initially, "after-<entry>" once the entry has fired). Real
    // state extraction would need data-flow analysis on the
    // barrier expressions — that's a v0.2 deliverable. For v0.1 we
    // emit:
    //   - one initial state "ready" with all unguarded entries open
    //   - one per-entry state "after-<entry>" reachable via that
    //     entry transition
    // Transitions go from "ready" -> "after-<entry>" via each
    // entry, with the barrier as the gate.
    let initial_open: Vec<String> = entries
        .iter()
        .filter(|(_, barrier)| barrier.is_none())
        .map(|(n, _)| n.clone())
        .collect();

    let mut states = vec![State {
        name: "ready".to_owned(),
        open_entries: initial_open,
    }];
    let mut transitions = Vec::new();
    for (entry_name, barrier) in &entries {
        let to = format!("after-{entry_name}");
        states.push(State {
            name: to.clone(),
            open_entries: entry_names.clone(),
        });
        transitions.push(Transition {
            from: "ready".to_owned(),
            entry: entry_name.clone(),
            to,
            barrier: barrier.as_ref().map(|src| EntryBarrier {
                source: src.clone(),
            }),
        });
    }

    Some(StateMachine {
        kind,
        name,
        states,
        transitions,
    })
}

fn find_type_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if matches!(child.kind(), "identifier" | "defining_identifier") {
            if let Ok(text) = child.utf8_text(source) {
                return Some(text.to_owned());
            }
        }
    }
    None
}

fn collect_entries(node: Node<'_>, source: &[u8], out: &mut Vec<(String, Option<String>)>) {
    let kind = node.kind();
    if matches!(kind, "entry_declaration" | "entry_body") {
        if let Some(entry) = extract_entry(node, source) {
            out.push(entry);
        }
        // Don't recurse into entry bodies — nested entries aren't
        // a thing in Ada.
        return;
    }
    let mut local_cursor = node.walk();
    for child in node.children(&mut local_cursor) {
        collect_entries(child, source, out);
    }
}

fn extract_entry(node: Node<'_>, source: &[u8]) -> Option<(String, Option<String>)> {
    let mut cursor = node.walk();
    let mut name: Option<String> = None;
    let mut barrier: Option<String> = None;
    for child in node.children(&mut cursor) {
        let child_kind = child.kind();
        if name.is_none() && matches!(child_kind, "identifier" | "defining_identifier") {
            if let Ok(text) = child.utf8_text(source) {
                name = Some(text.to_owned());
            }
        }
        // entry barrier in entry_body: `when <expr>`. tree-sitter-ada
        // exposes the condition under a child kind that varies; pick
        // it up if we find a `when` token followed by an expression.
        if child_kind == "entry_barrier" || child_kind == "barrier_condition" {
            if let Ok(text) = child.utf8_text(source) {
                let cleaned = text
                    .trim_start_matches("when")
                    .trim()
                    .trim_end_matches("is")
                    .trim()
                    .to_owned();
                if !cleaned.is_empty() {
                    barrier = Some(cleaned);
                }
            }
        }
    }
    // Fallback: scan the raw source text of the entry node for the
    // `when` keyword and grab everything up to `is`. This covers
    // grammar variants where the barrier isn't surfaced as a named
    // child node.
    if barrier.is_none() {
        if let Ok(full_text) = node.utf8_text(source) {
            if let Some(when_pos) = full_text.find(" when ") {
                let after_when = &full_text[when_pos + " when ".len()..];
                let end = after_when
                    .find(" is")
                    .or_else(|| after_when.find(';'))
                    .unwrap_or(after_when.len());
                let cleaned = after_when[..end].trim().to_owned();
                if !cleaned.is_empty() {
                    barrier = Some(cleaned);
                }
            }
        }
    }
    Some((name?, barrier))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machine_serializes_as_snake_case_kind() {
        let machine = StateMachine {
            kind: MachineKind::Protected,
            name: "Buffer".to_owned(),
            states: vec![State {
                name: "empty".to_owned(),
                open_entries: vec!["Push".to_owned()],
            }],
            transitions: vec![Transition {
                from: "empty".to_owned(),
                entry: "Push".to_owned(),
                to: "nonempty".to_owned(),
                barrier: Some(EntryBarrier {
                    source: "True".to_owned(),
                }),
            }],
        };
        let value = serde_json::to_value(&machine).unwrap();
        assert_eq!(value["kind"], "protected");
        assert_eq!(value["transitions"][0]["from"], "empty");
    }

    #[test]
    fn infer_extracts_protected_type_entries() {
        let source = r#"
package P is
   protected type Counter is
      entry Increment;
      entry Decrement;
   end Counter;
end P;
"#;
        let machines = infer_from_source(source).expect("parse ok");
        assert_eq!(machines.len(), 1, "got: {machines:#?}");
        let m = &machines[0];
        assert_eq!(m.kind, MachineKind::Protected);
        assert_eq!(m.name.to_lowercase(), "counter");
        let entry_names: Vec<&str> = m.transitions.iter().map(|t| t.entry.as_str()).collect();
        assert!(entry_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case("increment")));
        assert!(entry_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case("decrement")));
    }

    #[test]
    fn infer_extracts_task_type_entries() {
        let source = r#"
package P is
   task type Worker is
      entry Start;
      entry Stop;
   end Worker;
end P;
"#;
        let machines = infer_from_source(source).expect("parse ok");
        assert_eq!(machines.len(), 1, "got: {machines:#?}");
        let m = &machines[0];
        assert_eq!(m.kind, MachineKind::Task);
        let entry_names: Vec<&str> = m.transitions.iter().map(|t| t.entry.as_str()).collect();
        assert!(entry_names.iter().any(|n| n.eq_ignore_ascii_case("start")));
        assert!(entry_names.iter().any(|n| n.eq_ignore_ascii_case("stop")));
    }

    #[test]
    fn infer_returns_empty_when_no_protected_or_task_types() {
        let source = r#"
package P is
   procedure Hello;
end P;
"#;
        let machines = infer_from_source(source).expect("parse ok");
        assert!(machines.is_empty());
    }

    #[test]
    fn infer_handles_empty_source() {
        let machines = infer_from_source("").expect("parse ok");
        assert!(machines.is_empty());
    }

    #[test]
    fn infer_extracts_multiple_machines_in_one_unit() {
        let source = r#"
package P is
   protected type Gate is
      entry Lock;
      entry Unlock;
   end Gate;
   task type Worker is
      entry Start;
   end Worker;
end P;
"#;
        let machines = infer_from_source(source).expect("parse ok");
        assert_eq!(machines.len(), 2);
        let kinds: Vec<MachineKind> = machines.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&MachineKind::Protected));
        assert!(kinds.contains(&MachineKind::Task));
    }
}
