// SPDX-License-Identifier: Apache-2.0

use tree_sitter::Parser;
fn main() {
    let path = std::env::args().nth(1).expect("usage: dump <path>");
    let src = std::fs::read_to_string(&path).unwrap();
    let mut p = Parser::new();
    p.set_language(&tree_sitter_c::LANGUAGE.into()).unwrap();
    let tree = p.parse(&src, None).unwrap();
    dump(tree.root_node(), 0, src.as_bytes());
}
fn dump(n: tree_sitter::Node, indent: usize, src: &[u8]) {
    let text = n.utf8_text(src).unwrap_or("");
    let snip = if text.len() > 60 {
        format!("{}...", &text[..60])
    } else {
        text.to_owned()
    };
    println!(
        "{}{} [{}-{}] {:?}",
        " ".repeat(indent),
        n.kind(),
        n.start_byte(),
        n.end_byte(),
        snip
    );
    let mut c = n.walk();
    for ch in n.children(&mut c) {
        dump(ch, indent + 2, src);
    }
}
