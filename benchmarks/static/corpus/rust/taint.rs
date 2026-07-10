// SPDX-License-Identifier: Apache-2.0
// M23 Phase 2: interprocedural taint for Rust. A source-like parameter reaching
// a command sink (std::process::Command) is GF-304 (proven flow). These use
// Command::new(arg) WITHOUT a shell literal so only the taint engine fires (no
// GF-404 overlap), isolating GF-304.
fn run(user_input: &str) {
    std::process::Command::new(user_input); // EXPECT GF-304
}

fn dispatch(user_query: String) {
    forward(user_query);
}

fn forward(a: String) {
    std::process::Command::new(a); // EXPECT GF-304
}

fn clean(user_path: &str) {
    let v = sanitize(user_path);
    std::process::Command::new(v);
}

fn log_user(user_input: &str) {
    log::warn!("{}", user_input); // EXPECT GF-544
    log::info!("fixed");
}
