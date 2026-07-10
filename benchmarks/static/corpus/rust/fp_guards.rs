// SPDX-License-Identifier: Apache-2.0
// Campaign 2026-07-03 Rust guard: `clap::Command::new("cmd")` is an argument
// parser builder, NOT std::process — a literal `"cmd"` must not be flagged as a
// shell spawn.
fn build_cli() {
    let _ = clap::Command::new("cmd").arg(clap::Arg::new("verbose"));
    let _ = Command::new("myapp").subcommand(Command::new("run"));
}

fn spawn_shell(payload: &str) {
    // A real shell interpreter spawn stays flagged.
    let _ = std::process::Command::new("bash").arg("-c").arg(payload); // EXPECT GF-404
}
