// SPDX-License-Identifier: Apache-2.0

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mcp = std::env::args_os().skip(1).any(|arg| arg == "--mcp");

    let result = if mcp {
        daemon::run_mcp(stdin.lock(), stdout.lock())
    } else {
        daemon::run_json_rpc(stdin.lock(), stdout.lock())
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
