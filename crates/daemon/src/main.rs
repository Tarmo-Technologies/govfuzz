// SPDX-License-Identifier: Apache-2.0

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();

    if let Err(error) = daemon::run_json_rpc(stdin.lock(), stdout.lock()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
