// SPDX-License-Identifier: Apache-2.0
fn h() {
    std::process::Command::new("ls").arg("-l");         // safe: no shell
    let count = 5;                                       // not a secret
}
