// SPDX-License-Identifier: Apache-2.0
fn h(a: &str) {
    std::process::Command::new("sh").arg("-c").arg(a);  // EXPECT GF-404
    let secret = "topSecretValue99";                    // EXPECT GF-429
}
