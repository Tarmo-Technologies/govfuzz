// SPDX-License-Identifier: Apache-2.0

pub const DIRECT_HARNESS_TEMPLATE: &str = include_str!("templates/direct_harness.adb.tera");
pub const SEQUENCE_HARNESS_TEMPLATE: &str = include_str!("templates/sequence_harness.adb.tera");
pub const SERVANT_DIRECT_HARNESS_TEMPLATE: &str =
    include_str!("templates/servant_direct_harness.adb.tera");
pub const GPR_TEMPLATE: &str = include_str!("templates/harness.gpr.tera");
pub const DIRECT_HARNESS_C_TEMPLATE: &str = include_str!("templates/direct_harness.c.tera");
pub const SEQUENCE_HARNESS_C_TEMPLATE: &str = include_str!("templates/sequence_harness.c.tera");
pub const HARNESS_MAKEFILE_TEMPLATE: &str = include_str!("templates/harness.makefile.tera");
pub const DIRECT_HARNESS_CPP_TEMPLATE: &str = include_str!("templates/direct_harness.cpp.tera");
pub const HARNESS_MAKEFILE_CPP_TEMPLATE: &str = include_str!("templates/harness.makefile.cpp.tera");

pub fn build_tera() -> Result<tera::Tera, tera::Error> {
    let mut tera = tera::Tera::default();
    tera.add_raw_template("direct_harness", DIRECT_HARNESS_TEMPLATE)?;
    tera.add_raw_template("sequence_harness", SEQUENCE_HARNESS_TEMPLATE)?;
    tera.add_raw_template("servant_direct_harness", SERVANT_DIRECT_HARNESS_TEMPLATE)?;
    tera.add_raw_template("harness_gpr", GPR_TEMPLATE)?;
    tera.add_raw_template("direct_harness_c", DIRECT_HARNESS_C_TEMPLATE)?;
    tera.add_raw_template("sequence_harness_c", SEQUENCE_HARNESS_C_TEMPLATE)?;
    tera.add_raw_template("harness_makefile", HARNESS_MAKEFILE_TEMPLATE)?;
    tera.add_raw_template("direct_harness_cpp", DIRECT_HARNESS_CPP_TEMPLATE)?;
    tera.add_raw_template("harness_makefile_cpp", HARNESS_MAKEFILE_CPP_TEMPLATE)?;
    Ok(tera)
}
