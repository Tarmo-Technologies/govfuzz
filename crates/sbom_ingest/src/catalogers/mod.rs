// SPDX-License-Identifier: Apache-2.0

//! Built-in catalogers. Phase 1 ships the Tier-A native-manifest catalogers;
//! later phases add Tier-B (Python, Go, …) and Tier-A deep extractors here.

pub mod ada_source;
pub mod alire;
pub mod c_source;
pub mod cargo;
pub mod cmake;
pub mod conan;
pub mod go;
pub mod gradle;
pub mod java_classpath;
pub mod maven;
pub mod meson;
pub mod native_manifest;
pub mod npm;
pub mod nuget;
pub mod perl;
pub mod php;
pub mod python;
pub mod ruby;
pub mod vcpkg;
