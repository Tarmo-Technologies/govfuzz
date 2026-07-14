// SPDX-License-Identifier: Apache-2.0

//! Offline binary inventory for GovFuzz.

use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

pub const BINARY_SCHEMA_VERSION: &str = "govfuzz.binary.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryScanOptions {
    pub root: PathBuf,
    pub out_dir: PathBuf,
    pub max_bytes: Option<u64>,
    pub cve_db_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryScanSummary {
    pub json_path: PathBuf,
    pub files: usize,
    pub skipped: usize,
    pub containers: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryInventoryReport {
    pub schema_version: &'static str,
    pub root: String,
    pub counts: BinaryCounts,
    pub binaries: Vec<BinaryRecord>,
    pub skipped: Vec<SkippedBinary>,
    pub containers: Vec<ContainerRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct BinaryCounts {
    pub files: usize,
    pub skipped: usize,
    pub containers: usize,
    pub binaries_with_interesting_strings: usize,
    pub binaries_with_secrets: usize,
    pub binaries_with_cve_matches: usize,
    pub cve_matches: usize,
    pub by_format: BTreeMap<String, usize>,
    pub by_architecture: BTreeMap<String, usize>,
    pub by_skip_reason: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryRecord {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_name: Option<String>,
    pub format: String,
    pub architecture: String,
    pub bits: u16,
    pub endian: String,
    pub layout: BinaryLayout,
    pub bytes: u64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    /// Producer/toolchain provenance recovered from embedded strings (e.g. `GCC 13.3.0`,
    /// `clang 17.0.6`, `Go 1.23`, `rustc 1.79.0`); `None` when stripped/undeterminable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<String>,
    pub symbols_present: bool,
    pub debug_info_present: bool,
    pub symbol_status: String,
    pub debug_info_status: String,
    pub imports: BinaryImports,
    pub exports: BinaryExports,
    pub dependencies: BinaryDependencies,
    pub hardening: BinaryHardening,
    pub strings: BinaryStrings,
    pub secrets: Vec<BinarySecret>,
    pub entropy: BinaryEntropy,
    pub sbom: BinarySbom,
    pub cve_matches: Vec<BinaryCveMatch>,
    pub triage: BinaryTriage,
    pub analysis_plan: BinaryAnalysisPlan,
    pub evidence: BinaryEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryImports {
    pub status: String,
    pub markers: Vec<String>,
    pub symbols: Vec<String>,
    pub risky_apis: Vec<RiskyApi>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskyApi {
    pub name: String,
    pub category: String,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryExports {
    pub status: String,
    pub markers: Vec<String>,
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryDependencies {
    pub libraries: Vec<String>,
    pub interpreters: Vec<String>,
    pub rpaths: Vec<String>,
    /// ELF link mode: `static` (no `PT_INTERP` and no `DT_NEEDED` — self-contained,
    /// harder to hook/LD_PRELOAD), `dynamic`, `unknown` (program headers unparsed, e.g.
    /// 32-bit), or `not_applicable` (non-ELF).
    pub linking: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryLayout {
    pub entrypoint: Option<u64>,
    pub image_base: Option<u64>,
    pub program_header_count: Option<u32>,
    pub section_count: Option<u32>,
    pub load_command_count: Option<u32>,
    pub load_command_bytes: Option<u32>,
    pub sections: Vec<BinarySection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinarySection {
    pub name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryHardening {
    /// RELRO fidelity: `full` (RELRO segment + `BIND_NOW`, GOT read-only), `partial`
    /// (RELRO segment without `BIND_NOW`), `none`, or `not_applicable` (non-ELF).
    pub relro: String,
    pub stack_canary: String,
    pub pie: String,
    /// Non-executable stack / data (NX/DEP), cross-format: `present` (ELF PT_GNU_STACK
    /// without the exec bit, or PE `NX_COMPAT`), `disabled` (executable stack, or PE
    /// without `NX_COMPAT`), `not_detected` (undeterminable), or `not_applicable`.
    pub nx: String,
    /// `_FORTIFY_SOURCE`: `present` when fortified `*_chk` libc wrappers are linked in,
    /// `not_detected` for an ELF without them, `not_applicable` off ELF (glibc-only).
    pub fortify_source: String,
    /// Address-space layout randomization (PE `DYNAMIC_BASE`): `present`/`not_detected`
    /// for PE, `not_applicable` off PE (ELF ASLR is conveyed by the `pie` field).
    pub aslr: String,
    /// Control Flow Guard (PE `GUARD_CF`): `present`/`not_detected` for PE,
    /// `not_applicable` off PE.
    pub control_flow_guard: String,
    /// Code signing (Mach-O `LC_CODE_SIGNATURE`): `present`/`not_detected` for Mach-O,
    /// `not_applicable` off Mach-O. An unsigned macOS/iOS binary is a tampering signal.
    pub code_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryStrings {
    pub total: usize,
    pub interesting: Vec<String>,
}

/// A hardcoded credential recovered from the binary's embedded strings. Compiled
/// artifacts and firmware routinely bake in API keys / private keys that source-level
/// secret scanning never sees. The value is redacted (kind + a short masked preview).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinarySecret {
    pub kind: String,
    pub preview: String,
    /// CWE for the finding: `CWE-321` (hard-coded cryptographic key) for private keys,
    /// `CWE-798` (hard-coded credentials) for API tokens.
    pub cwe: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryEntropy {
    #[serde(rename = "shannon", serialize_with = "serialize_millibits_as_float")]
    pub shannon_millibits: u32,
    pub classification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinarySbom {
    pub components: Vec<BinaryComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryComponent {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryCveMatch {
    pub id: String,
    pub component: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    pub severity: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryTriage {
    pub dedup_key: String,
    pub priority: String,
    pub crash_replay: CrashReplayPlan,
    pub risk_factors: Vec<String>,
    pub recommended_campaigns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrashReplayPlan {
    pub stdin: bool,
    pub file: bool,
    pub network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryAnalysisPlan {
    pub symbolization: String,
    pub reverse_engineering_tools: Vec<ReverseEngineeringToolPlan>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReverseEngineeringToolPlan {
    pub tool: String,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryEvidence {
    pub markers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedBinary {
    pub path: String,
    pub reason: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerRecord {
    pub path: String,
    pub format: String,
    pub members: usize,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BinaryScanError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("JSON error")]
    Json(#[from] serde_json::Error),
    #[error("scan root is neither file nor directory: {}", path.display())]
    InvalidRoot { path: PathBuf },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CveDatabase {
    components: Vec<CveComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CveDatabaseFile {
    #[allow(dead_code)]
    schema_version: Option<String>,
    #[serde(default)]
    components: Vec<CveComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CveComponent {
    name: String,
    version: Option<String>,
    purl: Option<String>,
    #[serde(default)]
    match_strings: Vec<String>,
    #[serde(default)]
    cves: Vec<CveEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CveEntry {
    id: String,
    severity: String,
    summary: String,
}

fn load_cve_db(path: Option<&Path>) -> Result<CveDatabase, BinaryScanError> {
    let Some(path) = path else {
        return Ok(CveDatabase::default());
    };
    let file: CveDatabaseFile = serde_json::from_slice(&fs::read(path)?)?;
    Ok(CveDatabase {
        components: file.components,
    })
}

pub fn write_inventory(options: &BinaryScanOptions) -> Result<BinaryScanSummary, BinaryScanError> {
    let report = scan(options)?;
    fs::create_dir_all(&options.out_dir)?;
    let json_path = options.out_dir.join("binary-inventory.json");
    fs::write(&json_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(BinaryScanSummary {
        json_path,
        files: report.counts.files,
        skipped: report.counts.skipped,
        containers: report.counts.containers,
    })
}

pub fn scan(options: &BinaryScanOptions) -> Result<BinaryInventoryReport, BinaryScanError> {
    let cve_db = load_cve_db(options.cve_db_path.as_deref())?;
    let mut binaries = Vec::new();
    let mut skipped = Vec::new();
    let mut containers = Vec::new();

    for path in walk_files(&options.root)? {
        scan_disk_file(
            options,
            &path,
            &cve_db,
            &mut binaries,
            &mut skipped,
            &mut containers,
        )?;
    }

    binaries.sort_by(|left, right| left.path.cmp(&right.path));
    skipped.sort_by(|left, right| left.path.cmp(&right.path));
    containers.sort_by(|left, right| left.path.cmp(&right.path));
    let counts = counts(&binaries, &skipped, &containers);

    Ok(BinaryInventoryReport {
        schema_version: BINARY_SCHEMA_VERSION,
        root: path_string(&options.root),
        counts,
        binaries,
        skipped,
        containers,
    })
}

fn scan_disk_file(
    options: &BinaryScanOptions,
    path: &Path,
    cve_db: &CveDatabase,
    binaries: &mut Vec<BinaryRecord>,
    skipped: &mut Vec<SkippedBinary>,
    containers: &mut Vec<ContainerRecord>,
) -> Result<(), BinaryScanError> {
    let bytes_len = fs::metadata(path)?.len();
    let path_label = relative_path(&options.root, path);
    if size_exceeds(options.max_bytes, bytes_len) {
        skipped.push(skipped_binary(
            &path_label,
            "size_limit",
            "file exceeds configured maximum byte size",
            Some(bytes_len),
            None,
        ));
        return Ok(());
    }

    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::InvalidData => return Ok(()),
        Err(error) => return Err(error.into()),
    };

    scan_bytes(
        options, path, path_label, &bytes, None, None, cve_db, binaries, skipped, containers,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn scan_bytes(
    options: &BinaryScanOptions,
    physical_path: &Path,
    path_label: String,
    bytes: &[u8],
    container_path: Option<String>,
    member_name: Option<String>,
    cve_db: &CveDatabase,
    binaries: &mut Vec<BinaryRecord>,
    skipped: &mut Vec<SkippedBinary>,
    containers: &mut Vec<ContainerRecord>,
) {
    if container_path.is_none() && is_ar_archive(bytes) {
        match parse_ar_archive(bytes) {
            Ok(members) => {
                containers.push(ContainerRecord {
                    path: path_label.clone(),
                    format: "ar".to_owned(),
                    members: members.len(),
                    bytes: bytes.len() as u64,
                    sha256: sha256_hex(bytes),
                });
                for member in members {
                    let member_path = format!("{path_label}!{}", member.name);
                    if size_exceeds(options.max_bytes, member.data.len() as u64) {
                        skipped.push(skipped_binary(
                            &member_path,
                            "size_limit",
                            "archive member exceeds configured maximum byte size",
                            Some(member.data.len() as u64),
                            None,
                        ));
                        continue;
                    }
                    scan_bytes(
                        options,
                        physical_path,
                        member_path,
                        &member.data,
                        Some(path_label.clone()),
                        Some(member.name),
                        cve_db,
                        binaries,
                        skipped,
                        containers,
                    );
                }
            }
            Err(error) => skipped.push(skipped_binary(
                &path_label,
                "malformed_archive",
                &error,
                Some(bytes.len() as u64),
                Some(sha256_hex(bytes)),
            )),
        }
        return;
    }

    match identify(physical_path, bytes) {
        Identification::Binary(kind) => {
            let symbol_info = symbol_info(bytes);
            let layout = binary_layout(kind, bytes);
            let imports = binary_imports(kind, bytes, &symbol_info.markers);
            let exports = binary_exports(kind, bytes, &symbol_info.markers);
            let dependencies = binary_dependencies(kind, bytes);
            let hardening = binary_hardening(kind, bytes);
            let strings = binary_strings(bytes);
            let secrets = binary_secrets(bytes);
            let entropy = binary_entropy(bytes);
            let sbom = binary_sbom(&path_label, bytes, cve_db);
            let cve_matches = binary_cve_matches(&sbom, cve_db);
            let sha256 = sha256_hex(bytes);
            let build_id = binary_build_id(kind, bytes);
            let toolchain = binary_toolchain(bytes);
            let triage = binary_triage(
                kind,
                &sha256,
                &layout,
                &strings,
                &secrets,
                &cve_matches,
                &imports,
                &dependencies,
                &entropy,
                &hardening,
            );
            let analysis_plan = binary_analysis_plan(&symbol_info);
            let mut evidence_markers = symbol_info.markers.clone();
            if build_id.is_some() {
                evidence_markers.push(format!("{}:build_id", kind.format));
            }
            binaries.push(BinaryRecord {
                path: path_label,
                container_path,
                member_name,
                format: kind.format.to_owned(),
                architecture: kind.architecture.to_owned(),
                bits: kind.bits,
                endian: kind.endian.to_owned(),
                layout,
                bytes: bytes.len() as u64,
                sha256,
                build_id,
                toolchain,
                symbols_present: symbol_info.symbols_present,
                debug_info_present: symbol_info.debug_info_present,
                symbol_status: symbol_info.symbol_status,
                debug_info_status: symbol_info.debug_info_status,
                imports,
                exports,
                dependencies,
                hardening,
                strings,
                secrets,
                entropy,
                sbom,
                cve_matches,
                triage,
                analysis_plan,
                evidence: BinaryEvidence {
                    markers: evidence_markers,
                },
            });
        }
        Identification::Malformed(reason) => skipped.push(skipped_binary(
            &path_label,
            reason,
            "recognized binary header could not be parsed",
            Some(bytes.len() as u64),
            Some(sha256_hex(bytes)),
        )),
        Identification::NotBinary => {}
    }
}

fn identify(path: &Path, bytes: &[u8]) -> Identification {
    if bytes.starts_with(b"\x7fELF") {
        return match identify_elf(bytes) {
            Ok(kind) => Identification::Binary(kind),
            Err(reason) => Identification::Malformed(reason),
        };
    }
    if bytes.starts_with(b"MZ") {
        return match identify_pe(bytes) {
            Ok(kind) => Identification::Binary(kind),
            Err(reason) => Identification::Malformed(reason),
        };
    }
    if has_macho_magic(bytes) {
        return match identify_macho(bytes) {
            Ok(kind) => Identification::Binary(kind),
            Err(reason) => Identification::Malformed(reason),
        };
    }
    if firmware_extension(path) {
        return Identification::Binary(BinaryKind {
            format: "firmware_blob",
            architecture: "unknown",
            bits: 0,
            endian: "unknown",
        });
    }
    Identification::NotBinary
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Identification {
    Binary(BinaryKind),
    Malformed(&'static str),
    NotBinary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BinaryKind {
    format: &'static str,
    architecture: &'static str,
    bits: u16,
    endian: &'static str,
}

fn identify_elf(bytes: &[u8]) -> Result<BinaryKind, &'static str> {
    if bytes.len() < 20 || !bytes.starts_with(b"\x7fELF") {
        return Err("malformed_elf");
    }
    let bits = match bytes[4] {
        1 => 32,
        2 => 64,
        _ => 0,
    };
    let endian = match bytes[5] {
        1 => "little",
        2 => "big",
        _ => "unknown",
    };
    let machine = read_u16(bytes, 18, endian).ok_or("malformed_elf")?;
    Ok(BinaryKind {
        format: "elf",
        architecture: elf_machine(machine),
        bits,
        endian,
    })
}

fn identify_pe(bytes: &[u8]) -> Result<BinaryKind, &'static str> {
    if bytes.len() < 0x40 || !bytes.starts_with(b"MZ") {
        return Err("malformed_pe");
    }
    let pe_offset = u32::from_le_bytes(
        bytes
            .get(0x3c..0x40)
            .ok_or("malformed_pe")?
            .try_into()
            .map_err(|_| "malformed_pe")?,
    ) as usize;
    if bytes.get(pe_offset..pe_offset + 4).ok_or("malformed_pe")? != b"PE\0\0" {
        return Err("malformed_pe");
    }
    let machine = u16::from_le_bytes(
        bytes
            .get(pe_offset + 4..pe_offset + 6)
            .ok_or("malformed_pe")?
            .try_into()
            .map_err(|_| "malformed_pe")?,
    );
    let (architecture, bits) = pe_machine(machine);
    Ok(BinaryKind {
        format: "pe",
        architecture,
        bits,
        endian: "little",
    })
}

fn identify_macho(bytes: &[u8]) -> Result<BinaryKind, &'static str> {
    let le = u32::from_le_bytes(
        bytes
            .get(0..4)
            .ok_or("malformed_mach_o")?
            .try_into()
            .map_err(|_| "malformed_mach_o")?,
    );
    let be = u32::from_be_bytes(
        bytes
            .get(0..4)
            .ok_or("malformed_mach_o")?
            .try_into()
            .map_err(|_| "malformed_mach_o")?,
    );
    match le {
        0xfeedfacf => {
            let cputype = read_u32_le(bytes, 4).ok_or("malformed_mach_o")?;
            Ok(BinaryKind {
                format: "mach_o",
                architecture: macho_cpu(cputype),
                bits: 64,
                endian: "little",
            })
        }
        0xfeedface => {
            let cputype = read_u32_le(bytes, 4).ok_or("malformed_mach_o")?;
            Ok(BinaryKind {
                format: "mach_o",
                architecture: macho_cpu(cputype),
                bits: 32,
                endian: "little",
            })
        }
        _ => match be {
            0xfeedfacf => Ok(BinaryKind {
                format: "mach_o",
                architecture: "unknown",
                bits: 64,
                endian: "big",
            }),
            0xfeedface => Ok(BinaryKind {
                format: "mach_o",
                architecture: "unknown",
                bits: 32,
                endian: "big",
            }),
            _ => Err("malformed_mach_o"),
        },
    }
}

fn binary_layout(kind: BinaryKind, bytes: &[u8]) -> BinaryLayout {
    match kind.format {
        "elf" => elf_layout(kind, bytes),
        "pe" => pe_layout(bytes),
        "mach_o" => macho_layout(kind, bytes),
        _ => BinaryLayout {
            entrypoint: None,
            image_base: None,
            program_header_count: None,
            section_count: None,
            load_command_count: None,
            load_command_bytes: None,
            sections: Vec::new(),
        },
    }
}

fn elf_layout(kind: BinaryKind, bytes: &[u8]) -> BinaryLayout {
    let (entrypoint, program_header_count, section_count) = if kind.bits == 64 {
        (
            read_u64(bytes, 24, kind.endian),
            read_u16(bytes, 56, kind.endian).map(u32::from),
            read_u16(bytes, 60, kind.endian).map(u32::from),
        )
    } else {
        (
            read_u32(bytes, 24, kind.endian).map(u64::from),
            read_u16(bytes, 44, kind.endian).map(u32::from),
            read_u16(bytes, 48, kind.endian).map(u32::from),
        )
    };
    let mut sections = elf_sections(kind, bytes);
    sections.extend(elf_segments(kind, bytes));
    BinaryLayout {
        entrypoint,
        image_base: None,
        program_header_count,
        section_count,
        load_command_count: None,
        load_command_bytes: None,
        sections,
    }
}

fn pe_layout(bytes: &[u8]) -> BinaryLayout {
    let pe_offset = read_u32_le(bytes, 0x3c).map(|offset| offset as usize);
    let section_count = pe_offset
        .and_then(|offset| read_u16(bytes, offset + 6, "little"))
        .map(u32::from);
    let optional_header = pe_offset.map(|offset| offset + 24);
    let magic = optional_header.and_then(|offset| read_u16(bytes, offset, "little"));
    let entrypoint = optional_header
        .and_then(|offset| read_u32_le(bytes, offset + 16))
        .map(u64::from);
    let image_base = match (optional_header, magic) {
        (Some(offset), Some(0x20b)) => read_u64(bytes, offset + 24, "little"),
        (Some(offset), Some(0x10b)) => read_u32_le(bytes, offset + 28).map(u64::from),
        _ => None,
    };
    BinaryLayout {
        entrypoint,
        image_base,
        program_header_count: None,
        section_count,
        load_command_count: None,
        load_command_bytes: None,
        sections: pe_sections(bytes),
    }
}

fn macho_layout(kind: BinaryKind, bytes: &[u8]) -> BinaryLayout {
    BinaryLayout {
        entrypoint: None,
        image_base: None,
        program_header_count: None,
        section_count: None,
        load_command_count: read_u32(bytes, 16, kind.endian),
        load_command_bytes: read_u32(bytes, 20, kind.endian),
        sections: macho_sections(kind, bytes),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ElfSectionHeader {
    index: usize,
    name: String,
    section_type: u32,
    flags: u64,
    address: u64,
    file_offset: u64,
    size: u64,
    link: u32,
    info: u32,
    entsize: u64,
}

fn elf_sections(kind: BinaryKind, bytes: &[u8]) -> Vec<BinarySection> {
    elf_section_headers(kind, bytes)
        .into_iter()
        .map(|header| BinarySection {
            name: header.name,
            kind: "section".to_owned(),
            virtual_address: Some(header.address),
            file_offset: Some(header.file_offset),
            size: Some(header.size),
            flags: elf_section_flags(header.section_type, header.flags),
        })
        .collect()
}

fn elf_section_headers(kind: BinaryKind, bytes: &[u8]) -> Vec<ElfSectionHeader> {
    if kind.bits != 64 {
        return Vec::new();
    }
    let Some(section_header_offset) =
        read_u64(bytes, 40, kind.endian).map(|offset| offset as usize)
    else {
        return Vec::new();
    };
    let Some(section_entry_size) = read_u16(bytes, 58, kind.endian).map(usize::from) else {
        return Vec::new();
    };
    let Some(section_count) = read_u16(bytes, 60, kind.endian).map(usize::from) else {
        return Vec::new();
    };
    let Some(name_table_index) = read_u16(bytes, 62, kind.endian).map(usize::from) else {
        return Vec::new();
    };
    if section_entry_size < 64 || section_count == 0 || section_count > 512 {
        return Vec::new();
    }
    let Some(name_table_header_offset) =
        table_entry_offset(section_header_offset, name_table_index, section_entry_size)
    else {
        return Vec::new();
    };
    let Some(name_table_offset) =
        read_u64(bytes, name_table_header_offset + 24, kind.endian).map(|offset| offset as usize)
    else {
        return Vec::new();
    };
    let Some(name_table_size) =
        read_u64(bytes, name_table_header_offset + 32, kind.endian).map(|size| size as usize)
    else {
        return Vec::new();
    };
    let Some(name_table) = checked_slice(bytes, name_table_offset, name_table_size) else {
        return Vec::new();
    };

    let mut sections = Vec::new();
    for index in 0..section_count {
        let Some(offset) = table_entry_offset(section_header_offset, index, section_entry_size)
        else {
            continue;
        };
        let Some(header) = checked_slice(bytes, offset, section_entry_size) else {
            continue;
        };
        let name_offset = read_u32(header, 0, kind.endian).unwrap_or(0) as usize;
        let name = string_table_name(name_table, name_offset);
        if name.is_empty() {
            continue;
        }
        sections.push(ElfSectionHeader {
            index,
            name,
            section_type: read_u32(header, 4, kind.endian).unwrap_or(0),
            flags: read_u64(header, 8, kind.endian).unwrap_or(0),
            address: read_u64(header, 16, kind.endian).unwrap_or(0),
            file_offset: read_u64(header, 24, kind.endian).unwrap_or(0),
            size: read_u64(header, 32, kind.endian).unwrap_or(0),
            link: read_u32(header, 40, kind.endian).unwrap_or(0),
            info: read_u32(header, 44, kind.endian).unwrap_or(0),
            entsize: read_u64(header, 56, kind.endian).unwrap_or(0),
        });
    }
    sections
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ElfProgramHeader {
    index: usize,
    segment_type: u32,
    flags: u32,
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
}

fn elf_program_headers(kind: BinaryKind, bytes: &[u8]) -> Vec<ElfProgramHeader> {
    if kind.format != "elf" || kind.bits != 64 {
        return Vec::new();
    }
    let Some(program_header_offset) = read_u64(bytes, 32, kind.endian).and_then(usize_from_u64)
    else {
        return Vec::new();
    };
    let Some(program_header_entry_size) = read_u16(bytes, 54, kind.endian).map(usize::from) else {
        return Vec::new();
    };
    let Some(program_header_count) = read_u16(bytes, 56, kind.endian).map(usize::from) else {
        return Vec::new();
    };
    if program_header_entry_size < 56 || program_header_count == 0 || program_header_count > 256 {
        return Vec::new();
    }

    let mut headers = Vec::new();
    for index in 0..program_header_count {
        let Some(offset) =
            table_entry_offset(program_header_offset, index, program_header_entry_size)
        else {
            continue;
        };
        let Some(header) = checked_slice(bytes, offset, program_header_entry_size) else {
            continue;
        };
        let Some(segment_type) = read_u32(header, 0, kind.endian) else {
            continue;
        };
        headers.push(ElfProgramHeader {
            index,
            segment_type,
            flags: read_u32(header, 4, kind.endian).unwrap_or(0),
            file_offset: read_u64(header, 8, kind.endian).unwrap_or(0),
            virtual_address: read_u64(header, 16, kind.endian).unwrap_or(0),
            file_size: read_u64(header, 32, kind.endian).unwrap_or(0),
            memory_size: read_u64(header, 40, kind.endian).unwrap_or(0),
        });
    }
    headers
}

fn elf_segments(kind: BinaryKind, bytes: &[u8]) -> Vec<BinarySection> {
    let mut segments = Vec::new();
    for header in elf_program_headers(kind, bytes) {
        let name = elf_segment_name(header.segment_type, header.index);
        if name.is_empty() {
            continue;
        }
        segments.push(BinarySection {
            name,
            kind: "segment".to_owned(),
            virtual_address: Some(header.virtual_address),
            file_offset: Some(header.file_offset),
            size: Some(header.file_size),
            flags: elf_segment_flags(header.flags),
        });
    }
    segments
}

fn pe_sections(bytes: &[u8]) -> Vec<BinarySection> {
    pe_section_headers(bytes)
        .into_iter()
        .map(|header| BinarySection {
            name: header.name,
            kind: "section".to_owned(),
            virtual_address: Some(u64::from(header.virtual_address)),
            file_offset: Some(u64::from(header.raw_pointer)),
            size: Some(u64::from(header.raw_size)),
            flags: pe_section_flags(header.characteristics),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeSectionHeader {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
}

fn pe_section_headers(bytes: &[u8]) -> Vec<PeSectionHeader> {
    let Some(pe_offset) = read_u32_le(bytes, 0x3c).map(|offset| offset as usize) else {
        return Vec::new();
    };
    let Some(section_count) = read_u16(bytes, pe_offset + 6, "little").map(usize::from) else {
        return Vec::new();
    };
    let Some(optional_header_size) = read_u16(bytes, pe_offset + 20, "little").map(usize::from)
    else {
        return Vec::new();
    };
    if section_count == 0 || section_count > 128 {
        return Vec::new();
    }
    let section_table_offset = pe_offset + 24 + optional_header_size;
    let mut sections = Vec::new();
    for index in 0..section_count {
        let Some(offset) = table_entry_offset(section_table_offset, index, 40) else {
            continue;
        };
        let Some(header) = checked_slice(bytes, offset, 40) else {
            continue;
        };
        let name = fixed_name(&header[..8]);
        if name.is_empty() {
            continue;
        }
        let characteristics = read_u32(header, 36, "little").unwrap_or(0);
        sections.push(PeSectionHeader {
            name,
            virtual_size: read_u32(header, 8, "little").unwrap_or(0),
            virtual_address: read_u32(header, 12, "little").unwrap_or(0),
            raw_size: read_u32(header, 16, "little").unwrap_or(0),
            raw_pointer: read_u32(header, 20, "little").unwrap_or(0),
            characteristics,
        });
    }
    sections
}

fn macho_sections(kind: BinaryKind, bytes: &[u8]) -> Vec<BinarySection> {
    let Some(load_command_count) = read_u32(bytes, 16, kind.endian).map(usize::try_from) else {
        return Vec::new();
    };
    let Ok(load_command_count) = load_command_count else {
        return Vec::new();
    };
    let command_start = if kind.bits == 64 { 32 } else { 28 };
    let mut offset = command_start;
    let mut sections = Vec::new();
    for _ in 0..load_command_count.min(128) {
        let Some(command) = read_u32(bytes, offset, kind.endian) else {
            break;
        };
        let Some(command_size) = read_u32(bytes, offset + 4, kind.endian).map(|size| size as usize)
        else {
            break;
        };
        if command_size < 8 || checked_slice(bytes, offset, command_size).is_none() {
            break;
        }
        if command == 0x19 && command_size >= 72 {
            let name = fixed_name(bytes.get(offset + 8..offset + 24).unwrap_or_default());
            if !name.is_empty() {
                sections.push(BinarySection {
                    name,
                    kind: "segment".to_owned(),
                    virtual_address: read_u64(bytes, offset + 24, kind.endian),
                    file_offset: read_u64(bytes, offset + 40, kind.endian),
                    size: read_u64(bytes, offset + 48, kind.endian),
                    flags: Vec::new(),
                });
            }
        } else if command == 0x1 && command_size >= 56 {
            let name = fixed_name(bytes.get(offset + 8..offset + 24).unwrap_or_default());
            if !name.is_empty() {
                sections.push(BinarySection {
                    name,
                    kind: "segment".to_owned(),
                    virtual_address: read_u32(bytes, offset + 24, kind.endian).map(u64::from),
                    file_offset: read_u32(bytes, offset + 32, kind.endian).map(u64::from),
                    size: read_u32(bytes, offset + 36, kind.endian).map(u64::from),
                    flags: Vec::new(),
                });
            }
        }
        offset += command_size;
    }
    sections
}

fn table_entry_offset(base: usize, index: usize, entry_size: usize) -> Option<usize> {
    index.checked_mul(entry_size)?.checked_add(base)
}

fn checked_slice(bytes: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    let end = offset.checked_add(len)?;
    bytes.get(offset..end)
}

fn align4(value: usize) -> Option<usize> {
    Some(value.checked_add(3)? & !3)
}

fn string_table_name(table: &[u8], offset: usize) -> String {
    let Some(rest) = table.get(offset..) else {
        return String::new();
    };
    fixed_name(rest)
}

fn fixed_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).trim().to_owned()
}

fn elf_section_flags(section_type: u32, flags: u64) -> Vec<String> {
    let mut names = Vec::new();
    if flags & 0x1 != 0 {
        names.push("writable".to_owned());
    }
    if flags & 0x2 != 0 {
        names.push("allocated".to_owned());
    }
    if flags & 0x4 != 0 {
        names.push("executable".to_owned());
    }
    if section_type == 3 {
        names.push("string_table".to_owned());
    }
    if section_type == 8 {
        names.push("nobits".to_owned());
    }
    names
}

fn elf_segment_name(segment_type: u32, index: usize) -> String {
    let kind = match segment_type {
        1 => "PT_LOAD",
        2 => "PT_DYNAMIC",
        3 => "PT_INTERP",
        4 => "PT_NOTE",
        6 => "PT_PHDR",
        0x6474_e551 => "PT_GNU_STACK",
        0x6474_e552 => "PT_GNU_RELRO",
        _ => return String::new(),
    };
    format!("{kind}[{index}]")
}

fn elf_segment_flags(flags: u32) -> Vec<String> {
    let mut names = Vec::new();
    if flags & 0x4 != 0 {
        names.push("readable".to_owned());
    }
    if flags & 0x2 != 0 {
        names.push("writable".to_owned());
    }
    if flags & 0x1 != 0 {
        names.push("executable".to_owned());
    }
    names
}

fn pe_section_flags(characteristics: u32) -> Vec<String> {
    let mut names = Vec::new();
    if characteristics & 0x4000_0000 != 0 {
        names.push("readable".to_owned());
    }
    if characteristics & 0x8000_0000 != 0 {
        names.push("writable".to_owned());
    }
    if characteristics & 0x2000_0000 != 0 {
        names.push("executable".to_owned());
    }
    if characteristics & 0x0000_0040 != 0 {
        names.push("initialized_data".to_owned());
    }
    names
}

fn read_u16(bytes: &[u8], offset: usize, endian: &str) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
    Some(match endian {
        "little" => u16::from_le_bytes(raw),
        "big" => u16::from_be_bytes(raw),
        _ => u16::from_le_bytes(raw),
    })
}

fn read_u32(bytes: &[u8], offset: usize, endian: &str) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(match endian {
        "little" => u32::from_le_bytes(raw),
        "big" => u32::from_be_bytes(raw),
        _ => u32::from_le_bytes(raw),
    })
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize, endian: &str) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(match endian {
        "little" => u64::from_le_bytes(raw),
        "big" => u64::from_be_bytes(raw),
        _ => u64::from_le_bytes(raw),
    })
}

fn usize_from_u64(value: u64) -> Option<usize> {
    usize::try_from(value).ok()
}

fn usize_from_u32(value: u32) -> Option<usize> {
    usize::try_from(value).ok()
}

fn has_macho_magic(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let le = u32::from_le_bytes(bytes[0..4].try_into().expect("four bytes"));
    let be = u32::from_be_bytes(bytes[0..4].try_into().expect("four bytes"));
    matches!(le, 0xfeedfacf | 0xfeedface) || matches!(be, 0xfeedfacf | 0xfeedface)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SymbolInfo {
    symbols_present: bool,
    debug_info_present: bool,
    symbol_status: String,
    debug_info_status: String,
    markers: Vec<String>,
}

fn symbol_info(bytes: &[u8]) -> SymbolInfo {
    let marker_specs = [
        (".symtab", b".symtab".as_slice()),
        (".dynsym", b".dynsym".as_slice()),
        (".debug_info", b".debug_info".as_slice()),
        ("DWARF", b"DWARF".as_slice()),
        ("RSDS", b"RSDS".as_slice()),
        (".pdb", b".pdb".as_slice()),
        ("__debug", b"__debug".as_slice()),
        (".edata", b".edata".as_slice()),
        (".idata", b".idata".as_slice()),
    ];
    let markers = marker_specs
        .iter()
        .filter(|(_, marker)| contains_bytes(bytes, marker))
        .map(|(name, _)| (*name).to_owned())
        .collect::<Vec<_>>();
    let debug_info_present = markers.iter().any(|marker| {
        matches!(
            marker.as_str(),
            ".debug_info" | "DWARF" | "RSDS" | ".pdb" | "__debug"
        )
    });
    let symbols_present = debug_info_present
        || markers
            .iter()
            .any(|marker| matches!(marker.as_str(), ".symtab" | ".dynsym" | ".edata" | ".idata"));
    let symbol_status = if debug_info_present {
        "debug_info_rich"
    } else if symbols_present {
        "partially_symbolized"
    } else {
        "stripped"
    }
    .to_owned();
    let debug_info_status = if debug_info_present {
        "present"
    } else {
        "absent"
    }
    .to_owned();
    SymbolInfo {
        symbols_present,
        debug_info_present,
        symbol_status,
        debug_info_status,
        markers,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct BinarySymbolNames {
    imports: Vec<String>,
    exports: Vec<String>,
}

fn binary_imports(kind: BinaryKind, bytes: &[u8], markers: &[String]) -> BinaryImports {
    let mut import_markers = Vec::new();
    let symbol_names = binary_symbol_names(kind, bytes);
    let status = match kind.format {
        "elf" => {
            if !symbol_names.imports.is_empty()
                || markers.iter().any(|marker| marker == ".dynsym")
                || contains_bytes(bytes, b".rela.plt")
                || contains_bytes(bytes, b".plt")
            {
                if markers.iter().any(|marker| marker == ".dynsym") {
                    import_markers.push(".dynsym".to_owned());
                }
                if contains_bytes(bytes, b".rela.plt") {
                    import_markers.push(".rela.plt".to_owned());
                }
                "dynamic_imports_present"
            } else {
                "not_detected"
            }
        }
        "pe" => {
            if !symbol_names.imports.is_empty() || markers.iter().any(|marker| marker == ".idata") {
                if markers.iter().any(|marker| marker == ".idata") {
                    import_markers.push(".idata".to_owned());
                } else {
                    import_markers.push("import_directory".to_owned());
                }
                "import_table_present"
            } else {
                "not_detected"
            }
        }
        "mach_o" => {
            if !symbol_names.imports.is_empty()
                || contains_bytes(bytes, b"__la_symbol_ptr")
                || contains_bytes(bytes, b"__LINKEDIT")
            {
                if contains_bytes(bytes, b"__la_symbol_ptr") {
                    import_markers.push("__la_symbol_ptr".to_owned());
                }
                if contains_bytes(bytes, b"__LINKEDIT") {
                    import_markers.push("__LINKEDIT".to_owned());
                }
                if import_markers.is_empty() {
                    import_markers.push("LC_SYMTAB".to_owned());
                }
                "dynamic_imports_present"
            } else {
                "not_detected"
            }
        }
        _ => "not_applicable",
    };
    BinaryImports {
        status: status.to_owned(),
        markers: import_markers,
        symbols: symbol_names.imports,
        risky_apis: risky_apis(bytes),
    }
}

fn binary_exports(kind: BinaryKind, bytes: &[u8], markers: &[String]) -> BinaryExports {
    let mut export_markers = Vec::new();
    let symbol_names = binary_symbol_names(kind, bytes);
    let status = match kind.format {
        "elf" => {
            if !symbol_names.exports.is_empty()
                || markers
                    .iter()
                    .any(|marker| marker == ".dynsym" || marker == ".symtab")
            {
                export_markers.extend(
                    markers
                        .iter()
                        .filter(|marker| {
                            marker.as_str() == ".dynsym" || marker.as_str() == ".symtab"
                        })
                        .cloned(),
                );
                "symbol_table_present"
            } else {
                "not_detected"
            }
        }
        "pe" => {
            if !symbol_names.exports.is_empty() || markers.iter().any(|marker| marker == ".edata") {
                if markers.iter().any(|marker| marker == ".edata") {
                    export_markers.push(".edata".to_owned());
                } else {
                    export_markers.push("export_directory".to_owned());
                }
                "export_table_present"
            } else {
                "not_detected"
            }
        }
        "mach_o" => {
            if !symbol_names.exports.is_empty() || contains_bytes(bytes, b"__LINKEDIT") {
                if contains_bytes(bytes, b"__LINKEDIT") {
                    export_markers.push("__LINKEDIT".to_owned());
                    "linkedit_present"
                } else {
                    export_markers.push("LC_SYMTAB".to_owned());
                    "symbol_table_present"
                }
            } else {
                "not_detected"
            }
        }
        _ => "not_applicable",
    };
    BinaryExports {
        status: status.to_owned(),
        markers: export_markers,
        symbols: symbol_names.exports,
    }
}

fn binary_symbol_names(kind: BinaryKind, bytes: &[u8]) -> BinarySymbolNames {
    match kind.format {
        "elf" => elf_symbol_names(kind, bytes),
        "pe" => BinarySymbolNames {
            imports: pe_import_symbols(bytes),
            exports: pe_export_symbols(bytes),
        },
        "mach_o" => macho_symbol_names(kind, bytes),
        _ => BinarySymbolNames::default(),
    }
}

fn elf_symbol_names(kind: BinaryKind, bytes: &[u8]) -> BinarySymbolNames {
    let sections = elf_section_headers(kind, bytes);
    let mut names = BinarySymbolNames::default();
    for section in sections
        .iter()
        .filter(|section| matches!(section.section_type, 2 | 11))
    {
        let Some(strtab) = usize::try_from(section.link)
            .ok()
            .and_then(|index| sections.iter().find(|candidate| candidate.index == index))
        else {
            continue;
        };
        let Some(symbol_offset) = usize_from_u64(section.file_offset) else {
            continue;
        };
        let Some(symbol_size) = usize_from_u64(section.size) else {
            continue;
        };
        let entry_size = usize_from_u64(section.entsize)
            .filter(|size| *size >= 24)
            .unwrap_or(24);
        let Some(symbol_bytes) = checked_slice(bytes, symbol_offset, symbol_size) else {
            continue;
        };
        let Some(string_offset) = usize_from_u64(strtab.file_offset) else {
            continue;
        };
        let Some(string_size) = usize_from_u64(strtab.size) else {
            continue;
        };
        let Some(string_table) = checked_slice(bytes, string_offset, string_size) else {
            continue;
        };
        for index in 1..(symbol_bytes.len() / entry_size).min(4096) {
            let offset = index * entry_size;
            let name_offset = read_u32(symbol_bytes, offset, kind.endian).unwrap_or(0) as usize;
            if name_offset == 0 {
                continue;
            }
            let name = string_table_name(string_table, name_offset);
            if !is_binary_symbol_name(&name) {
                continue;
            }
            let section_index = read_u16(symbol_bytes, offset + 6, kind.endian).unwrap_or(0);
            if section_index == 0 {
                names.imports.push(name);
            } else {
                names.exports.push(name);
            }
        }
    }
    names.imports.sort();
    names.imports.dedup();
    names.exports.sort();
    names.exports.dedup();
    names
}

fn macho_symbol_names(kind: BinaryKind, bytes: &[u8]) -> BinarySymbolNames {
    let Some(load_command_count) = read_u32(bytes, 16, kind.endian).map(usize::try_from) else {
        return BinarySymbolNames::default();
    };
    let Ok(load_command_count) = load_command_count else {
        return BinarySymbolNames::default();
    };
    let command_start = if kind.bits == 64 { 32 } else { 28 };
    let symbol_entry_size = if kind.bits == 64 { 16 } else { 12 };
    let mut offset = command_start;
    let mut names = BinarySymbolNames::default();

    for _ in 0..load_command_count.min(128) {
        let Some(command) = read_u32(bytes, offset, kind.endian) else {
            break;
        };
        let Some(command_size) = read_u32(bytes, offset + 4, kind.endian).map(|size| size as usize)
        else {
            break;
        };
        let Some(command_bytes) = checked_slice(bytes, offset, command_size) else {
            break;
        };
        if command_size < 8 {
            break;
        }
        if command == 0x2 && command_size >= 24 {
            let symbol_offset = read_u32(command_bytes, 8, kind.endian)
                .and_then(usize_from_u32)
                .unwrap_or(0);
            let symbol_count = read_u32(command_bytes, 12, kind.endian)
                .and_then(usize_from_u32)
                .unwrap_or(0);
            let string_offset = read_u32(command_bytes, 16, kind.endian)
                .and_then(usize_from_u32)
                .unwrap_or(0);
            let string_size = read_u32(command_bytes, 20, kind.endian)
                .and_then(usize_from_u32)
                .unwrap_or(0);
            collect_macho_symtab_names(
                kind,
                bytes,
                symbol_offset,
                symbol_count,
                symbol_entry_size,
                string_offset,
                string_size,
                &mut names,
            );
        }
        offset += command_size;
    }

    names.imports.sort();
    names.imports.dedup();
    names.exports.sort();
    names.exports.dedup();
    names
}

#[allow(clippy::too_many_arguments)]
fn collect_macho_symtab_names(
    kind: BinaryKind,
    bytes: &[u8],
    symbol_offset: usize,
    symbol_count: usize,
    symbol_entry_size: usize,
    string_offset: usize,
    string_size: usize,
    names: &mut BinarySymbolNames,
) {
    let Some(symbol_size) = symbol_count.checked_mul(symbol_entry_size) else {
        return;
    };
    let Some(symbols) = checked_slice(bytes, symbol_offset, symbol_size) else {
        return;
    };
    let Some(string_table) = checked_slice(bytes, string_offset, string_size) else {
        return;
    };

    for index in 0..symbol_count.min(4096) {
        let Some(offset) = table_entry_offset(0, index, symbol_entry_size) else {
            break;
        };
        let Some(entry) = checked_slice(symbols, offset, symbol_entry_size) else {
            break;
        };
        let name_offset = read_u32(entry, 0, kind.endian)
            .and_then(usize_from_u32)
            .unwrap_or(0);
        if name_offset == 0 {
            continue;
        }
        let name = string_table_name(string_table, name_offset);
        if !is_binary_symbol_name(&name) {
            continue;
        }
        let symbol_type = entry.get(4).copied().unwrap_or(0);
        let type_kind = symbol_type & 0x0e;
        if type_kind == 0 {
            names.imports.push(name);
        } else if type_kind == 0x0e && symbol_type & 0x01 != 0 {
            names.exports.push(name);
        }
    }
}

fn is_binary_symbol_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '@' | '$' | '.' | '-'))
}

fn binary_dependencies(kind: BinaryKind, bytes: &[u8]) -> BinaryDependencies {
    let strings = ascii_strings(bytes, 4);
    let dynamic = elf_dynamic_dependencies(kind, bytes);
    let mut libraries = dynamic.libraries;
    if kind.format == "pe" {
        libraries.extend(pe_import_libraries(bytes));
    } else if kind.format == "mach_o" {
        libraries.extend(macho_dylib_libraries(kind, bytes));
    }
    let mut interpreters = elf_interpreters(kind, bytes);
    let mut rpaths = dynamic.rpaths;
    for value in strings {
        let trimmed = value.trim();
        let folded = trimmed.to_ascii_lowercase();
        if looks_like_dynamic_library(trimmed, &folded) {
            libraries.push(trimmed.to_owned());
        }
        if folded.contains("ld-linux") || folded.contains("ld-musl") || folded.contains("dyld") {
            interpreters.push(trimmed.to_owned());
        }
        if let Some(paths) = rpaths_from_string(trimmed, &folded) {
            rpaths.extend(paths);
        }
    }
    libraries.sort();
    libraries.dedup();
    interpreters.sort();
    interpreters.dedup();
    rpaths.sort();
    rpaths.dedup();
    BinaryDependencies {
        libraries,
        interpreters,
        rpaths,
        linking: elf_linking(kind, bytes),
    }
}

/// ELF link mode from the structured signals (not the string-scan): a `PT_INTERP`
/// segment or any `DT_NEEDED` entry means dynamically linked; neither means a
/// self-contained static binary. `unknown` when program headers can't be parsed.
fn elf_linking(kind: BinaryKind, bytes: &[u8]) -> String {
    if kind.format != "elf" {
        return "not_applicable".to_owned();
    }
    let headers = elf_program_headers(kind, bytes);
    if headers.is_empty() {
        return "unknown".to_owned();
    }
    if headers.iter().any(|header| header.segment_type == 3)
        || !elf_dynamic_dependencies(kind, bytes).libraries.is_empty()
    {
        "dynamic".to_owned()
    } else {
        "static".to_owned()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ElfDynamicDependencies {
    libraries: Vec<String>,
    rpaths: Vec<String>,
}

fn elf_dynamic_dependencies(kind: BinaryKind, bytes: &[u8]) -> ElfDynamicDependencies {
    let headers = elf_program_headers(kind, bytes);
    let mut dependencies = ElfDynamicDependencies::default();
    for dynamic_header in headers
        .iter()
        .filter(|header| header.segment_type == 2 && header.file_size >= 16)
    {
        let Some(dynamic_offset) = usize_from_u64(dynamic_header.file_offset) else {
            continue;
        };
        let Some(dynamic_size) = usize_from_u64(dynamic_header.file_size) else {
            continue;
        };
        let Some(dynamic_table) = checked_slice(bytes, dynamic_offset, dynamic_size) else {
            continue;
        };
        let mut string_table_virtual_address = None;
        let mut string_table_size = None;
        let mut needed_offsets = Vec::new();
        let mut rpath_offsets = Vec::new();
        for index in 0..(dynamic_table.len() / 16).min(4096) {
            let entry_offset = index * 16;
            let tag = read_u64(dynamic_table, entry_offset, kind.endian).unwrap_or(0);
            let value = read_u64(dynamic_table, entry_offset + 8, kind.endian).unwrap_or(0);
            match tag {
                0 => break,
                1 => needed_offsets.push(value),
                5 => string_table_virtual_address = Some(value),
                10 => string_table_size = Some(value),
                15 | 29 => rpath_offsets.push(value),
                _ => {}
            }
        }

        let Some(string_table_virtual_address) = string_table_virtual_address else {
            continue;
        };
        let Some(string_table_size) = string_table_size.and_then(usize_from_u64) else {
            continue;
        };
        let Some(string_table_offset) = elf_virtual_address_to_file_offset(
            &headers,
            string_table_virtual_address,
            string_table_size as u64,
        ) else {
            continue;
        };
        let Some(string_table) = checked_slice(bytes, string_table_offset, string_table_size)
        else {
            continue;
        };

        for offset in needed_offsets {
            let Some(offset) = usize_from_u64(offset) else {
                continue;
            };
            let library = string_table_name(string_table, offset);
            if !library.is_empty() {
                dependencies.libraries.push(library);
            }
        }
        for offset in rpath_offsets {
            let Some(offset) = usize_from_u64(offset) else {
                continue;
            };
            let value = string_table_name(string_table, offset);
            dependencies.rpaths.extend(split_rpath_entries(&value));
        }
    }
    dependencies
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeImportDirectory {
    sections: Vec<PeSectionHeader>,
    import_offset: usize,
    descriptor_limit: usize,
    thunk_size: usize,
    ordinal_flag: u64,
}

fn pe_import_directory(bytes: &[u8]) -> Option<PeImportDirectory> {
    let pe_offset = read_u32_le(bytes, 0x3c).and_then(usize_from_u32)?;
    let optional_header_size = read_u16(bytes, pe_offset + 20, "little").map(usize::from)?;
    let optional_header = pe_offset + 24;
    let magic = read_u16(bytes, optional_header, "little")?;
    checked_slice(bytes, optional_header, optional_header_size)?;
    let data_directory = match magic {
        0x10b => optional_header + 0x60,
        0x20b => optional_header + 0x70,
        _ => return None,
    };
    let import_directory_offset = data_directory.checked_add(8)?;
    let import_directory_end = import_directory_offset.checked_add(8)?;
    if import_directory_end > optional_header.saturating_add(optional_header_size)
        || checked_slice(bytes, import_directory_offset, 8).is_none()
    {
        return None;
    }
    let import_rva = read_u32(bytes, import_directory_offset, "little")?;
    let import_size = read_u32(bytes, import_directory_offset + 4, "little").unwrap_or(0);
    if import_rva == 0 {
        return None;
    }

    let sections = pe_section_headers(bytes);
    let import_offset = pe_rva_to_file_offset(&sections, import_rva, 20)?;
    let descriptor_limit = if import_size >= 20 {
        (import_size / 20).min(1024) as usize
    } else {
        1024
    };
    Some(PeImportDirectory {
        sections,
        import_offset,
        descriptor_limit,
        thunk_size: if magic == 0x20b { 8 } else { 4 },
        ordinal_flag: if magic == 0x20b {
            0x8000_0000_0000_0000
        } else {
            0x8000_0000
        },
    })
}

fn pe_import_libraries(bytes: &[u8]) -> Vec<String> {
    let Some(directory) = pe_import_directory(bytes) else {
        return Vec::new();
    };
    let mut libraries = Vec::new();
    for index in 0..directory.descriptor_limit {
        let Some(descriptor_offset) = table_entry_offset(directory.import_offset, index, 20) else {
            break;
        };
        let Some(descriptor) = checked_slice(bytes, descriptor_offset, 20) else {
            break;
        };
        if descriptor.iter().all(|byte| *byte == 0) {
            break;
        }
        let name_rva = read_u32(descriptor, 12, "little").unwrap_or(0);
        let Some(name_offset) = pe_rva_to_file_offset(&directory.sections, name_rva, 1) else {
            continue;
        };
        let name = fixed_name(bytes.get(name_offset..).unwrap_or_default());
        if !name.is_empty() {
            libraries.push(name);
        }
    }
    libraries
}

fn pe_import_symbols(bytes: &[u8]) -> Vec<String> {
    let Some(directory) = pe_import_directory(bytes) else {
        return Vec::new();
    };
    let mut symbols = Vec::new();
    for index in 0..directory.descriptor_limit {
        let Some(descriptor_offset) = table_entry_offset(directory.import_offset, index, 20) else {
            break;
        };
        let Some(descriptor) = checked_slice(bytes, descriptor_offset, 20) else {
            break;
        };
        if descriptor.iter().all(|byte| *byte == 0) {
            break;
        }
        let name_rva = read_u32(descriptor, 12, "little").unwrap_or(0);
        let Some(name_offset) = pe_rva_to_file_offset(&directory.sections, name_rva, 1) else {
            continue;
        };
        let library = fixed_name(bytes.get(name_offset..).unwrap_or_default());
        if library.is_empty() {
            continue;
        }
        let lookup_rva = read_u32(descriptor, 0, "little").unwrap_or(0);
        let first_thunk_rva = read_u32(descriptor, 16, "little").unwrap_or(0);
        let thunk_rva = if lookup_rva != 0 {
            lookup_rva
        } else {
            first_thunk_rva
        };
        if thunk_rva == 0 {
            continue;
        }
        let Some(thunk_offset) =
            pe_rva_to_file_offset(&directory.sections, thunk_rva, directory.thunk_size as u32)
        else {
            continue;
        };
        for thunk_index in 0..1024 {
            let Some(entry_offset) =
                table_entry_offset(thunk_offset, thunk_index, directory.thunk_size)
            else {
                break;
            };
            let Some(entry) = pe_import_thunk_value(bytes, entry_offset, directory.thunk_size)
            else {
                break;
            };
            if entry == 0 {
                break;
            }
            if entry & directory.ordinal_flag != 0 {
                continue;
            }
            let Ok(hint_name_rva) = u32::try_from(entry) else {
                continue;
            };
            let Some(hint_offset) = pe_rva_to_file_offset(&directory.sections, hint_name_rva, 2)
            else {
                continue;
            };
            let Some(symbol_offset) = hint_offset.checked_add(2) else {
                continue;
            };
            let symbol = fixed_name(bytes.get(symbol_offset..).unwrap_or_default());
            if is_binary_symbol_name(&symbol) {
                symbols.push(format!("{library}!{symbol}"));
            }
        }
    }
    symbols.sort();
    symbols.dedup();
    symbols
}

fn pe_export_symbols(bytes: &[u8]) -> Vec<String> {
    let Some((sections, export_offset)) = pe_export_directory(bytes) else {
        return Vec::new();
    };
    let Some(export_directory) = checked_slice(bytes, export_offset, 40) else {
        return Vec::new();
    };
    let name_count = read_u32(export_directory, 24, "little").unwrap_or(0);
    let name_table_rva = read_u32(export_directory, 32, "little").unwrap_or(0);
    if name_count == 0 || name_table_rva == 0 {
        return Vec::new();
    }

    let mut symbols = Vec::new();
    for index in 0..name_count.min(4096) {
        let Some(entry_rva) = index
            .checked_mul(4)
            .and_then(|delta| name_table_rva.checked_add(delta))
        else {
            break;
        };
        let Some(entry_offset) = pe_rva_to_file_offset(&sections, entry_rva, 4) else {
            continue;
        };
        let Some(name_rva) = read_u32(bytes, entry_offset, "little") else {
            continue;
        };
        let Some(name_offset) = pe_rva_to_file_offset(&sections, name_rva, 1) else {
            continue;
        };
        let name = fixed_name(bytes.get(name_offset..).unwrap_or_default());
        if is_binary_symbol_name(&name) {
            symbols.push(name);
        }
    }
    symbols.sort();
    symbols.dedup();
    symbols
}

fn pe_export_directory(bytes: &[u8]) -> Option<(Vec<PeSectionHeader>, usize)> {
    let pe_offset = read_u32_le(bytes, 0x3c).and_then(usize_from_u32)?;
    let optional_header_size = read_u16(bytes, pe_offset + 20, "little").map(usize::from)?;
    let optional_header = pe_offset + 24;
    let magic = read_u16(bytes, optional_header, "little")?;
    checked_slice(bytes, optional_header, optional_header_size)?;
    let data_directory = match magic {
        0x10b => optional_header + 0x60,
        0x20b => optional_header + 0x70,
        _ => return None,
    };
    let export_directory_end = data_directory.checked_add(8)?;
    if export_directory_end > optional_header.saturating_add(optional_header_size)
        || checked_slice(bytes, data_directory, 8).is_none()
    {
        return None;
    }
    let export_rva = read_u32(bytes, data_directory, "little")?;
    if export_rva == 0 {
        return None;
    }

    let sections = pe_section_headers(bytes);
    let export_offset = pe_rva_to_file_offset(&sections, export_rva, 40)?;
    Some((sections, export_offset))
}

fn pe_import_thunk_value(bytes: &[u8], offset: usize, size: usize) -> Option<u64> {
    match size {
        8 => read_u64(bytes, offset, "little"),
        4 => read_u32(bytes, offset, "little").map(u64::from),
        _ => None,
    }
}

fn pe_rva_to_file_offset(sections: &[PeSectionHeader], rva: u32, size: u32) -> Option<usize> {
    for section in sections {
        let Some(delta) = rva.checked_sub(section.virtual_address) else {
            continue;
        };
        let section_size = section.virtual_size.max(section.raw_size);
        let Some(end_delta) = delta.checked_add(size) else {
            continue;
        };
        if end_delta > section_size {
            continue;
        }
        let file_offset = section.raw_pointer.checked_add(delta)?;
        return usize_from_u32(file_offset);
    }
    None
}

fn macho_dylib_libraries(kind: BinaryKind, bytes: &[u8]) -> Vec<String> {
    let Some(load_command_count) = read_u32(bytes, 16, kind.endian).map(usize::try_from) else {
        return Vec::new();
    };
    let Ok(load_command_count) = load_command_count else {
        return Vec::new();
    };
    let command_start = if kind.bits == 64 { 32 } else { 28 };
    let mut offset = command_start;
    let mut libraries = Vec::new();
    for _ in 0..load_command_count.min(128) {
        let Some(command) = read_u32(bytes, offset, kind.endian) else {
            break;
        };
        let Some(command_size) = read_u32(bytes, offset + 4, kind.endian).map(|size| size as usize)
        else {
            break;
        };
        let Some(command_bytes) = checked_slice(bytes, offset, command_size) else {
            break;
        };
        if command_size < 8 {
            break;
        }
        if is_macho_dylib_command(command) && command_size >= 24 {
            let name_offset = read_u32(command_bytes, 8, kind.endian).unwrap_or(0) as usize;
            if name_offset < command_size {
                let name = fixed_name(&command_bytes[name_offset..]);
                if !name.is_empty() {
                    libraries.push(name);
                }
            }
        }
        offset += command_size;
    }
    libraries
}

fn is_macho_dylib_command(command: u32) -> bool {
    matches!(
        command,
        0x0c | 0x18 | 0x8000_0018 | 0x8000_001f | 0x20 | 0x8000_0023
    )
}

fn elf_virtual_address_to_file_offset(
    headers: &[ElfProgramHeader],
    address: u64,
    size: u64,
) -> Option<usize> {
    for header in headers.iter().filter(|header| header.segment_type == 1) {
        let segment_size = header.file_size.min(header.memory_size);
        let Some(delta) = address.checked_sub(header.virtual_address) else {
            continue;
        };
        let Some(end_delta) = delta.checked_add(size) else {
            continue;
        };
        if end_delta > segment_size {
            continue;
        }
        return header
            .file_offset
            .checked_add(delta)
            .and_then(usize_from_u64);
    }
    None
}

fn elf_interpreters(kind: BinaryKind, bytes: &[u8]) -> Vec<String> {
    let mut interpreters = Vec::new();
    for header in elf_program_headers(kind, bytes) {
        if header.segment_type != 3 {
            continue;
        }
        let Some(offset) = usize_from_u64(header.file_offset) else {
            continue;
        };
        let Some(size) = usize_from_u64(header.file_size) else {
            continue;
        };
        let Some(raw) = checked_slice(bytes, offset, size) else {
            continue;
        };
        let interpreter = fixed_name(raw);
        if !interpreter.is_empty() {
            interpreters.push(interpreter);
        }
    }
    interpreters
}

fn binary_build_id(kind: BinaryKind, bytes: &[u8]) -> Option<String> {
    match kind.format {
        "elf" => elf_build_id(kind, bytes),
        _ => None,
    }
}

fn elf_build_id(kind: BinaryKind, bytes: &[u8]) -> Option<String> {
    for header in elf_program_headers(kind, bytes)
        .into_iter()
        .filter(|header| header.segment_type == 4)
    {
        let Some(offset) = usize_from_u64(header.file_offset) else {
            continue;
        };
        let Some(size) = usize_from_u64(header.file_size) else {
            continue;
        };
        let Some(notes) = checked_slice(bytes, offset, size) else {
            continue;
        };
        if let Some(build_id) = elf_build_id_from_notes(kind, notes) {
            return Some(build_id);
        }
    }

    for section in elf_section_headers(kind, bytes)
        .into_iter()
        .filter(|section| section.section_type == 7)
    {
        let Some(offset) = usize_from_u64(section.file_offset) else {
            continue;
        };
        let Some(size) = usize_from_u64(section.size) else {
            continue;
        };
        let Some(notes) = checked_slice(bytes, offset, size) else {
            continue;
        };
        if let Some(build_id) = elf_build_id_from_notes(kind, notes) {
            return Some(build_id);
        }
    }
    None
}

fn elf_build_id_from_notes(kind: BinaryKind, notes: &[u8]) -> Option<String> {
    let mut offset = 0usize;
    let mut entries = 0usize;
    while entries < 128 {
        let Some(header) = checked_slice(notes, offset, 12) else {
            break;
        };
        let namesz = read_u32(header, 0, kind.endian).and_then(usize_from_u32)?;
        let descsz = read_u32(header, 4, kind.endian).and_then(usize_from_u32)?;
        let note_type = read_u32(header, 8, kind.endian)?;
        if namesz == 0 && descsz == 0 {
            break;
        }

        let name_start = offset.checked_add(12)?;
        let name_end = name_start.checked_add(namesz)?;
        let name = checked_slice(notes, name_start, namesz)?;
        let desc_start = align4(name_end)?;
        let desc_end = desc_start.checked_add(descsz)?;
        let description = checked_slice(notes, desc_start, descsz)?;

        let owner = name.strip_suffix(&[0]).unwrap_or(name);
        if note_type == 3 && owner == b"GNU" && !description.is_empty() {
            return Some(bytes_to_lower_hex(description));
        }

        let next = align4(desc_end)?;
        if next <= offset {
            break;
        }
        offset = next;
        entries += 1;
    }
    None
}

fn looks_like_dynamic_library(value: &str, folded: &str) -> bool {
    let candidate = value
        .rsplit('/')
        .next()
        .unwrap_or(value)
        .trim_matches(|ch: char| ch == '"' || ch == '\'');
    let folded_candidate = candidate.to_ascii_lowercase();
    (folded_candidate.contains(".so")
        || folded_candidate.ends_with(".dll")
        || folded_candidate.ends_with(".dylib"))
        && !folded.contains("runpath=")
        && !folded.contains("rpath=")
}

fn rpaths_from_string(value: &str, folded: &str) -> Option<Vec<String>> {
    let (_, paths) = if folded.starts_with("runpath=") || folded.starts_with("rpath=") {
        value.split_once('=')?
    } else {
        return None;
    };
    Some(split_rpath_entries(paths))
}

fn split_rpath_entries(paths: &str) -> Vec<String> {
    paths
        .split(':')
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect()
}

fn binary_hardening(kind: BinaryKind, bytes: &[u8]) -> BinaryHardening {
    let format = kind.format;
    // Stack cookies: glibc `__stack_chk_fail` and MSVC `/GS` `__security_cookie`.
    let stack_canary = if contains_bytes(bytes, b"__stack_chk_fail")
        || contains_bytes(bytes, b"__security_cookie")
    {
        "present"
    } else {
        "not_detected"
    };
    BinaryHardening {
        relro: elf_relro_status(kind, bytes),
        stack_canary: stack_canary.to_owned(),
        pie: pie_status(kind, bytes),
        nx: nx_status(kind, bytes),
        fortify_source: elf_fortify_status(format, bytes),
        aslr: pe_aslr_status(kind, bytes),
        control_flow_guard: pe_control_flow_guard_status(kind, bytes),
        code_signature: macho_code_signature_status(kind, bytes),
    }
}

/// Position-independent code: ELF `ET_DYN`, or Mach-O `MH_PIE`. On PE this is
/// `not_applicable` — a PE's ASLR posture is reported by the `aslr` field instead.
fn pie_status(kind: BinaryKind, bytes: &[u8]) -> String {
    match kind.format {
        "elf" => {
            if read_u16(bytes, 16, kind.endian) == Some(3) {
                "present".to_owned()
            } else {
                "not_detected".to_owned()
            }
        }
        "mach_o" => {
            if macho_header_flags(kind, bytes).is_some_and(|flags| flags & 0x0020_0000 != 0) {
                "present".to_owned()
            } else {
                "not_detected".to_owned()
            }
        }
        _ => "not_applicable".to_owned(),
    }
}

/// The Mach-O header `flags` word (offset 24 in both 32- and 64-bit headers).
fn macho_header_flags(kind: BinaryKind, bytes: &[u8]) -> Option<u32> {
    if kind.format != "mach_o" {
        return None;
    }
    read_u32(bytes, 24, kind.endian)
}

/// Code signing via the Mach-O `LC_CODE_SIGNATURE` (0x1d) load command;
/// `not_applicable` off Mach-O.
fn macho_code_signature_status(kind: BinaryKind, bytes: &[u8]) -> String {
    if kind.format != "mach_o" {
        return "not_applicable".to_owned();
    }
    if macho_has_load_command(kind, bytes, 0x1d) {
        "present".to_owned()
    } else {
        "not_detected".to_owned()
    }
}

/// Iterate the Mach-O load commands looking for `target_cmd`.
fn macho_has_load_command(kind: BinaryKind, bytes: &[u8], target_cmd: u32) -> bool {
    let Some(count) = read_u32(bytes, 16, kind.endian).and_then(|c| usize::try_from(c).ok()) else {
        return false;
    };
    let mut offset = if kind.bits == 64 { 32 } else { 28 };
    for _ in 0..count.min(128) {
        let Some(command) = read_u32(bytes, offset, kind.endian) else {
            break;
        };
        let Some(command_size) = read_u32(bytes, offset + 4, kind.endian).map(|s| s as usize)
        else {
            break;
        };
        if command_size < 8 || checked_slice(bytes, offset, command_size).is_none() {
            break;
        }
        if command == target_cmd {
            return true;
        }
        offset += command_size;
    }
    false
}

/// PE `DllCharacteristics` (the Windows exploit-mitigation bitfield). The field sits at
/// optional-header offset 0x46 for BOTH PE32 and PE32+ (their layouts converge before
/// it), i.e. `e_lfanew + 4 (PE sig) + 20 (COFF) + 0x46`.
fn pe_dll_characteristics(bytes: &[u8]) -> Option<u16> {
    let pe_offset = read_u32_le(bytes, 0x3c).and_then(usize_from_u32)?;
    if bytes.get(pe_offset..pe_offset + 4)? != b"PE\0\0" {
        return None;
    }
    let optional_header_size = read_u16(bytes, pe_offset + 20, "little")?;
    if usize::from(optional_header_size) < 0x48 {
        return None;
    }
    read_u16(bytes, pe_offset + 24 + 0x46, "little")
}

/// Non-executable stack/data, dispatched by format: ELF `PT_GNU_STACK`, PE `NX_COMPAT`.
fn nx_status(kind: BinaryKind, bytes: &[u8]) -> String {
    match kind.format {
        "elf" => elf_nx_status(kind, bytes),
        "pe" => match pe_dll_characteristics(bytes) {
            Some(flags) if flags & 0x0100 != 0 => "present".to_owned(),
            Some(_) => "disabled".to_owned(),
            None => "not_detected".to_owned(),
        },
        // MH_ALLOW_STACK_EXECUTION (0x20000) permits an executable stack.
        "mach_o" => match macho_header_flags(kind, bytes) {
            Some(flags) if flags & 0x0002_0000 != 0 => "disabled".to_owned(),
            Some(_) => "present".to_owned(),
            None => "not_detected".to_owned(),
        },
        _ => "not_applicable".to_owned(),
    }
}

/// ASLR via the PE `DYNAMIC_BASE` bit. Off PE this is `not_applicable` — an ELF's ASLR
/// posture is its PIE status, already reported in `pie`.
fn pe_aslr_status(kind: BinaryKind, bytes: &[u8]) -> String {
    if kind.format != "pe" {
        return "not_applicable".to_owned();
    }
    if pe_dll_characteristics(bytes).is_some_and(|flags| flags & 0x0040 != 0) {
        "present".to_owned()
    } else {
        "not_detected".to_owned()
    }
}

/// Control Flow Guard via the PE `GUARD_CF` bit; `not_applicable` off PE.
fn pe_control_flow_guard_status(kind: BinaryKind, bytes: &[u8]) -> String {
    if kind.format != "pe" {
        return "not_applicable".to_owned();
    }
    if pe_dll_characteristics(bytes).is_some_and(|flags| flags & 0x4000 != 0) {
        "present".to_owned()
    } else {
        "not_detected".to_owned()
    }
}

/// RELRO fidelity, as `checksec` reports it: `full` (a `PT_GNU_RELRO` segment AND
/// immediate binding, so the GOT is remapped read-only after relocation), `partial`
/// (RELRO segment without `BIND_NOW` — the GOT stays writable), `none` (no RELRO),
/// or `not_applicable` (non-ELF). Detection is segment-based (the numeric
/// `PT_GNU_RELRO` program header) — the literal string "GNU_RELRO" does not appear in
/// a real binary, so a byte-scan is a false negative on essentially every hardened ELF.
fn elf_relro_status(kind: BinaryKind, bytes: &[u8]) -> String {
    if kind.format != "elf" {
        return "not_applicable".to_owned();
    }
    let has_relro_segment = elf_program_headers(kind, bytes)
        .iter()
        .any(|header| header.segment_type == 0x6474_e552);
    // Byte-scan fallback keeps zero-program-header synthetic inputs classifiable.
    if !has_relro_segment && !contains_bytes(bytes, b"GNU_RELRO") {
        return "none".to_owned();
    }
    if elf_has_bind_now(kind, bytes) {
        "full".to_owned()
    } else {
        "partial".to_owned()
    }
}

/// Immediate binding (`BIND_NOW`): resolves every relocation at load time so the GOT can
/// be made read-only (the difference between Full and Partial RELRO). Signalled by
/// `DT_BIND_NOW`, `DT_FLAGS & DF_BIND_NOW`, or `DT_FLAGS_1 & DF_1_NOW` in the dynamic table.
fn elf_has_bind_now(kind: BinaryKind, bytes: &[u8]) -> bool {
    const DT_BIND_NOW: u64 = 24;
    const DT_FLAGS: u64 = 30;
    const DT_FLAGS_1: u64 = 0x6fff_fffb;
    const DF_BIND_NOW: u64 = 0x8;
    const DF_1_NOW: u64 = 0x1;
    for dynamic_header in elf_program_headers(kind, bytes)
        .iter()
        .filter(|header| header.segment_type == 2 && header.file_size >= 16)
    {
        let Some(offset) = usize_from_u64(dynamic_header.file_offset) else {
            continue;
        };
        let Some(size) = usize_from_u64(dynamic_header.file_size) else {
            continue;
        };
        let Some(table) = checked_slice(bytes, offset, size) else {
            continue;
        };
        for index in 0..(table.len() / 16).min(4096) {
            let entry_offset = index * 16;
            let tag = read_u64(table, entry_offset, kind.endian).unwrap_or(0);
            let value = read_u64(table, entry_offset + 8, kind.endian).unwrap_or(0);
            if tag == 0 {
                break;
            }
            if tag == DT_BIND_NOW
                || (tag == DT_FLAGS && value & DF_BIND_NOW != 0)
                || (tag == DT_FLAGS_1 && value & DF_1_NOW != 0)
            {
                return true;
            }
        }
    }
    false
}

/// Non-executable stack (NX/DEP). A modern ELF carries a `PT_GNU_STACK` program header
/// whose flags declare the stack's permissions: NX is enabled when that segment is
/// present WITHOUT the executable bit (`PF_X`, 0x1); an executable stack is a real
/// exploit-mitigation gap. Absent PT_GNU_STACK (or a form we do not parse, e.g. 32-bit)
/// → `not_detected`; non-ELF → `not_applicable`.
fn elf_nx_status(kind: BinaryKind, bytes: &[u8]) -> String {
    if kind.format != "elf" {
        return "not_applicable".to_owned();
    }
    match elf_program_headers(kind, bytes)
        .into_iter()
        .find(|header| header.segment_type == 0x6474_e551)
    {
        Some(header) if header.flags & 0x1 != 0 => "disabled".to_owned(),
        Some(_) => "present".to_owned(),
        None => "not_detected".to_owned(),
    }
}

/// `_FORTIFY_SOURCE`. glibc's fortified libc wrappers (`__printf_chk`, `__memcpy_chk`,
/// …) replace unbounded calls with bounds-checked `*_chk` variants; their presence in
/// the symbol table is the canonical `checksec` signal that FORTIFY was enabled. Note
/// `__stack_chk_fail` (the canary) is deliberately excluded — it is a different
/// mitigation. glibc-specific → `not_applicable` off ELF.
fn elf_fortify_status(format: &str, bytes: &[u8]) -> String {
    if format != "elf" {
        return "not_applicable".to_owned();
    }
    const FORTIFIED_SYMBOLS: &[&[u8]] = &[
        b"__printf_chk",
        b"__fprintf_chk",
        b"__sprintf_chk",
        b"__snprintf_chk",
        b"__vsnprintf_chk",
        b"__memcpy_chk",
        b"__memmove_chk",
        b"__memset_chk",
        b"__strcpy_chk",
        b"__strncpy_chk",
        b"__strcat_chk",
        b"__strncat_chk",
        b"__stpcpy_chk",
        b"__gets_chk",
        b"__fortify_fail",
    ];
    if FORTIFIED_SYMBOLS
        .iter()
        .any(|needle| contains_bytes(bytes, needle))
    {
        "present".to_owned()
    } else {
        "not_detected".to_owned()
    }
}

fn binary_strings(bytes: &[u8]) -> BinaryStrings {
    let all = ascii_strings(bytes, 4);
    let mut interesting = all
        .iter()
        .filter(|value| interesting_string(value))
        .take(32)
        .cloned()
        .collect::<Vec<_>>();
    interesting.sort();
    interesting.dedup();
    BinaryStrings {
        total: all.len(),
        interesting,
    }
}

/// Scan the embedded ASCII strings for hardcoded credentials — high-signal,
/// gitleaks-style prefix rules with charset/length validation (no regex dependency).
/// Previews are redacted so the inventory JSON is safe to share.
fn binary_secrets(bytes: &[u8]) -> Vec<BinarySecret> {
    let mut secrets = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for value in ascii_strings(bytes, 8) {
        for (kind, preview) in scan_secret_tokens(&value) {
            if seen.insert((kind, preview.clone())) {
                secrets.push(BinarySecret {
                    kind: kind.to_owned(),
                    preview,
                    cwe: secret_cwe(kind).to_owned(),
                });
            }
        }
        if secrets.len() >= 32 {
            break;
        }
    }
    secrets
}

/// A hard-coded cryptographic key is CWE-321; every other token type is CWE-798
/// (use of hard-coded credentials).
fn secret_cwe(kind: &str) -> &'static str {
    if kind == "private_key_pem" {
        "CWE-321"
    } else {
        "CWE-798"
    }
}

fn scan_secret_tokens(value: &str) -> Vec<(&'static str, String)> {
    let mut found = Vec::new();
    if value.contains("-----BEGIN") && value.contains("PRIVATE KEY") {
        found.push((
            "private_key_pem",
            "-----BEGIN … PRIVATE KEY-----".to_owned(),
        ));
    }
    for prefix in ["AKIA", "ASIA", "AGPA", "AIDA", "AROA"] {
        if let Some(token) = extract_secret(value, prefix, 16, is_upper_alnum) {
            found.push(("aws_access_key_id", redact_secret(&token)));
        }
    }
    for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        if let Some(token) = extract_secret(value, prefix, 36, is_ascii_alnum) {
            found.push(("github_token", redact_secret(&token)));
        }
    }
    if let Some(token) = extract_secret(value, "glpat-", 20, is_key_char) {
        found.push(("gitlab_token", redact_secret(&token)));
    }
    if let Some(token) = extract_secret(value, "AIza", 35, is_key_char) {
        found.push(("google_api_key", redact_secret(&token)));
    }
    if let Some(token) = extract_secret(value, "ya29.", 30, is_key_char) {
        found.push(("google_oauth_token", redact_secret(&token)));
    }
    for prefix in ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"] {
        if let Some(token) = extract_secret(value, prefix, 10, is_slack_char) {
            found.push(("slack_token", redact_secret(&token)));
        }
    }
    for prefix in ["sk_live_", "rk_live_"] {
        if let Some(token) = extract_secret(value, prefix, 24, is_ascii_alnum) {
            found.push(("stripe_secret_key", redact_secret(&token)));
        }
    }
    if let Some(token) = extract_secret(value, "npm_", 36, is_ascii_alnum) {
        found.push(("npm_token", redact_secret(&token)));
    }
    if let Some(token) = extract_secret(value, "pypi-", 40, is_key_char) {
        found.push(("pypi_token", redact_secret(&token)));
    }
    if let Some(token) = extract_secret(value, "SG.", 22, is_key_char) {
        found.push(("sendgrid_key", redact_secret(&token)));
    }
    if let Some(token) = extract_secret(value, "github_pat_", 40, is_key_char) {
        found.push(("github_fine_grained_pat", redact_secret(&token)));
    }
    if let Some(token) = extract_secret(value, "sk-ant-", 40, is_key_char) {
        found.push(("anthropic_api_key", redact_secret(&token)));
    }
    if let Some(token) = extract_secret(value, "sk-proj-", 40, is_key_char) {
        found.push(("openai_api_key", redact_secret(&token)));
    }
    if let Some(token) = extract_secret(value, "hf_", 34, is_ascii_alnum) {
        found.push(("huggingface_token", redact_secret(&token)));
    }
    found
}

/// Find `prefix` in `value` and consume the following run of `char_ok` bytes; a token is
/// returned only when that run is at least `min_len` long (the distinctive prefix plus a
/// plausible body keeps this high-signal).
fn extract_secret(
    value: &str,
    prefix: &str,
    min_len: usize,
    char_ok: fn(char) -> bool,
) -> Option<String> {
    let idx = value.find(prefix)?;
    let rest = &value[idx + prefix.len()..];
    let run: String = rest.chars().take_while(|c| char_ok(*c)).collect();
    (run.chars().count() >= min_len).then(|| format!("{prefix}{run}"))
}

fn redact_secret(token: &str) -> String {
    let head: String = token.chars().take(4).collect();
    format!("{head}***[{} chars]", token.chars().count())
}

fn is_upper_alnum(c: char) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit()
}

fn is_ascii_alnum(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

fn is_slack_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// Best-effort producer/toolchain provenance from embedded strings — the compiler/runtime
/// that built the binary (GCC/clang `.comment`, Go/Rust version stamps). Useful for triage:
/// an old compiler implies known miscompilations; an EOL Go/Rust runtime implies stdlib CVEs.
fn binary_toolchain(bytes: &[u8]) -> Option<String> {
    for value in ascii_strings(bytes, 4) {
        if let Some(version) = extract_go_version(&value) {
            return Some(format!("Go {version}"));
        }
        if let Some(rest) = value.strip_prefix("clang version ") {
            if let Some(version) = leading_version(rest) {
                return Some(format!("clang {version}"));
            }
        }
        if let Some(rest) = value.strip_prefix("GCC: ") {
            // e.g. "(Ubuntu 13.3.0-6ubuntu2) 13.3.0" — the trailing token is the version.
            if let Some(version) = rest.split_whitespace().last().and_then(leading_version) {
                return Some(format!("GCC {version}"));
            }
        }
        if let Some(rest) = value.strip_prefix("rustc ") {
            if let Some(version) = leading_version(rest) {
                return Some(format!("rustc {version}"));
            }
        }
    }
    None
}

/// The whitespace-delimited token at the front of `s`, but only when it looks like a
/// version (starts with a digit).
fn leading_version(s: &str) -> Option<String> {
    let token = s.split_whitespace().next()?;
    token
        .chars()
        .next()
        .filter(char::is_ascii_digit)
        .map(|_| token.to_owned())
}

/// A boundary-anchored Go version stamp (`go1.23`, `go1.21.5`) → `1.23` / `1.21.5`.
fn extract_go_version(value: &str) -> Option<String> {
    let raw = value.as_bytes();
    let mut from = 0;
    while let Some(rel) = value[from..].find("go1.") {
        let idx = from + rel;
        let at_boundary = idx == 0 || !raw[idx - 1].is_ascii_alphanumeric();
        if at_boundary {
            let version: String = value[idx + 2..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if version.starts_with("1.") && version.len() >= 4 {
                return Some(version);
            }
        }
        from = idx + 4;
    }
    None
}

fn binary_entropy(bytes: &[u8]) -> BinaryEntropy {
    if bytes.is_empty() {
        return BinaryEntropy {
            shannon_millibits: 0,
            classification: "low".to_owned(),
        };
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let len = bytes.len() as f64;
    let shannon = counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / len;
            -probability * probability.log2()
        })
        .sum::<f64>();
    let shannon_millibits = (shannon * 1000.0).round() as u32;
    let classification = if shannon_millibits >= 7500 {
        "high"
    } else if shannon_millibits >= 5000 {
        "medium"
    } else {
        "low"
    };
    BinaryEntropy {
        shannon_millibits,
        classification: classification.to_owned(),
    }
}

fn serialize_millibits_as_float<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_f64(*value as f64 / 1000.0)
}

fn binary_sbom(path_label: &str, bytes: &[u8], cve_db: &CveDatabase) -> BinarySbom {
    let mut components = Vec::new();
    let lower_path = path_label.to_ascii_lowercase();
    for component in &cve_db.components {
        let mut evidence = Vec::new();
        if lower_path.contains(&component.name.to_ascii_lowercase()) {
            evidence.push(format!("path:{path_label}"));
        }
        for marker in &component.match_strings {
            if contains_bytes(bytes, marker.as_bytes()) {
                evidence.push(format!("string:{marker}"));
            }
        }
        evidence.sort();
        evidence.dedup();
        if evidence.is_empty() {
            continue;
        }
        components.push(BinaryComponent {
            name: component.name.clone(),
            version: component.version.clone(),
            purl: component.purl.clone(),
            evidence,
        });
    }
    // Go static binaries embed their full module dependency tree (the `go version -m`
    // data). Extract it — otherwise these dependencies are invisible in a stripped binary.
    for (path, version) in go_buildinfo_modules(bytes) {
        if components.iter().any(|component| component.name == path) {
            continue;
        }
        let purl = format!("pkg:golang/{path}@{version}");
        components.push(BinaryComponent {
            name: path,
            version: Some(version),
            purl: Some(purl),
            evidence: vec!["go_buildinfo".to_owned()],
        });
    }
    BinarySbom { components }
}

/// Extract the Go module dependency list the linker embeds in a Go binary (the
/// `go version -m` data), for the inline buildinfo format (Go 1.18+). Returns
/// `(module_path, version)` for the main module (`mod`) and each dependency (`dep`).
fn go_buildinfo_modules(bytes: &[u8]) -> Vec<(String, String)> {
    const MAGIC: &[u8] = b"\xff Go buildinf:";
    let Some(magic_off) = bytes
        .windows(MAGIC.len())
        .position(|window| window == MAGIC)
    else {
        return Vec::new();
    };
    // header: magic (14) + ptrSize (1) + flags (1). The inline string format is flag 0x2.
    let Some(&flags) = bytes.get(magic_off + 15) else {
        return Vec::new();
    };
    if flags & 0x2 == 0 {
        // The older pointer-based format needs virtual-address resolution; skip it.
        return Vec::new();
    }
    // The version and modinfo strings are stored inline starting at magic + 32.
    let Some(after_header) = bytes.get(magic_off + 32..) else {
        return Vec::new();
    };
    let Some((_version, rest)) = decode_go_string(after_header) else {
        return Vec::new();
    };
    let Some((modinfo, _)) = decode_go_string(rest) else {
        return Vec::new();
    };
    // The linker frames modinfo with 16-byte sentinels; strip them (matching the check
    // `debug/buildinfo` uses: a newline just before the trailing sentinel).
    if modinfo.len() < 33 || modinfo[modinfo.len() - 17] != b'\n' {
        return Vec::new();
    }
    parse_go_modinfo(&modinfo[16..modinfo.len() - 16])
}

/// Decode a Go length-delimited string (uvarint length prefix + bytes); returns the
/// string bytes and the remaining slice after it.
fn decode_go_string(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, read) = uvarint(data)?;
    let len = usize::try_from(len).ok()?;
    let end = read.checked_add(len)?;
    let string = data.get(read..end)?;
    Some((string, &data[end..]))
}

/// Minimal unsigned LEB128 decoder; returns `(value, bytes_read)`.
fn uvarint(data: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (index, &byte) in data.iter().enumerate() {
        if index >= 10 {
            return None;
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((result, index + 1));
        }
        shift += 7;
    }
    None
}

fn parse_go_modinfo(modinfo: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(modinfo);
    let mut modules = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        // "mod\t<path>\t<version>\t<hash>" (main) or "dep\t<path>\t<version>[\t<hash>]".
        if (fields[0] == "mod" || fields[0] == "dep") && fields.len() >= 3 {
            let path = fields[1].trim();
            let version = fields[2].trim();
            if !path.is_empty() && !version.is_empty() {
                modules.push((path.to_owned(), version.to_owned()));
            }
        }
    }
    modules
}

fn binary_cve_matches(sbom: &BinarySbom, cve_db: &CveDatabase) -> Vec<BinaryCveMatch> {
    let mut matches = Vec::new();
    for component in &sbom.components {
        let Some(source) = cve_db.components.iter().find(|candidate| {
            candidate.name == component.name && candidate.version == component.version
        }) else {
            continue;
        };
        for cve in &source.cves {
            matches.push(BinaryCveMatch {
                id: cve.id.clone(),
                component: component.name.clone(),
                version: component.version.clone(),
                purl: component.purl.clone(),
                severity: cve.severity.clone(),
                summary: cve.summary.clone(),
            });
        }
    }
    matches.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.component.cmp(&right.component))
    });
    matches
}

fn risky_apis(bytes: &[u8]) -> Vec<RiskyApi> {
    let strings = ascii_strings(bytes, 4);
    let specs = [
        ("system", "command_execution", "high"),
        ("popen", "command_execution", "high"),
        ("execve", "command_execution", "high"),
        ("execl", "command_execution", "high"),
        ("execvp", "command_execution", "high"),
        ("WinExec", "command_execution", "high"),
        ("CreateProcessA", "command_execution", "high"),
        ("CreateProcessW", "command_execution", "high"),
        ("strcpy", "memory_unsafe", "high"),
        ("strcat", "memory_unsafe", "high"),
        ("gets", "memory_unsafe", "high"),
        ("sprintf", "memory_unsafe", "high"),
        ("vsprintf", "memory_unsafe", "high"),
        ("memcpy", "memory_unsafe", "medium"),
        ("CreateFileA", "filesystem", "medium"),
        ("CreateFileW", "filesystem", "medium"),
        ("fopen", "filesystem", "medium"),
        ("socket", "network", "medium"),
        ("connect", "network", "medium"),
        ("recv", "network", "medium"),
        ("send", "network", "medium"),
        ("InternetOpenA", "network", "medium"),
        ("InternetOpenW", "network", "medium"),
    ];
    let mut apis = Vec::new();
    for (name, category, severity) in specs {
        let folded_name = name.to_ascii_lowercase();
        if !strings
            .iter()
            .any(|value| token_in_ascii_string(&value.to_ascii_lowercase(), &folded_name))
        {
            continue;
        }
        apis.push(RiskyApi {
            name: name.to_owned(),
            category: category.to_owned(),
            severity: severity.to_owned(),
        });
    }
    apis.sort_by(|left, right| left.name.cmp(&right.name));
    apis.dedup_by(|left, right| left.name == right.name);
    apis
}

fn binary_risk_factors(
    kind: BinaryKind,
    layout: &BinaryLayout,
    imports: &BinaryImports,
    dependencies: &BinaryDependencies,
    entropy: &BinaryEntropy,
    hardening: &BinaryHardening,
    secrets: &[BinarySecret],
) -> Vec<String> {
    let mut factors = imports
        .risky_apis
        .iter()
        .map(|api| format!("risky_import:{}", api.name))
        .collect::<Vec<_>>();
    for secret in secrets {
        factors.push(format!("embedded_secret:{}", secret.kind));
    }
    factors.extend(loader_path_risk_factors(dependencies));
    factors.extend(section_layout_risk_factors(layout));
    if entropy.classification == "high" {
        factors.push("binary_entropy:high".to_owned());
    }
    if kind.format == "elf" {
        if hardening.relro == "none" {
            factors.push("hardening:relro_missing".to_owned());
        } else if hardening.relro == "partial" {
            factors.push("hardening:relro_partial".to_owned());
        }
        if hardening.stack_canary == "not_detected" {
            factors.push("hardening:stack_canary_missing".to_owned());
        }
        if hardening.pie == "not_detected" {
            factors.push("hardening:pie_missing".to_owned());
        }
        if hardening.nx == "disabled" {
            factors.push("hardening:nx_disabled".to_owned());
        }
        if hardening.fortify_source == "not_detected" {
            factors.push("hardening:fortify_source_missing".to_owned());
        }
    }
    if kind.format == "pe" {
        if hardening.nx == "disabled" {
            factors.push("hardening:nx_disabled".to_owned());
        }
        if hardening.aslr == "not_detected" {
            factors.push("hardening:aslr_missing".to_owned());
        }
        if hardening.control_flow_guard == "not_detected" {
            factors.push("hardening:control_flow_guard_missing".to_owned());
        }
    }
    if kind.format == "mach_o" {
        if hardening.pie == "not_detected" {
            factors.push("hardening:pie_missing".to_owned());
        }
        if hardening.nx == "disabled" {
            factors.push("hardening:nx_disabled".to_owned());
        }
        if hardening.code_signature == "not_detected" {
            factors.push("hardening:code_signature_missing".to_owned());
        }
    }
    factors
}

fn section_layout_risk_factors(layout: &BinaryLayout) -> Vec<String> {
    let mut factors = Vec::new();
    for section in &layout.sections {
        let folded = section.name.to_ascii_lowercase();
        if folded.starts_with("upx") {
            factors.push("section:upx".to_owned());
        }
        if folded.contains("packed") {
            factors.push("section:packed".to_owned());
        }
        if section.flags.iter().any(|flag| flag == "executable")
            && section.flags.iter().any(|flag| flag == "writable")
        {
            factors.push(format!("{}:executable_writable", section.kind));
        }
    }
    factors.sort();
    factors.dedup();
    factors
}

fn loader_path_risk_factors(dependencies: &BinaryDependencies) -> Vec<String> {
    let mut factors = Vec::new();
    for path in &dependencies.rpaths {
        if is_writable_loader_path(path) {
            factors.push(format!("loader_path:writable_rpath:{path}"));
        } else if is_relative_loader_path(path) {
            factors.push(format!("loader_path:relative_rpath:{path}"));
        }
    }
    factors
}

fn is_writable_loader_path(path: &str) -> bool {
    let folded = path.to_ascii_lowercase();
    folded == "/tmp"
        || folded.starts_with("/tmp/")
        || folded == "/var/tmp"
        || folded.starts_with("/var/tmp/")
        || folded == "/dev/shm"
        || folded.starts_with("/dev/shm/")
}

fn is_relative_loader_path(path: &str) -> bool {
    let trimmed = path.trim();
    trimmed == "."
        || trimmed == ".."
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || (!trimmed.starts_with('/') && !trimmed.starts_with('$'))
}

fn token_in_ascii_string(text: &str, token: &str) -> bool {
    text.match_indices(token).any(|(index, _)| {
        let before = text[..index].chars().next_back();
        let after = text[index + token.len()..].chars().next();
        !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    })
}

#[allow(clippy::too_many_arguments)]
fn binary_triage(
    kind: BinaryKind,
    sha256: &str,
    layout: &BinaryLayout,
    strings: &BinaryStrings,
    secrets: &[BinarySecret],
    cve_matches: &[BinaryCveMatch],
    imports: &BinaryImports,
    dependencies: &BinaryDependencies,
    entropy: &BinaryEntropy,
    hardening: &BinaryHardening,
) -> BinaryTriage {
    let has_network_import = imports
        .risky_apis
        .iter()
        .any(|api| api.category == "network");
    let replay = CrashReplayPlan {
        stdin: true,
        file: kind.format != "firmware_blob",
        network: has_network_import
            || strings.interesting.iter().any(|value| {
                let folded = value.to_ascii_lowercase();
                folded.contains("socket")
                    || folded.contains("http://")
                    || folded.contains("https://")
            }),
    };
    let high_risky_import = imports.risky_apis.iter().any(|api| api.severity == "high");
    let medium_risky_import = imports
        .risky_apis
        .iter()
        .any(|api| api.severity == "medium");
    let loader_path_risk = dependencies
        .rpaths
        .iter()
        .any(|path| is_writable_loader_path(path) || is_relative_loader_path(path));
    let high_entropy = entropy.classification == "high";
    let section_layout_risks = section_layout_risk_factors(layout);
    let packed_section_risk = section_layout_risks
        .iter()
        .any(|risk| risk == "section:upx" || risk == "section:packed");
    let section_layout_risk = !section_layout_risks.is_empty();
    let priority = if high_risky_import
        || !secrets.is_empty()
        || cve_matches
            .iter()
            .any(|cve| matches!(cve.severity.as_str(), "critical" | "high"))
    {
        "high"
    } else if medium_risky_import
        || loader_path_risk
        || high_entropy
        || section_layout_risk
        || !strings.interesting.is_empty()
    {
        "medium"
    } else {
        "normal"
    };
    let mut risk_factors = binary_risk_factors(
        kind,
        layout,
        imports,
        dependencies,
        entropy,
        hardening,
        secrets,
    );
    let mut recommended_campaigns = vec!["binary-fuzz".to_owned()];
    if replay.file {
        recommended_campaigns.push("file-replay".to_owned());
    }
    if imports
        .risky_apis
        .iter()
        .any(|api| api.category == "command_execution")
    {
        recommended_campaigns.push("command-injection-review".to_owned());
    }
    if imports
        .risky_apis
        .iter()
        .any(|api| api.category == "memory_unsafe")
    {
        recommended_campaigns.push("memory-corruption-review".to_owned());
    }
    if replay.network {
        recommended_campaigns.push("network-model-review".to_owned());
    }
    if loader_path_risk {
        recommended_campaigns.push("loader-path-review".to_owned());
    }
    if high_entropy || packed_section_risk {
        recommended_campaigns.push("packed-binary-review".to_owned());
    }
    if section_layout_risk {
        recommended_campaigns.push("binary-layout-review".to_owned());
    }
    risk_factors.sort();
    risk_factors.dedup();
    recommended_campaigns.sort();
    recommended_campaigns.dedup();
    BinaryTriage {
        dedup_key: binary_dedup_key(kind, sha256),
        priority: priority.to_owned(),
        crash_replay: replay,
        risk_factors,
        recommended_campaigns,
    }
}

fn binary_dedup_key(kind: BinaryKind, sha256: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.format.as_bytes());
    hasher.update(b"|");
    hasher.update(kind.architecture.as_bytes());
    hasher.update(b"|");
    hasher.update(sha256.as_bytes());
    format!("{:x}", hasher.finalize())
        .chars()
        .take(48)
        .collect()
}

fn binary_analysis_plan(symbol_info: &SymbolInfo) -> BinaryAnalysisPlan {
    let symbolization = if symbol_info.debug_info_present {
        "debug_info_present"
    } else {
        symbol_info.symbol_status.as_str()
    };
    BinaryAnalysisPlan {
        symbolization: symbolization.to_owned(),
        reverse_engineering_tools: ["ghidra", "rizin", "angr"]
            .into_iter()
            .map(|tool| ReverseEngineeringToolPlan {
                tool: tool.to_owned(),
                status: "offline_export_supported".to_owned(),
                reason: "inventory includes format, architecture, symbols/debug state, strings, and stable sha256 handoff".to_owned(),
            })
            .collect(),
        notes: vec![
            "Use sha256 and dedup_key to join binary-scan, binary-fuzz, and crash-triage exports."
                .to_owned(),
        ],
    }
}

fn ascii_strings(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Vec::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            current.push(*byte);
        } else {
            if current.len() >= min_len {
                out.push(String::from_utf8_lossy(&current).to_string());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        out.push(String::from_utf8_lossy(&current).to_string());
    }
    out
}

fn interesting_string(value: &str) -> bool {
    let folded = value.to_ascii_lowercase();
    folded.contains("/etc/")
        || folded.contains("http://")
        || folded.contains("https://")
        || folded.contains("createfile")
        || folded.contains("socket")
        || folded.contains("password")
        || folded.contains("passwd")
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn elf_machine(machine: u16) -> &'static str {
    match machine {
        3 => "x86",
        40 => "arm",
        62 => "x86_64",
        183 => "aarch64",
        243 => "riscv",
        _ => "unknown",
    }
}

fn pe_machine(machine: u16) -> (&'static str, u16) {
    match machine {
        0x014c => ("x86", 32),
        0x8664 => ("x86_64", 64),
        0xaa64 => ("aarch64", 64),
        0x01c0 | 0x01c4 => ("arm", 32),
        _ => ("unknown", 0),
    }
}

fn macho_cpu(cputype: u32) -> &'static str {
    match cputype {
        7 => "x86",
        0x01000007 => "x86_64",
        12 => "arm",
        0x0100000c => "aarch64",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArchiveMember {
    name: String,
    data: Vec<u8>,
}

fn is_ar_archive(bytes: &[u8]) -> bool {
    bytes.starts_with(b"!<arch>\n")
}

fn parse_ar_archive(bytes: &[u8]) -> Result<Vec<ArchiveMember>, String> {
    if !is_ar_archive(bytes) {
        return Ok(Vec::new());
    }
    let mut members = Vec::new();
    let mut offset = 8usize;
    while offset < bytes.len() {
        if offset + 60 > bytes.len() {
            return Err("truncated ar member header".to_owned());
        }
        let header = &bytes[offset..offset + 60];
        offset += 60;
        if &header[58..60] != b"`\n" {
            return Err("invalid ar member header magic".to_owned());
        }
        let name = std::str::from_utf8(&header[0..16])
            .unwrap_or("")
            .trim()
            .trim_end_matches('/')
            .to_owned();
        let size_text = std::str::from_utf8(&header[48..58]).unwrap_or("").trim();
        let size = size_text
            .parse::<usize>()
            .map_err(|_| format!("invalid ar member size `{size_text}`"))?;
        if offset + size > bytes.len() {
            return Err(format!("truncated ar member `{name}`"));
        }
        let data = bytes[offset..offset + size].to_vec();
        offset += size;
        if size % 2 != 0 {
            offset = offset.saturating_add(1);
        }
        if !name.is_empty() {
            members.push(ArchiveMember { name, data });
        }
    }
    Ok(members)
}

fn firmware_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "bin" | "fw" | "img" | "rom" | "hex"
            )
        })
}

fn counts(
    binaries: &[BinaryRecord],
    skipped: &[SkippedBinary],
    containers: &[ContainerRecord],
) -> BinaryCounts {
    let mut counts = BinaryCounts {
        files: binaries.len(),
        skipped: skipped.len(),
        containers: containers.len(),
        ..BinaryCounts::default()
    };
    for binary in binaries {
        *counts.by_format.entry(binary.format.clone()).or_insert(0) += 1;
        *counts
            .by_architecture
            .entry(binary.architecture.clone())
            .or_insert(0) += 1;
        if !binary.strings.interesting.is_empty() {
            counts.binaries_with_interesting_strings += 1;
        }
        if !binary.secrets.is_empty() {
            counts.binaries_with_secrets += 1;
        }
        if !binary.cve_matches.is_empty() {
            counts.binaries_with_cve_matches += 1;
            counts.cve_matches += binary.cve_matches.len();
        }
    }
    for skipped in skipped {
        *counts
            .by_skip_reason
            .entry(skipped.reason.clone())
            .or_insert(0) += 1;
    }
    counts
}

fn size_exceeds(max_bytes: Option<u64>, bytes: u64) -> bool {
    max_bytes.is_some_and(|limit| bytes > limit)
}

fn skipped_binary(
    path: &str,
    reason: &str,
    detail: &str,
    bytes: Option<u64>,
    sha256: Option<String>,
) -> SkippedBinary {
    SkippedBinary {
        path: path.to_owned(),
        reason: reason.to_owned(),
        detail: detail.to_owned(),
        bytes,
        sha256,
    }
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, BinaryScanError> {
    if root.is_file() {
        return Ok(vec![root.to_path_buf()]);
    }
    if !root.is_dir() {
        return Err(BinaryScanError::InvalidRoot {
            path: root.to_path_buf(),
        });
    }
    let mut out = Vec::new();
    collect_files(root, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), BinaryScanError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            if !dir_is_excluded(&child) {
                collect_files(&child, out)?;
            }
        } else if ty.is_file() {
            out.push(child);
        }
    }
    Ok(())
}

fn dir_is_excluded(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, ".git" | "target" | "govfuzz_work" | "build"))
}

fn relative_path(root: &Path, path: &Path) -> String {
    let rel = if root.is_file() {
        path.file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| path.to_path_buf())
    } else {
        path.strip_prefix(root).unwrap_or(path).to_path_buf()
    };
    path_string(&rel)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn bytes_to_lower_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
