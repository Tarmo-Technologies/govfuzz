# GovFuzz Static Scan

- Findings: 13
- Suppressed: 0
- Resolved: 0
- Analysis gaps: 32

| ID | Rule | Severity | Confidence | Triage | Location |
| --- | --- | --- | --- | --- | --- |
| S-0001 | GF-472 | high | high | unreviewed | .github/workflows/ci.yml:17 |
| S-0002 | GF-472 | high | high | unreviewed | .github/workflows/ci.yml:31 |
| S-0003 | GF-472 | high | high | unreviewed | .github/workflows/ci.yml:57 |
| S-0004 | GF-472 | high | high | unreviewed | .github/workflows/ci.yml:71 |
| S-0005 | GF-472 | high | high | unreviewed | .github/workflows/ci.yml:85 |
| S-0006 | GF-472 | high | high | unreviewed | .github/workflows/ci.yml:86 |
| S-0007 | GF-472 | high | high | unreviewed | .github/workflows/ci.yml:96 |
| S-0008 | GF-472 | high | high | unreviewed | .github/workflows/ci.yml:109 |
| S-0009 | GF-472 | high | high | unreviewed | .github/workflows/ci.yml:127 |
| S-0010 | GF-472 | high | high | unreviewed | .github/workflows/ci.yml:128 |
| S-0011 | GF-472 | high | high | unreviewed | .github/workflows/ci.yml:138 |
| S-0012 | GF-472 | high | high | unreviewed | .github/workflows/ci.yml:139 |
| S-0013 | GF-304 | critical | medium | unreviewed | build.rs:19 |

## Analysis Gaps

- build.rs:18 unresolved `env::var_os` from `rustc_minor_version` (unresolved_project_local_call)
- build.rs:19 unresolved `Command::new` from `rustc_minor_version` (unresolved_project_local_call)
- build.rs:20 unresolved `str::from_utf8` from `rustc_minor_version` (unresolved_project_local_call)
- build.rs:21 unresolved `version.split` from `rustc_minor_version` (unresolved_project_local_call)
- build.rs:25 unresolved `pieces.next` from `rustc_minor_version` (unresolved_project_local_call)
- src/parse.rs:165 unresolved `Error::new` from `numeric_identifier` (unresolved_project_local_call)
- src/parse.rs:165 unresolved `ErrorKind::LeadingZero` from `numeric_identifier` (unresolved_project_local_call)
- src/parse.rs:172 unresolved `Error::new` from `numeric_identifier` (unresolved_project_local_call)
- src/parse.rs:172 unresolved `ErrorKind::Overflow` from `numeric_identifier` (unresolved_project_local_call)
- src/parse.rs:180 unresolved `Error::new` from `numeric_identifier` (unresolved_project_local_call)
- src/parse.rs:180 unresolved `ErrorKind::UnexpectedChar` from `numeric_identifier` (unresolved_project_local_call)
- src/parse.rs:182 unresolved `Error::new` from `numeric_identifier` (unresolved_project_local_call)
- src/parse.rs:182 unresolved `ErrorKind::UnexpectedEnd` from `numeric_identifier` (unresolved_project_local_call)
- src/parse.rs:202 unresolved `Error::new` from `dot` (unresolved_project_local_call)
- src/parse.rs:202 unresolved `ErrorKind::UnexpectedCharAfter` from `dot` (unresolved_project_local_call)
- src/parse.rs:204 unresolved `Error::new` from `dot` (unresolved_project_local_call)
- src/parse.rs:204 unresolved `ErrorKind::UnexpectedEnd` from `dot` (unresolved_project_local_call)
- src/parse.rs:209 unresolved `let` from `prerelease_identifier` (unresolved_project_local_call)
- src/parse.rs:215 unresolved `let` from `build_identifier` (unresolved_project_local_call)
- src/parse.rs:239 unresolved `Error::new` from `identifier` (unresolved_project_local_call)
- src/parse.rs:239 unresolved `ErrorKind::EmptySegment` from `identifier` (unresolved_project_local_call)
- src/parse.rs:247 unresolved `Error::new` from `identifier` (unresolved_project_local_call)
- src/parse.rs:247 unresolved `ErrorKind::LeadingZero` from `identifier` (unresolved_project_local_call)
- src/parse.rs:255 unresolved `input.split_at` from `identifier` (unresolved_project_local_call)
- src/parse.rs:255 unresolved `input.split_at` from `identifier` (unresolved_project_local_call)
- src/parse.rs:263 unresolved `input.as_bytes` from `op` (unresolved_project_local_call)
- src/parse.rs:288 unresolved `let` from `comparator` (unresolved_project_local_call)
- src/parse.rs:289 unresolved `input.len` from `comparator` (unresolved_project_local_call)
- src/parse.rs:289 unresolved `text.len` from `comparator` (unresolved_project_local_call)
- src/parse.rs:381 unresolved `out.reserve_exact` from `version_req` (unresolved_project_local_call)
- src/parse.rs:382 unresolved `out.as_mut_ptr` from `version_req` (unresolved_project_local_call)
- src/parse.rs:402 unresolved `out.as_mut_ptr` from `version_req` (unresolved_project_local_call)
