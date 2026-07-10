# GovFuzz Static Scan

- Findings: 5
- Suppressed: 0
- Resolved: 0
- Analysis gaps: 2

| ID | Rule | Severity | Confidence | Triage | Location |
| --- | --- | --- | --- | --- | --- |
| S-0001 | GF-472 | high | high | unreviewed | .github/workflows/cifuzz.yml:14 |
| S-0002 | GF-472 | high | high | unreviewed | .github/workflows/cifuzz.yml:21 |
| S-0003 | GF-421 | high | medium | unreviewed | gson/src/test/java/com/google/gson/JavaSerializationTest.java:76 |
| S-0004 | GF-421 | high | medium | unreviewed | gson/src/test/java/com/google/gson/internal/LazilyParsedNumberTest.java:51 |
| S-0005 | GF-421 | high | medium | unreviewed | gson/src/test/java/com/google/gson/internal/LinkedTreeMapTest.java:221 |

## Analysis Gaps

- gson/src/main/java/com/google/gson/internal/JavaVersion.java:48 unresolved `javaVersion.split` from `parseDotted` (unresolved_project_local_call)
- gson/src/main/java/com/google/gson/internal/JavaVersion.java:66 unresolved `num.append` from `extractBeginningInt` (unresolved_project_local_call)
