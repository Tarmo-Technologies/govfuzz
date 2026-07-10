# GovFuzz Static Scan

- Findings: 18
- Suppressed: 0
- Resolved: 0
- Analysis gaps: 11

| ID | Rule | Severity | Confidence | Triage | Location |
| --- | --- | --- | --- | --- | --- |
| S-0001 | GF-500 | medium | high | unreviewed | .github/workflows/linux.yml:10 |
| S-0002 | GF-500 | medium | high | unreviewed | .github/workflows/macos.yml:10 |
| S-0003 | GF-500 | medium | high | unreviewed | .github/workflows/perltidy.yml:10 |
| S-0004 | GF-497 | medium | high | unreviewed | .github/workflows/perltidy.yml:13 |
| S-0005 | GF-500 | medium | high | unreviewed | .github/workflows/rebuild-website.yml:7 |
| S-0006 | GF-500 | medium | high | unreviewed | .github/workflows/windows.yml:10 |
| S-0007 | GF-420 | critical | medium | unreviewed | lib/Mojo/Base.pm:112 |
| S-0008 | GF-420 | critical | medium | unreviewed | lib/Mojo/Exception.pm:75 |
| S-0009 | GF-420 | critical | medium | unreviewed | lib/Mojo/Loader.pm:50 |
| S-0010 | GF-422 | medium | high | unreviewed | lib/Mojo/Message/Request.pm:15 |
| S-0011 | GF-404 | critical | medium | unreviewed | lib/Mojo/Server/Hypnotoad.pm:47 |
| S-0012 | GF-404 | critical | medium | unreviewed | lib/Mojo/Server/Hypnotoad.pm:130 |
| S-0013 | GF-420 | critical | medium | unreviewed | lib/Mojo/Template.pm:149 |
| S-0014 | GF-422 | medium | high | unreviewed | lib/Mojo/Util.pm:6 |
| S-0015 | GF-420 | critical | medium | unreviewed | lib/Mojo/Util.pm:458 |
| S-0016 | GF-420 | critical | medium | unreviewed | lib/Mojolicious/Command/eval.pm:18 |
| S-0017 | GF-420 | critical | medium | unreviewed | lib/Mojolicious/Plugin/Config.pm:13 |
| S-0018 | GF-420 | critical | medium | unreviewed | lib/ojo.pm:20 |

## Analysis Gaps

- lib/Mojo/DOM.pm:288 unresolved `my` from `_parse` (unresolved_project_local_call)
- lib/Mojo/DOM.pm:289 unresolved `isa` from `_parse` (unresolved_project_local_call)
- lib/Mojo/Server/Daemon.pm:174 unresolved `qw` from `_listen` (unresolved_project_local_call)
- lib/Mojo/Server/Daemon.pm:182 unresolved `_` from `_listen` (unresolved_project_local_call)
- lib/Mojo/Server/Daemon.pm:194 unresolved `my` from `_listen` (unresolved_project_local_call)
- lib/Mojo/Server/Hypnotoad.pm:120 unresolved `unless` from `_manage` (unresolved_project_local_call)
- lib/Mojo/Util.pm:481 unresolved `my` from `xor_encode` (unresolved_project_local_call)
- lib/Mojo/Util.pm:486 unresolved `length` from `xor_encode` (unresolved_project_local_call)
- lib/Mojo/Util.pm:486 unresolved `substr` from `xor_encode` (unresolved_project_local_call)
- lib/Mojo/Util.pm:487 unresolved `substr` from `xor_encode` (unresolved_project_local_call)
- lib/Mojolicious/Plugin/TagHelpers.pm:144 unresolved `my` from `_option` (unresolved_project_local_call)
