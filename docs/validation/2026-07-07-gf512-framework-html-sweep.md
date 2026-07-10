<!-- SPDX-License-Identifier: Apache-2.0 -->
# GF-512 Framework Raw-HTML Sweep - 2026-07-07

This memo records validation for the `GF-512` JavaScript raw-HTML sink expansion:
DOM `outerHTML` / `insertAdjacentHTML` / `setHTMLUnsafe`, Vue `v-html`, Svelte
`{@html}`, Angular `bypassSecurityTrustHtml`, and `.vue` / `.svelte` scan routing.

## Scope

- Worktree: `sast-framework-html-sinks-2026-07-07`
- Sweep root: `/tmp/govfuzz-sast-gf512-framework-sweep-2026-07-07`
- Scanner: `target/debug/govfuzz static-scan <repo> --debug --enable-rule GF-512`
- Corpus: 50 shallow-cloned GitHub projects across Vue, Svelte, Angular, React,
  Express/Node, build tooling, and deliberately vulnerable app code.

## Research Sources

- MDN documents `insertAdjacentHTML` and `setHTMLUnsafe` as injection sinks that
  require TrustedHTML / sanitizer handling.
- Vue documents `v-html` as raw HTML rendering and warns against untrusted content.
- Svelte documents `{@html}` as raw HTML rendering and warns that content must be
  escaped or trusted.
- Angular documents `bypassSecurityTrustHtml` as an explicit security bypass.

## Initial Sweep

- Repos cloned: 50 / 50
- Successful scans: 49 / 50
- Timeout: `next` (Next.js), even with a later 600 second focused retry
- Initial real `GF-512` findings: 20

Initial hit repos:

| Repo | Initial `GF-512` findings | Triage |
|---|---:|---|
| `primeng` | 4 | False positives: `text/plain` markdown responses with `res.send(content)` |
| `storybook` | 3 | One JSON manifest write false positive; two reflected manifest-name error responses retained |
| `gatsby` | 4 | False positives: e2e test routes and page-data JSON object responses |
| `juice-shop` | 9 | False positives: localized constant error messages whose string literals contained alias words |

## Fixes From Triage

- Suppress response XSS findings when the immediate response context sets
  `Content-Type` to `text/plain` or `application/json`; the backward scan stops at
  branch boundaries so an earlier JSON branch does not suppress a later error branch.
- Match tainted aliases only in code tokens, not inside quoted string literals.
- Avoid treating property names such as `page.path` as uses of an alias named
  `path`.
- Treat Gatsby page-data loader helpers as JSON/data object producers, not raw
  HTML producers.
- Suppress `GF-512` in `e2e-test` / `e2e-tests` fixture directories.

## Final Focused Rescan

After the fixes, the hit repos were rescanned into `out-fixed/`:

| Repo | Final scan status | Final `GF-512` findings |
|---|---|---:|
| `primeng` | ok | 0 |
| `storybook` | ok | 2 |
| `gatsby` | ok | 0 |
| `juice-shop` | ok | 0 |
| `next` | timeout | 0 |

The two remaining Storybook findings are both reflected `req.params.name` values
written directly into `res.end(...)` error responses under the manifest JSON route:

- `code/core/src/core-server/utils/manifests/manifests.ts:368`
- `code/core/src/core-server/utils/manifests/manifests.ts:383`

They are defensible `GF-512` reports for the current source-only rule because the
responses do not set a non-HTML content type in those branches.

## Commands

```sh
cargo fmt --all
cargo test -p static_analysis javascript_rule_pack -- --nocapture
cargo test -p static_analysis config_files_are_supported_static_scan_inputs -- --nocapture
cargo test -p finding_rules
cargo test -p static_analysis --test precision_benchmark -- --nocapture
cargo build -p govfuzz
cargo run -p spdx_check -- check
python3 scripts/docs/build-site.py
git diff --check
```

Corrected sweep summaries were written during validation at:

```text
/tmp/govfuzz-sast-gf512-framework-sweep-2026-07-07/summary-corrected.tsv
/tmp/govfuzz-sast-gf512-framework-sweep-2026-07-07/out-fixed/
```
