#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import argparse
import html
import re
import shutil
from dataclasses import dataclass
from pathlib import Path


DEFAULT_BASE_URL = "https://docs.govfuzz.dev"


@dataclass(frozen=True)
class Page:
    slug: str
    source: str
    title: str


PAGES = [
    Page("index", "index.md", "Overview"),
    Page("install", "install.md", "Install"),
    Page("architecture", "architecture.md", "Architecture"),
    Page("cli", "cli.md", "CLI"),
    Page("auto", "auto.md", "Auto"),
    Page("run-modes", "run-modes.md", "Run Modes"),
    Page("ci", "ci.md", "CI"),
    Page("llm", "llm.md", "LLM and MCP"),
    Page("comparison", "comparison.md", "Comparison"),
    Page("comparison-2026-07", "comparison-2026-07.md", "Comparison: July 2026"),
    Page("libfuzzer-parity", "libfuzzer-parity.md", "libFuzzer Parity"),
    Page("engine-parity-benchmark", "engine-parity-benchmark.md", "Engine Benchmark"),
    Page("whitepaper", "whitepaper.md", "White Paper"),
    Page("vulnerability-coverage", "vulnerability-coverage.md", "Vulnerability Coverage"),
    Page("static-cwe-coverage", "static-cwe-coverage.md", "Static CWE Coverage"),
    Page("sast-comparison", "sast-comparison.md", "SAST Comparison"),
    Page("whitepaper-coverage", "whitepaper-coverage.md", "White Paper: Coverage"),
    Page("sink-oracles", "sink-oracles.md", "Sink Oracles"),
    Page("c-cpp", "c-cpp.md", "C and C++"),
    Page("csharp", "csharp.md", "C#"),
    Page("javascript", "javascript.md", "JavaScript and TypeScript"),
    Page("cobol", "cobol.md", "COBOL"),
    Page("fortran", "fortran.md", "Fortran"),
    Page("sanitizers", "sanitizers.md", "Sanitizers"),
    Page("runtime-virtualisation", "runtime-virtualisation.md", "Runtime Virtualisation"),
    Page("instrumentation", "instrumentation.md", "Instrumentation"),
    Page("fake-corba", "fake-corba.md", "Fake-CORBA"),
    Page("fake-resource-sdk", "fake-resource-sdk.md", "Fake Resource SDK"),
    Page("cross-compilation", "cross-compilation.md", "Cross-Compilation"),
    Page("windows", "windows.md", "Windows"),
    Page("daemon", "daemon.md", "Daemon"),
    Page("licensing", "licensing.md", "Licensing"),
    Page("release-packaging", "release-packaging.md", "Release Packaging"),
    Page("release-checklist", "release-checklist.md", "Release Checklist"),
    Page("offline-deployment", "offline-deployment.md", "Offline Deployment"),
    Page("offline-auto-runbook", "offline-auto-runbook.md", "Offline Auto Runbook"),
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the GovFuzz docs site")
    parser.add_argument("--source", default="docs/site", help="Markdown source directory")
    parser.add_argument("--out", default="target/docs-site", help="Generated site directory")
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="Canonical site URL used in sitemap and robots.txt",
    )
    args = parser.parse_args()

    source = Path(args.source)
    out = Path(args.out)
    base_url = args.base_url.rstrip("/")

    validate_manifest(source)

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    for page in PAGES:
        markdown = (source / page.source).read_text(encoding="utf-8")
        write_page(out, page, render_markdown(rewrite_source_links(markdown, page)), base_url)

    copy_assets(source, out)
    copy_cname(source, out)
    write_sitemap(out, base_url)
    write_robots(out, base_url)
    validate_generated_links(out)


def validate_manifest(source: Path) -> None:
    """Keep every operator-facing Markdown page published and uniquely routed."""
    sources = [page.source for page in PAGES]
    slugs = [page.slug for page in PAGES]
    if len(sources) != len(set(sources)) or len(slugs) != len(set(slugs)):
        raise ValueError("docs page manifest contains a duplicate source or slug")

    discovered = {path.name for path in source.glob("*.md")}
    configured = set(sources)
    if discovered != configured:
        omitted = ", ".join(sorted(discovered - configured)) or "none"
        missing = ", ".join(sorted(configured - discovered)) or "none"
        raise ValueError(
            f"docs page manifest is incomplete (omitted: {omitted}; missing: {missing})"
        )


def rewrite_source_links(markdown: str, page: Page) -> str:
    """Turn GitHub-friendly links to sibling Markdown files into site routes."""
    routes = {item.source: item.slug for item in PAGES}

    def replace(match: re.Match) -> str:
        label, target = match.group(1), match.group(2)
        path, marker, fragment = target.partition("#")
        source_name = path.removeprefix("./")
        slug = routes.get(source_name)
        if slug is None:
            return match.group(0)
        if page.slug == "index":
            route = "./" if slug == "index" else f"./{slug}/"
        else:
            route = "../" if slug == "index" else f"../{slug}/"
        suffix = f"#{fragment}" if marker else ""
        return f"[{label}]({route}{suffix})"

    return re.sub(r"\[([^\]]+)\]\(([^)]+\.md(?:#[^)]+)?)\)", replace, markdown)


def validate_generated_links(out: Path) -> None:
    """Fail the build when a generated relative hyperlink has no local target."""
    failures = []
    for document in out.glob("**/*.html"):
        body = document.read_text(encoding="utf-8")
        for target in re.findall(r'href="([^"]+)"', body):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path = target.split("#", 1)[0].split("?", 1)[0]
            if not path:
                continue
            resolved = document.parent / path
            exists = resolved.is_file() or (
                resolved.is_dir() and (resolved / "index.html").is_file()
            )
            if not exists:
                failures.append(f"{document.relative_to(out)} -> {target}")
    if failures:
        raise ValueError("broken generated docs links:\n  " + "\n  ".join(failures))


def write_page(out: Path, page: Page, content: str, base_url: str) -> None:
    if page.slug == "index":
        destination = out / "index.html"
    else:
        destination = out / page.slug / "index.html"
        destination.parent.mkdir(parents=True, exist_ok=True)

    destination.write_text(
        render_shell(page, content, base_url),
        encoding="utf-8",
    )


def render_shell(page: Page, content: str, base_url: str) -> str:
    nav = "\n".join(
        f'<a class="{nav_class(page.slug, item.slug)}" href="{nav_href(page.slug, item.slug)}">'
        f"{html.escape(item.title)}</a>"
        for item in PAGES
    )
    canonical = canonical_url(base_url, page.slug)
    title = "GovFuzz Documentation" if page.slug == "index" else f"{page.title} - GovFuzz"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <link rel="canonical" href="{html.escape(canonical, quote=True)}">
  <style>
    :root {{
      color-scheme: light;
      --background: #f7f8f4;
      --surface: #ffffff;
      --text: #1e2a31;
      --muted: #5f6b72;
      --line: #d7ddd8;
      --accent: #2f6f5e;
      --code: #17222a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--background);
      color: var(--text);
      font: 16px/1.6 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    header {{
      border-bottom: 1px solid var(--line);
      background: var(--surface);
    }}
    .masthead {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 18px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }}
    .brand {{
      font-weight: 700;
      letter-spacing: 0;
    }}
    .domain {{
      color: var(--muted);
      font-size: 14px;
      overflow-wrap: anywhere;
    }}
    .layout {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px 24px 56px;
      display: grid;
      grid-template-columns: 240px minmax(0, 1fr);
      gap: 34px;
    }}
    nav {{
      display: flex;
      flex-direction: column;
      gap: 4px;
      position: sticky;
      top: 18px;
      align-self: start;
      max-height: calc(100vh - 36px);
      overflow-y: auto;
    }}
    nav a {{
      color: var(--text);
      text-decoration: none;
      padding: 8px 10px;
      border-radius: 6px;
    }}
    nav a:hover,
    nav a.active {{
      background: #e7eee9;
      color: var(--accent);
    }}
    main {{
      min-width: 0;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 32px;
    }}
    h1, h2, h3 {{
      line-height: 1.25;
      margin: 0 0 14px;
    }}
    h1 {{ font-size: 34px; }}
    h2 {{
      font-size: 24px;
      margin-top: 30px;
      border-top: 1px solid var(--line);
      padding-top: 24px;
    }}
    h3 {{
      font-size: 18px;
      margin-top: 24px;
    }}
    p, ul, ol, pre {{ margin: 0 0 16px; }}
    a {{ color: var(--accent); }}
    table {{ border-collapse: collapse; width: 100%; margin: 0 0 16px; font-size: 0.92em; }}
    th, td {{ border: 1px solid var(--line); padding: 7px 10px; text-align: left; vertical-align: top; }}
    thead th {{ background: #eef2ef; }}
    tbody tr:nth-child(even) {{ background: #f7f9f8; }}
    code {{
      background: #eef2ef;
      border-radius: 4px;
      padding: 1px 5px;
      font-size: 0.94em;
    }}
    pre {{
      overflow-x: auto;
      background: var(--code);
      color: #edf4ef;
      padding: 16px;
      border-radius: 8px;
    }}
    pre code {{
      background: transparent;
      color: inherit;
      padding: 0;
    }}
    @media (max-width: 760px) {{
      .masthead {{
        align-items: flex-start;
        flex-direction: column;
      }}
      .layout {{
        grid-template-columns: 1fr;
        padding: 18px 16px 40px;
      }}
      nav {{
        position: static;
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      }}
      main {{
        padding: 22px;
      }}
      h1 {{
        font-size: 28px;
      }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="masthead">
      <div class="brand">GovFuzz Documentation</div>
      <div class="domain">{html.escape(DEFAULT_BASE_URL.removeprefix("https://"))}</div>
    </div>
  </header>
  <div class="layout">
    <nav aria-label="Documentation">{nav}</nav>
    <main>{content}</main>
  </div>
</body>
</html>
"""


def render_markdown(markdown: str) -> str:
    lines = strip_spdx(markdown).splitlines()
    blocks = []
    paragraph = []
    list_kind = None
    code_lines = []
    code_language = ""
    in_code = False
    table_lines: list = []

    def flush_paragraph() -> None:
        if paragraph:
            text = " ".join(line.strip() for line in paragraph)
            blocks.append(f"<p>{render_inline(text)}</p>")
            paragraph.clear()

    def close_list() -> None:
        nonlocal list_kind
        if list_kind:
            blocks.append(f"</{list_kind}>")
            list_kind = None

    def flush_table() -> None:
        nonlocal table_lines
        if not table_lines:
            return
        rows = table_lines
        table_lines = []
        # A GFM table needs a `|---|---|` separator as its second row; without it
        # the buffered lines aren't a table, so fall back to a paragraph.
        is_sep = (
            len(rows) >= 2
            and "-" in rows[1]
            and re.match(r"^\s*\|?[\s:|\-]+\|?\s*$", rows[1])
        )
        if not is_sep:
            text = " ".join(r.strip() for r in rows)
            blocks.append(f"<p>{render_inline(text)}</p>")
            return

        def cells(row: str) -> list:
            return [c.strip() for c in row.strip().strip("|").split("|")]

        out = ["<table>", "<thead><tr>"]
        out += [f"<th>{render_inline(c)}</th>" for c in cells(rows[0])]
        out.append("</tr></thead><tbody>")
        for row in rows[2:]:
            out.append(
                "<tr>"
                + "".join(f"<td>{render_inline(c)}</td>" for c in cells(row))
                + "</tr>"
            )
        out.append("</tbody></table>")
        blocks.append("".join(out))

    for raw_line in lines:
        line = raw_line.rstrip()

        if line.startswith("```"):
            if in_code:
                language_class = (
                    f' class="language-{html.escape(code_language, quote=True)}"'
                    if code_language
                    else ""
                )
                code = html.escape("\n".join(code_lines))
                blocks.append(f"<pre><code{language_class}>{code}</code></pre>")
                code_lines = []
                code_language = ""
                in_code = False
            else:
                flush_paragraph()
                close_list()
                code_language = line[3:].strip()
                in_code = True
            continue

        if in_code:
            code_lines.append(raw_line)
            continue

        if not line.strip():
            flush_paragraph()
            close_list()
            flush_table()
            continue

        # GFM pipe-table rows: buffer consecutive `| ... |` lines, render on close.
        if re.match(r"^\s*\|.*\|\s*$", line):
            flush_paragraph()
            close_list()
            table_lines.append(line)
            continue
        flush_table()

        heading = re.match(r"^(#{1,3})\s+(.+)$", line)
        if heading:
            flush_paragraph()
            close_list()
            level = len(heading.group(1))
            text = heading.group(2).strip()
            blocks.append(
                f'<h{level} id="{slugify(text)}">{render_inline(text)}</h{level}>'
            )
            continue

        bullet = re.match(r"^\s*-\s+(.+)$", line)
        numbered = re.match(r"^\s*\d+\.\s+(.+)$", line)
        if bullet or numbered:
            flush_paragraph()
            wanted_kind = "ul" if bullet else "ol"
            if list_kind != wanted_kind:
                close_list()
                blocks.append(f"<{wanted_kind}>")
                list_kind = wanted_kind
            item = (bullet or numbered).group(1)
            blocks.append(f"<li>{render_inline(item)}</li>")
            continue

        close_list()
        paragraph.append(line)

    flush_paragraph()
    close_list()
    flush_table()

    if in_code:
        code = html.escape("\n".join(code_lines))
        blocks.append(f"<pre><code>{code}</code></pre>")

    return "\n".join(blocks)


def render_inline(text: str) -> str:
    parts = re.split(r"(`[^`]+`)", text)
    rendered = []
    for part in parts:
        if part.startswith("`") and part.endswith("`"):
            rendered.append(f"<code>{html.escape(part[1:-1])}</code>")
        else:
            # Links first (escapes literal text), then bold on the escaped result
            # (`**` survives HTML-escaping, so the post-pass is safe).
            linked = render_links(part)
            rendered.append(re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", linked))
    return "".join(rendered)


def render_links(text: str) -> str:
    result = []
    offset = 0
    for match in re.finditer(r"\[([^\]]+)\]\(([^)]+)\)", text):
        result.append(html.escape(text[offset : match.start()]))
        label = html.escape(match.group(1))
        url = html.escape(match.group(2), quote=True)
        result.append(f'<a href="{url}">{label}</a>')
        offset = match.end()
    result.append(html.escape(text[offset:]))
    return "".join(result)


def strip_spdx(markdown: str) -> str:
    lines = markdown.splitlines()
    if lines and "SPDX-License-Identifier:" in lines[0]:
        lines = lines[1:]
        if lines and not lines[0].strip():
            lines = lines[1:]
    return "\n".join(lines)


def nav_class(current_slug: str, target_slug: str) -> str:
    return "active" if current_slug == target_slug else ""


def nav_href(current_slug: str, target_slug: str) -> str:
    if current_slug == "index":
        return "index.html" if target_slug == "index" else f"{target_slug}/"
    return "../" if target_slug == "index" else f"../{target_slug}/"


def canonical_url(base_url: str, slug: str) -> str:
    return f"{base_url}/" if slug == "index" else f"{base_url}/{slug}/"


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "section"


def copy_assets(source: Path, out: Path) -> None:
    """Copy the `img/` asset directory to the site root and into each non-index
    page directory, so a relative `img/foo.png` reference resolves both on the
    built site and in GitHub markdown preview."""
    img = source / "img"
    if not img.is_dir():
        return
    shutil.copytree(img, out / "img", dirs_exist_ok=True)
    for page in PAGES:
        if page.slug == "index":
            continue
        shutil.copytree(img, out / page.slug / "img", dirs_exist_ok=True)


def copy_cname(source: Path, out: Path) -> None:
    cname = source / "CNAME"
    if cname.is_file():
        shutil.copyfile(cname, out / "CNAME")


def write_sitemap(out: Path, base_url: str) -> None:
    urls = "\n".join(
        f"  <url><loc>{html.escape(canonical_url(base_url, page.slug))}</loc></url>"
        for page in PAGES
    )
    out.joinpath("sitemap.xml").write_text(
        f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{urls}
</urlset>
""",
        encoding="utf-8",
    )


def write_robots(out: Path, base_url: str) -> None:
    out.joinpath("robots.txt").write_text(
        f"User-agent: *\nAllow: /\nSitemap: {base_url}/sitemap.xml\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
