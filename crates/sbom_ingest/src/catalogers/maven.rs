// SPDX-License-Identifier: Apache-2.0

//! Maven (JVM) ecosystem cataloger.
//!
//! **Declared only**: `pom.xml`. Maven has no native lockfile — all components
//! are `EvidenceKind::Declared` unless hashes can be found in `~/.m2` sidecars
//! (out of scope for an offline source scan).
//!
//! # XML parsing
//! Uses a targeted bounded string-scan of the specific element shapes that appear
//! in `<dependencies>` / `<dependencyManagement>` / `<properties>`.  No external
//! XML crate is required — the scan is robust against missing whitespace and
//! common XML variations found in real pom.xml files.  Malformed input is
//! tolerated (entries with no groupId/artifactId are skipped).
//!
//! # Property resolution
//! `${name}` placeholders in `<version>` are resolved against the local
//! `<properties>` block and two built-in aliases (`${project.version}` /
//! `${project.groupId}`).  A placeholder that remains unresolvable becomes
//! version-unknown: the `version` field is `None` and no PURL `@version` is
//! emitted.
//!
//! # `<dependencyManagement>`
//! Managed entries supply fallback versions for `<dependency>` blocks that omit
//! `<version>`.  They are **not** emitted as components themselves.
//!
//! # PURL
//! `pkg:maven/<groupId>/<artifactId>@<version>` — groupId dots are literal
//! (one path segment).  `type` qualifier emitted when not `jar`; `classifier`
//! qualifier emitted when present.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::Component;
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct MavenCataloger;

impl Cataloger for MavenCataloger {
    fn ecosystem(&self) -> &str {
        "maven"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("pom.xml").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        // Reactor pre-pass: parse every pom's own coordinates, `<parent>` link,
        // `<properties>` and `<dependencyManagement>`. A multi-module reactor pins
        // a child's version-less dependency in the root/parent pom's management, so
        // each pom is resolved against the MERGED managed view of its parent chain.
        let mut docs = Vec::new();
        for path in ctx.files_named("pom.xml") {
            let rel = relative_path(&ctx.root, path);
            docs.push(parse_pom_doc(path, &rel)?);
        }

        // Index every pom by its own coordinate (groupId may be inherited from
        // `<parent>`) so a child can locate its parent pom in the same tree.
        let mut by_coord: HashMap<String, usize> = HashMap::new();
        for (i, doc) in docs.iter().enumerate() {
            if let Some(coord) = doc.own_coord() {
                by_coord.entry(coord).or_insert(i);
            }
        }

        let mut out = Vec::new();
        for i in 0..docs.len() {
            let (props, managed) = merged_inherited_view(&docs, &by_coord, i);
            let license = inherited_license(&docs, &by_coord, i);
            out.extend(emit_pom_components(
                &docs[i],
                &props,
                &managed,
                license.as_deref(),
            ));
        }
        Ok(out)
    }
}

/// One parsed pom: enough to resolve its dependencies against the reactor's
/// inherited `<properties>` + `<dependencyManagement>`. `source` is retained for
/// the dependency / self-component scan; the pre-extracted fields key reactor
/// linkage (own coords, parent coords).
struct PomDoc {
    relative: String,
    source: String,
    own_group: Option<String>,
    own_artifact: Option<String>,
    parent_group: Option<String>,
    parent_artifact: Option<String>,
    /// Local `<properties>` + project builtins (project.version/groupId).
    properties: HashMap<String, String>,
    /// `groupId:artifactId` → raw managed version (may carry `${...}`).
    managed: HashMap<String, String>,
    /// This pom's OWN `<licenses><license><name>`, if it declares one. A reactor
    /// child that omits `<licenses>` inherits the nearest ancestor's.
    own_license: Option<String>,
}

impl PomDoc {
    /// The pom's own coordinate (`groupId:artifactId`), with the groupId taken
    /// from `<parent>` when the module omits its own. Used as the reactor key a
    /// child's `<parent>` resolves to.
    fn own_coord(&self) -> Option<String> {
        let group = self.own_group.as_ref().or(self.parent_group.as_ref())?;
        let artifact = self.own_artifact.as_ref()?;
        Some(format!("{group}:{artifact}"))
    }

    /// The coordinate of this pom's `<parent>`, if it declares one.
    fn parent_coord(&self) -> Option<String> {
        let group = self.parent_group.as_ref()?;
        let artifact = self.parent_artifact.as_ref()?;
        Some(format!("{group}:{artifact}"))
    }
}

/// Parse a pom into a `PomDoc`. Oversized poms (>8 MiB) yield an inert empty doc
/// (no coords, no deps) so they neither index nor emit.
fn parse_pom_doc(path: &Path, relative: &str) -> Result<PomDoc, CatalogError> {
    let source = read_to_string(path)?;
    if source.len() > 8 * 1024 * 1024 {
        return Ok(PomDoc {
            relative: relative.to_owned(),
            source: String::new(),
            own_group: None,
            own_artifact: None,
            parent_group: None,
            parent_artifact: None,
            properties: HashMap::new(),
            managed: HashMap::new(),
            own_license: None,
        });
    }

    // The project's OWN coordinates: read from the body with `<parent>` and the
    // dependency/build/profile blocks removed so neither a parent's nor a
    // dependency's coordinates shadow the project's own.
    let parent_block = extract_block(&source, "parent");
    let mut body = remove_blocks(&source, "parent");
    for tag in [
        "dependencyManagement",
        "dependencies",
        "build",
        "profiles",
        "reporting",
    ] {
        body = remove_blocks(&body, tag);
    }
    let own_group = nonempty(extract_first_element(&body, "groupId"));
    let own_artifact = nonempty(extract_first_element(&body, "artifactId"));
    let own_version = nonempty(extract_first_element(&body, "version"));
    let parent_group = parent_block
        .as_deref()
        .and_then(|p| nonempty(extract_first_element(p, "groupId")));
    let parent_artifact = parent_block
        .as_deref()
        .and_then(|p| nonempty(extract_first_element(p, "artifactId")));
    let parent_version = parent_block
        .as_deref()
        .and_then(|p| nonempty(extract_first_element(p, "version")));

    // Local <properties> + project builtins.
    let mut properties: HashMap<String, String> = HashMap::new();
    if let Some(props_block) = extract_block(&source, "properties") {
        parse_properties(&props_block, &mut properties);
    }
    if let Some(v) = own_version.clone().or_else(|| parent_version.clone()) {
        properties.insert("project.version".to_owned(), v);
    }
    if let Some(g) = own_group.clone().or_else(|| parent_group.clone()) {
        properties.insert("project.groupId".to_owned(), g);
    }

    // <dependencyManagement> → groupId:artifactId → raw version (unresolved).
    let mut managed: HashMap<String, String> = HashMap::new();
    if let Some(mgmt_block) = extract_block(&source, "dependencyManagement") {
        if let Some(deps_block) = extract_block(&mgmt_block, "dependencies") {
            for entry in parse_dependency_blocks(&deps_block) {
                if let Some(v) = entry.version {
                    let key = format!("{}:{}", entry.group_id, entry.artifact_id);
                    managed.entry(key).or_insert(v);
                }
            }
        }
    }

    let own_license = extract_project_license(&source);

    Ok(PomDoc {
        relative: relative.to_owned(),
        source,
        own_group,
        own_artifact,
        parent_group,
        parent_artifact,
        properties,
        managed,
        own_license,
    })
}

/// The pom's `<parent>` chain within the scanned reactor: `[start, parent, …,
/// root-most ancestor present in the tree]`. Bounded by a visited-set against
/// cycles. Shared by the property/management merge and license inheritance.
fn parent_chain(docs: &[PomDoc], by_coord: &HashMap<String, usize>, start: usize) -> Vec<usize> {
    let mut chain = vec![start];
    let mut visited = std::collections::HashSet::new();
    visited.insert(start);
    let mut current = start;
    while let Some(parent_coord) = docs[current].parent_coord() {
        let Some(&parent_idx) = by_coord.get(&parent_coord) else {
            break;
        };
        if !visited.insert(parent_idx) {
            break;
        }
        chain.push(parent_idx);
        current = parent_idx;
    }
    chain
}

/// Merge `<properties>` + `<dependencyManagement>` along the pom's `<parent>`
/// chain (walked within the scanned reactor). Ancestors supply fallbacks; the
/// child overrides on key collision. Bounded by a visited-set against cycles.
fn merged_inherited_view(
    docs: &[PomDoc],
    by_coord: &HashMap<String, usize>,
    start: usize,
) -> (HashMap<String, String>, HashMap<String, String>) {
    let chain = parent_chain(docs, by_coord, start);

    // Apply ancestor-first so the child (applied last) wins on collisions.
    let mut props = HashMap::new();
    let mut managed = HashMap::new();
    for &idx in chain.iter().rev() {
        for (k, v) in &docs[idx].properties {
            props.insert(k.clone(), v.clone());
        }
        for (k, v) in &docs[idx].managed {
            managed.insert(k.clone(), v.clone());
        }
    }
    (props, managed)
}

/// Resolve a pom's effective `<licenses>` along its `<parent>` chain: the nearest
/// pom (self first, then ancestors) that declares its own `<licenses>` wins. Maven
/// license inheritance: a reactor child that omits `<licenses>` inherits the
/// parent's. Returns `None` when no pom in the chain declares one.
fn inherited_license(
    docs: &[PomDoc],
    by_coord: &HashMap<String, usize>,
    start: usize,
) -> Option<String> {
    parent_chain(docs, by_coord, start)
        .into_iter()
        .find_map(|idx| docs[idx].own_license.clone())
}

/// Emit the project-self + dependency components for one pom, using the merged
/// inherited `<properties>` + `<dependencyManagement>` view.
fn emit_pom_components(
    doc: &PomDoc,
    properties: &HashMap<String, String>,
    managed: &HashMap<String, String>,
    inherited_license: Option<&str>,
) -> Vec<Component> {
    let source = &doc.source;
    let relative = &doc.relative;
    let mut out = Vec::new();
    if source.is_empty() {
        return out;
    }

    // The project's OWN identity (tagged `source` for metadata.component adoption).
    if let Some(self_component) =
        parse_project_self_component(source, relative, properties, inherited_license)
    {
        out.push(self_component);
    }

    let deps_block = find_direct_dependencies_block(source);
    if let Some(deps_text) = deps_block {
        for mut entry in parse_dependency_blocks(&deps_text) {
            // Substitute ${property} in groupId/artifactId. A surviving
            // placeholder means the coordinate is unresolvable offline.
            entry.group_id = substitute_properties(&entry.group_id, properties);
            entry.artifact_id = substitute_properties(&entry.artifact_id, properties);
            let coord_resolved =
                !entry.group_id.contains("${") && !entry.artifact_id.contains("${");

            entry.version = resolve_version(
                entry.version,
                properties,
                managed,
                &entry.group_id,
                &entry.artifact_id,
            );

            let name = if entry.artifact_id.contains("${") {
                strip_placeholder(&entry.artifact_id)
            } else {
                entry.artifact_id.clone()
            };

            let group_field = coord_resolved.then(|| entry.group_id.clone());
            let purl_val = maven_dep_purl(&entry, coord_resolved);

            let source_loc = format!("{}:{}:{}", relative, entry.group_id, entry.artifact_id);
            out.push(Component {
                component_ref: String::new(),
                name,
                group: group_field,
                version: entry.version.clone(),
                ecosystem: "maven".to_owned(),
                component_type: "library".to_owned(),
                supplier: None,
                license: None,
                purl: purl_val,
                cpe: None,
                sha256: None,
                hashes: Vec::new(),
                identity_confidence: "medium".to_owned(),
                matching_method: "pom_xml".to_owned(),
                evidence: vec![Evidence::new(EvidenceKind::Declared, source_loc)],
                runtime_harnesses: Vec::new(),
            });
        }
    }

    out
}

/// Build the purl for a dependency: versioned when resolved, version-less
/// `pkg:maven/<group>/<artifact>` when the coordinate resolved but the version is
/// externally managed/unknown, `None` when the coordinate itself is unresolvable.
/// Appends `type`/`classifier` qualifiers in both versioned and version-less forms.
fn maven_dep_purl(entry: &DepEntry, coord_resolved: bool) -> Option<String> {
    if !coord_resolved {
        return None;
    }
    let mut p = match &entry.version {
        Some(v) => purl::maven(&entry.group_id, &entry.artifact_id, v),
        None => purl::maven_nameonly(&entry.group_id, &entry.artifact_id),
    };
    let mut quals = Vec::new();
    if entry.dep_type != "jar" {
        quals.push(format!("type={}", entry.dep_type));
    }
    if let Some(cls) = &entry.classifier {
        quals.push(format!("classifier={cls}"));
    }
    if !quals.is_empty() {
        p.push('?');
        p.push_str(&quals.join("&"));
    }
    Some(p)
}

// ---------------------------------------------------------------------------
// Internal data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DepEntry {
    group_id: String,
    artifact_id: String,
    /// None = version-unknown (managed/absent/unresolvable property).
    version: Option<String>,
    classifier: Option<String>,
    /// defaults to "jar"
    dep_type: String,
}

// ---------------------------------------------------------------------------
// version resolution
// ---------------------------------------------------------------------------

/// Resolve a raw version string: replace `${...}` placeholders, fall back to
/// the merged `<dependencyManagement>` view when absent, return `None` if still
/// unresolvable. A managed value may itself carry `${...}` (a parent BOM pinned
/// via a property), so it is substituted against the merged properties too.
fn resolve_version(
    raw: Option<String>,
    properties: &HashMap<String, String>,
    managed: &HashMap<String, String>,
    group_id: &str,
    artifact_id: &str,
) -> Option<String> {
    match raw {
        None => {
            // No <version> element — look up the (possibly inherited) managed
            // version, then resolve any property placeholder it carries.
            let key = format!("{group_id}:{artifact_id}");
            let managed_raw = managed.get(&key)?;
            let resolved = substitute_properties(managed_raw, properties);
            if resolved.contains("${") {
                None
            } else {
                Some(resolved)
            }
        }
        Some(v) => {
            let resolved = substitute_properties(&v, properties);
            // If still contains ${...} after substitution, it's unresolvable.
            if resolved.contains("${") {
                None
            } else {
                Some(resolved)
            }
        }
    }
}

/// Reduce a string still containing an unresolved `${key}` placeholder to a
/// readable bare name (`${my.artifact}` → `my.artifact`) for the component
/// `name` field, so a literal placeholder never reaches output.
fn strip_placeholder(s: &str) -> String {
    s.replace("${", "").replace('}', "")
}

/// Build the project's OWN component — the reactor/module identity, distinct from
/// its `<dependencies>`. Maven inheritance: a module pom may omit its own
/// `<groupId>`/`<version>` and inherit them from `<parent>`. The project's own
/// coordinates are read from the pom body with the `<parent>`, `<dependencies>`,
/// `<dependencyManagement>`, `<build>`, `<profiles>` and `<reporting>` blocks
/// removed (so neither a parent's nor a dependency's nor a plugin's coordinates
/// shadow the project's own), falling back to `<parent>` for a missing
/// groupId/version. Tagged `component_type = "source"` /
/// `matching_method = "pom_xml_project"` so the SBOM renderer can adopt the root
/// pom's identity as the CycloneDX `metadata.component`. Returns `None` when no
/// `<artifactId>` is identifiable (a malformed or coordinate-less pom).
fn parse_project_self_component(
    source: &str,
    relative: &str,
    properties: &HashMap<String, String>,
    inherited_license: Option<&str>,
) -> Option<Component> {
    let parent_block = extract_block(source, "parent");
    let mut body = remove_blocks(source, "parent");
    for tag in [
        "dependencyManagement",
        "dependencies",
        "build",
        "profiles",
        "reporting",
    ] {
        body = remove_blocks(&body, tag);
    }

    let artifact_id = nonempty(extract_first_element(&body, "artifactId"))?;
    let group_id = nonempty(extract_first_element(&body, "groupId")).or_else(|| {
        parent_block
            .as_deref()
            .and_then(|p| nonempty(extract_first_element(p, "groupId")))
    });
    let raw_version = nonempty(extract_first_element(&body, "version")).or_else(|| {
        parent_block
            .as_deref()
            .and_then(|p| nonempty(extract_first_element(p, "version")))
    });

    // Resolve ${property} placeholders, mirroring the dependency path.
    let group_id = group_id.map(|g| substitute_properties(&g, properties));
    let artifact_id = substitute_properties(&artifact_id, properties);
    let version = raw_version
        .map(|v| substitute_properties(&v, properties))
        .filter(|v| !v.contains("${"));

    let coord_resolved =
        group_id.as_deref().is_some_and(|g| !g.contains("${")) && !artifact_id.contains("${");

    // A literal placeholder must never reach the component name.
    let name = if artifact_id.contains("${") {
        strip_placeholder(&artifact_id)
    } else {
        artifact_id.clone()
    };

    // A resolved coordinate always yields a purl: versioned when the version is
    // known, version-less `pkg:maven/<group>/<artifact>` otherwise.
    let purl_val = match (&group_id, &version) {
        (Some(g), Some(v)) if coord_resolved => Some(purl::maven(g, &artifact_id, v)),
        (Some(g), None) if coord_resolved => Some(purl::maven_nameonly(g, &artifact_id)),
        _ => None,
    };
    let group_field = group_id.clone().filter(|_| coord_resolved);

    Some(Component {
        component_ref: String::new(),
        name,
        group: group_field,
        version,
        ecosystem: "maven".to_owned(),
        component_type: "source".to_owned(),
        supplier: None,
        // Own `<licenses>` wins; a child that omits it inherits the parent's.
        license: extract_project_license(source).or_else(|| inherited_license.map(str::to_owned)),
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "high".to_owned(),
        matching_method: "pom_xml_project".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, relative.to_owned())],
        runtime_harnesses: Vec::new(),
    })
}

/// First `<licenses><license><name>` of the pom, if any. Maven license names are
/// free-form (often an SPDX id like `Apache-2.0`, sometimes a long title); the
/// renderer maps a single-token name to an SPDX `id` and anything else to a
/// license `name`/expression — same path as every other component license.
fn extract_project_license(source: &str) -> Option<String> {
    let licenses = extract_block(source, "licenses")?;
    let license = extract_block(&licenses, "license")?;
    nonempty(extract_first_element(&license, "name"))
}

/// `Some(s)` only when `s` has non-whitespace content; trims surrounding space.
fn nonempty(value: Option<String>) -> Option<String> {
    value.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

/// Remove every `<tag>...</tag>` block from `text` (all occurrences). Used to
/// scrub `<parent>`/`<dependencies>`/`<build>` etc. so the project's own
/// coordinates are not shadowed by a parent's, a dependency's, or a plugin's.
fn remove_blocks(text: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(&open) {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        if let Some(end) = after.find(&close) {
            rest = &after[end + close.len()..];
        } else {
            // Malformed — drop the unterminated tail.
            rest = "";
            break;
        }
    }
    out.push_str(rest);
    out
}

/// Substitute `${key}` placeholders in `s` using `props`.
fn substitute_properties(s: &str, props: &HashMap<String, String>) -> String {
    let mut result = s.to_owned();
    // Iteratively resolve; cap at 10 passes to avoid infinite loops.
    for _ in 0..10 {
        if !result.contains("${") {
            break;
        }
        let before = result.clone();
        let mut out = String::with_capacity(result.len());
        let mut rest = result.as_str();
        while let Some(start) = rest.find("${") {
            out.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            if let Some(end) = after.find('}') {
                let key = &after[..end];
                if let Some(val) = props.get(key) {
                    out.push_str(val);
                } else {
                    // Keep original placeholder — will mark as unresolvable later.
                    out.push_str("${");
                    out.push_str(key);
                    out.push('}');
                }
                rest = &after[end + 1..];
            } else {
                // Malformed placeholder — keep rest as-is.
                out.push_str("${");
                out.push_str(after);
                rest = "";
                break;
            }
        }
        out.push_str(rest);
        result = out;
        if result == before {
            break;
        }
    }
    result
}

/// Extract all `<dependency>` blocks from a raw text fragment.
fn parse_dependency_blocks(text: &str) -> Vec<DepEntry> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<dependency>") {
        rest = &rest[start + "<dependency>".len()..];
        let end = rest.find("</dependency>").unwrap_or(rest.len());
        let block = &rest[..end];
        if let Some(entry) = parse_single_dependency(block) {
            out.push(entry);
        }
        rest = if end < rest.len() {
            &rest[end + "</dependency>".len()..]
        } else {
            ""
        };
    }
    out
}

fn parse_single_dependency(block: &str) -> Option<DepEntry> {
    let group_id = extract_first_element(block, "groupId")?;
    let artifact_id = extract_first_element(block, "artifactId")?;
    if group_id.is_empty() || artifact_id.is_empty() {
        return None;
    }
    let version = extract_first_element(block, "version");
    let classifier = extract_first_element(block, "classifier");
    let dep_type = extract_first_element(block, "type").unwrap_or_else(|| "jar".to_owned());

    Some(DepEntry {
        group_id,
        artifact_id,
        version,
        classifier,
        dep_type,
    })
}

/// Extract the text content of the first occurrence of `<tag>...</tag>`.
/// Returns `None` when the tag is absent; returns `Some("")` for empty tags.
fn extract_first_element(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)?;
    let after = &text[start + open.len()..];
    let end = after.find(&close).unwrap_or(after.len());
    Some(after[..end].trim().to_owned())
}

/// Extract the content of the first occurrence of `<tag>...</tag>` where the
/// content may span multiple lines and contain nested elements.
fn extract_block(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)?;
    let after = &text[start + open.len()..];
    let end = after.find(&close)?;
    Some(after[..end].to_owned())
}

/// Find the `<dependencies>` block that belongs directly to `<project>`, not
/// inside `<dependencyManagement>`, `<build>`, or `<reporting>`.  Strategy: strip
/// those wrapper sections first, then find the first `<dependencies>` block in
/// the remainder. `<build>`/`<reporting>` carry plugin tooling deps (e.g.
/// proguard-base, r8) that are NOT project dependencies; without scrubbing them a
/// module pom with no top-level `<dependencies>` would surface plugin deps as
/// library components. `<profiles>` is deliberately NOT scrubbed — a profile can
/// carry real project dependencies.
fn find_direct_dependencies_block(text: &str) -> Option<String> {
    let mut scrubbed = remove_blocks(text, "dependencyManagement");
    scrubbed = remove_blocks(&scrubbed, "build");
    scrubbed = remove_blocks(&scrubbed, "reporting");
    extract_block(&scrubbed, "dependencies")
}

/// Parse `<key>value</key>` pairs from a `<properties>` block into `props`.
fn parse_properties(block: &str, props: &mut HashMap<String, String>) {
    let mut rest = block;
    while let Some(open_start) = rest.find('<') {
        let after_lt = &rest[open_start + 1..];
        // Find the tag name (up to `>` or whitespace).
        let tag_end = after_lt
            .find(|c: char| c == '>' || c.is_whitespace())
            .unwrap_or(after_lt.len());
        let tag = &after_lt[..tag_end];
        if tag.is_empty() || tag.starts_with('/') || tag.starts_with('!') || tag.starts_with('?') {
            rest = &rest[open_start + 1..];
            continue;
        }
        let close = format!("</{tag}>");
        let open = format!("<{tag}>");
        // Find the value between the open and close tag.
        if let Some(val_start) = rest[open_start..].find('>') {
            let content_start = open_start + val_start + 1;
            if content_start >= rest.len() {
                break;
            }
            let content_rest = &rest[content_start..];
            if let Some(close_pos) = content_rest.find(&close) {
                let value = content_rest[..close_pos].trim().to_owned();
                props.insert(tag.to_owned(), value);
                rest = &content_rest[close_pos + close.len()..];
            } else {
                // Skip this element.
                rest = &rest[open_start + open.len()..];
            }
        } else {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_to_string(path: &Path) -> Result<String, CatalogError> {
    fs::read_to_string(path).map_err(|source| CatalogError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(path_string)
        .unwrap_or_else(|_| path_string(path))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{top_rung, EvidenceKind};
    use std::path::PathBuf;

    fn fixture_ctx(name: &str) -> CatalogContext {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        let files = collect_files(&root);
        CatalogContext::new(root, files)
    }

    fn collect_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        collect_recursive(dir, &mut files);
        files.sort();
        files
    }

    fn collect_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_recursive(&path, out);
            } else {
                out.push(path);
            }
        }
    }

    // -----------------------------------------------------------------------
    // property substitution
    // -----------------------------------------------------------------------

    #[test]
    fn property_resolved_version() {
        let ctx = fixture_ctx("maven");
        let out = MavenCataloger.catalog(&ctx).unwrap();
        let jackson = out
            .iter()
            .find(|c| c.name == "jackson-databind")
            .expect("jackson-databind must be present");
        assert_eq!(jackson.version.as_deref(), Some("2.17.0"));
        assert_eq!(
            jackson.purl.as_deref(),
            Some("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0")
        );
    }

    // -----------------------------------------------------------------------
    // managed version fallback
    // -----------------------------------------------------------------------

    #[test]
    fn managed_version_fills_absent_version_element() {
        let ctx = fixture_ctx("maven");
        let out = MavenCataloger.catalog(&ctx).unwrap();
        let spring = out
            .iter()
            .find(|c| c.name == "spring-core")
            .expect("spring-core must be present");
        assert_eq!(spring.version.as_deref(), Some("6.1.0"));
        assert_eq!(
            spring.purl.as_deref(),
            Some("pkg:maven/org.springframework/spring-core@6.1.0")
        );
    }

    // -----------------------------------------------------------------------
    // unresolvable property → version-unknown
    // -----------------------------------------------------------------------

    #[test]
    fn unresolvable_property_yields_version_unknown() {
        let ctx = fixture_ctx("maven");
        let out = MavenCataloger.catalog(&ctx).unwrap();
        let unk = out
            .iter()
            .find(|c| c.name == "unknown-prop")
            .expect("unknown-prop must be present");
        assert!(
            unk.version.is_none(),
            "unresolvable property must yield version=None"
        );
        // The COORDINATE still resolves (groupId/artifactId are literal), so a
        // versionless `pkg:maven/<group>/<artifact>` purl + group are emitted —
        // only the version is unknown.
        assert_eq!(
            unk.purl.as_deref(),
            Some("pkg:maven/org.example/unknown-prop"),
            "a resolved coordinate gets a versionless purl"
        );
        assert_eq!(unk.group.as_deref(), Some("org.example"));
    }

    // -----------------------------------------------------------------------
    // ${property} substitution in groupId / artifactId
    // -----------------------------------------------------------------------

    #[test]
    fn property_in_group_and_artifact_id_is_substituted() {
        // groupId=${project.groupId} → com.example, artifactId=${my.artifact}
        // → resolved-artifact. Placeholders must NOT leak into the PURL.
        let ctx = fixture_ctx("maven");
        let out = MavenCataloger.catalog(&ctx).unwrap();
        let comp = out
            .iter()
            .find(|c| c.name == "resolved-artifact")
            .expect("artifactId property must be substituted");
        assert_eq!(
            comp.purl.as_deref(),
            Some("pkg:maven/com.example/resolved-artifact@2.5.0"),
            "groupId/artifactId ${{...}} must be substituted in the PURL"
        );
    }

    #[test]
    fn unresolvable_property_in_group_id_yields_name_only_no_purl() {
        // groupId=${missing.group} cannot resolve → emit the component name-only
        // (artifactId), with NO PURL (version-unknown style).
        let ctx = fixture_ctx("maven");
        let out = MavenCataloger.catalog(&ctx).unwrap();
        let orphan = out
            .iter()
            .find(|c| c.name == "orphan-lib")
            .expect("orphan-lib must be present by artifactId");
        assert!(
            orphan.purl.is_none(),
            "unresolved ${{...}} in groupId must yield NO PURL: {:?}",
            orphan.purl
        );
        // Name must never contain a literal placeholder.
        assert!(
            !orphan.name.contains("${"),
            "component name must not carry a literal placeholder"
        );
    }

    // -----------------------------------------------------------------------
    // classifier + non-default type
    // -----------------------------------------------------------------------

    #[test]
    fn classifier_and_type_appear_as_qualifiers() {
        let ctx = fixture_ctx("maven");
        let out = MavenCataloger.catalog(&ctx).unwrap();
        let some_lib = out
            .iter()
            .find(|c| c.name == "some-lib")
            .expect("some-lib must be present");
        let purl = some_lib.purl.as_deref().unwrap();
        assert!(
            purl.contains("type=test-jar"),
            "type qualifier must be present: {purl}"
        );
        assert!(
            purl.contains("classifier=jdk11"),
            "classifier qualifier must be present: {purl}"
        );
    }

    // -----------------------------------------------------------------------
    // dependencyManagement entries NOT emitted as components
    // -----------------------------------------------------------------------

    #[test]
    fn dependency_management_not_emitted_as_component() {
        let ctx = fixture_ctx("maven");
        let out = MavenCataloger.catalog(&ctx).unwrap();
        // spring-core appears as a real dep (managed version); it must appear
        // exactly once, not twice (once from management + once from deps).
        let spring_count = out.iter().filter(|c| c.name == "spring-core").count();
        assert_eq!(spring_count, 1, "spring-core must appear exactly once");
    }

    // -----------------------------------------------------------------------
    // evidence rung
    // -----------------------------------------------------------------------

    #[test]
    fn all_components_are_declared() {
        let ctx = fixture_ctx("maven");
        let out = MavenCataloger.catalog(&ctx).unwrap();
        assert!(!out.is_empty());
        for c in &out {
            assert_eq!(
                top_rung(&c.evidence),
                Some(EvidenceKind::Declared),
                "{} must be Declared",
                c.name
            );
        }
    }

    // -----------------------------------------------------------------------
    // no hashes (Maven is declared-only offline)
    // -----------------------------------------------------------------------

    #[test]
    fn no_hashes_emitted_for_maven() {
        let ctx = fixture_ctx("maven");
        let out = MavenCataloger.catalog(&ctx).unwrap();
        for c in &out {
            assert!(
                c.hashes.is_empty(),
                "Maven pom.xml carries no hashes offline"
            );
        }
    }

    // -----------------------------------------------------------------------
    // detect
    // -----------------------------------------------------------------------

    #[test]
    fn detect_true_for_pom_xml() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/pom.xml".into()]);
        assert!(MavenCataloger.detect(&ctx));
    }

    #[test]
    fn detect_false_without_pom() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/build.gradle".into()]);
        assert!(!MavenCataloger.detect(&ctx));
    }

    // -----------------------------------------------------------------------
    // all declared deps are present
    // -----------------------------------------------------------------------

    #[test]
    fn all_declared_deps_parsed() {
        let ctx = fixture_ctx("maven");
        let out = MavenCataloger.catalog(&ctx).unwrap();
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"jackson-databind"));
        assert!(names.contains(&"spring-core"));
        assert!(names.contains(&"unknown-prop"));
        assert!(names.contains(&"some-lib"));
        assert!(names.contains(&"junit"));
    }

    // -----------------------------------------------------------------------
    // property substitution unit test
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // project-self component (the BOM's primary subject)
    // -----------------------------------------------------------------------

    #[test]
    fn project_self_component_carries_root_coordinates() {
        // The fixture pom is com.example/demo/1.0.0 — emit a `source` component
        // for the project itself, distinct from its <dependencies> (which are
        // `library`), so the SBOM renderer can adopt it as metadata.component.
        let ctx = fixture_ctx("maven");
        let out = MavenCataloger.catalog(&ctx).unwrap();
        let self_comp = out
            .iter()
            .find(|c| c.matching_method == "pom_xml_project")
            .expect("a project-self component must be emitted");
        assert_eq!(self_comp.name, "demo");
        assert_eq!(self_comp.version.as_deref(), Some("1.0.0"));
        assert_eq!(self_comp.component_type, "source");
        assert_eq!(
            self_comp.purl.as_deref(),
            Some("pkg:maven/com.example/demo@1.0.0")
        );
        assert_eq!(self_comp.evidence_summary(), "pom.xml");
        // The project itself must not also be one of the dependency components.
        assert!(
            out.iter()
                .filter(|c| c.name == "demo")
                .all(|c| c.matching_method == "pom_xml_project"),
            "the project's own coordinates must not be emitted as a dependency"
        );
    }

    #[test]
    fn module_pom_inherits_group_and_version_from_parent() {
        // A reactor submodule that declares only its own <artifactId> inherits
        // groupId + version from <parent> — those must populate the self
        // component (not the parent's artifactId).
        let source = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <parent>\n    \
             <groupId>com.acme</groupId>\n    <artifactId>acme-parent</artifactId>\n    \
             <version>3.2.1</version>\n  </parent>\n  <artifactId>acme-core</artifactId>\n  \
             <name>Acme Core</name>\n  <dependencies>\n    <dependency>\n      \
             <groupId>org.other</groupId>\n      <artifactId>helper</artifactId>\n      \
             <version>1.0.0</version>\n    </dependency>\n  </dependencies>\n</project>\n";
        let self_comp =
            parse_project_self_component(source, "module/pom.xml", &HashMap::new(), None).unwrap();
        assert_eq!(self_comp.name, "acme-core");
        assert_eq!(self_comp.version.as_deref(), Some("3.2.1"));
        assert_eq!(
            self_comp.purl.as_deref(),
            Some("pkg:maven/com.acme/acme-core@3.2.1")
        );
        assert_eq!(self_comp.evidence_summary(), "module/pom.xml");
    }

    #[test]
    fn project_self_component_extracts_license_name() {
        let source = "<project>\n  <groupId>g</groupId>\n  <artifactId>a</artifactId>\n  \
             <version>1.0</version>\n  <licenses>\n    <license>\n      \
             <name>Apache-2.0</name>\n    </license>\n  </licenses>\n</project>\n";
        let self_comp =
            parse_project_self_component(source, "pom.xml", &HashMap::new(), None).unwrap();
        assert_eq!(self_comp.license.as_deref(), Some("Apache-2.0"));
    }

    #[test]
    fn substitute_properties_replaces_placeholders() {
        let mut props = HashMap::new();
        props.insert("foo.version".to_owned(), "1.2.3".to_owned());
        assert_eq!(substitute_properties("${foo.version}", &props), "1.2.3");
        assert_eq!(substitute_properties("${missing}", &props), "${missing}");
    }

    // -----------------------------------------------------------------------
    // reactor-wide dependencyManagement inheritance + group/versionless purl
    // -----------------------------------------------------------------------

    fn temp_tree(files: &[(&str, &str)]) -> (tempfile::TempDir, CatalogContext) {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let mut paths = Vec::new();
        for (name, body) in files {
            let p = dir.path().join(name);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::File::create(&p)
                .unwrap()
                .write_all(body.as_bytes())
                .unwrap();
            paths.push(p);
        }
        let ctx = CatalogContext::new(dir.path().to_path_buf(), paths);
        (dir, ctx)
    }

    #[test]
    fn child_inherits_managed_version_from_parent_pom() {
        // A multi-module reactor: the root pom pins helper's version in
        // <dependencyManagement>; the child declares helper version-less. The
        // child's dep must resolve to the managed version via inheritance.
        let root = "<project>\n  <groupId>com.acme</groupId>\n  \
             <artifactId>acme-parent</artifactId>\n  <version>4.5.6</version>\n  \
             <dependencyManagement>\n    <dependencies>\n      <dependency>\n        \
             <groupId>org.lib</groupId>\n        <artifactId>helper</artifactId>\n        \
             <version>9.9.9</version>\n      </dependency>\n    </dependencies>\n  \
             </dependencyManagement>\n</project>\n";
        let child = "<project>\n  <parent>\n    <groupId>com.acme</groupId>\n    \
             <artifactId>acme-parent</artifactId>\n    <version>4.5.6</version>\n  </parent>\n  \
             <artifactId>acme-core</artifactId>\n  <dependencies>\n    <dependency>\n      \
             <groupId>org.lib</groupId>\n      <artifactId>helper</artifactId>\n    \
             </dependency>\n  </dependencies>\n</project>\n";
        let (_d, ctx) = temp_tree(&[("pom.xml", root), ("core/pom.xml", child)]);
        let out = MavenCataloger.catalog(&ctx).unwrap();
        let helper = out
            .iter()
            .find(|c| c.name == "helper" && c.matching_method == "pom_xml")
            .expect("helper dependency must be present");
        assert_eq!(
            helper.version.as_deref(),
            Some("9.9.9"),
            "child must inherit the parent's managed version"
        );
        assert_eq!(
            helper.purl.as_deref(),
            Some("pkg:maven/org.lib/helper@9.9.9")
        );
        assert_eq!(helper.group.as_deref(), Some("org.lib"));
    }

    #[test]
    fn child_inherits_managed_version_pinned_via_parent_property() {
        // The parent's managed version is a ${property} defined in the parent's
        // <properties>; the child must resolve it through the merged view.
        let root = "<project>\n  <groupId>com.acme</groupId>\n  \
             <artifactId>p</artifactId>\n  <version>1.0.0</version>\n  \
             <properties>\n    <lib.version>2.3.4</lib.version>\n  </properties>\n  \
             <dependencyManagement>\n    <dependencies>\n      <dependency>\n        \
             <groupId>org.lib</groupId>\n        <artifactId>helper</artifactId>\n        \
             <version>${lib.version}</version>\n      </dependency>\n    </dependencies>\n  \
             </dependencyManagement>\n</project>\n";
        let child = "<project>\n  <parent>\n    <groupId>com.acme</groupId>\n    \
             <artifactId>p</artifactId>\n    <version>1.0.0</version>\n  </parent>\n  \
             <artifactId>c</artifactId>\n  <dependencies>\n    <dependency>\n      \
             <groupId>org.lib</groupId>\n      <artifactId>helper</artifactId>\n    \
             </dependency>\n  </dependencies>\n</project>\n";
        let (_d, ctx) = temp_tree(&[("pom.xml", root), ("c/pom.xml", child)]);
        let out = MavenCataloger.catalog(&ctx).unwrap();
        let helper = out
            .iter()
            .find(|c| c.name == "helper" && c.matching_method == "pom_xml")
            .expect("helper dependency must be present");
        assert_eq!(helper.version.as_deref(), Some("2.3.4"));
    }

    #[test]
    fn child_inherits_license_from_parent_pom() {
        // Bug #50: a reactor child with NO own <licenses> must inherit the
        // parent pom's <licenses> rather than emitting license=null.
        let root = "<project>\n  <groupId>com.acme</groupId>\n  \
             <artifactId>acme-parent</artifactId>\n  <version>1.0.0</version>\n  \
             <licenses>\n    <license>\n      <name>Apache-2.0</name>\n    \
             </license>\n  </licenses>\n</project>\n";
        let child = "<project>\n  <parent>\n    <groupId>com.acme</groupId>\n    \
             <artifactId>acme-parent</artifactId>\n    <version>1.0.0</version>\n  </parent>\n  \
             <artifactId>acme-child</artifactId>\n</project>\n";
        let (_d, ctx) = temp_tree(&[("pom.xml", root), ("child/pom.xml", child)]);
        let out = MavenCataloger.catalog(&ctx).unwrap();
        let child_self = out
            .iter()
            .find(|c| c.name == "acme-child" && c.matching_method == "pom_xml_project")
            .expect("child self-component present");
        assert_eq!(
            child_self.license.as_deref(),
            Some("Apache-2.0"),
            "child with no own <licenses> must inherit the parent's"
        );
        // The parent keeps its own license too.
        let parent_self = out
            .iter()
            .find(|c| c.name == "acme-parent" && c.matching_method == "pom_xml_project")
            .expect("parent self-component present");
        assert_eq!(parent_self.license.as_deref(), Some("Apache-2.0"));
    }

    #[test]
    fn child_own_license_overrides_inherited() {
        // A child that declares its OWN <licenses> keeps it (no inheritance).
        let root = "<project>\n  <groupId>com.acme</groupId>\n  \
             <artifactId>acme-parent</artifactId>\n  <version>1.0.0</version>\n  \
             <licenses>\n    <license>\n      <name>Apache-2.0</name>\n    \
             </license>\n  </licenses>\n</project>\n";
        let child = "<project>\n  <parent>\n    <groupId>com.acme</groupId>\n    \
             <artifactId>acme-parent</artifactId>\n    <version>1.0.0</version>\n  </parent>\n  \
             <artifactId>acme-child</artifactId>\n  <licenses>\n    <license>\n      \
             <name>MIT</name>\n    </license>\n  </licenses>\n</project>\n";
        let (_d, ctx) = temp_tree(&[("pom.xml", root), ("child/pom.xml", child)]);
        let out = MavenCataloger.catalog(&ctx).unwrap();
        let child_self = out
            .iter()
            .find(|c| c.name == "acme-child" && c.matching_method == "pom_xml_project")
            .expect("child self-component present");
        assert_eq!(child_self.license.as_deref(), Some("MIT"));
    }

    #[test]
    fn plugin_build_dependencies_are_not_emitted_as_project_deps() {
        // Bug #51: a module pom with NO top-level <dependencies>, only plugin
        // tooling deps inside <build><plugins><plugin><dependencies>. Those must
        // NOT surface as project library components.
        let pom = "<project>\n  <groupId>com.example</groupId>\n  \
             <artifactId>shrinker</artifactId>\n  <version>1.0.0</version>\n  \
             <build>\n    <plugins>\n      <plugin>\n        \
             <groupId>com.android.tools</groupId>\n        \
             <artifactId>r8-plugin</artifactId>\n        <dependencies>\n          \
             <dependency>\n            <groupId>com.android.tools</groupId>\n            \
             <artifactId>r8</artifactId>\n            <version>8.0.0</version>\n          \
             </dependency>\n        </dependencies>\n      </plugin>\n    </plugins>\n  \
             </build>\n</project>\n";
        let (_d, ctx) = temp_tree(&[("pom.xml", pom)]);
        let out = MavenCataloger.catalog(&ctx).unwrap();
        assert!(
            out.iter().all(|c| c.name != "r8"),
            "plugin <build> deps must not be emitted as project deps: {:?}",
            out.iter().map(|c| c.name.as_str()).collect::<Vec<_>>()
        );
        // The project self-component is still emitted.
        assert!(out
            .iter()
            .any(|c| c.matching_method == "pom_xml_project" && c.name == "shrinker"));
    }

    #[test]
    fn reporting_dependencies_are_not_emitted_as_project_deps() {
        // <reporting> plugin deps must also be scrubbed (mirror <build>).
        let pom = "<project>\n  <groupId>com.example</groupId>\n  \
             <artifactId>site</artifactId>\n  <version>1.0.0</version>\n  \
             <reporting>\n    <plugins>\n      <plugin>\n        \
             <groupId>org.report</groupId>\n        <artifactId>report-tool</artifactId>\n        \
             <dependencies>\n          <dependency>\n            \
             <groupId>org.report</groupId>\n            <artifactId>report-dep</artifactId>\n            \
             <version>2.0.0</version>\n          </dependency>\n        </dependencies>\n      \
             </plugin>\n    </plugins>\n  </reporting>\n</project>\n";
        let (_d, ctx) = temp_tree(&[("pom.xml", pom)]);
        let out = MavenCataloger.catalog(&ctx).unwrap();
        assert!(
            out.iter().all(|c| c.name != "report-dep"),
            "<reporting> deps must not be emitted: {:?}",
            out.iter().map(|c| c.name.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn resolved_coord_without_version_gets_versionless_purl_and_group() {
        // A dependency with a known coordinate but NO resolvable version (not in
        // management) must still get a versionless `pkg:maven/<g>/<a>` purl and a
        // group field, rather than no purl at all.
        let pom = "<project>\n  <groupId>com.example</groupId>\n  \
             <artifactId>app</artifactId>\n  <version>1.0.0</version>\n  \
             <dependencies>\n    <dependency>\n      <groupId>org.unmanaged</groupId>\n      \
             <artifactId>thing</artifactId>\n    </dependency>\n  </dependencies>\n</project>\n";
        let (_d, ctx) = temp_tree(&[("pom.xml", pom)]);
        let out = MavenCataloger.catalog(&ctx).unwrap();
        let thing = out
            .iter()
            .find(|c| c.name == "thing" && c.matching_method == "pom_xml")
            .expect("thing dependency present");
        assert!(thing.version.is_none(), "version is externally managed");
        assert_eq!(
            thing.purl.as_deref(),
            Some("pkg:maven/org.unmanaged/thing"),
            "a resolved coordinate must carry a versionless purl"
        );
        assert_eq!(thing.group.as_deref(), Some("org.unmanaged"));

        // The self-component carries its groupId in the group field.
        let self_comp = out
            .iter()
            .find(|c| c.matching_method == "pom_xml_project")
            .unwrap();
        assert_eq!(self_comp.group.as_deref(), Some("com.example"));
        assert_eq!(
            self_comp.purl.as_deref(),
            Some("pkg:maven/com.example/app@1.0.0")
        );
    }
}
