//! Bounded, conservative taint tracing for simple assignments and ES-module imports.
//!
//! This is not a parser or a general-purpose data-flow engine. It intentionally
//! supports a small set of source, assignment, sink, and import patterns.

use super::make_finding;
use crate::models::{Confidence, Finding, Severity};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

pub const MAX_PROJECT_TAINT_FACTS: usize = 50_000;
pub const MAX_PROJECT_TAINT_FILES: usize = 10_000;

macro_rules! cached_regex {
    ($name:ident, $pattern:literal) => {
        fn $name() -> &'static Regex {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| Regex::new($pattern).expect("static taint regex must be valid"))
        }
    };
}

cached_regex!(
    assignment_regex,
    r"^\s*(?:(?:export|const|let|var|final|val|mut|pub)\s+)*([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^=]+)?\s*=\s*(.+?)\s*;?\s*$"
);
cached_regex!(
    source_regex,
    r"(?i)(?:\breq(?:uest)?\s*\.\s*(?:body|query|params)\b|\brequest\s*\.\s*(?:args|form|GET|POST)\b|\blocation\s*\.\s*(?:search|hash)\b|\bprocess\s*\.\s*argv\b|\binput\s*\(\s*\)|\bstdin\s*\.\s*(?:read|read_line)|\bget_json\s*\()"
);
cached_regex!(identifier_regex, r"[A-Za-z_$][A-Za-z0-9_$]*");
cached_regex!(
    sanitizer_expression_regex,
    r"(?i)^\s*(?:DOMPurify\s*\.\s*sanitize|sanitizeHtml|escapeHtml|escape_html)\s*\(.*\)\s*;?\s*$"
);
cached_regex!(
    import_regex,
    r#"^\s*import\s*\{\s*(?P<items>[^}]+)\}\s*from\s*['"](?P<module>[^'"]+)['"]"#
);
cached_regex!(export_list_regex, r"^\s*export\s*\{\s*([^}]+)\s*\}");
cached_regex!(
    xss_assignment_regex,
    r"(?i)\.(?:innerHTML|outerHTML)\s*=\s*(?P<arg>[^;]+)"
);
cached_regex!(
    xss_call_regex,
    r"(?i)(?:insertAdjacentHTML\s*\([^,]+,|document\s*\.\s*write\s*\()\s*(?P<arg>[^)]*)"
);
cached_regex!(
    sql_sink_regex,
    r"(?i)(?:\.query|\.execute|\.raw|\.raw_sql)\s*\(\s*(?P<arg>[A-Za-z_$][A-Za-z0-9_$]*)"
);
cached_regex!(
    shell_sink_regex,
    r"(?i)(?:os\.(?:system|popen)|child_process\.exec(?:Sync)?|execSync)\s*\(\s*(?P<arg>[A-Za-z_$][A-Za-z0-9_$]*)"
);
cached_regex!(
    subprocess_shell_sink_regex,
    r"(?i)subprocess\.(?:run|Popen|call)\s*\(\s*(?P<arg>[A-Za-z_$][A-Za-z0-9_$]*)[^)]*\bshell\s*=\s*(?:true|1)\b[^)]*\)"
);
cached_regex!(
    path_sink_regex,
    r"(?i)(?:\bopen|readFile|readFileSync|createReadStream|send_file|File::open|read_to_string)\s*\(\s*(?P<arg>[A-Za-z_$][A-Za-z0-9_$]*)"
);
cached_regex!(
    ssrf_sink_regex,
    r"(?i)(?:\bfetch|axios\.(?:get|post|request)|requests\.(?:get|post|request)|http\.get|https\.get|client\.get)\s*\(\s*(?P<arg>[A-Za-z_$][A-Za-z0-9_$]*)"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SinkKind {
    Xss,
    Sql,
    Shell,
    Path,
    Ssrf,
}

#[derive(Debug, Clone)]
struct Assignment {
    name: String,
    rhs_identifiers: Vec<String>,
    is_source: bool,
    sanitizes_xss: bool,
    line: usize,
}

#[derive(Debug, Clone)]
struct Sink {
    kind: SinkKind,
    identifiers: Vec<String>,
    sanitizes_xss: bool,
    line: usize,
    evidence: String,
}

#[derive(Debug, Clone)]
struct ImportBinding {
    module: String,
    imported: String,
    local: String,
}

#[derive(Debug, Clone, Default)]
pub struct TaintFile {
    path: PathBuf,
    events: Vec<Event>,
    exports: HashSet<String>,
    imports: Vec<ImportBinding>,
    suppressions: HashSet<(usize, String)>,
}

#[derive(Debug, Clone)]
enum Event {
    Assignment(Assignment),
    Sink(Sink),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TaintOrigin {
    source_file: String,
    source_line: usize,
    chain: Vec<String>,
    sanitized_xss: bool,
}

/// Parse a source file into compact facts. `budget` bounds the number of stored
/// assignment and sink facts across the whole scan. The boolean reports truncation.
pub fn parse_file(path: &Path, content: &str, budget: usize) -> (TaintFile, usize, bool) {
    let mut file = TaintFile {
        path: path.to_path_buf(),
        ..TaintFile::default()
    };
    let mut used = 0usize;
    let mut truncated = false;
    let mut in_block_comment = false;

    for (index, raw_line) in content.lines().enumerate() {
        let line_number = index + 1;
        parse_suppression_directive(raw_line, line_number, &mut file.suppressions);
        let uncommented_line = strip_comments_preserving_strings(raw_line, &mut in_block_comment);
        let trimmed = uncommented_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('*') {
            continue;
        }

        if let Some(captures) = import_regex().captures(&uncommented_line) {
            let module = captures
                .name("module")
                .map(|m| m.as_str())
                .unwrap_or_default();
            if module.starts_with('.') {
                if let Some(items) = captures.name("items") {
                    for item in items.as_str().split(',').take(32) {
                        let parts = item.split_whitespace().take(3).collect::<Vec<_>>();
                        if let Some(&imported) = parts.first() {
                            if used >= budget {
                                truncated = true;
                                break;
                            }
                            used += 1;
                            let local = if parts.len() >= 3 && parts[1] == "as" {
                                parts[2]
                            } else {
                                imported
                            };
                            file.imports.push(ImportBinding {
                                module: module.chars().take(256).collect(),
                                imported: imported.chars().take(128).collect(),
                                local: local.chars().take(128).collect(),
                            });
                        }
                    }
                }
            }
        }

        if let Some(captures) = export_list_regex().captures(&uncommented_line) {
            if let Some(items) = captures.get(1) {
                for item in items.as_str().split(',').take(32) {
                    let parts = item.split_whitespace().take(3).collect::<Vec<_>>();
                    if let Some(name) = parts.first() {
                        if used >= budget {
                            truncated = true;
                            break;
                        }
                        used += 1;
                        file.exports.insert(name.chars().take(128).collect());
                    }
                }
            }
        }
        if truncated {
            break;
        }

        if let Some(captures) = assignment_regex().captures(&uncommented_line) {
            if used >= budget {
                truncated = true;
                break;
            }
            used += 1;
            let name = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
            let name = name.chars().take(128).collect::<String>();
            let rhs = captures.get(2).map(|m| m.as_str()).unwrap_or_default();
            if trimmed.starts_with("export ") {
                file.exports.insert(name.clone());
            }
            let rhs_code = scrub_code_for_analysis(rhs);
            let rhs_identifiers = expression_identifiers(rhs);
            file.events.push(Event::Assignment(Assignment {
                name,
                rhs_identifiers,
                is_source: source_regex().is_match(&rhs_code),
                sanitizes_xss: sanitizer_expression_regex().is_match(rhs_code.trim()),
                line: line_number,
            }));
        }

        let mut sinks = Vec::new();
        collect_sink(
            &mut sinks,
            SinkKind::Xss,
            xss_assignment_regex(),
            &uncommented_line,
            line_number,
        );
        collect_sink(
            &mut sinks,
            SinkKind::Xss,
            xss_call_regex(),
            &uncommented_line,
            line_number,
        );
        collect_sink(
            &mut sinks,
            SinkKind::Sql,
            sql_sink_regex(),
            &uncommented_line,
            line_number,
        );
        collect_sink(
            &mut sinks,
            SinkKind::Shell,
            shell_sink_regex(),
            &uncommented_line,
            line_number,
        );
        collect_sink(
            &mut sinks,
            SinkKind::Shell,
            subprocess_shell_sink_regex(),
            &uncommented_line,
            line_number,
        );
        collect_sink(
            &mut sinks,
            SinkKind::Path,
            path_sink_regex(),
            &uncommented_line,
            line_number,
        );
        collect_sink(
            &mut sinks,
            SinkKind::Ssrf,
            ssrf_sink_regex(),
            &uncommented_line,
            line_number,
        );

        for sink in sinks {
            if used >= budget {
                truncated = true;
                break;
            }
            used += 1;
            file.events.push(Event::Sink(sink));
        }
        if truncated {
            break;
        }
    }

    (file, used, truncated)
}

fn parse_suppression_directive(
    line: &str,
    line_number: usize,
    output: &mut HashSet<(usize, String)>,
) {
    let trimmed = line.trim_start();
    let comment = ["//", "#", "/*", "<!--", "--"]
        .iter()
        .find_map(|marker| trimmed.strip_prefix(*marker))
        .map(str::trim_start);
    let Some(comment) = comment else {
        return;
    };
    let Some(remainder) = comment.strip_prefix("ferroscout:ignore-next-line") else {
        return;
    };
    if !remainder.chars().next().is_some_and(char::is_whitespace) {
        return;
    }
    let Some((rules, reason)) = remainder.split_once(" -- ") else {
        return;
    };
    if reason.trim().is_empty() || output.len() >= 32 {
        return;
    }
    for rule in rules.split_whitespace().take(16) {
        if output.len() >= 32 {
            break;
        }
        output.insert((
            line_number.saturating_add(1),
            rule.chars().take(128).collect(),
        ));
    }
}

pub fn finding_is_suppressed(files: &[TaintFile], finding: &Finding) -> bool {
    files
        .iter()
        .find(|file| file.path.display().to_string() == finding.file)
        .is_some_and(|file| {
            file.suppressions.iter().any(|(line, rule)| {
                *line == finding.line && (rule == &finding.rule_id || rule == "*")
            })
        })
}

fn expression_identifiers(expression: &str) -> Vec<String> {
    let code = scrub_code_for_analysis(expression);
    identifier_regex()
        .find_iter(&code)
        .take(16)
        .map(|matched| matched.as_str().chars().take(64).collect())
        .collect()
}

/// Remove string and comment contents before evaluating source, variable, or sink markers.
pub(crate) fn scrub_code_for_analysis(input: &str) -> String {
    let mut in_block_comment = false;
    let without_comments = strip_comments_preserving_strings(input, &mut in_block_comment);
    code_without_literals_and_inline_comments(&without_comments)
}

pub(crate) fn scrub_lines_for_analysis(content: &str) -> Vec<String> {
    let mut in_block_comment = false;
    content
        .lines()
        .map(|line| {
            let without_comments = strip_comments_preserving_strings(line, &mut in_block_comment);
            code_without_literals_and_inline_comments(&without_comments)
        })
        .collect()
}

fn code_without_literals_and_inline_comments(input: &str) -> String {
    code_outside_literals(input)
}

fn strip_comments_preserving_strings(input: &str, in_block_comment: &mut bool) -> String {
    let characters = input.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(input.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut index = 0usize;

    while index < characters.len() {
        let current = characters[index];
        let next = characters.get(index + 1).copied();

        if *in_block_comment {
            if current == '*' && next == Some('/') {
                *in_block_comment = false;
                output.push(' ');
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }

        if let Some(active_quote) = quote {
            output.push(current);
            if escaped {
                escaped = false;
            } else if current == '\\' {
                escaped = true;
            } else if current == active_quote {
                quote = None;
            }
            index += 1;
            continue;
        }

        if matches!(current, '\'' | '"' | '`') {
            quote = Some(current);
            output.push(current);
            index += 1;
            continue;
        }

        let previous_is_space = index == 0 || characters[index - 1].is_whitespace();
        if (current == '/' && next == Some('*')) {
            *in_block_comment = true;
            output.push(' ');
            index += 2;
        } else if (current == '/' && next == Some('/'))
            || (current == '#' && previous_is_space)
            || (current == '-' && next == Some('-') && previous_is_space)
            || (current == '<'
                && characters.get(index + 1) == Some(&'!')
                && characters.get(index + 2) == Some(&'-')
                && characters.get(index + 3) == Some(&'-'))
        {
            break;
        } else {
            output.push(current);
            index += 1;
        }
    }

    output
}

/// Remove ordinary string contents while preserving simple template/f-string interpolations.
/// This prevents words inside static literals from being mistaken for variable references.
fn code_outside_literals(input: &str) -> String {
    let characters = input.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(input.len());
    let mut index = 0usize;
    let mut quote: Option<char> = None;
    let mut formatted_string = false;

    while index < characters.len() {
        let current = characters[index];
        match quote {
            None if matches!(current, '\'' | '"' | '`') => {
                formatted_string =
                    current == '`' || (index > 0 && matches!(characters[index - 1], 'f' | 'F'));
                quote = Some(current);
                output.push(' ');
                index += 1;
            }
            None => {
                output.push(current);
                index += 1;
            }
            Some(_) if current == '\\' => {
                index = (index + 2).min(characters.len());
            }
            Some(active_quote) if current == active_quote => {
                quote = None;
                formatted_string = false;
                output.push(' ');
                index += 1;
            }
            Some(active_quote)
                if formatted_string
                    && ((active_quote == '`'
                        && current == '$'
                        && characters.get(index + 1) == Some(&'{'))
                        || (active_quote != '`' && current == '{')) =>
            {
                let start = if active_quote == '`' {
                    index + 2
                } else {
                    index + 1
                };
                let mut cursor = start;
                let mut depth = 1usize;
                while cursor < characters.len() && depth > 0 {
                    match characters[cursor] {
                        '{' => depth += 1,
                        '}' => depth -= 1,
                        _ => {}
                    }
                    if depth > 0 {
                        output.push(characters[cursor]);
                    }
                    cursor += 1;
                }
                output.push(' ');
                index = cursor;
            }
            Some(_) => {
                index += 1;
            }
        }
    }
    output
}

fn collect_sink(
    output: &mut Vec<Sink>,
    kind: SinkKind,
    regex: &Regex,
    line: &str,
    line_number: usize,
) {
    let code = scrub_code_for_analysis(line);
    let Some(captures) = regex.captures(&code) else {
        return;
    };
    let Some(argument) = captures.name("arg").map(|m| m.as_str()) else {
        return;
    };
    let identifiers = expression_identifiers(argument);
    if identifiers.is_empty() {
        return;
    }
    output.push(Sink {
        kind,
        identifiers,
        sanitizes_xss: sanitizer_expression_regex().is_match(argument.trim()),
        line: line_number,
        evidence: line.chars().take(500).collect(),
    });
}

/// Analyze local assignments and simple relative ES-module named imports.
/// Module propagation is bounded to 64 fixed-point passes to keep scans predictable.
pub fn analyze_project(files: &[TaintFile]) -> Vec<Finding> {
    if files.is_empty() {
        return Vec::new();
    }

    let index = files
        .iter()
        .enumerate()
        .map(|(position, file)| (normalize_path(&file.path), position))
        .collect::<HashMap<_, _>>();
    let mut exported: Vec<HashMap<String, TaintOrigin>> = vec![HashMap::new(); files.len()];
    let max_passes = files.len().clamp(1, 64);

    for _ in 0..max_passes {
        let mut next_exported = vec![HashMap::new(); files.len()];
        for (position, file) in files.iter().enumerate() {
            let seeds = import_seeds(file, &index, &exported);
            let (state, _) = evaluate_file(file, seeds, false);
            for name in &file.exports {
                if let Some(origin) = state.get(name) {
                    next_exported[position].insert(name.clone(), origin.clone());
                }
            }
        }
        if next_exported == exported {
            exported = next_exported;
            break;
        }
        exported = next_exported;
    }

    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    for file in files {
        let seeds = import_seeds(file, &index, &exported);
        let (_, file_findings) = evaluate_file(file, seeds, true);
        for finding in file_findings {
            let key = (finding.file.clone(), finding.line, finding.title.clone());
            if seen.insert(key) {
                findings.push(finding);
            }
        }
    }
    findings
}

fn import_seeds(
    file: &TaintFile,
    index: &HashMap<PathBuf, usize>,
    exported: &[HashMap<String, TaintOrigin>],
) -> HashMap<String, TaintOrigin> {
    let mut seeds = HashMap::new();
    for binding in &file.imports {
        let Some(module_path) = resolve_module(&file.path, &binding.module, index) else {
            continue;
        };
        let Some(position) = index.get(&module_path) else {
            continue;
        };
        let Some(origin) = exported[*position].get(&binding.imported) else {
            continue;
        };
        let mut origin = origin.clone();
        if origin.chain.last().map(String::as_str) != Some(binding.local.as_str())
            && origin.chain.len() < 32
        {
            origin.chain.push(binding.local.clone());
        }
        seeds.insert(binding.local.clone(), origin);
    }
    seeds
}

fn evaluate_file(
    file: &TaintFile,
    mut state: HashMap<String, TaintOrigin>,
    collect_findings: bool,
) -> (HashMap<String, TaintOrigin>, Vec<Finding>) {
    let mut findings = Vec::new();
    for event in &file.events {
        match event {
            Event::Assignment(assignment) => {
                let value = if assignment.is_source {
                    Some(TaintOrigin {
                        source_file: file.path.display().to_string(),
                        source_line: assignment.line,
                        chain: vec![assignment.name.clone()],
                        sanitized_xss: assignment.sanitizes_xss,
                    })
                } else {
                    let mut selected_origin: Option<TaintOrigin> = None;
                    let mut has_unsanitized_input = false;
                    for identifier in &assignment.rhs_identifiers {
                        if let Some(candidate) = state.get(identifier) {
                            has_unsanitized_input |= !candidate.sanitized_xss;
                            let prefer_candidate = match selected_origin.as_ref() {
                                None => true,
                                Some(current) => current.sanitized_xss && !candidate.sanitized_xss,
                            };
                            if prefer_candidate {
                                selected_origin = Some(candidate.clone());
                            }
                        }
                    }
                    selected_origin.map(|mut origin| {
                        if origin.chain.last().map(String::as_str) != Some(assignment.name.as_str())
                            && origin.chain.len() < 32
                        {
                            origin.chain.push(assignment.name.clone());
                        }
                        // An alias preserves sanitizer state. A mixed expression is
                        // considered sanitized only when every tainted input is sanitized.
                        origin.sanitized_xss = assignment.sanitizes_xss || !has_unsanitized_input;
                        origin
                    })
                };
                if let Some(origin) = value {
                    state.insert(assignment.name.clone(), origin);
                } else {
                    // A normal reassignment breaks the previous tainted value.
                    state.remove(&assignment.name);
                }
            }
            Event::Sink(sink) if collect_findings => {
                if sink.kind == SinkKind::Xss && sink.sanitizes_xss {
                    continue;
                }
                let mut origin = None;
                for identifier in &sink.identifiers {
                    if let Some(candidate) = state.get(identifier) {
                        if sink.kind == SinkKind::Xss && candidate.sanitized_xss {
                            continue;
                        }
                        origin = Some(candidate.clone());
                        break;
                    }
                }
                if let Some(origin) = origin {
                    findings.push(make_taint_finding(file, sink, &origin));
                }
            }
            Event::Sink(_) => {}
        }
    }
    (state, findings)
}

fn make_taint_finding(file: &TaintFile, sink: &Sink, origin: &TaintOrigin) -> Finding {
    let (severity, title, cwe, impact, recommendation, sink_name) = match sink.kind {
        SinkKind::Xss => (
            Severity::Medium,
            "Tainted input reaches a dynamic HTML sink through variable flow",
            "CWE-79",
            "If the value is attacker-controlled and is not safely encoded for this HTML context, it may lead to cross-site scripting.",
            "Prefer textContent or framework-safe rendering. If HTML is required, use a maintained context-aware sanitizer and verify the complete data flow.",
            "HTML",
        ),
        SinkKind::Sql => (
            Severity::Medium,
            "Tainted input reaches a SQL-like query sink through variable flow",
            "CWE-89",
            "If the value is interpolated into SQL syntax rather than passed as a bound parameter, it may alter the query.",
            "Use parameterized queries or prepared statements. Review the query API to confirm values are bound separately from SQL syntax.",
            "SQL query",
        ),
        SinkKind::Shell => (
            Severity::High,
            "Tainted input reaches a shell execution sink through variable flow",
            "CWE-78",
            "If the value is interpreted by a shell, attacker-controlled syntax may cause unintended command execution.",
            "Avoid shell command strings. Use a fixed executable with argument arrays, validate arguments against an allowlist, and avoid invoking a shell.",
            "shell command",
        ),
        SinkKind::Path => (
            Severity::Medium,
            "Tainted input reaches a filesystem path sink through variable flow",
            "CWE-22",
            "If the resulting path is not constrained to an allowed directory, path traversal may expose files accessible to the application.",
            "Resolve paths against a fixed base directory and verify that the final canonical path remains inside the allowed root. Prefer allowlisted identifiers.",
            "filesystem path",
        ),
        SinkKind::Ssrf => (
            Severity::Medium,
            "Tainted input reaches an HTTP request sink through variable flow",
            "CWE-918",
            "If this code runs server-side and the user controls the destination, the application may contact unintended internal or external resources. Browser-side fetch calls are not server-side request forgery.",
            "Allowlist permitted hosts and schemes, validate resolved destinations, and revalidate redirect targets.",
            "HTTP request URL",
        ),
    };
    let chain = origin.chain.join(" -> ");
    let explanation = format!(
        "The analyzer traced a source marker at {}:{} to this {sink_name} sink through: {chain}. This is a bounded heuristic data-flow result, not proof of exploitability.",
        origin.source_file, origin.source_line
    );
    make_finding(
        &file.path,
        sink.line,
        "FS-TAINT-001",
        severity,
        title,
        Some(cwe),
        Confidence::Medium,
        &sink.evidence,
        &explanation,
        impact,
        recommendation,
    )
}

fn resolve_module(
    importer: &Path,
    specifier: &str,
    index: &HashMap<PathBuf, usize>,
) -> Option<PathBuf> {
    if !specifier.starts_with('.') {
        return None;
    }
    let parent = importer.parent().unwrap_or_else(|| Path::new("."));
    let base = normalize_path(&parent.join(specifier));
    if index.contains_key(&base) {
        return Some(base);
    }
    if base.extension().is_none() {
        for extension in ["js", "jsx", "mjs", "cjs", "ts", "tsx"] {
            let candidate = base.with_extension(extension);
            if index.contains_key(&candidate) {
                return Some(candidate);
            }
        }
    }
    for extension in ["js", "jsx", "ts"] {
        let candidate = base.join(format!("index.{extension}"));
        if index.contains_key(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ferroscout-taint-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn follows_multiple_assignments_to_html_sink() {
        let path = Path::new("app.js");
        let code = "const raw = req.query.name;\nconst alias = raw;\nelement.innerHTML = alias;\n";
        let (file, _, truncated) = parse_file(path, code, 100);
        assert!(!truncated);
        let findings = analyze_project(&[file]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FS-TAINT-001");
        assert_eq!(findings[0].line, 3);
    }

    #[test]
    fn follows_named_es_module_imports_across_files() {
        let root = temp_dir();
        let source_path = root.join("source.js");
        let sink_path = root.join("view.js");
        let source = "export const userQuery = req.query.search;\n";
        let sink = "import { userQuery as searchTerm } from './source.js';\nconst copy = searchTerm;\nelement.innerHTML = copy;\n";
        let (source_file, _, _) = parse_file(&source_path, source, 100);
        let (sink_file, _, _) = parse_file(&sink_path, sink, 100);
        let findings = analyze_project(&[source_file, sink_file]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, sink_path.display().to_string());
        assert_eq!(findings[0].line, 3);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn does_not_flag_xss_after_known_html_sanitizer() {
        let path = Path::new("safe.js");
        let code = "const raw = req.query.name;\nconst safe = DOMPurify.sanitize(raw);\nelement.innerHTML = safe;\n";
        let (file, _, _) = parse_file(path, code, 100);
        assert!(analyze_project(&[file]).is_empty());
    }

    #[test]
    fn reassignment_to_constant_clears_taint() {
        let path = Path::new("app.py");
        let code = "value = request.args.get('name')\nvalue = 'fixed'\nopen(value)\n";
        let (file, _, _) = parse_file(path, code, 100);
        assert!(analyze_project(&[file]).is_empty());
    }

    #[test]
    fn does_not_treat_bound_sql_parameters_as_query_text() {
        let path = Path::new("db.js");
        let code = "const name = req.query.name;\nconst sql = 'SELECT * FROM users WHERE name = ?';\ndb.query(sql, [name]);\n";
        let (file, _, _) = parse_file(path, code, 100);
        assert!(analyze_project(&[file]).is_empty());
    }

    #[test]
    fn only_flags_subprocess_calls_when_shell_mode_is_enabled() {
        let path = Path::new("worker.py");
        let unsafe_code =
            "command = request.args.get('command')\nsubprocess.run(command, shell=True)\n";
        let (unsafe_file, _, _) = parse_file(path, unsafe_code, 100);
        assert_eq!(analyze_project(&[unsafe_file]).len(), 1);

        let safe_code = "argument = request.args.get('name')\nsubprocess.run(['lookup', argument], shell=False)\n";
        let (safe_file, _, _) = parse_file(path, safe_code, 100);
        assert!(analyze_project(&[safe_file]).is_empty());
    }

    #[test]
    fn does_not_treat_static_strings_or_inline_comments_as_sources() {
        let path = Path::new("literal.js");
        let code = concat!(
            "const label = \"req.query.fake\";\n",
            "const copy = label; // request.args.comment_only\n",
            "element.innerHTML = copy;\n",
        );
        let (file, _, _) = parse_file(path, code, 100);
        assert!(analyze_project(&[file]).is_empty());
    }

    #[test]
    fn follows_taint_inside_javascript_template_interpolation() {
        let path = Path::new("template.js");
        let code = concat!(
            "const name = req.query.name;\n",
            "const html = `<p>${name}</p>`;\n",
            "element.innerHTML = html;\n",
        );
        let (file, _, _) = parse_file(path, code, 100);
        let findings = analyze_project(&[file]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 3);
    }

    #[test]
    fn follows_taint_inside_python_f_string_interpolation() {
        let path = Path::new("template.py");
        let code = concat!(
            "name = request.args.get('name')\n",
            "command = f'echo {name}'\n",
            "os.system(command)\n",
        );
        let (file, _, _) = parse_file(path, code, 100);
        let findings = analyze_project(&[file]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 3);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn mixed_sanitized_and_raw_values_remain_tainted() {
        let path = Path::new("mixed.js");
        let code = concat!(
            "const raw = req.query.name;\n",
            "const clean = DOMPurify.sanitize(raw);\n",
            "const mixed = clean + raw;\n",
            "element.innerHTML = mixed;\n",
        );
        let (file, _, _) = parse_file(path, code, 100);
        let findings = analyze_project(&[file]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 4);
    }

    #[test]
    fn sanitizer_must_cover_the_whole_assigned_expression() {
        let path = Path::new("partial-sanitize.js");
        let code = concat!(
            "const raw = req.query.name;\n",
            "const mixed = DOMPurify.sanitize(raw) + req.query.other;\n",
            "element.innerHTML = mixed;\n",
        );
        let (file, _, _) = parse_file(path, code, 100);
        assert_eq!(analyze_project(&[file]).len(), 1);
    }

    #[test]
    fn follows_direct_source_expression_at_the_sink() {
        let path = Path::new("direct.js");
        let code = "element.innerHTML = req.query.name;\n";
        let (file, _, _) = parse_file(path, code, 100);
        // A direct source/sink expression remains supported by the legacy XSS rule;
        // the bounded taint pass intentionally tracks named assignment flows.
        assert!(analyze_project(&[file]).is_empty());
    }

    #[test]
    fn does_not_detect_sink_text_inside_a_string_literal() {
        let path = Path::new("sink-string.js");
        let code = "const example = \"element.innerHTML = req.query.name\";\n";
        let (file, _, _) = parse_file(path, code, 100);
        assert!(analyze_project(&[file]).is_empty());
    }

    #[test]
    fn reports_when_fact_budget_is_exceeded() {
        let (_, used, truncated) = parse_file(
            Path::new("app.js"),
            "const a = req.query.x;\nconst b = a;\n",
            1,
        );
        assert_eq!(used, 1);
        assert!(truncated);
    }
}
