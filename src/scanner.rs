use crate::models::{Finding, ScanReport, Severity};
use crate::rules;
use crate::VERSION;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub const MAX_ALLOWED_FILE_SIZE: u64 = 16 * 1024 * 1024;

const DEFAULT_EXCLUDES: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".idea",
    ".vscode",
];

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub excludes: Vec<String>,
    pub max_file_size: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            excludes: Vec::new(),
            max_file_size: 2 * 1024 * 1024,
        }
    }
}

pub fn scan_target(target: &Path, options: &ScanOptions) -> io::Result<ScanReport> {
    let metadata = fs::symlink_metadata(target)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the scan target itself is a symbolic link",
        ));
    }

    let mut taint_files = Vec::new();
    let mut taint_budget = rules::taint::MAX_PROJECT_TAINT_FACTS;
    let mut taint_truncated = false;

    let mut report = ScanReport {
        tool: "FerroScout".to_owned(),
        version: VERSION.to_owned(),
        target: target.display().to_string(),
        status: crate::models::ScanStatus::InsufficientContext,
        files_scanned: 0,
        entries_skipped: 0,
        suppressed_findings: 0,
        filtered_findings: 0,
        findings: Vec::new(),
        scan_errors: Vec::new(),
    };

    let max_file_size = options.max_file_size.min(MAX_ALLOWED_FILE_SIZE);
    if metadata.is_file() {
        scan_one_file(
            target,
            max_file_size,
            &mut report,
            &mut taint_files,
            &mut taint_budget,
            &mut taint_truncated,
        );
    } else if metadata.is_dir() {
        let bounded_options = ScanOptions {
            excludes: options.excludes.clone(),
            max_file_size,
        };
        scan_directory(
            target,
            &bounded_options,
            &mut report,
            &mut taint_files,
            &mut taint_budget,
            &mut taint_truncated,
        );
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "scan target is not a regular file or directory",
        ));
    }

    let taint_findings = rules::taint::analyze_project(&taint_files);
    let mut taint_locations = HashSet::new();
    let mut active_taint_findings = Vec::new();
    for finding in taint_findings {
        if rules::taint::finding_is_suppressed(&taint_files, &finding) {
            report.suppressed_findings += 1;
            continue;
        }
        if let Some(rule_id) = superseded_pattern_rule(&finding.title) {
            taint_locations.insert((finding.file.clone(), finding.line, rule_id.to_owned()));
        }
        active_taint_findings.push(finding);
    }
    report.findings.retain(|finding| {
        !taint_locations.contains(&(finding.file.clone(), finding.line, finding.rule_id.clone()))
    });
    report.findings.extend(active_taint_findings);
    if taint_truncated {
        report.scan_errors.push(format!(
            "data-flow indexing reached a project bound ({} supported files or {} facts); pattern checks continued, but some taint paths may not have been analyzed",
            rules::taint::MAX_PROJECT_TAINT_FILES,
            rules::taint::MAX_PROJECT_TAINT_FACTS
        ));
    }

    report.findings.sort_by_key(|finding| {
        (
            finding.file.clone(),
            finding.line,
            std::cmp::Reverse(finding.severity.rank()),
        )
    });
    report.refresh_status();
    Ok(report)
}

fn superseded_pattern_rule(title: &str) -> Option<&'static str> {
    if title.contains("dynamic HTML sink") {
        Some("FS-XSS-001")
    } else if title.contains("SQL-like query sink") || title.contains("shell execution sink") {
        Some("FS-INJECT-001")
    } else if title.contains("filesystem path sink") {
        Some("FS-PATH-001")
    } else if title.contains("HTTP request sink") {
        Some("FS-SSRF-001")
    } else {
        None
    }
}

fn scan_directory(
    root: &Path,
    options: &ScanOptions,
    report: &mut ScanReport,
    taint_files: &mut Vec<rules::taint::TaintFile>,
    taint_budget: &mut usize,
    taint_truncated: &mut bool,
) {
    let mut pending = vec![root.to_path_buf()];
    let excluded: HashSet<String> = options.excludes.iter().cloned().collect();

    while let Some(directory) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                report.scan_errors.push(format!(
                    "cannot read directory {}: {error}",
                    directory.display()
                ));
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    report.scan_errors.push(format!(
                        "cannot inspect an entry in {}: {error}",
                        directory.display()
                    ));
                    continue;
                }
            };
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().into_owned();
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            if DEFAULT_EXCLUDES.contains(&file_name.as_str())
                || excluded.contains(&file_name)
                || excluded.contains(&relative)
            {
                report.entries_skipped += 1;
                continue;
            }

            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    report
                        .scan_errors
                        .push(format!("cannot inspect {}: {error}", path.display()));
                    continue;
                }
            };
            if file_type.is_symlink() {
                report.entries_skipped += 1;
                continue;
            }
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() && is_supported_file(&path) {
                scan_one_file(
                    &path,
                    options.max_file_size,
                    report,
                    taint_files,
                    taint_budget,
                    taint_truncated,
                );
            }
        }
    }
}

fn scan_one_file(
    path: &Path,
    max_file_size: u64,
    report: &mut ScanReport,
    taint_files: &mut Vec<rules::taint::TaintFile>,
    taint_budget: &mut usize,
    taint_truncated: &mut bool,
) {
    if !is_supported_file(path) {
        report.entries_skipped += 1;
        return;
    }

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_symlink() => metadata,
        Ok(_) => {
            report.entries_skipped += 1;
            return;
        }
        Err(error) => {
            report
                .scan_errors
                .push(format!("cannot inspect {}: {error}", path.display()));
            return;
        }
    };
    if metadata.len() > max_file_size {
        report.entries_skipped += 1;
        return;
    }

    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            report
                .scan_errors
                .push(format!("cannot open {}: {error}", path.display()));
            return;
        }
    };
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    if let Err(error) = file
        .take(max_file_size.saturating_add(1))
        .read_to_end(&mut bytes)
    {
        report
            .scan_errors
            .push(format!("cannot read {}: {error}", path.display()));
        return;
    }
    if bytes.len() as u64 > max_file_size {
        report.entries_skipped += 1;
        return;
    }
    if bytes.contains(&0) {
        report.entries_skipped += 1;
        return;
    }

    let contents = String::from_utf8_lossy(&bytes);
    report.files_scanned += 1;
    let lines: Vec<&str> = contents.lines().collect();
    for finding in rules::scan_file(path, &contents) {
        if is_suppressed(&lines, finding.line, &finding.rule_id) {
            report.suppressed_findings += 1;
        } else {
            report.findings.push(finding);
        }
    }
    if taint_files.len() < rules::taint::MAX_PROJECT_TAINT_FILES {
        let (facts, used, truncated) = rules::taint::parse_file(path, &contents, *taint_budget);
        *taint_budget = (*taint_budget).saturating_sub(used);
        *taint_truncated |= truncated;
        taint_files.push(facts);
    } else {
        *taint_truncated = true;
    }
}

/// A suppression must be a full-line comment, name an exact rule ID (or `*`),
/// and include a reason. Supported comment starts: `//`, `#`, `/*`, `<!--`, `--`.
/// Example: `# ferroscout:ignore-next-line FS-TLS-001 -- local test fixture`
fn directive_matches(line: &str, rule_id: &str) -> bool {
    let trimmed = line.trim_start();
    let comment = ["//", "#", "/*", "<!--", "--"]
        .iter()
        .find_map(|marker| trimmed.strip_prefix(*marker))
        .map(str::trim_start);
    let Some(comment) = comment else {
        return false;
    };
    let Some(remainder) = comment.strip_prefix("ferroscout:ignore-next-line") else {
        return false;
    };
    if !remainder.chars().next().is_some_and(char::is_whitespace) {
        return false;
    }
    let Some((rules, reason)) = remainder.split_once(" -- ") else {
        return false;
    };
    if reason.trim().is_empty() {
        return false;
    }
    rules
        .split_whitespace()
        .any(|candidate| candidate == rule_id || candidate == "*")
}

fn is_suppressed(lines: &[&str], finding_line: usize, rule_id: &str) -> bool {
    let Some(current_index) = finding_line.checked_sub(1) else {
        return false;
    };
    current_index
        .checked_sub(1)
        .and_then(|index| lines.get(index))
        .is_some_and(|line| directive_matches(line, rule_id))
}

fn is_supported_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if name == ".env"
        || name.starts_with(".env.")
        || matches!(
            name,
            "Dockerfile" | "docker-compose.yml" | ".htaccess" | ".npmrc" | ".pypirc" | ".netrc"
        )
    {
        return true;
    }
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "rs" | "js"
            | "jsx"
            | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "py"
            | "php"
            | "java"
            | "go"
            | "rb"
            | "yml"
            | "yaml"
            | "json"
            | "toml"
            | "ini"
            | "env"
            | "conf"
            | "cfg"
            | "properties"
            | "xml"
            | "html"
            | "htm"
            | "vue"
            | "svelte"
            | "sh"
            | "bash"
            | "sql"
            | "gradle"
            | "tf"
            | "hcl"
            | "lock"
            | "http"
            | "har"
            | "txt"
    )
}

pub fn filter_findings(
    findings: &mut Vec<Finding>,
    minimum: Option<Severity>,
    excluded_rules: &[String],
) -> usize {
    let before = findings.len();
    findings.retain(|finding| {
        let excluded_by_rule = excluded_rules.iter().any(|rule| rule == &finding.rule_id);
        let below_minimum = minimum.is_some_and(|minimum| finding.severity.rank() < minimum.rank());
        !excluded_by_rule && !below_minimum
    });
    before - findings.len()
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
            std::env::temp_dir().join(format!("ferroscout-test-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn scans_supported_source_file_and_reports_line() {
        let root = temp_dir();
        let file = root.join("app.py");
        fs::write(
            &file,
            concat!("print('hello')\nrequests.get(url, verify=", "False)\n"),
        )
        .unwrap();
        let report = scan_target(&file, &ScanOptions::default()).unwrap();
        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.findings[0].line, 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn skips_binary_and_large_files() {
        let root = temp_dir();
        let binary = root.join("binary.js");
        let large = root.join("large.py");
        fs::write(&binary, &[0_u8, 1, 2]).unwrap();
        fs::write(&large, "x".repeat(128)).unwrap();
        let options = ScanOptions {
            excludes: Vec::new(),
            max_file_size: 32,
        };
        let report = scan_target(&root, &options).unwrap();
        assert_eq!(report.files_scanned, 0);
        assert_eq!(report.entries_skipped, 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn skips_excluded_directories() {
        let root = temp_dir();
        fs::create_dir_all(root.join("vendor")).unwrap();
        fs::write(
            root.join("vendor/app.py"),
            concat!("app.run(debug=", "True)\n"),
        )
        .unwrap();
        fs::write(root.join("app.py"), "print('ok')\n").unwrap();
        let report = scan_target(&root, &ScanOptions::default()).unwrap();
        assert_eq!(report.files_scanned, 1);
        assert!(report.findings.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_directory_has_insufficient_context_status() {
        let root = temp_dir();
        let report = scan_target(&root, &ScanOptions::default()).unwrap();
        assert_eq!(
            report.status,
            crate::models::ScanStatus::InsufficientContext
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn next_line_suppression_works_and_requires_a_reason() {
        let root = temp_dir();
        let file = root.join("app.py");
        fs::write(&file, "# ferroscout:ignore-next-line FS-TLS-001 -- local test fixture\nrequests.get(url, verify=False)\n").unwrap();
        let report = scan_target(&file, &ScanOptions::default()).unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.suppressed_findings, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn suppression_without_reason_does_not_hide_a_finding() {
        let root = temp_dir();
        let file = root.join("app.py");
        fs::write(
            &file,
            "# ferroscout:ignore-next-line FS-TLS-001\nrequests.get(url, verify=False)\n",
        )
        .unwrap();
        let report = scan_target(&file, &ScanOptions::default()).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.suppressed_findings, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn suppression_directive_inside_a_string_does_not_suppress() {
        let root = temp_dir();
        let file = root.join("app.py");
        fs::write(&file, "message = '# ferroscout:ignore-next-line FS-TLS-001 -- not a comment'\nrequests.get(url, verify=False)\n").unwrap();
        let report = scan_target(&file, &ScanOptions::default()).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.suppressed_findings, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn detects_taint_flow_across_named_module_imports() {
        let root = temp_dir();
        fs::write(
            root.join("source.js"),
            "export const userQuery = req.query.search;\n",
        )
        .unwrap();
        fs::write(
            root.join("view.js"),
            "import { userQuery as searchTerm } from './source.js';\nconst copy = searchTerm;\nelement.innerHTML = copy;\n",
        )
        .unwrap();

        let report = scan_target(&root, &ScanOptions::default()).unwrap();
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == "FS-TAINT-001"
                && finding.file.ends_with("view.js")
                && finding.line == 3
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_comment_suppresses_taint_finding() {
        let root = temp_dir();
        fs::write(root.join("input.py"), "value = request.args.get('path')\ncopy = value\n# ferroscout:ignore-next-line FS-TAINT-001 -- test path is constrained by fixture setup\nopen(copy)\n").unwrap();
        let report = scan_target(&root, &ScanOptions::default()).unwrap();
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "FS-TAINT-001"));
        assert_eq!(report.suppressed_findings, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_target_returns_error() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let missing = std::env::temp_dir().join(format!("ferroscout-missing-{nonce}"));
        assert!(scan_target(&missing, &ScanOptions::default()).is_err());
    }
}
