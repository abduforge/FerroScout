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

    let mut report = ScanReport {
        tool: "FerroScout".to_owned(),
        version: VERSION.to_owned(),
        target: target.display().to_string(),
        status: crate::models::ScanStatus::InsufficientContext,
        files_scanned: 0,
        entries_skipped: 0,
        findings: Vec::new(),
        scan_errors: Vec::new(),
    };

    let max_file_size = options.max_file_size.min(MAX_ALLOWED_FILE_SIZE);
    if metadata.is_file() {
        scan_one_file(target, max_file_size, &mut report);
    } else if metadata.is_dir() {
        let bounded_options = ScanOptions {
            excludes: options.excludes.clone(),
            max_file_size,
        };
        scan_directory(target, &bounded_options, &mut report);
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "scan target is not a regular file or directory",
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

fn scan_directory(root: &Path, options: &ScanOptions, report: &mut ScanReport) {
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
                scan_one_file(&path, options.max_file_size, report);
            }
        }
    }
}

fn scan_one_file(path: &Path, max_file_size: u64, report: &mut ScanReport) {
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
    report.findings.extend(rules::scan_file(path, &contents));
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

pub fn filter_findings(findings: &mut [Finding], minimum: Option<Severity>) {
    if let Some(minimum) = minimum {
        findings.retain(|finding| finding.severity.rank() >= minimum.rank());
    }
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
        fs::write(&file, "print('hello')\nrequests.get(url, verify=False)\n").unwrap();
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
        fs::write(root.join("vendor/app.py"), "app.run(debug=True)\n").unwrap();
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
    fn missing_target_returns_error() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let missing = std::env::temp_dir().join(format!("ferroscout-missing-{nonce}"));
        assert!(scan_target(&missing, &ScanOptions::default()).is_err());
    }
}
