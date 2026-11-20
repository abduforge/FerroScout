//! Persistent finding baselines for incremental security reviews.
//!
//! Fingerprints deliberately exclude line numbers so inserting lines above a
//! finding does not make it appear new. The stored baseline contains only
//! redacted metadata and a non-cryptographic digest, never source evidence.

use crate::models::{Finding, ScanReport};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const BASELINE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    schema_version: u32,
    tool: String,
    tool_version: String,
    findings: Vec<BaselineFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaselineFinding {
    fingerprint: String,
    rule_id: String,
    file: String,
    line: usize,
    title: String,
}

/// Capture all findings from a complete scan. Source evidence is not stored.
pub fn build_baseline(report: &ScanReport, target: &Path) -> Baseline {
    let findings = report
        .findings
        .iter()
        .map(|finding| BaselineFinding {
            fingerprint: fingerprint(finding, target),
            rule_id: finding.rule_id.clone(),
            file: relative_file(&finding.file, target),
            line: finding.line,
            title: finding.title.clone(),
        })
        .collect();

    Baseline {
        schema_version: BASELINE_SCHEMA_VERSION,
        tool: report.tool.clone(),
        tool_version: report.version.clone(),
        findings,
    }
}

pub fn save_baseline(path: &Path, baseline: &Baseline) -> Result<(), String> {
    let encoded = serde_json::to_vec_pretty(baseline)
        .map_err(|error| format!("cannot encode baseline: {error}"))?;
    fs::write(path, encoded)
        .map_err(|error| format!("cannot write baseline {}: {error}", path.display()))
}

pub fn load_baseline(path: &Path) -> Result<Baseline, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("cannot read baseline {}: {error}", path.display()))?;
    let baseline: Baseline = serde_json::from_str(&content)
        .map_err(|error| format!("invalid baseline {}: {error}", path.display()))?;

    if baseline.schema_version != BASELINE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported baseline schema version {} (this build supports {})",
            baseline.schema_version, BASELINE_SCHEMA_VERSION
        ));
    }
    if baseline.tool != "FerroScout" {
        return Err(format!(
            "baseline belongs to '{}', not FerroScout",
            baseline.tool
        ));
    }
    Ok(baseline)
}

/// Remove occurrences already present in the baseline while retaining newly
/// introduced occurrences. Duplicate findings are counted rather than using
/// a simple set, so one old occurrence cannot hide an additional new one.
pub fn apply_baseline(
    report: &mut ScanReport,
    baseline: &Baseline,
    target: &Path,
) -> Result<usize, String> {
    if baseline.schema_version != BASELINE_SCHEMA_VERSION || baseline.tool != "FerroScout" {
        return Err("baseline is incompatible with this version of FerroScout".to_owned());
    }

    let mut remaining: HashMap<&str, usize> = HashMap::new();
    for entry in &baseline.findings {
        *remaining.entry(entry.fingerprint.as_str()).or_insert(0) += 1;
    }

    let mut retained = Vec::with_capacity(report.findings.len());
    let mut suppressed = 0usize;
    for finding in report.findings.drain(..) {
        let key = fingerprint(&finding, target);
        match remaining.get_mut(key.as_str()) {
            Some(count) if *count > 0 => {
                *count -= 1;
                suppressed += 1;
            }
            _ => retained.push(finding),
        }
    }

    report.findings = retained;
    report.baseline_suppressed_findings += suppressed;
    report.refresh_status();
    Ok(suppressed)
}

fn fingerprint(finding: &Finding, target: &Path) -> String {
    let file = relative_file(&finding.file, target);
    let material = format!("{}\0{}\0{}", finding.rule_id, file, finding.evidence.trim());
    // FNV-1a 64-bit is used for a deterministic, dependency-free identifier.
    // It is not a cryptographic hash and must not be used for authentication.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in material.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn relative_file(file: &str, target: &Path) -> String {
    let file_path = Path::new(file);
    let relative = if target.is_file() {
        file_path.file_name().map(Path::new).unwrap_or(file_path)
    } else {
        file_path
            .strip_prefix(target)
            .unwrap_or_else(|_| file_path.file_name().map(Path::new).unwrap_or(file_path))
    };
    let normalized = relative.to_string_lossy().replace('\\', "/");
    normalized
        .strip_prefix("./")
        .unwrap_or(&normalized)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, ScanStatus, Severity};
    use std::path::PathBuf;

    fn finding(file: &str, line: usize, evidence: &str) -> Finding {
        Finding {
            severity: Severity::High,
            title: "Potential hardcoded credential".to_owned(),
            file: file.to_owned(),
            line,
            rule_id: "FS-SECRET-001".to_owned(),
            cwe: Some("CWE-798".to_owned()),
            confidence: Confidence::Medium,
            evidence: evidence.to_owned(),
            explanation: "Synthetic test finding.".to_owned(),
            impact: "Synthetic impact.".to_owned(),
            recommendation: "Use a secret store.".to_owned(),
        }
    }

    fn report(findings: Vec<Finding>, target: &str) -> ScanReport {
        ScanReport {
            tool: "FerroScout".to_owned(),
            version: "0.5.0".to_owned(),
            target: target.to_owned(),
            status: ScanStatus::FindingsFound,
            files_scanned: 1,
            entries_skipped: 0,
            suppressed_findings: 0,
            filtered_findings: 0,
            baseline_suppressed_findings: 0,
            findings,
            scan_errors: Vec::new(),
        }
    }

    #[test]
    fn fingerprint_ignores_line_number_and_scan_root() {
        let first_root = PathBuf::from("/tmp/project");
        let moved_root = PathBuf::from("/workspace/project");
        let first = finding("/tmp/project/src/app.py", 10, "password = [REDACTED]");
        let shifted = finding("/workspace/project/src/app.py", 99, "password = [REDACTED]");
        assert_eq!(
            fingerprint(&first, &first_root),
            fingerprint(&shifted, &moved_root)
        );
    }

    #[test]
    fn baseline_hides_old_findings_but_keeps_new_ones_and_duplicate_excess() {
        let root = PathBuf::from("/tmp/project");
        let old = finding("/tmp/project/src/app.py", 10, "password = [REDACTED]");
        let baseline_report = report(vec![old.clone()], "/tmp/project");
        let baseline = build_baseline(&baseline_report, &root);
        let mut current = report(
            vec![
                old.clone(),
                finding("/tmp/project/src/app.py", 11, "password = [REDACTED]"),
                finding("/tmp/project/src/other.py", 2, "token = [REDACTED]"),
            ],
            "/tmp/project",
        );

        let suppressed = apply_baseline(&mut current, &baseline, &root).unwrap();
        assert_eq!(suppressed, 1);
        assert_eq!(current.baseline_suppressed_findings, 1);
        assert_eq!(current.findings.len(), 2);
        assert!(current
            .findings
            .iter()
            .any(|item| item.file.ends_with("other.py")));
    }

    #[test]
    fn saved_baseline_does_not_contain_evidence_text() {
        let root = PathBuf::from("/tmp/project");
        let report = report(
            vec![finding(
                "/tmp/project/src/app.py",
                10,
                "password = [REDACTED]",
            )],
            "/tmp/project",
        );
        let baseline = build_baseline(&report, &root);
        let encoded = serde_json::to_string(&baseline).unwrap();
        assert!(!encoded.contains("password = [REDACTED]"));
        assert!(encoded.contains("fingerprint"));
    }
}
