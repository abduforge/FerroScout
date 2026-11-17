use crate::models::{Confidence, ScanReport, ScanStatus, Severity};
use std::fmt::Write;

pub fn render_text(report: &ScanReport) -> String {
    let mut output = String::new();
    output.push_str("FerroScout Security Report\n");
    output.push_str("==========================\n\n");
    writeln!(&mut output, "Target: {}", report.target).expect("String writes cannot fail");
    writeln!(&mut output, "Files scanned: {}", report.files_scanned)
        .expect("String writes cannot fail");
    writeln!(&mut output, "Entries skipped: {}", report.entries_skipped)
        .expect("String writes cannot fail");
    writeln!(&mut output, "Findings: {}", report.findings.len())
        .expect("String writes cannot fail");
    writeln!(&mut output, "Status: {}", status_name(report.status))
        .expect("String writes cannot fail");

    for finding in &report.findings {
        output.push_str("\n--------------------------------\n\n");
        writeln!(
            &mut output,
            "[{}] {}",
            severity_name(finding.severity),
            finding.title
        )
        .expect("String writes cannot fail");
        writeln!(&mut output, "File: {}", finding.file).expect("String writes cannot fail");
        writeln!(&mut output, "Line: {}", finding.line).expect("String writes cannot fail");
        writeln!(&mut output, "Rule: {}", finding.rule_id).expect("String writes cannot fail");
        if let Some(cwe) = &finding.cwe {
            writeln!(&mut output, "CWE: {cwe}").expect("String writes cannot fail");
        }
        writeln!(
            &mut output,
            "Confidence: {}\n",
            confidence_name(finding.confidence)
        )
        .expect("String writes cannot fail");
        writeln!(&mut output, "Evidence:\n{}", finding.evidence)
            .expect("String writes cannot fail");
        writeln!(&mut output, "\nExplanation:\n{}", finding.explanation)
            .expect("String writes cannot fail");
        writeln!(&mut output, "\nPotential impact:\n{}", finding.impact)
            .expect("String writes cannot fail");
        writeln!(&mut output, "\nRecommendation:\n{}", finding.recommendation)
            .expect("String writes cannot fail");
    }

    if !report.scan_errors.is_empty() {
        output.push_str("\nScan warnings/errors:\n");
        for error in &report.scan_errors {
            writeln!(&mut output, "- {error}").expect("String writes cannot fail");
        }
    }
    output.push_str(
        "\nScan completed. Static findings are review leads, not proof of exploitability.\n",
    );
    output
}

fn status_name(status: ScanStatus) -> &'static str {
    match status {
        ScanStatus::FindingsFound => "FINDINGS_FOUND",
        ScanStatus::NoIssuesFound => "NO_ISSUES_FOUND",
        ScanStatus::InsufficientContext => "INSUFFICIENT_CONTEXT",
    }
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
    }
}

fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "LOW",
        Confidence::Medium => "MEDIUM",
        Confidence::High => "HIGH",
    }
}

pub fn render_json(report: &ScanReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ScanStatus;

    #[test]
    fn json_output_contains_status_and_finding_array() {
        let report = ScanReport {
            tool: "FerroScout".to_owned(),
            version: "0.1.0".to_owned(),
            target: "./sample".to_owned(),
            status: ScanStatus::NoIssuesFound,
            files_scanned: 1,
            entries_skipped: 0,
            findings: Vec::new(),
            scan_errors: Vec::new(),
        };
        let json = render_json(&report).unwrap();
        assert!(json.contains("NO_ISSUES_FOUND"));
        assert!(json.contains("\"findings\": []"));
    }
}
