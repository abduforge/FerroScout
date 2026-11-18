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
    writeln!(
        &mut output,
        "Suppressed by source comments: {}",
        report.suppressed_findings
    )
    .expect("String writes cannot fail");
    writeln!(
        &mut output,
        "Filtered by CLI options: {}",
        report.filtered_findings
    )
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

fn markdown_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '\\' => escaped.push_str("\\\\"),
            '`' => escaped.push_str("\\`"),
            '*' => escaped.push_str("\\*"),
            '_' => escaped.push_str("\\_"),
            '[' => escaped.push_str("\\["),
            ']' => escaped.push_str("\\]"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '|' => escaped.push_str("\\|"),
            '\n' | '\r' => escaped.push(' '),
            other => escaped.push(other),
        }
    }
    escaped
}

pub fn render_markdown(report: &ScanReport) -> String {
    let mut output = String::new();
    output.push_str("# FerroScout Security Report\n\n");
    writeln!(
        &mut output,
        "- **Target:** {}",
        markdown_escape(&report.target)
    )
    .expect("String writes cannot fail");
    writeln!(&mut output, "- **Status:** {}", status_name(report.status))
        .expect("String writes cannot fail");
    writeln!(&mut output, "- **Files scanned:** {}", report.files_scanned)
        .expect("String writes cannot fail");
    writeln!(
        &mut output,
        "- **Entries skipped:** {}",
        report.entries_skipped
    )
    .expect("String writes cannot fail");
    writeln!(&mut output, "- **Findings:** {}", report.findings.len())
        .expect("String writes cannot fail");
    writeln!(
        &mut output,
        "- **Suppressed by source comments:** {}",
        report.suppressed_findings
    )
    .expect("String writes cannot fail");
    writeln!(
        &mut output,
        "- **Filtered by CLI options:** {}\n",
        report.filtered_findings
    )
    .expect("String writes cannot fail");

    if report.findings.is_empty() {
        output.push_str("No findings passed the selected filters. This is not a guarantee that the scanned code is secure.\n");
    }

    for finding in &report.findings {
        output.push_str("\n---\n\n");
        writeln!(
            &mut output,
            "## [{}] {}",
            severity_name(finding.severity),
            markdown_escape(&finding.title)
        )
        .expect("String writes cannot fail");
        writeln!(
            &mut output,
            "- **Location:** {}:{}",
            markdown_escape(&finding.file),
            finding.line
        )
        .expect("String writes cannot fail");
        writeln!(
            &mut output,
            "- **Rule:** {}",
            markdown_escape(&finding.rule_id)
        )
        .expect("String writes cannot fail");
        if let Some(cwe) = &finding.cwe {
            writeln!(&mut output, "- **CWE:** {}", markdown_escape(cwe))
                .expect("String writes cannot fail");
        }
        writeln!(
            &mut output,
            "- **Confidence:** {}\n",
            confidence_name(finding.confidence)
        )
        .expect("String writes cannot fail");
        writeln!(
            &mut output,
            "**Evidence:** {}\n",
            markdown_escape(&finding.evidence)
        )
        .expect("String writes cannot fail");
        writeln!(
            &mut output,
            "**Explanation:** {}\n",
            markdown_escape(&finding.explanation)
        )
        .expect("String writes cannot fail");
        writeln!(
            &mut output,
            "**Potential impact:** {}\n",
            markdown_escape(&finding.impact)
        )
        .expect("String writes cannot fail");
        writeln!(
            &mut output,
            "**Recommendation:** {}",
            markdown_escape(&finding.recommendation)
        )
        .expect("String writes cannot fail");
    }

    if !report.scan_errors.is_empty() {
        output.push_str("\n## Scan errors\n\n");
        for error in &report.scan_errors {
            writeln!(&mut output, "- {}", markdown_escape(error))
                .expect("String writes cannot fail");
        }
    }
    output.push_str("\n---\n\n*Static findings are review leads, not proof of exploitability. A clean report does not guarantee security.*\n");
    output
}

fn sarif_uri(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let normalized = normalized.strip_prefix("./").unwrap_or(&normalized);
    let mut encoded = String::with_capacity(normalized.len());

    for byte in normalized.bytes() {
        let character = byte as char;
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_' | '~' | '/') {
            encoded.push(character);
        } else {
            write!(&mut encoded, "%{byte:02X}").expect("String writes cannot fail");
        }
    }

    encoded
}

pub fn render_sarif(report: &ScanReport) -> Result<String, serde_json::Error> {
    use serde_json::json;

    let rules = crate::rules::rule_catalog()
        .iter()
        .map(|(id, description)| {
            json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": description },
                "fullDescription": { "text": description },
                "help": { "text": description },
                "defaultConfiguration": { "level": "warning" },
                "properties": { "tags": ["security"] }
            })
        })
        .collect::<Vec<_>>();

    let results = report
        .findings
        .iter()
        .map(|finding| {
            let level = match finding.severity {
                Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };
            let mut properties = serde_json::Map::new();
            properties.insert("severity".to_owned(), json!(finding.severity));
            properties.insert("confidence".to_owned(), json!(finding.confidence));
            properties.insert("evidence".to_owned(), json!(&finding.evidence));
            properties.insert("impact".to_owned(), json!(&finding.impact));
            properties.insert("recommendation".to_owned(), json!(&finding.recommendation));
            if let Some(cwe) = &finding.cwe {
                properties.insert("cwe".to_owned(), json!(cwe));
            }

            let uri = sarif_uri(&finding.file);

            json!({
                "ruleId": finding.rule_id,
                "level": level,
                "message": {
                    "text": format!("{}\n\n{}", finding.title, finding.explanation)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri
                        },
                        "region": { "startLine": finding.line }
                    }
                }],
                "properties": properties
            })
        })
        .collect::<Vec<_>>();

    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "FerroScout",
                    "version": &report.version,
                    "informationUri": "https://github.com/abduforge/FerroScout",
                    "rules": rules
                }
            },
            "results": results,
            "properties": {
                "scanStatus": status_name(report.status),
                "target": &report.target,
                "filesScanned": report.files_scanned,
                "entriesSkipped": report.entries_skipped,
                "suppressedFindings": report.suppressed_findings,
                "filteredFindings": report.filtered_findings,
                "scanErrors": &report.scan_errors
            }
        }]
    });

    serde_json::to_string_pretty(&document)
}

#[cfg(test)]
mod tests {
    use super::{markdown_escape, render_json, render_markdown, render_sarif, sarif_uri};
    use crate::models::{Confidence, Finding, ScanReport, ScanStatus, Severity};

    #[test]
    fn json_output_contains_status_and_finding_array() {
        let report = ScanReport {
            tool: "FerroScout".to_owned(),
            version: "0.3.0".to_owned(),
            target: "./sample".to_owned(),
            status: ScanStatus::NoIssuesFound,
            files_scanned: 1,
            entries_skipped: 0,
            suppressed_findings: 0,
            filtered_findings: 0,
            findings: Vec::new(),
            scan_errors: Vec::new(),
        };
        let json = render_json(&report).unwrap();
        assert!(json.contains("NO_ISSUES_FOUND"));
        assert!(json.contains("\"findings\": []"));
    }

    #[test]
    fn markdown_report_contains_summary_and_escapes_untrusted_text() {
        let report = ScanReport {
            tool: "FerroScout".to_owned(),
            version: "0.3.0".to_owned(),
            target: "./sample`[x]".to_owned(),
            status: ScanStatus::FindingsFound,
            files_scanned: 1,
            entries_skipped: 0,
            suppressed_findings: 1,
            filtered_findings: 2,
            findings: vec![Finding {
                severity: Severity::Medium,
                title: "Unsafe *rendering*".to_owned(),
                file: "./src/app.js".to_owned(),
                line: 7,
                rule_id: "FS-XSS-001".to_owned(),
                cwe: Some("CWE-79".to_owned()),
                confidence: Confidence::Medium,
                evidence: "element.innerHTML = userInput".to_owned(),
                explanation: "Untrusted input may reach an HTML sink.".to_owned(),
                impact: "Script execution may be possible.".to_owned(),
                recommendation: "Use textContent or a vetted sanitizer.".to_owned(),
            }],
            scan_errors: Vec::new(),
        };
        let markdown = render_markdown(&report);
        assert!(markdown.contains("# FerroScout Security Report"));
        assert!(markdown.contains("Suppressed by source comments: 1"));
        assert!(markdown.contains("Filtered by CLI options: 2"));
        assert!(markdown.contains("Unsafe \\*rendering\\*"));
        assert!(markdown.contains("sample\\`\\[x\\]"));
        assert!(markdown_escape("<script>&").contains("&lt;script&gt;&amp;"));
    }

    #[test]
    fn sarif_uri_is_relative_and_escapes_spaces() {
        assert_eq!(sarif_uri("./src/my file.rs"), "src/my%20file.rs");
    }

    #[test]
    fn sarif_output_contains_rule_location_and_redacted_evidence() {
        let report = ScanReport {
            tool: "FerroScout".to_owned(),
            version: "0.3.0".to_owned(),
            target: "./sample".to_owned(),
            status: ScanStatus::FindingsFound,
            files_scanned: 1,
            entries_skipped: 0,
            suppressed_findings: 0,
            filtered_findings: 0,
            findings: vec![Finding {
                severity: Severity::High,
                title: "Potential hardcoded credential".to_owned(),
                file: "./src/config.py".to_owned(),
                line: 12,
                rule_id: "FS-SECRET-001".to_owned(),
                cwe: Some("CWE-798".to_owned()),
                confidence: Confidence::Medium,
                evidence: "password = [REDACTED]".to_owned(),
                explanation: "Credential-like assignment found.".to_owned(),
                impact: "A real credential may be exposed.".to_owned(),
                recommendation: "Use a secret store.".to_owned(),
            }],
            scan_errors: Vec::new(),
        };

        let sarif = render_sarif(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["results"][0]["ruleId"], "FS-SECRET-001");
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
                ["startLine"],
            12
        );
        assert_eq!(
            parsed["runs"][0]["results"][0]["properties"]["evidence"],
            "password = [REDACTED]"
        );
        assert_eq!(
            parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "src/config.py"
        );
    }
}
