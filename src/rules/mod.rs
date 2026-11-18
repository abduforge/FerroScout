pub mod cors;
pub mod crypto;
pub mod debug;
pub mod deserialization;
pub mod injection;
pub mod path_traversal;
pub mod secrets;
pub mod ssrf;
pub mod taint;
pub mod tls;
pub mod xss;

use crate::models::Finding;
use std::path::Path;

pub fn scan_file(path: &Path, content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(secrets::check(path, content));
    findings.extend(xss::check(path, content));
    findings.extend(injection::check(path, content));
    findings.extend(path_traversal::check(path, content));
    findings.extend(ssrf::check(path, content));
    findings.extend(cors::check(path, content));
    findings.extend(deserialization::check(path, content));
    findings.extend(tls::check(path, content));
    findings.extend(debug::check(path, content));
    findings.extend(crypto::check(path, content));
    findings
}

pub fn rule_catalog() -> &'static [(&'static str, &'static str)] {
    &[
        ("FS-SECRET-001", "Potential hardcoded credential or private key material"),
        ("FS-XSS-001", "Untrusted input appears near a dangerous HTML sink"),
        ("FS-INJECT-001", "Dynamic data appears in a SQL or shell command construction"),
        ("FS-PATH-001", "Untrusted data appears in a filesystem path operation"),
        ("FS-SSRF-001", "Untrusted data appears to control a server-side request URL"),
        ("FS-TAINT-001", "User-controlled data reaches a sensitive sink through simple assignment or module-import flow"),
        ("FS-CORS-001", "Credentialed CORS appears to reflect arbitrary origins"),
        ("FS-DESER-001", "Potentially unsafe deserialization API"),
        ("FS-TLS-001", "TLS certificate verification appears to be disabled"),
        ("FS-DEBUG-001", "Application debug mode appears to be enabled"),
        ("FS-CRYPTO-001", "Potentially weak password hashing or security-sensitive randomness"),
    ]
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn make_finding(
    path: &Path,
    line: usize,
    rule_id: &str,
    severity: crate::models::Severity,
    title: &str,
    cwe: Option<&str>,
    confidence: crate::models::Confidence,
    evidence: &str,
    explanation: &str,
    impact: &str,
    recommendation: &str,
) -> Finding {
    Finding {
        severity,
        title: title.to_owned(),
        file: path.display().to_string(),
        line,
        rule_id: rule_id.to_owned(),
        cwe: cwe.map(str::to_owned),
        confidence,
        evidence: redact_evidence(evidence),
        explanation: explanation.to_owned(),
        impact: impact.to_owned(),
        recommendation: recommendation.to_owned(),
    }
}

pub(crate) fn redact_evidence(line: &str) -> String {
    use regex::Regex;
    let secret_assignment = Regex::new(
        r#"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)["']?\s*([:=])\s*["']?[^\s,;"']+"#,
    )
    .expect("literal regex is valid");
    let redacted = secret_assignment.replace_all(line, "$1$2[REDACTED]");
    let bearer = Regex::new(r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._~+/-]+=*")
        .expect("literal regex is valid");
    let redacted = bearer.replace_all(&redacted, "$1[REDACTED]");
    let private_key =
        Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").expect("literal regex is valid");
    private_key
        .replace_all(&redacted, "[PRIVATE KEY MATERIAL REDACTED]")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::redact_evidence;

    #[test]
    fn redacts_json_style_secret_assignments() {
        let evidence = r#"{ "password": "my-real-password-value" }"#;
        let redacted = redact_evidence(evidence);
        assert!(!redacted.contains("my-real-password-value"));
        assert!(redacted.contains("REDACTED"));
    }

    #[test]
    fn redacts_bearer_tokens() {
        let evidence = "Authorization: Bearer abc.def.ghi";
        let redacted = redact_evidence(evidence);
        assert!(!redacted.contains("abc.def.ghi"));
    }
}
