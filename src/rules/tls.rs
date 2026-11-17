use super::make_finding;
use crate::models::{Confidence, Severity};
use regex::Regex;
use std::path::Path;

pub fn check(path: &Path, content: &str) -> Vec<crate::models::Finding> {
    let disabled = Regex::new(
        r"(?i)(verify\s*=\s*false|CERT_NONE|danger_accept_invalid_certs\s*\(\s*true\s*\)|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)",
    )
    .expect("literal regex is valid");
    let mut findings = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if disabled.is_match(line) {
            findings.push(make_finding(
                path, index + 1, "FS-TLS-001", Severity::High,
                "TLS certificate verification appears to be disabled", Some("CWE-295"), Confidence::High,
                line,
                "The source explicitly disables a common TLS certificate verification check.",
                "Connections may accept certificates that cannot be authenticated, increasing exposure to man-in-the-middle attacks.",
                "Enable certificate verification and configure a trusted certificate authority. Restrict any test-only bypass to isolated tests and ensure it cannot reach production builds.",
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_disabled_verification() {
        assert_eq!(
            check(Path::new("client.py"), "requests.get(url, verify=False)\n").len(),
            1
        );
    }

    #[test]
    fn ignores_normal_tls_configuration() {
        assert!(check(Path::new("client.py"), "requests.get(url, verify=True)\n").is_empty());
    }
}
