use super::make_finding;
use crate::models::{Confidence, Severity};
use regex::Regex;
use std::path::Path;

pub fn check(path: &Path, content: &str) -> Vec<crate::models::Finding> {
    let request = Regex::new(
        r"(?i)\b(?:fetch|axios\.(?:get|post|request)|requests\.(?:get|post|request)|http\.get|https\.get|client\.get)\s*\(",
    )
    .expect("literal regex is valid");
    let dynamic_url = Regex::new(
        r"(?i)(req(?:uest)?\.(?:body|query|params)|request\.(?:args|form)|user[_A-Z]?input)",
    )
    .expect("literal regex is valid");
    let mut findings = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if request.is_match(line) && dynamic_url.is_match(line) {
            findings.push(make_finding(
                path, index + 1, "FS-SSRF-001", Severity::Medium,
                "Potential user-controlled server-side request URL", Some("CWE-918"), Confidence::Medium,
                line,
                "An HTTP request call and a dynamic URL marker appear on the same line. The destination validation and network context are not known.",
                "If users can control the destination, the server may be induced to request internal or otherwise unintended resources.",
                "Use an allowlist of permitted hosts and schemes, validate resolved destinations, reject loopback and private network ranges where appropriate, and disable redirects or revalidate each redirect.",
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_request_using_user_supplied_url() {
        let code = "const response = await fetch(req.query.url);\n";
        assert_eq!(check(Path::new("api.js"), code).len(), 1);
    }

    #[test]
    fn ignores_constant_url() {
        let code = "const response = await fetch('https://example.test/status');\n";
        assert!(check(Path::new("api.js"), code).is_empty());
    }
}
