use super::make_finding;
use crate::models::{Confidence, Severity};
use regex::Regex;
use std::path::Path;

pub fn check(path: &Path, content: &str) -> Vec<crate::models::Finding> {
    let credentials = Regex::new(
        r#"(?i)(access-control-allow-credentials\s*[:=]\s*["']?true|(?:allow_)?credentials\s*[:=]\s*true)"#,
    )
    .expect("literal regex is valid");
    let dynamic_origin = Regex::new(r#"(?i)(origin\s*:\s*true|setHeader\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*(?:origin|req\.headers\.origin))"#)
        .expect("literal regex is valid");
    let lines: Vec<&str> = content.lines().collect();
    let credentialed = lines.iter().any(|line| credentials.is_match(line));
    if !credentialed {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if dynamic_origin.is_match(line) {
            findings.push(make_finding(
                path, index + 1, "FS-CORS-001", Severity::Medium,
                "Credentialed CORS appears to reflect arbitrary origins", Some("CWE-942"), Confidence::Medium,
                line,
                "The same file contains credentialed CORS configuration and a pattern that reflects the requesting origin. Runtime behavior and framework defaults still require review.",
                "If browsers are allowed to send credentials to arbitrary origins, a malicious website may be able to read authenticated responses in affected configurations.",
                "Use an explicit allowlist of trusted origins. Do not combine wildcard origins with credentialed requests, and validate reflected origins against that allowlist.",
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_reflected_origin_with_credentials() {
        let code = "origin: true\nallow_credentials = true\n";
        assert_eq!(check(Path::new("cors.conf"), code).len(), 1);
    }

    #[test]
    fn does_not_flag_wildcard_origin_alone() {
        let code = "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true\n";
        assert!(check(Path::new("headers.conf"), code).is_empty());
    }
}
